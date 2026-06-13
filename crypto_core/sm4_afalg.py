import os
import socket
import sys
import struct

IS_LINUX = sys.platform.startswith("linux")

# AF_ALG 常量 (Linux 内核 if_alg.h)
AF_ALG         = 38
SOL_ALG        = 279
ALG_SET_KEY    = 1
ALG_SET_IV     = 2
ALG_SET_OP     = 3
ALG_OP_DECRYPT = 0
ALG_OP_ENCRYPT = 1

# Linux 内核 crypto/af_alg.c:  #define ALG_MAX_PAGES 16
# 单次 recv 的用户缓冲区上限 (pages * PAGE_SIZE)，超过会被 skcipher_recvmsg
# 内部分批循环，配合 ctx->init 重置逻辑会造成永久阻塞。
_ALG_MAX_PAGES  = 16
_PAGE_SIZE      = 4096
_RECV_CHUNK_MAX = _ALG_MAX_PAGES * _PAGE_SIZE  # 64 KiB

# SM4 ECB 已知答案测试向量 (GB/T 32907-2016 附录 A)
_KAT_KEY = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
_KAT_PT  = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
_KAT_CT  = bytes.fromhex("681EDF34D206965E86B3E94F536E4246")

# 字节序适配标志: None=未探测, True=需要适配, False=不需要
_BYTESWAP_NEEDED = None


def _pkcs7_pad(data: bytes, block: int = 16) -> bytes:
    pad_len = block - (len(data) % block)
    return data + bytes([pad_len]) * pad_len


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"非法 PKCS7 填充: {pad_len}")
    return data[:-pad_len]


def _byteswap32(data: bytes) -> bytes:
    """对每个 4 字节字做字节序翻转（大端 <-> 小端）"""
    if len(data) % 4 != 0:
        raise ValueError("byteswap32 要求数据长度为 4 的倍数")
    result = bytearray(len(data))
    for i in range(0, len(data), 4):
        result[i:i+4] = data[i:i+4][::-1]
    return bytes(result)


class AFAlgUnavailable(Exception):
    pass


def _raw_op(op: int, key: bytes, iv: bytes, data: bytes) -> bytes:
    """直接调用 AF_ALG，不做任何字节序适配

    实现细节（基于 Linux 5.10 crypto/af_alg.c + crypto/algif_skcipher.c）:
      1. sndbuf 上限问题: AF_ALG 是"累积式"接口——sendmsg 把数据以页为单位
         拷贝到 scatterlist (ctx->used 增长), recv 触发解密后 ctx->used 才
         减少。sendmsg 外层循环检查 af_alg_writable(sk) =
         (PAGE_SIZE <= sk_sndbuf & PAGE_MASK - ctx->used), 不可写时阻塞在
         af_alg_wait_for_wmem 永久等待 sndbuf 空间。
         sk_sndbuf 受 /proc/sys/net/core/wmem_max 默认 212992 (≈ 208KB) 限制,
         即使 setsockopt(SO_SNDBUF) 也会被 cap. 所以 sendmsg 一次不能超过
         208KB 左右；超过就需要分块 sendmsg + 立即 recv 交替。
      2. ctx->init 重置问题: algif_skcipher.c 中 af_alg_pull_tsgl 末尾执行
         ctx->init = ctx->more. 不带 MSG_MORE 时第二次 _skcipher_recvmsg
         会因 ctx->init=false 永远阻塞在 af_alg_wait_for_data。我们让最后一块
         sendmsg 不带 MSG_MORE (more=false), 之前所有块带 MSG_MORE, 保证
         "中间块 recv 后 ctx->init 仍为 true, 最后一块 recv 后 ctx->init=false
         但已经拿到全部数据, recv 循环自然退出"。
      3. recv 单次限制: skcipher_recvmsg 内部是 while(msg_data_left) 循环,
         每次 _skcipher_recvmsg 都重置 ctx->init. 单次 recv 缓冲区限制在
         ALG_MAX_PAGES * PAGE_SIZE (64KiB) 以下, 避免触发内层循环。
    """
    if not IS_LINUX:
        raise AFAlgUnavailable("AF_ALG 仅在 Linux 上可用")

    sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        try:
            sock.bind(("skcipher", "cbc(sm4)"))
        except OSError as e:
            raise AFAlgUnavailable(f"内核不支持 cbc(sm4): {e}")

        sock.setsockopt(SOL_ALG, ALG_SET_KEY, key)
        op_sock, _ = sock.accept()
        try:
            iv_buf = struct.pack("I", len(iv)) + iv
            base_cmsgs = [
                (SOL_ALG, ALG_SET_OP, struct.pack("I", op)),
                (SOL_ALG, ALG_SET_IV, iv_buf),
            ]

            # 每块发送大小: 取 sndbuf 上限减去 16 KiB 余量. sndbuf 由 wmem_max
            # 默认 212992 限定, 按页对齐后可用 208KB, 减去余量取 192 KiB.
            # 这样不论内核 sndbuf 默认值还是调大后 (但被 cap) 都安全.
            BLOCK_SIZE = 192 * 1024
            if len(data) <= BLOCK_SIZE:
                # 小于等于单块: 直接一发一收, 不需要 MSG_MORE
                op_sock.sendmsg([data], base_cmsgs)
                out = bytearray()
                remaining = len(data)
                while remaining > 0:
                    want = remaining if remaining < _RECV_CHUNK_MAX else _RECV_CHUNK_MAX
                    got = op_sock.recv(want)
                    if not got:
                        break
                    out.extend(got)
                    remaining -= len(got)
                return bytes(out)

            # 多块: 分块 sendmsg + 立即 recv. 最后一块不带 MSG_MORE.
            out = bytearray()
            offset = 0
            is_first = True
            while offset < len(data):
                chunk = data[offset:offset + BLOCK_SIZE]
                offset += len(chunk)
                is_last = (offset >= len(data))

                if is_first:
                    cmsgs = list(base_cmsgs)
                    is_first = False
                else:
                    cmsgs = []

                flags = 0 if is_last else socket.MSG_MORE
                op_sock.sendmsg([chunk], cmsgs, flags)

                # 立即 recv 触发解密, 释放 sndbuf 空间
                recv_need = len(chunk)
                while recv_need > 0:
                    want = recv_need if recv_need < _RECV_CHUNK_MAX else _RECV_CHUNK_MAX
                    got = op_sock.recv(want)
                    if not got:
                        raise RuntimeError(
                            f"AF_ALG recv returned 0, need {recv_need} more bytes"
                        )
                    out.extend(got)
                    recv_need -= len(got)

            return bytes(out)
        finally:
            op_sock.close()
    finally:
        sock.close()


def _detect_byteswap() -> bool:
    """
    探测内核 SM4 是否需要字节序适配。
    """
    zero_iv = b"\x00" * 16
    try:
        raw = _raw_op(ALG_OP_ENCRYPT, _KAT_KEY, zero_iv, _KAT_PT)
    except AFAlgUnavailable:
        return False

    if raw == _KAT_CT:
        print("[AF_ALG] 字节序探测: 内核 SM4 与国标一致, 无需适配")
        return False
    elif raw == _byteswap32(_KAT_CT):
        print("[AF_ALG] 字节序探测: 内核 SM4 存在字节序差异, 已启用自动适配")
        return True
    else:
        try:
            from . import sm4_soft
            pt_zero = b"\x00" * 16
            ct_soft = sm4_soft.sm4_cbc_encrypt(_KAT_KEY, zero_iv, pt_zero, pad=False)
            ct_hw   = _raw_op(ALG_OP_ENCRYPT, _KAT_KEY, zero_iv, pt_zero)
            if ct_soft == ct_hw:
                print("[AF_ALG] 字节序探测(备用): 内核 SM4 与软件一致, 无需适配")
                return False
            elif ct_soft == _byteswap32(ct_hw):
                print("[AF_ALG] 字节序探测(备用): 内核 SM4 存在字节序差异, 已启用自动适配")
                return True
        except Exception:
            pass
        print(f"[AF_ALG] 警告: 内核 SM4 输出与已知答案不符 (raw={raw.hex()[:32]}), 尝试直接使用")
        return False


def is_available() -> bool:
    """探测内核是否支持 cbc(sm4)"""
    if not IS_LINUX:
        return False
    try:
        sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        try:
            sock.bind(("skcipher", "cbc(sm4)"))
            return True
        finally:
            sock.close()
    except Exception:
        return False


def _ensure_detected():
    """懒加载：首次调用时执行字节序探测"""
    global _BYTESWAP_NEEDED
    if _BYTESWAP_NEEDED is None:
        if not is_available():
            _BYTESWAP_NEEDED = False
        else:
            _BYTESWAP_NEEDED = _detect_byteswap()


def _do_op(op: int, key: bytes, iv: bytes, data: bytes) -> bytes:
    """带字节序适配的 AF_ALG 操作"""
    _ensure_detected()
    if _BYTESWAP_NEEDED:
        data_in = _byteswap32(data)
        raw = _raw_op(op, key, iv, data_in)
        return _byteswap32(raw)
    else:
        return _raw_op(op, key, iv, data)


def sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes, pad: bool = True) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    data = _pkcs7_pad(plaintext) if pad else plaintext
    return _do_op(ALG_OP_ENCRYPT, key, iv, data)


def sm4_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes, pad: bool = True) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    if len(ciphertext) % 16 != 0:
        raise ValueError("SM4-CBC 密文长度必须是 16 的倍数")
    out = _do_op(ALG_OP_DECRYPT, key, iv, ciphertext)
    return _pkcs7_unpad(out) if pad else out