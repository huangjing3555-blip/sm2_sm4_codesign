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

# SM4 ECB 已知答案测试向量 (GB/T 32907-2016 附录 A)
# key = 0123456789ABCDEFFEDCBA9876543210
# plaintext  = 0123456789ABCDEFFEDCBA9876543210
# ciphertext = 681EDF34D206965E86B3E94F536E4246
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
    """直接调用 AF_ALG，不做任何字节序适配"""
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
            cmsgs = [
                (SOL_ALG, ALG_SET_OP, struct.pack("I", op)),
                (SOL_ALG, ALG_SET_IV, iv_buf),
            ]
            op_sock.sendmsg([data], cmsgs)
            out = bytearray()
            remaining = len(data)
            while remaining > 0:
                chunk = op_sock.recv(remaining)
                if not chunk:
                    break
                out.extend(chunk)
                remaining -= len(chunk)
            return bytes(out)
        finally:
            op_sock.close()
    finally:
        sock.close()


def _detect_byteswap() -> bool:
    """
    探测内核 SM4 是否需要字节序适配。
    用 SM4 ECB 已知答案向量测试：
      - 若内核结果与标准一致 → 不需要适配
      - 若内核结果是标准结果的每 4 字节翻转 → 需要适配
      - 其他情况 → 抛出异常（内核实现不兼容）
    """
    # ECB 模式: IV 全零, 数据 = 1 块 16 字节
    zero_iv = b"\x00" * 16
    try:
        # 用 ECB 等效方法: CBC with zero IV, 单块, 不做 PKCS7
        raw = _raw_op(ALG_OP_ENCRYPT, _KAT_KEY, zero_iv, _KAT_PT)
    except AFAlgUnavailable:
        return False  # 不可用时不需要适配（is_available 会返回 False）

    if raw == _KAT_CT:
        print("[AF_ALG] 字节序探测: 内核 SM4 与国标一致, 无需适配")
        return False
    elif raw == _byteswap32(_KAT_CT):
        print("[AF_ALG] 字节序探测: 内核 SM4 存在字节序差异, 已启用自动适配")
        return True
    else:
        # 可能是 CBC 模式下 IV 影响了结果，尝试另一种探测方式
        # 用全零明文 + 全零 IV，比较软件实现
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
        # 加密前对明文做字节序翻转，加密后再翻转回来，使结果与软件一致
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