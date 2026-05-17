"""
SM4 硬件加速实现 - 通过 Linux AF_ALG 接口直接调用内核 Crypto 引擎

工作原理:
1. AF_ALG 是 Linux 内核提供给用户态的密码学接口, 通过 Netlink 风格的 socket
   将数据交给内核 crypto subsystem。
2. RK3588 的 rk_crypto 驱动 (CONFIG_CRYPTO_DEV_ROCKCHIP) 注册到内核 crypto
   subsystem 后, 内核会优先选择硬件实现来处理 SM4-CBC。
3. 因此从用户态看, 我们只需要打开 AF_ALG socket 并指定 cbc(sm4), 数据就会
   自动被 RK3588 的硬件 Crypto Engine 处理, 无需改一行用户态代码。

注意:
- 本模块仅在 Linux (香橙派) 上可用, Windows 端不应导入。
- 如果当前内核未编译 sm4 算法, 调用 bind 会失败, 此时 try_open 返回 False,
  上层应回退到软件实现。
"""
import os
import socket
import sys
import struct

# 仅在 Linux 上可用
IS_LINUX = sys.platform.startswith("linux")

# AF_ALG 常量 (Linux 内核 if_alg.h)
AF_ALG       = 38
SOL_ALG      = 279
ALG_SET_KEY  = 1
ALG_SET_IV   = 2
ALG_SET_OP   = 3
ALG_OP_DECRYPT = 0
ALG_OP_ENCRYPT = 1


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


class AFAlgUnavailable(Exception):
    pass


def is_available() -> bool:
    """探测内核是否支持 cbc(sm4) 算法 (用于 RK3588 硬件加速)"""
    if not IS_LINUX:
        return False
    try:
        sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        try:
            sock.bind(("skcipher", "cbc(sm4)"))
            return True
        finally:
            sock.close()
    except OSError:
        return False
    except Exception:
        return False


def _do_op(op: int, key: bytes, iv: bytes, data: bytes) -> bytes:
    if not IS_LINUX:
        raise AFAlgUnavailable("AF_ALG 仅在 Linux 上可用")
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")

    sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        try:
            sock.bind(("skcipher", "cbc(sm4)"))
        except OSError as e:
            raise AFAlgUnavailable(f"内核不支持 cbc(sm4): {e}")

        sock.setsockopt(SOL_ALG, ALG_SET_KEY, key)

        op_sock, _ = sock.accept()
        try:
            # 通过 sendmsg 一次性送上 IV、操作类型 与 数据
            # 控制消息: SOL_ALG + ALG_SET_OP / ALG_SET_IV
            # ALG_SET_OP cmsg data: 4 字节 int
            # ALG_SET_IV cmsg data: af_alg_iv 结构 -> u32 ivlen + iv
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


def sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes, pad: bool = True) -> bytes:
    data = _pkcs7_pad(plaintext) if pad else plaintext
    return _do_op(ALG_OP_ENCRYPT, key, iv, data)


def sm4_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes, pad: bool = True) -> bytes:
    if len(ciphertext) % 16 != 0:
        raise ValueError("SM4-CBC 密文长度必须是 16 的倍数")
    out = _do_op(ALG_OP_DECRYPT, key, iv, ciphertext)
    return _pkcs7_unpad(out) if pad else out
