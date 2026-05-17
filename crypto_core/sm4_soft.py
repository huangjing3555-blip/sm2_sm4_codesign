"""
SM4 纯软件实现 (调用 gmssl-python)
作为 PC 端默认实现, 也作为香橙派端 Benchmark 对比的"软件基线"。
"""
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


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


def sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes, pad: bool = True) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    cipher = CryptSM4()
    cipher.set_key(key, SM4_ENCRYPT)
    data = _pkcs7_pad(plaintext) if pad else plaintext
    return cipher.crypt_cbc(iv, data)


def sm4_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes, pad: bool = True) -> bytes:
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    cipher = CryptSM4()
    cipher.set_key(key, SM4_DECRYPT)
    out = cipher.crypt_cbc(iv, ciphertext)
    return _pkcs7_unpad(out) if pad else out
