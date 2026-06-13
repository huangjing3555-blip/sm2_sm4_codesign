"""
SM4 纯软件实现 (调用 gmssl-python)
作为 PC 端默认实现, 也作为香橙派端 Benchmark 对比的"软件基线"。
"""
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"非法 PKCS7 填充: {pad_len}")
    return data[:-pad_len]


def sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes, pad: bool = True) -> bytes:
    """SM4-CBC 加密。

    重要: gmssl 的 CryptSM4.crypt_cbc 在 SM4_ENCRYPT 路径内部已经调用了
    pkcs7_padding(), 这里不能再外层 padding 一次, 否则会出现 "双重 PKCS7"
    (密文长度比预期多一个 16 字节块), 且 soft 加密的输出与 AF_ALG 加密不兼容。

    参数:
      pad=False 时不进行 PKCS7 padding。但 gmssl 的 crypt_cbc 总会 padding,
      因此 pad=False 暂不支持。
    """
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    if not pad:
        raise NotImplementedError(
            "gmssl.CryptSM4.crypt_cbc 总会执行 PKCS7 padding, 不支持无填充模式"
        )
    cipher = CryptSM4()
    cipher.set_key(key, SM4_ENCRYPT)
    return cipher.crypt_cbc(iv, plaintext)


def sm4_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes, pad: bool = True) -> bytes:
    """SM4-CBC 解密。

    重要: gmssl 的 CryptSM4.crypt_cbc 在 SM4_DECRYPT 路径不执行 unpad,
    所以 unpad 由本函数负责。
    """
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    if pad and len(ciphertext) % 16 != 0:
        raise ValueError("SM4-CBC 密文长度必须是 16 的倍数")
    cipher = CryptSM4()
    cipher.set_key(key, SM4_DECRYPT)
    out = cipher.crypt_cbc(iv, ciphertext)
    return _pkcs7_unpad(out) if pad else out