"""
SM4 纯软件实现 (调用 gmssl-python)
作为 PC 端默认实现, 也作为香橙派端 Benchmark 对比的"软件基线"。

重要: gmssl 的 CryptSM4.crypt_cbc 在加密和解密路径都会自动处理 PKCS7:
  - 加密路径: input_data = pkcs7_padding(bytes_to_list(input_data))
  - 解密路径: return list_to_bytes(pkcs7_unpadding(output_data))
所以本模块不能在外层再 pad / unpad, 否则会出现双重 PKCS7 处理.
"""
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT


def sm4_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes, pad: bool = True) -> bytes:
    """SM4-CBC 加密。

    重要: gmssl 的 CryptSM4.crypt_cbc 在 SM4_ENCRYPT 路径内部已经调用了
    pkcs7_padding(), 这里不能再外层 padding 一次, 否则会出现 "双重 PKCS7"
    (密文长度比预期多一个 16 字节块), 且 soft 加密的输出与 AF_ALG 加密不兼容。

    参数:
      pad=False 时不进行 PKCS7 padding。但 gmssl 的 crypt_cbc 总会 padding,
      因此 pad=False 必须保证 plaintext 本身已是 16 字节倍数 (此时 gmssl
      仍会补一个完整 16 字节的 0x10 padding 块)。
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

    重要: gmssl 的 CryptSM4.crypt_cbc 在 SM4_DECRYPT 路径会调用
    pkcs7_unpadding() (gmssl/sm4.py 最后一行), 所以 unpad 由 gmssl 负责,
    这里不能再外层 unpad 一次. 否则会出现 "双重 PKCS7 unpadding",
    第二个 unpad 会把明文末尾的随机字节当作 padding 解析, 报
    "非法 PKCS7 填充: <某个 > 16 的值>"。

    加密路径一样: gmssl.crypt_cbc(SM4_ENCRYPT) 也会调用 pkcs7_padding(),
    所以 sm4_cbc_encrypt 也不能外层 padding.

    总结:
      - 加密: gmssl 自动 PKCS7 padding, 外层不能再 padding
      - 解密: gmssl 自动 PKCS7 unpadding, 外层不能再 unpad
      - padding 参数暂时固定为 True, gmssl 不支持 raw CBC
    """
    if len(key) != 16 or len(iv) != 16:
        raise ValueError("SM4 key/iv 必须为 16 字节")
    if pad and len(ciphertext) % 16 != 0:
        raise ValueError("SM4-CBC 密文长度必须是 16 的倍数")
    cipher = CryptSM4()
    cipher.set_key(key, SM4_DECRYPT)
    return cipher.crypt_cbc(iv, ciphertext)