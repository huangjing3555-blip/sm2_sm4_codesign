"""
SM4 后端统一入口
提供两个后端: 'soft'(软件) 和 'hw'(AF_ALG 硬件加速)
软硬协同的核心: 上层调用方只需选择 backend, 即可在两种实现间无缝切换。
"""
from . import sm4_soft

try:
    from . import sm4_afalg
    HW_AVAILABLE = sm4_afalg.is_available()
except Exception:
    sm4_afalg = None
    HW_AVAILABLE = False


def encrypt(key: bytes, iv: bytes, plaintext: bytes, backend: str = "soft") -> bytes:
    if backend == "hw":
        if not HW_AVAILABLE:
            raise RuntimeError("AF_ALG 硬件后端不可用, 请检查内核是否启用 SM4")
        return sm4_afalg.sm4_cbc_encrypt(key, iv, plaintext)
    return sm4_soft.sm4_cbc_encrypt(key, iv, plaintext)


def decrypt(key: bytes, iv: bytes, ciphertext: bytes, backend: str = "soft") -> bytes:
    if backend == "hw":
        if not HW_AVAILABLE:
            raise RuntimeError("AF_ALG 硬件后端不可用, 请检查内核是否启用 SM4")
        return sm4_afalg.sm4_cbc_decrypt(key, iv, ciphertext)
    return sm4_soft.sm4_cbc_decrypt(key, iv, ciphertext)


def list_backends() -> dict:
    return {
        "soft": True,
        "hw":   HW_AVAILABLE,
    }
