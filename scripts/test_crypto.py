"""crypto_core 模块自测脚本: 验证 SM2 协商 + SM4 加解密能跑通"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_core.sm2_kex import (
    gen_keypair, point_to_bytes, bytes_to_point,
    SM2KeyExchange, derive_key_id,
)
from crypto_core.sm4_soft import sm4_cbc_encrypt, sm4_cbc_decrypt
from crypto_core import sm4_backend


def test_sm2_kex():
    print("[*] 生成长期密钥对...")
    dA, PA = gen_keypair()
    dB, PB = gen_keypair()
    idA = b"client@pc"
    idB = b"server@pi"

    a = SM2KeyExchange("A", idA, dA, PA, idB, PB, klen=16)
    b = SM2KeyExchange("B", idB, dB, PB, idA, PA, klen=16)

    RA = a.gen_ephemeral()
    RB = b.gen_ephemeral()

    KB = b.compute_shared(RA)
    KA = a.compute_shared(RB)
    assert KA == KB, "SM2 协商失败: KA != KB"
    print(f"    KA = {KA.hex()}")
    print(f"    KB = {KB.hex()}")
    print(f"    Key ID = {derive_key_id(KA)}")

    # 双向校验
    assert a.S1 == b.S1 and a.SA == b.SA, "SM2 校验值不一致"
    print("[+] SM2 三轮密钥协商成功, 双向校验通过")
    return KA


def test_sm4(key):
    iv = os.urandom(16)
    pt = b"Hello, SM4 cipher! This is a longer message for CBC test." * 100
    print(f"[*] 软件 SM4-CBC 加解密 ({len(pt)} bytes)...")
    t0 = time.time()
    ct = sm4_cbc_encrypt(key, iv, pt)
    t1 = time.time()
    pt2 = sm4_cbc_decrypt(key, iv, ct)
    t2 = time.time()
    assert pt == pt2, "SM4 解密结果不一致"
    print(f"    加密耗时 {(t1-t0)*1000:.2f} ms, 解密耗时 {(t2-t1)*1000:.2f} ms")
    print(f"    密文前 32 字节: {ct[:32].hex()}")
    print("[+] 软件 SM4 加解密成功")

    print(f"[*] 后端可用情况: {sm4_backend.list_backends()}")
    if sm4_backend.HW_AVAILABLE:
        print("[*] 检测到 AF_ALG 硬件后端, 测试硬件解密...")
        ct_hw = sm4_backend.encrypt(key, iv, pt, backend="hw")
        pt_hw = sm4_backend.decrypt(key, iv, ct_hw, backend="hw")
        assert pt == pt_hw and ct == ct_hw, "硬件后端结果与软件不一致"
        print("[+] AF_ALG 硬件后端验证通过, 软硬结果一致")
    else:
        print("[!] 当前环境无 AF_ALG cbc(sm4) 支持 (在 PC/沙箱中是正常的)")


if __name__ == "__main__":
    K = test_sm2_kex()
    test_sm4(K)
    print("\n所有测试通过 ✓")
