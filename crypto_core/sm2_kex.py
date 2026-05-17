"""
SM2 密钥协商 (基于 gmssl-python 软件实现)

按照 GB/T 32918.3-2016 标准的 SM2 密钥交换协议（三轮握手）实现。
为了在课堂演示和真机部署中保持稳定可靠，本模块在底层通过 gmssl 库进行
椭圆曲线点乘和大数模运算，上层完整实现协议状态机。

注意：本系统的设计中，SM2 走纯软件，SM4 才是硬件加速的对象。
如此既能保留学术展示价值（密钥协商可读），又能突出 SM4 大流量
解密时硬件加速的吞吐优势。
"""
import os
import hashlib
import binascii

# 我们使用 gmssl 库提供 SM3，并自己实现 SM2 的椭圆曲线运算
# 这样不依赖 gmssl 的内部 SM2 类细节，跨版本更稳定。
from gmssl import sm3, func


# ================== SM2 推荐参数 (GB/T 32918.5-2017) ==================
SM2_P  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
SM2_A  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)
SM2_B  = int("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16)
SM2_N  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", 16) - 0
# 修正: SM2 推荐曲线的 n
SM2_N  = int("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
SM2_GX = int("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16)
SM2_GY = int("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16)
SM2_G  = (SM2_GX, SM2_GY)


def _inv(a, p):
    return pow(a, p - 2, p)


def _ec_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % SM2_P == 0:
        return None
    if P == Q:
        m = (3 * x1 * x1 + SM2_A) * _inv(2 * y1 % SM2_P, SM2_P) % SM2_P
    else:
        m = (y2 - y1) * _inv((x2 - x1) % SM2_P, SM2_P) % SM2_P
    x3 = (m * m - x1 - x2) % SM2_P
    y3 = (m * (x1 - x3) - y1) % SM2_P
    return (x3, y3)


def _ec_mul(k, P):
    """k * P 二进制展开法"""
    R = None
    Q = P
    while k > 0:
        if k & 1:
            R = _ec_add(R, Q)
        Q = _ec_add(Q, Q)
        k >>= 1
    return R


def _int_to_bytes(x, length=32):
    return x.to_bytes(length, "big")


def _bytes_to_int(b):
    return int.from_bytes(b, "big")


def _kdf(z: bytes, klen_bytes: int) -> bytes:
    """SM3 KDF, 返回 klen_bytes 字节的密钥派生输出"""
    ct = 1
    out = b""
    while len(out) < klen_bytes:
        msg = z + ct.to_bytes(4, "big")
        out += bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(msg)))
        ct += 1
    return out[:klen_bytes]


def sm3_hash(data: bytes) -> bytes:
    return bytes.fromhex(sm3.sm3_hash(func.bytes_to_list(data)))


# ================== SM2 密钥对 ==================

def gen_keypair():
    """生成 SM2 密钥对, 返回 (d, P), d 为整数, P 为点 (x, y)"""
    while True:
        d = _bytes_to_int(os.urandom(32)) % (SM2_N - 1)
        if d > 1:
            break
    P = _ec_mul(d, SM2_G)
    return d, P


def point_to_bytes(P):
    """未压缩点格式: 04 || x || y"""
    if P is None:
        return b"\x00"
    x, y = P
    return b"\x04" + _int_to_bytes(x) + _int_to_bytes(y)


def bytes_to_point(b):
    if b[0] != 0x04 or len(b) != 65:
        raise ValueError("仅支持未压缩 SM2 点格式 (04||x||y)")
    x = _bytes_to_int(b[1:33])
    y = _bytes_to_int(b[33:65])
    return (x, y)


def compute_ZA(id_str: bytes, P):
    """计算 ZA = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)"""
    entl = (len(id_str) * 8).to_bytes(2, "big")
    x, y = P
    msg = (entl + id_str
           + _int_to_bytes(SM2_A) + _int_to_bytes(SM2_B)
           + _int_to_bytes(SM2_GX) + _int_to_bytes(SM2_GY)
           + _int_to_bytes(x) + _int_to_bytes(y))
    return sm3_hash(msg)


# ================== SM2 密钥交换协议 ==================

class SM2KeyExchange:
    """SM2 密钥交换协议状态机
    role: 'A' 或 'B', A 为发起方, B 为响应方
    klen: 协商密钥长度 (字节), 默认 16 (用于 SM4)
    """

    def __init__(self, role: str, my_id: bytes, my_static_priv: int,
                 my_static_pub, peer_id: bytes, peer_static_pub, klen: int = 16):
        assert role in ("A", "B")
        self.role = role
        self.klen = klen
        self.my_id = my_id
        self.my_d = my_static_priv
        self.my_P = my_static_pub
        self.peer_id = peer_id
        self.peer_P = peer_static_pub
        self.w = (SM2_N.bit_length() + 1) // 2 - 1  # ceil(log2(n)/2) - 1
        self._2w = 1 << self.w
        # 临时密钥对
        self.r = None      # 临时私钥
        self.R = None      # 临时公钥
        # 协商完成后的密钥
        self.K = None
        self.S1 = None     # B 发给 A 的校验
        self.SA = None     # A 发给 B 的校验

    def gen_ephemeral(self):
        """生成临时密钥对"""
        self.r, self.R = gen_keypair()
        return self.R

    def _x_bar(self, x):
        return self._2w + (x & (self._2w - 1))

    def compute_shared(self, peer_R):
        """计算共享密钥 K, peer_R 为对方临时公钥点"""
        # x1_bar = 2^w + (x1 & (2^w-1))   x1 是己方临时公钥 X
        # tA = (dA + x1_bar * rA) mod n
        x1_bar = self._x_bar(self.R[0])
        t = (self.my_d + x1_bar * self.r) % SM2_N

        # 验证对方临时点合法
        if peer_R is None:
            raise ValueError("对方临时公钥为空")

        x2_bar = self._x_bar(peer_R[0])
        # U = h * tA * (PB + x2_bar * RB)   h = 1
        T = _ec_add(self.peer_P, _ec_mul(x2_bar, peer_R))
        U = _ec_mul(t, T)
        if U is None:
            raise ValueError("协商失败: 共享点为无穷远")

        xU, yU = U
        ZA = compute_ZA(self.my_id if self.role == "A" else self.peer_id,
                        self.my_P if self.role == "A" else self.peer_P)
        ZB = compute_ZA(self.peer_id if self.role == "A" else self.my_id,
                        self.peer_P if self.role == "A" else self.my_P)
        # KDF 输入: xU || yU || ZA || ZB
        kdf_in = _int_to_bytes(xU) + _int_to_bytes(yU) + ZA + ZB
        self.K = _kdf(kdf_in, self.klen)

        # 计算校验值, 用于双向认证
        # S1 = SM3(0x02 || yU || SM3(xU || ZA || ZB || x1 || y1 || x2 || y2))
        if self.role == "A":
            x1, y1 = self.R       # RA
            x2, y2 = peer_R       # RB
        else:
            x1, y1 = peer_R       # RA
            x2, y2 = self.R       # RB

        inner = sm3_hash(_int_to_bytes(xU) + ZA + ZB
                         + _int_to_bytes(x1) + _int_to_bytes(y1)
                         + _int_to_bytes(x2) + _int_to_bytes(y2))
        self.S1 = sm3_hash(b"\x02" + _int_to_bytes(yU) + inner)
        self.SA = sm3_hash(b"\x03" + _int_to_bytes(yU) + inner)
        return self.K

    def verify_peer(self, tag: bytes, expect: str) -> bool:
        """expect = 'S1' 或 'SA'"""
        target = self.S1 if expect == "S1" else self.SA
        return target == tag


def derive_key_id(K: bytes) -> str:
    """根据协商密钥派生一个简短的密钥 ID, 用于前端显示"""
    return hashlib.sha256(K).hexdigest()[:16].upper()
