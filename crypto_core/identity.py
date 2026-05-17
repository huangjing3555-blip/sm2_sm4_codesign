"""
长期身份密钥管理: 首次启动时生成 SM2 长期密钥对并保存到本地 JSON, 之后复用。
PC 端与 Pi 端各自维护自己的身份, 并需要预先互换公钥(类似 SSH 公钥分发)。
"""
import os
import json
from .sm2_kex import gen_keypair, point_to_bytes, bytes_to_point, _bytes_to_int


def load_or_create_identity(path: str, my_id: str):
    """加载或创建本地身份, 返回 (id, d, P)"""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        d = int(obj["d"], 16)
        P = bytes_to_point(bytes.fromhex(obj["P"]))
        return obj["id"], d, P
    # 新建
    d, P = gen_keypair()
    obj = {
        "id": my_id,
        "d":  hex(d)[2:].rjust(64, "0"),
        "P":  point_to_bytes(P).hex(),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    return my_id, d, P


def export_pubkey(path: str) -> dict:
    """导出本地公钥(供分发)"""
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    return {"id": obj["id"], "P": obj["P"]}


def import_peer_pubkey(path: str):
    """导入对端公钥, 返回 (id, P)"""
    with open(path, "r", encoding="utf-8") as f:
        obj = json.load(f)
    return obj["id"], bytes_to_point(bytes.fromhex(obj["P"]))
