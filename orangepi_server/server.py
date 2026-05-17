"""
香橙派 5 Plus 服务端
功能:
  1. TCP 监听 PC 客户端连接
  2. 完成 SM2 三轮握手 (软件实现)
  3. 接收密文, 通过 AF_ALG 硬件后端 (RK3588 Crypto Engine) 解密
  4. 同时支持软件后端用于 Benchmark 对比
  5. 实时记录解密时延、CPU 占用、吞吐率到 SQLite
  6. 支持 CSV 导出
"""
import os
import sys
import json
import time
import socket
import struct
import sqlite3
import hashlib
import threading
import csv
import argparse
from typing import Optional

# 支持以脚本方式运行: python orangepi_server/server.py
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import psutil

from crypto_core import sm4_backend
from crypto_core.sm2_kex import (
    SM2KeyExchange, point_to_bytes, bytes_to_point, derive_key_id,
)
from crypto_core.identity import (
    load_or_create_identity, export_pubkey, import_peer_pubkey,
)
from crypto_core.protocol import (
    pack_frame, read_frame,
    MSG_HELLO, MSG_HELLO_ACK, MSG_HANDSHAKE_DONE,
    MSG_FILE_BEGIN, MSG_FILE_CHUNK, MSG_FILE_END, MSG_FILE_ACK,
    MSG_REKEY, MSG_ERROR,
)


# ================== 配置 ==================
DATA_DIR      = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)
IDENTITY_FILE = os.path.join(DATA_DIR, "pi_identity.json")
PEER_FILE     = os.path.join(DATA_DIR, "peer_pubkey.json")
DB_FILE       = os.path.join(DATA_DIR, "performance.db")
RECV_DIR      = os.path.join(DATA_DIR, "received")
os.makedirs(RECV_DIR, exist_ok=True)


# ================== SQLite ==================

def db_init():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS perf_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, peer_addr TEXT, key_id TEXT,
            file_name TEXT, file_size INTEGER,
            backend TEXT, decrypt_ms REAL, throughput_mbps REAL,
            cpu_percent REAL, sm3_match INTEGER
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS handshake_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT, peer_addr TEXT, key_id TEXT, elapsed_ms REAL
        );
    """)
    conn.commit()
    conn.close()


def db_log_perf(record: dict):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""INSERT INTO perf_log
        (ts, peer_addr, key_id, file_name, file_size, backend, decrypt_ms,
         throughput_mbps, cpu_percent, sm3_match)
        VALUES (?,?,?,?,?,?,?,?,?,?)""", (
        record["ts"], record["peer_addr"], record["key_id"],
        record["file_name"], record["file_size"], record["backend"],
        record["decrypt_ms"], record["throughput_mbps"],
        record["cpu_percent"], record["sm3_match"],
    ))
    conn.commit()
    conn.close()


def db_log_handshake(peer_addr: str, key_id: str, elapsed_ms: float):
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""INSERT INTO handshake_log (ts, peer_addr, key_id, elapsed_ms)
                    VALUES (?,?,?,?)""",
                 (time.strftime("%Y-%m-%d %H:%M:%S"), peer_addr, key_id, elapsed_ms))
    conn.commit()
    conn.close()


def db_export_csv(out_path: str):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.execute("SELECT * FROM perf_log ORDER BY id")
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    conn.close()
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(cols)
        writer.writerows(rows)
    return len(rows)


# ================== 服务端会话 ==================

class Session:
    def __init__(self, sock: socket.socket, addr, identity, peer_pubkey, peer_id):
        self.sock = sock
        self.addr = addr
        self.id_self, self.d_self, self.P_self = identity
        self.id_peer = peer_id
        self.P_peer = peer_pubkey
        self.shared_key: Optional[bytes] = None
        self.key_id: Optional[str] = None

    def handshake(self):
        # 等待 PC 的 MSG_HELLO
        mt, payload = read_frame(self.sock)
        if mt != MSG_HELLO:
            raise RuntimeError(f"协议错误: 期望 MSG_HELLO, 收到 0x{mt:02x}")
        obj = json.loads(payload.decode("utf-8"))
        client_id = obj["id_a"]
        RA = bytes_to_point(bytes.fromhex(obj["ra"]))
        if client_id != self.id_peer:
            print(f"[!] 警告: 客户端 ID '{client_id}' 与已注册 '{self.id_peer}' 不一致")

        t0 = time.time()
        kex = SM2KeyExchange(
            role="B", my_id=self.id_self.encode("utf-8"), my_static_priv=self.d_self,
            my_static_pub=self.P_self, peer_id=client_id.encode("utf-8"),
            peer_static_pub=self.P_peer, klen=16,
        )
        RB = kex.gen_ephemeral()
        K = kex.compute_shared(RA)
        # 第 2 轮: 发回 R_B 和 S_B (S1)
        msg2 = json.dumps({
            "id_b": self.id_self,
            "rb":   point_to_bytes(RB).hex(),
            "sb":   kex.S1.hex(),
        }).encode("utf-8")
        self.sock.sendall(pack_frame(MSG_HELLO_ACK, msg2))

        # 第 3 轮: 收 PC 的 S_A 校验
        mt, payload = read_frame(self.sock)
        if mt != MSG_HANDSHAKE_DONE:
            raise RuntimeError(f"协议错误: 期望 MSG_HANDSHAKE_DONE, 收到 0x{mt:02x}")
        obj = json.loads(payload.decode("utf-8"))
        SA_recv = bytes.fromhex(obj["sa"])
        if not kex.verify_peer(SA_recv, "SA"):
            raise RuntimeError("S_A 校验失败, 客户端可能被冒充")

        elapsed = (time.time() - t0) * 1000
        self.shared_key = K
        self.key_id = derive_key_id(K)
        db_log_handshake(f"{self.addr[0]}:{self.addr[1]}", self.key_id, elapsed)
        print(f"[+] [{self.addr[0]}:{self.addr[1]}] 握手成功, KeyID={self.key_id}, 耗时 {elapsed:.1f} ms")
        return self.shared_key

    def serve_files(self):
        """循环接收文件传输请求"""
        while True:
            mt, payload = read_frame(self.sock)
            if mt == MSG_FILE_BEGIN:
                self._recv_one_file(payload)
            elif mt == MSG_REKEY:
                # 重新协商
                print(f"[*] 收到重协商请求 from {self.addr}")
                self.handshake()
            else:
                print(f"[!] 未识别消息类型 0x{mt:02x}")

    def _recv_one_file(self, begin_payload: bytes):
        meta = json.loads(begin_payload.decode("utf-8"))
        file_name = os.path.basename(meta["name"])
        file_size = meta["size"]
        iv0 = bytes.fromhex(meta["iv"])
        backend_req = meta.get("backend", "hw")
        if backend_req == "hw" and not sm4_backend.HW_AVAILABLE:
            print(f"[!] 客户端请求 hw 后端, 但当前内核不支持 cbc(sm4), 自动回退到 soft")
            backend_used = "soft"
        else:
            backend_used = backend_req

        save_path = os.path.join(RECV_DIR, f"{int(time.time())}_{file_name}")
        print(f"[*] 接收文件 '{file_name}' ({file_size} 字节, backend={backend_used}) -> {save_path}")

        proc = psutil.Process(os.getpid())
        proc.cpu_percent(None)

        decrypted_total = 0
        decrypt_total_ms = 0.0
        sha256_hasher = hashlib.sha256()

        with open(save_path, "wb") as fout:
            while True:
                mt, payload = read_frame(self.sock)
                if mt == MSG_FILE_CHUNK:
                    idx = struct.unpack(">I", payload[:4])[0]
                    iv  = payload[4:20]
                    ct  = payload[20:]
                    t0 = time.time()
                    pt = sm4_backend.decrypt(self.shared_key, iv, ct, backend=backend_used)
                    decrypt_total_ms += (time.time() - t0) * 1000
                    fout.write(pt)
                    sha256_hasher.update(pt)
                    decrypted_total += len(pt)
                elif mt == MSG_FILE_END:
                    break
                else:
                    raise RuntimeError(f"传输中收到非法消息类型 0x{mt:02x}")

        end_obj = json.loads(payload.decode("utf-8"))
        sm3_expect = end_obj["sm3"]
        sm3_match = (sha256_hasher.hexdigest() == sm3_expect)

        cpu = proc.cpu_percent(None)
        # 吞吐率以 "总字节 / 总解密时间" 计算 (Mbps)
        throughput = decrypted_total * 8 / 1e6 / max(decrypt_total_ms / 1000, 1e-6)

        record = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "peer_addr": f"{self.addr[0]}:{self.addr[1]}",
            "key_id":    self.key_id,
            "file_name": file_name,
            "file_size": decrypted_total,
            "backend":   backend_used,
            "decrypt_ms": round(decrypt_total_ms, 2),
            "throughput_mbps": round(throughput, 2),
            "cpu_percent": round(cpu, 1),
            "sm3_match": 1 if sm3_match else 0,
        }
        db_log_perf(record)

        ack = json.dumps({
            "ok": True,
            "backend_used": backend_used,
            "decrypt_ms": record["decrypt_ms"],
            "throughput_mbps": record["throughput_mbps"],
            "cpu_percent": record["cpu_percent"],
            "sm3_match": sm3_match,
        }).encode("utf-8")
        self.sock.sendall(pack_frame(MSG_FILE_ACK, ack))

        print(f"[+] 文件接收完成: {file_name} | "
              f"backend={backend_used} | 解密 {record['decrypt_ms']} ms | "
              f"吞吐 {record['throughput_mbps']} Mbps | CPU {record['cpu_percent']}% | "
              f"完整性 {'OK' if sm3_match else 'FAIL'}")


# ================== 主服务循环 ==================

def serve(host: str, port: int):
    db_init()
    # 加载身份与对端公钥
    id_, d, P = load_or_create_identity(IDENTITY_FILE, "server@pi")
    if not os.path.exists(PEER_FILE):
        print(f"[!] 警告: 未找到 PC 端公钥文件 {PEER_FILE}")
        print(f"    请先从 PC 端拷贝 pc_identity.json 的 P 字段过来, 或拷贝整个文件并重命名为 peer_pubkey.json")
        print(f"    服务器仍将启动, 但握手将拒绝所有客户端")
        peer_id, P_peer = None, None
    else:
        peer_id, P_peer = import_peer_pubkey(PEER_FILE)
        print(f"[*] 已加载对端公钥: {peer_id}")

    print("=" * 70)
    print(f" SM2/SM4 软硬协同 - 香橙派服务端")
    print(f" 监听地址      : {host}:{port}")
    print(f" 本机身份 ID   : {id_}")
    print(f" 对端身份 ID   : {peer_id}")
    print(f" SM4 后端      : soft={sm4_backend.HW_AVAILABLE}    hw(AF_ALG)={sm4_backend.HW_AVAILABLE}")
    print(f" 性能数据库    : {DB_FILE}")
    print(f" 接收文件目录  : {RECV_DIR}")
    print("=" * 70)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(4)

    while True:
        conn, addr = srv.accept()
        if peer_id is None or P_peer is None:
            # 实时重新加载, 允许运行时分发公钥
            if os.path.exists(PEER_FILE):
                peer_id, P_peer = import_peer_pubkey(PEER_FILE)
                print(f"[*] 已加载对端公钥: {peer_id}")
        if peer_id is None:
            print(f"[!] 拒绝来自 {addr} 的连接: 尚未配置对端公钥")
            conn.close()
            continue
        threading.Thread(target=_handle_client,
                         args=(conn, addr, (id_, d, P), peer_id, P_peer),
                         daemon=True).start()


def _handle_client(conn, addr, identity, peer_id, P_peer):
    print(f"[+] 接受连接: {addr}")
    try:
        sess = Session(conn, addr, identity, P_peer, peer_id)
        sess.handshake()
        sess.serve_files()
    except (ConnectionError, OSError) as e:
        print(f"[-] {addr} 连接关闭: {e}")
    except Exception as e:
        print(f"[!] {addr} 发生错误: {e}")
        try:
            conn.sendall(pack_frame(MSG_ERROR, str(e).encode("utf-8")))
        except Exception:
            pass
    finally:
        try: conn.close()
        except Exception: pass


# ================== CLI ==================

def main():
    ap = argparse.ArgumentParser(description="SM2/SM4 软硬协同 - 香橙派服务端")
    ap.add_argument("--host", default="0.0.0.0", help="监听地址")
    ap.add_argument("--port", type=int, default=9000, help="监听端口")
    ap.add_argument("--export-csv", help="导出性能日志到指定 CSV 文件后退出")
    ap.add_argument("--show-pubkey", action="store_true",
                    help="打印本机 SM2 公钥 (供 PC 端配置)")
    args = ap.parse_args()

    if args.show_pubkey:
        load_or_create_identity(IDENTITY_FILE, "server@pi")
        obj = export_pubkey(IDENTITY_FILE)
        print(json.dumps(obj, indent=2))
        return

    if args.export_csv:
        db_init()
        n = db_export_csv(args.export_csv)
        print(f"已导出 {n} 条记录到 {args.export_csv}")
        return

    serve(args.host, args.port)


if __name__ == "__main__":
    main()
