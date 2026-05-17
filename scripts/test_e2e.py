"""
端到端集成测试: 在同一台机器上启动 server + 模拟 client, 跑完整握手 + 文件传输
不依赖 FastAPI, 直接调用底层逻辑, 用于 CI 与开发自验证。
"""
import os, sys, time, threading, socket, json, hashlib, struct, tempfile, shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_core.sm2_kex import (
    SM2KeyExchange, point_to_bytes, bytes_to_point, derive_key_id,
)
from crypto_core.identity import load_or_create_identity
from crypto_core import sm4_backend
from crypto_core.protocol import (
    pack_frame, read_frame,
    MSG_HELLO, MSG_HELLO_ACK, MSG_HANDSHAKE_DONE,
    MSG_FILE_BEGIN, MSG_FILE_CHUNK, MSG_FILE_END, MSG_FILE_ACK,
)


def run_server(server_id_path, peer_id, peer_P, port, ready_evt, done_evt, results):
    sid, sd, sP = load_or_create_identity(server_id_path, "server@pi")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    ready_evt.set()
    conn, addr = srv.accept()

    # 握手
    mt, payload = read_frame(conn)
    obj = json.loads(payload.decode())
    RA = bytes_to_point(bytes.fromhex(obj["ra"]))
    kex = SM2KeyExchange("B", sid.encode(), sd, sP,
                         peer_id.encode(), peer_P, klen=16)
    RB = kex.gen_ephemeral()
    K = kex.compute_shared(RA)
    conn.sendall(pack_frame(MSG_HELLO_ACK, json.dumps({
        "id_b": sid, "rb": point_to_bytes(RB).hex(), "sb": kex.S1.hex()
    }).encode()))
    mt, payload = read_frame(conn)
    sa = bytes.fromhex(json.loads(payload.decode())["sa"])
    assert kex.verify_peer(sa, "SA")
    results["server_key"] = K

    # 接收文件
    mt, payload = read_frame(conn)
    assert mt == MSG_FILE_BEGIN
    meta = json.loads(payload.decode())
    out = bytearray()
    while True:
        mt, payload = read_frame(conn)
        if mt == MSG_FILE_CHUNK:
            iv = payload[4:20]; ct = payload[20:]
            pt = sm4_backend.decrypt(K, iv, ct, backend="soft")
            out.extend(pt)
        elif mt == MSG_FILE_END:
            break
    conn.sendall(pack_frame(MSG_FILE_ACK,
        json.dumps({"ok": True, "backend_used": "soft", "decrypt_ms": 1.0}).encode()))
    results["received"] = bytes(out)
    conn.close()
    srv.close()
    done_evt.set()


def run_client(client_id_path, peer_id, peer_P, port, plaintext, results):
    cid, cd, cP = load_or_create_identity(client_id_path, "client@pc")
    sock = socket.create_connection(("127.0.0.1", port))
    kex = SM2KeyExchange("A", cid.encode(), cd, cP,
                         peer_id.encode(), peer_P, klen=16)
    RA = kex.gen_ephemeral()
    sock.sendall(pack_frame(MSG_HELLO,
        json.dumps({"id_a": cid, "ra": point_to_bytes(RA).hex()}).encode()))
    mt, payload = read_frame(sock)
    obj = json.loads(payload.decode())
    RB = bytes_to_point(bytes.fromhex(obj["rb"]))
    SB = bytes.fromhex(obj["sb"])
    K = kex.compute_shared(RB)
    assert kex.verify_peer(SB, "S1")
    sock.sendall(pack_frame(MSG_HANDSHAKE_DONE,
        json.dumps({"sa": kex.SA.hex()}).encode()))
    results["client_key"] = K

    # 发送文件
    iv0 = os.urandom(16)
    sock.sendall(pack_frame(MSG_FILE_BEGIN, json.dumps({
        "name": "test.bin", "size": len(plaintext),
        "iv": iv0.hex(), "backend": "soft"
    }).encode()))
    chunk_size = 1024
    last_iv = iv0
    idx = 0
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i:i+chunk_size]
        ct = sm4_backend.encrypt(K, last_iv, chunk, backend="soft")
        sock.sendall(pack_frame(MSG_FILE_CHUNK,
                                struct.pack(">I", idx) + last_iv + ct))
        last_iv = hashlib.sha256(last_iv + ct[-16:]).digest()[:16]
        idx += 1
    sock.sendall(pack_frame(MSG_FILE_END,
        json.dumps({"sm3": hashlib.sha256(plaintext).hexdigest(),
                    "chunks": idx}).encode()))
    mt, payload = read_frame(sock)
    assert mt == MSG_FILE_ACK
    results["ack"] = json.loads(payload.decode())
    sock.close()


def main():
    tmp = tempfile.mkdtemp(prefix="sm2sm4_e2e_")
    try:
        server_id = os.path.join(tmp, "server.json")
        client_id = os.path.join(tmp, "client.json")
        # 先生成两端身份
        sid, sd, sP = load_or_create_identity(server_id, "server@pi")
        cid, cd, cP = load_or_create_identity(client_id, "client@pc")

        port = 19999
        ready = threading.Event()
        done = threading.Event()
        results = {}
        srv_th = threading.Thread(target=run_server,
                                  args=(server_id, cid, cP, port, ready, done, results))
        srv_th.start()
        ready.wait()

        plaintext = (b"Hello SM2/SM4 codesign test! " * 200) + os.urandom(1234)
        run_client(client_id, sid, sP, port, plaintext, results)
        done.wait(timeout=10)

        assert results["client_key"] == results["server_key"], "密钥不一致"
        assert results["received"] == plaintext, "解密结果不一致"
        print("[+] E2E 测试通过 ✓")
        print(f"    协商密钥 = {results['client_key'].hex()}")
        print(f"    Key ID  = {derive_key_id(results['client_key'])}")
        print(f"    传输 {len(plaintext)} 字节, 双端完全一致")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
