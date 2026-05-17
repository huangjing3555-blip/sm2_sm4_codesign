"""
PC 客户端 - FastAPI 后端
功能:
  1. 提供前端 Dashboard 的 HTTP API (登录、连接、握手、传输、性能查询)
  2. 与香橙派建立 TCP 长连接, 完成 SM2 协商
  3. SM4 加密本地文件并发送
  4. 实时记录性能数据并推送给前端 (WebSocket)
"""
import os
import sys
import json
import time
import socket
import struct
import asyncio
import hashlib
import threading
import csv
from io import StringIO
from contextlib import asynccontextmanager
from typing import Optional, List

import psutil
from fastapi import FastAPI, HTTPException, UploadFile, File, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# 引入 crypto_core
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
    MSG_REKEY,
)


# ================== 全局状态 ==================

CONFIG_DIR    = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(CONFIG_DIR, exist_ok=True)
LOGIN_FILE    = os.path.join(CONFIG_DIR, "login.json")
IDENTITY_FILE = os.path.join(CONFIG_DIR, "pc_identity.json")
PEER_FILE     = os.path.join(CONFIG_DIR, "peer_pubkey.json")
PERF_CSV      = os.path.join(CONFIG_DIR, "performance_log.csv")
RECV_DIR      = os.path.join(CONFIG_DIR, "received")
os.makedirs(RECV_DIR, exist_ok=True)


class AppState:
    def __init__(self):
        self.lock = threading.Lock()
        self.session_token: Optional[str] = None
        self.tcp_sock: Optional[socket.socket] = None
        self.peer_addr: Optional[str] = None
        self.handshaked = False
        self.shared_key: Optional[bytes] = None
        self.key_id: Optional[str] = None
        self.handshake_at: Optional[float] = None
        self.rekey_count = 0
        self.id_self = b"client@pc"
        self.d_self = None
        self.P_self = None
        self.id_peer = None
        self.P_peer = None
        # 实时事件队列 (供 WebSocket 推送)
        self.event_subscribers: List[asyncio.Queue] = []
        self.event_loop: Optional[asyncio.AbstractEventLoop] = None
        # 性能日志
        self.perf_records: List[dict] = []

    def push_event(self, event: dict):
        """线程安全的事件推送"""
        if self.event_loop is None:
            return
        for q in list(self.event_subscribers):
            try:
                self.event_loop.call_soon_threadsafe(q.put_nowait, event)
            except Exception:
                pass


STATE = AppState()


# ================== 登录与身份初始化 ==================

def _hash_pw(pw: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, 100000).hex()


def login_set_password(password: str):
    salt = os.urandom(16)
    obj = {"salt": salt.hex(), "hash": _hash_pw(password, salt)}
    with open(LOGIN_FILE, "w") as f:
        json.dump(obj, f)


def login_check(password: str) -> bool:
    if not os.path.exists(LOGIN_FILE):
        return False
    with open(LOGIN_FILE, "r") as f:
        obj = json.load(f)
    salt = bytes.fromhex(obj["salt"])
    return _hash_pw(password, salt) == obj["hash"]


def login_initialized() -> bool:
    return os.path.exists(LOGIN_FILE)


def init_identity():
    """加载或创建 PC 端 SM2 长期身份"""
    id_, d, P = load_or_create_identity(IDENTITY_FILE, "client@pc")
    STATE.id_self = id_.encode("utf-8")
    STATE.d_self = d
    STATE.P_self = P


# ================== 性能日志 (CSV) ==================

PERF_FIELDS = [
    "timestamp", "scenario", "backend", "file_name", "file_size",
    "send_ms", "decrypt_ms", "throughput_mbps",
    "pc_cpu_percent", "key_id",
]


def perf_csv_init():
    if not os.path.exists(PERF_CSV):
        with open(PERF_CSV, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=PERF_FIELDS)
            writer.writeheader()


def perf_log(record: dict):
    """写入一条性能记录"""
    record = {k: record.get(k, "") for k in PERF_FIELDS}
    with open(PERF_CSV, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=PERF_FIELDS)
        writer.writerow(record)
    STATE.perf_records.append(record)
    STATE.push_event({"type": "perf", "record": record})


# ================== 网络握手 ==================

def do_connect(host: str, port: int):
    """TCP 连接到香橙派"""
    sock = socket.create_connection((host, port), timeout=10)
    sock.settimeout(60)
    STATE.tcp_sock = sock
    STATE.peer_addr = f"{host}:{port}"
    STATE.push_event({"type": "log", "msg": f"已连接到 {host}:{port}"})
    return sock


def do_disconnect():
    if STATE.tcp_sock:
        try:
            STATE.tcp_sock.close()
        except Exception:
            pass
        STATE.tcp_sock = None
    STATE.handshaked = False
    STATE.shared_key = None
    STATE.key_id = None
    STATE.push_event({"type": "log", "msg": "已断开连接"})


def do_handshake():
    """与香橙派完成 SM2 三轮握手"""
    if STATE.tcp_sock is None:
        raise RuntimeError("尚未连接到服务端")
    if STATE.P_peer is None:
        raise RuntimeError("尚未导入服务端公钥, 请先复制 server_pubkey.json 到 pc_client/data/peer_pubkey.json")

    sock = STATE.tcp_sock
    STATE.push_event({"type": "handshake", "stage": "start", "msg": "开始 SM2 三轮握手"})
    t0 = time.time()

    kex = SM2KeyExchange(
        role="A", my_id=STATE.id_self, my_static_priv=STATE.d_self,
        my_static_pub=STATE.P_self, peer_id=STATE.id_peer.encode("utf-8"),
        peer_static_pub=STATE.P_peer, klen=16,
    )
    RA = kex.gen_ephemeral()

    # 第 1 轮: A -> B 发送 ID_A, R_A
    msg1 = json.dumps({
        "id_a": STATE.id_self.decode("utf-8"),
        "ra":   point_to_bytes(RA).hex(),
    }).encode("utf-8")
    sock.sendall(pack_frame(MSG_HELLO, msg1))
    STATE.push_event({"type": "handshake", "stage": "round1",
                      "msg": f"[1/3] 发送 R_A ({point_to_bytes(RA).hex()[:32]}...)"})

    # 第 2 轮: B -> A 返回 ID_B, R_B, S_B
    mt, payload = read_frame(sock)
    if mt != MSG_HELLO_ACK:
        raise RuntimeError(f"握手失败, 期望 MSG_HELLO_ACK, 收到 0x{mt:02x}")
    obj = json.loads(payload.decode("utf-8"))
    RB = bytes_to_point(bytes.fromhex(obj["rb"]))
    SB = bytes.fromhex(obj["sb"])
    STATE.push_event({"type": "handshake", "stage": "round2",
                      "msg": f"[2/3] 收到 R_B 与校验值 S_B"})

    K = kex.compute_shared(RB)
    if not kex.verify_peer(SB, "S1"):
        raise RuntimeError("握手失败: S_B 校验不通过, 服务端可能被篡改")

    # 第 3 轮: A -> B 发送 S_A
    msg3 = json.dumps({"sa": kex.SA.hex()}).encode("utf-8")
    sock.sendall(pack_frame(MSG_HANDSHAKE_DONE, msg3))
    STATE.push_event({"type": "handshake", "stage": "round3",
                      "msg": "[3/3] 发送 S_A 完成确认"})

    elapsed = (time.time() - t0) * 1000
    STATE.shared_key = K
    STATE.key_id = derive_key_id(K)
    STATE.handshaked = True
    STATE.handshake_at = time.time()
    STATE.rekey_count += 1
    STATE.push_event({
        "type": "handshake", "stage": "done",
        "msg": f"协商成功 ✓ Key ID = {STATE.key_id}, 耗时 {elapsed:.1f} ms",
        "key_id": STATE.key_id, "elapsed_ms": round(elapsed, 1),
    })


# ================== 文件加密发送 ==================

CHUNK_SIZE = 64 * 1024   # 64KB 每片


def do_send_file(filepath: str, scenario: str = "hw"):
    """
    将文件分片 SM4-CBC 加密后发给服务端
    scenario: 'hw' 或 'soft' - 表示请求服务端使用哪种解密后端
    """
    if not STATE.handshaked or STATE.shared_key is None:
        raise RuntimeError("尚未完成 SM2 握手")
    if not os.path.exists(filepath):
        raise RuntimeError(f"文件不存在: {filepath}")

    sock = STATE.tcp_sock
    file_size = os.path.getsize(filepath)
    file_name = os.path.basename(filepath)

    # 文件传输开始
    iv = os.urandom(16)
    begin = json.dumps({
        "name":    file_name,
        "size":    file_size,
        "iv":      iv.hex(),
        "backend": scenario,    # 通知服务端使用哪种后端解密
    }).encode("utf-8")
    sock.sendall(pack_frame(MSG_FILE_BEGIN, begin))

    STATE.push_event({"type": "transfer", "stage": "begin",
                      "msg": f"开始传输 {file_name} ({file_size} 字节, 后端={scenario})"})

    proc = psutil.Process(os.getpid())
    proc.cpu_percent(None)  # 第一次调用初始化

    sm3_hasher = hashlib.sha256()  # 简化: 用 SHA256 作完整性校验, 报告中可换 SM3
    t_start = time.time()
    sent_bytes = 0
    chunk_idx = 0
    last_iv = iv

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            sm3_hasher.update(chunk)
            # 软件加密 (PC 端必然是软件), 每片用 PKCS7 填充, 独立 IV
            ct = sm4_backend.encrypt(STATE.shared_key, last_iv, chunk, backend="soft")
            chunk_msg = struct.pack(">I", chunk_idx) + last_iv + ct
            sock.sendall(pack_frame(MSG_FILE_CHUNK, chunk_msg))
            sent_bytes += len(chunk)
            # 滚动 IV: 用上一片密文末 16 字节作下一片 IV (链接性), 加上随机熵
            last_iv = hashlib.sha256(last_iv + ct[-16:]).digest()[:16]
            chunk_idx += 1
            # 上报进度 (每 16 片或最后一片)
            if chunk_idx % 4 == 0 or sent_bytes >= file_size:
                STATE.push_event({
                    "type": "transfer", "stage": "progress",
                    "sent": sent_bytes, "total": file_size,
                    "percent": round(sent_bytes / file_size * 100, 1),
                    "ciphertext_preview": ct[:32].hex(),
                })

    digest = sm3_hasher.digest()
    end = json.dumps({"sm3": digest.hex(), "chunks": chunk_idx}).encode("utf-8")
    sock.sendall(pack_frame(MSG_FILE_END, end))

    # 等待服务端 ACK (含解密性能)
    mt, payload = read_frame(sock)
    if mt != MSG_FILE_ACK:
        raise RuntimeError(f"未收到文件 ACK, mt=0x{mt:02x}")
    ack = json.loads(payload.decode("utf-8"))
    t_end = time.time()
    pc_cpu = proc.cpu_percent(None)

    send_ms = (t_end - t_start) * 1000
    throughput = file_size * 8 / 1e6 / max((t_end - t_start), 1e-6)  # Mbps
    record = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scenario":  scenario,
        "backend":   ack.get("backend_used", scenario),
        "file_name": file_name,
        "file_size": file_size,
        "send_ms":   round(send_ms, 2),
        "decrypt_ms": ack.get("decrypt_ms", ""),
        "throughput_mbps": round(throughput, 2),
        "pc_cpu_percent":  round(pc_cpu, 1),
        "key_id":    STATE.key_id,
    }
    perf_log(record)
    STATE.push_event({"type": "transfer", "stage": "done",
                      "msg": f"传输完成 ({scenario}): 总耗时 {send_ms:.1f} ms, "
                             f"服务端解密 {ack.get('decrypt_ms','-')} ms, "
                             f"吞吐 {throughput:.2f} Mbps",
                      "record": record})
    return record


# ================== FastAPI ==================

@asynccontextmanager
async def lifespan(app: FastAPI):
    STATE.event_loop = asyncio.get_running_loop()
    perf_csv_init()
    init_identity()
    # 自动加载对端公钥 (如果存在)
    if os.path.exists(PEER_FILE):
        try:
            pid, P = import_peer_pubkey(PEER_FILE)
            STATE.id_peer = pid
            STATE.P_peer = P
        except Exception:
            pass
    yield
    do_disconnect()


app = FastAPI(title="SM2/SM4 软硬协同 PC 客户端", lifespan=lifespan)


# ---------- 请求模型 ----------

class LoginReq(BaseModel):
    password: str

class ConnectReq(BaseModel):
    host: str
    port: int = 9000

class SendReq(BaseModel):
    filepath: str
    scenario: str = "hw"   # 'hw' 或 'soft'


# ---------- 鉴权依赖 ----------

def require_login(request: Request):
    token = request.headers.get("X-Auth-Token")
    if not STATE.session_token or token != STATE.session_token:
        raise HTTPException(status_code=401, detail="未登录")


# ---------- 路由 ----------

@app.get("/api/status")
def api_status():
    return {
        "login_initialized": login_initialized(),
        "logged_in":         STATE.session_token is not None,
        "connected":         STATE.tcp_sock is not None,
        "peer":              STATE.peer_addr,
        "handshaked":        STATE.handshaked,
        "key_id":            STATE.key_id,
        "rekey_count":       STATE.rekey_count,
        "handshake_at":      STATE.handshake_at,
        "self_id":           STATE.id_self.decode() if STATE.id_self else None,
        "peer_id":           STATE.id_peer,
        "peer_loaded":       STATE.P_peer is not None,
        "backends":          sm4_backend.list_backends(),
    }


@app.post("/api/login/init")
def api_login_init(req: LoginReq):
    """首次启动: 设置密码"""
    if login_initialized():
        raise HTTPException(status_code=400, detail="密码已设置, 不可重复初始化")
    login_set_password(req.password)
    return {"ok": True}


@app.post("/api/login")
def api_login(req: LoginReq):
    if not login_initialized():
        # 自动作为初始化
        login_set_password(req.password)
        STATE.session_token = hashlib.sha256(os.urandom(16)).hexdigest()
        return {"ok": True, "first_time": True, "token": STATE.session_token}
    if not login_check(req.password):
        raise HTTPException(status_code=401, detail="密码错误")
    STATE.session_token = hashlib.sha256(os.urandom(16)).hexdigest()
    return {"ok": True, "first_time": False, "token": STATE.session_token}


@app.post("/api/logout")
def api_logout(request: Request):
    require_login(request)
    STATE.session_token = None
    return {"ok": True}


@app.get("/api/identity/pubkey")
def api_get_pubkey(request: Request):
    require_login(request)
    return export_pubkey(IDENTITY_FILE)


@app.post("/api/identity/peer")
async def api_set_peer(request: Request):
    require_login(request)
    body = await request.json()
    pid = body.get("id")
    Phex = body.get("P")
    if not pid or not Phex:
        raise HTTPException(status_code=400, detail="需要字段 id, P")
    with open(PEER_FILE, "w") as f:
        json.dump({"id": pid, "P": Phex}, f)
    STATE.id_peer = pid
    STATE.P_peer = bytes_to_point(bytes.fromhex(Phex))
    return {"ok": True}


@app.post("/api/connect")
def api_connect(req: ConnectReq, request: Request):
    require_login(request)
    if STATE.tcp_sock is not None:
        do_disconnect()
    try:
        do_connect(req.host, req.port)
        return {"ok": True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/disconnect")
def api_disconnect(request: Request):
    require_login(request)
    do_disconnect()
    return {"ok": True}


@app.post("/api/handshake")
def api_handshake(request: Request):
    require_login(request)
    try:
        do_handshake()
        return {"ok": True, "key_id": STATE.key_id}
    except Exception as e:
        STATE.push_event({"type": "log", "msg": f"握手错误: {e}"})
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...), request: Request = None):
    """上传文件到本地暂存目录, 然后由 /api/send 加密发送"""
    require_login(request)
    save_path = os.path.join(CONFIG_DIR, "upload_" + file.filename)
    with open(save_path, "wb") as f:
        f.write(await file.read())
    return {"ok": True, "path": save_path, "size": os.path.getsize(save_path)}


@app.post("/api/send")
async def api_send(req: SendReq, request: Request):
    require_login(request)
    # 在线程池里跑, 避免阻塞事件循环
    loop = asyncio.get_running_loop()
    try:
        record = await loop.run_in_executor(None, do_send_file, req.filepath, req.scenario)
        return {"ok": True, "record": record}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/perf/list")
def api_perf_list(request: Request):
    require_login(request)
    return {"records": STATE.perf_records[-200:]}


@app.get("/api/perf/csv")
def api_perf_csv(request: Request):
    require_login(request)
    if not os.path.exists(PERF_CSV):
        raise HTTPException(status_code=404, detail="无性能日志")
    return FileResponse(PERF_CSV, media_type="text/csv",
                        filename="performance_log.csv")


@app.websocket("/ws")
async def ws_events(ws: WebSocket):
    await ws.accept()
    queue: asyncio.Queue = asyncio.Queue()
    STATE.event_subscribers.append(queue)
    try:
        # 初始状态
        await ws.send_text(json.dumps({"type": "snapshot", "status": api_status()}))
        while True:
            ev = await queue.get()
            await ws.send_text(json.dumps(ev, ensure_ascii=False))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if queue in STATE.event_subscribers:
            STATE.event_subscribers.remove(queue)


# ---------- 静态前端 ----------
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
if os.path.isdir(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


@app.get("/")
def root():
    index = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index):
        return FileResponse(index)
    return HTMLResponse("<h1>前端尚未部署</h1>")


# ================== 主入口 ==================

if __name__ == "__main__":
    import uvicorn
    print("=" * 60)
    print("PC 客户端启动中... 浏览器访问 http://127.0.0.1:8000")
    print(f"性能日志 CSV: {PERF_CSV}")
    print(f"PC 端公钥: {IDENTITY_FILE} (请将公钥分发给香橙派)")
    print("=" * 60)
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
