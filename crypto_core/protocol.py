"""
通信协议帧格式定义与编解码
帧结构: Magic(2) + Type(1) + Length(4, big-endian) + Payload(N)
"""
import struct

MAGIC = b"\xAA\x55"

# 消息类型
MSG_HELLO          = 0x01  # PC -> Pi: 协商请求 (含 ID_A, R_A)
MSG_HELLO_ACK      = 0x02  # Pi -> PC: 协商响应 (含 ID_B, R_B, S_B)
MSG_HANDSHAKE_DONE = 0x03  # PC -> Pi: 协商确认 (含 S_A)
MSG_FILE_BEGIN     = 0x04  # PC -> Pi: 开始传输文件 (含 文件名, 总长度, 是否硬件解密)
MSG_FILE_CHUNK     = 0x05  # PC -> Pi: 密文分片
MSG_FILE_END       = 0x06  # PC -> Pi: 传输结束 (含 SM3 哈希校验)
MSG_FILE_ACK       = 0x07  # Pi -> PC: 文件接收完成回执 (含 解密性能数据)
MSG_REKEY          = 0x08  # PC -> Pi: 重新协商密钥
MSG_ERROR          = 0xFF  # 错误


def pack_frame(msg_type: int, payload: bytes) -> bytes:
    """打包一个消息帧"""
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload 必须是 bytes")
    return MAGIC + struct.pack(">BI", msg_type, len(payload)) + payload


def recv_exact(sock, n: int) -> bytes:
    """从 socket 精确读取 n 字节"""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("连接关闭，读取数据不完整")
        buf.extend(chunk)
    return bytes(buf)


def read_frame(sock):
    """从 socket 读取一个完整帧, 返回 (msg_type, payload)"""
    head = recv_exact(sock, 2 + 1 + 4)
    if head[:2] != MAGIC:
        raise ValueError(f"非法帧头: {head[:2].hex()}, 期望 {MAGIC.hex()}")
    msg_type = head[2]
    length = struct.unpack(">I", head[3:7])[0]
    if length > 64 * 1024 * 1024:
        raise ValueError(f"Payload 过大: {length}")
    payload = recv_exact(sock, length) if length > 0 else b""
    return msg_type, payload
