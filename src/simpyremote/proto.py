import json
import queue
import selectors
import socket
import ssl
import struct
import threading
from collections.abc import Callable
from contextlib import suppress
from typing import Any

FRAME_EXEC_CMD = 0x01
FRAME_EXEC_PY = 0x02
FRAME_STDIN = 0x03
FRAME_STDIN_EOF = 0x04
FRAME_STDOUT = 0x05
FRAME_STDERR = 0x06
FRAME_SIGNAL = 0x07
FRAME_EXIT = 0x08
FRAME_ERROR = 0x09
FRAME_RETURN = 0x0A
FRAME_STARTED = 0x0B
FRAME_CONTROL = 0x0C
FRAME_RESIZE = 0x0D
FRAME_FILE_PUT = 0x10
FRAME_FILE_GET = 0x11
FRAME_FILE_DATA = 0x12
FRAME_FILE_DONE = 0x13

_HEADER_STRUCT = struct.Struct(">BI")
_RECV_CHUNK_SIZE = 65536
_TX_HIGH_WATER = 262144
MAX_FRAME_SIZE = 16 * 1024 * 1024


def pack_frame(msg_type: int, payload: bytes = b"") -> bytes:
    """Encode a length-prefixed binary frame."""
    if len(payload) > MAX_FRAME_SIZE:
        raise ValueError(f"Frame payload too large: {len(payload)} bytes")
    return _HEADER_STRUCT.pack(msg_type, len(payload)) + payload


def decode_error_payload(payload: bytes) -> str:
    """Decode a FRAME_ERROR payload from JSON {'error': ...} or plain UTF-8."""
    text = payload.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text)
    except ValueError:
        return text
    if isinstance(parsed, dict) and "error" in parsed:
        return str(parsed["error"])
    return text


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a socket without pre-allocating untrusted sizes."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        data = sock.recv(min(remaining, _RECV_CHUNK_SIZE))
        if not data:
            raise EOFError("Connection closed")
        chunks.append(data)
        remaining -= len(data)
    return b"".join(chunks)


def send_frame(
    sock: socket.socket,
    msg_type: int,
    payload: bytes = b"",
    lock: threading.Lock | None = None,
) -> None:
    """Send a length-prefixed binary frame over a blocking socket."""
    packet = pack_frame(msg_type, payload)
    if lock is not None:
        with lock:
            sock.sendall(packet)
    else:
        sock.sendall(packet)


def send_json(
    sock: socket.socket,
    msg_type: int,
    obj: Any,
    lock: threading.Lock | None = None,
) -> None:
    """Serialize obj as UTF-8 JSON and send as a frame."""
    send_frame(sock, msg_type, json.dumps(obj).encode("utf-8"), lock=lock)


def recv_frame(
    sock: socket.socket,
    *,
    max_size: int = MAX_FRAME_SIZE,
) -> tuple[int, bytes] | None:
    """Read the next binary frame; return None only on clean EOF at a frame boundary."""
    first = sock.recv(1)
    if not first:
        return None
    header = first + recv_exact(sock, _HEADER_STRUCT.size - 1)
    msg_type, length = _HEADER_STRUCT.unpack(header)
    if length > max_size:
        raise ValueError(f"Incoming frame exceeds max size: {length}")
    payload = recv_exact(sock, length) if length > 0 else b""
    return msg_type, payload


class FramedTLSSession:
    """Single-owner non-blocking TLS frame multiplexer safe for OpenSSL and signal handlers."""

    def __init__(self, tls_sock: ssl.SSLSocket) -> None:
        self._sock = tls_sock
        self._tx_q: queue.Queue[bytes | None] = queue.Queue(maxsize=64)
        self._urgent_q: queue.SimpleQueue[Any] = queue.SimpleQueue()
        self._tx_buf = bytearray()
        self.closed = threading.Event()
        self._wake_lock = threading.Lock()
        self._wake_closed = False
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self._wake_w.setblocking(False)

    def close(self) -> None:
        """Mark the session closed and release internal wakeup sockets."""
        self.closed.set()
        with self._wake_lock:
            if not self._wake_closed:
                self._wake_closed = True
                for s in (self._wake_r, self._wake_w):
                    with suppress(OSError):
                        s.close()

    def send_from_loop(self, msg_type: int, payload: bytes = b"") -> None:
        """Append a frame directly to the loop transmit buffer without blocking."""
        self._tx_buf.extend(pack_frame(msg_type, payload))

    def _wake(self) -> None:
        with self._wake_lock:
            if not self._wake_closed:
                with suppress(BlockingIOError, OSError):
                    self._wake_w.send(b"x")

    def _wake_lockfree(self) -> None:
        if not self._wake_closed:
            with suppress(BlockingIOError, OSError):
                self._wake_w.send(b"x")

    def enqueue_frame(self, msg_type: int, payload: bytes = b"") -> bool:
        """Queue an outgoing frame from any worker thread with backpressure."""
        packet = pack_frame(msg_type, payload)
        while not self.closed.is_set():
            try:
                self._tx_q.put(packet, timeout=0.1)
                self._wake()
                return True
            except queue.Full:
                continue
        return False

    def enqueue_json(self, msg_type: int, obj: Any) -> bool:
        """Serialize obj as JSON and queue it for sending."""
        return self.enqueue_frame(msg_type, json.dumps(obj).encode("utf-8"))

    def finish_tx(self) -> None:
        """Signal the loop to exit cleanly once all queued frames are flushed."""
        while not self.closed.is_set():
            try:
                self._tx_q.put(None, timeout=0.1)
                self._wake()
                return
            except queue.Full:
                continue

    def enqueue_urgent(self, item: Any) -> None:
        """Lock-free enqueue safe to invoke from Python signal handlers."""
        self._urgent_q.put_nowait(item)
        self._wake_lockfree()

    def _drain_wake(self) -> None:
        while True:
            try:
                if not self._wake_r.recv(4096):
                    break
            except (BlockingIOError, OSError):
                break

    def run(
        self,
        on_frame: Callable[[int, bytes], bool],
        *,
        on_eof: Callable[[], bool] | None = None,
        on_urgent: Callable[[Any], bool] | None = None,
    ) -> None:
        """Drive all TLS reads and writes exclusively on the calling thread."""
        self._sock.setblocking(False)
        sel = selectors.DefaultSelector()
        sel.register(self._wake_r, selectors.EVENT_READ, data="wake")
        sock_events = 0

        rx_buf = bytearray()
        tx_buf = self._tx_buf
        close_after_flush = False
        peer_eof = False
        stop_loop = False

        try:
            while not stop_loop:
                while not self._urgent_q.empty():
                    item = self._urgent_q.get_nowait()
                    if on_urgent is not None and not on_urgent(item):
                        stop_loop = True
                        break
                if stop_loop:
                    break

                while not close_after_flush and len(tx_buf) < _TX_HIGH_WATER:
                    try:
                        pkt = self._tx_q.get_nowait()
                    except queue.Empty:
                        break
                    if pkt is None:
                        close_after_flush = True
                        break
                    tx_buf.extend(pkt)

                want_write = False
                want_read_for_tx = False
                while tx_buf:
                    try:
                        sent = self._sock.send(tx_buf)
                    except (ssl.SSLWantWriteError, BlockingIOError):
                        want_write = True
                        break
                    except ssl.SSLWantReadError:
                        want_read_for_tx = True
                        break
                    if sent == 0:
                        raise BrokenPipeError("Connection closed during send")
                    del tx_buf[:sent]

                if close_after_flush and not tx_buf:
                    break

                want_write_for_rx = False
                if not peer_eof:
                    while not stop_loop:
                        try:
                            chunk = self._sock.recv(_RECV_CHUNK_SIZE)
                        except (ssl.SSLWantReadError, BlockingIOError):
                            break
                        except ssl.SSLWantWriteError:
                            want_write_for_rx = True
                            break
                        if not chunk:
                            peer_eof = True
                            if on_eof is not None and not on_eof():
                                stop_loop = True
                            break
                        rx_buf.extend(chunk)
                        while len(rx_buf) >= _HEADER_STRUCT.size:
                            msg_type, length = _HEADER_STRUCT.unpack_from(rx_buf, 0)
                            if length > MAX_FRAME_SIZE:
                                raise ValueError(f"Incoming frame exceeds max size: {length}")
                            total = _HEADER_STRUCT.size + length
                            if len(rx_buf) < total:
                                break
                            payload = bytes(rx_buf[_HEADER_STRUCT.size : total])
                            del rx_buf[:total]
                            if not on_frame(msg_type, payload):
                                stop_loop = True
                                break
                if stop_loop:
                    break

                if (
                    not self._urgent_q.empty()
                    or (tx_buf and not want_write and not want_read_for_tx)
                    or (
                        not close_after_flush
                        and len(tx_buf) < _TX_HIGH_WATER
                        and not self._tx_q.empty()
                    )
                ):
                    continue

                if peer_eof and not tx_buf and close_after_flush:
                    break

                desired = 0
                if not peer_eof or want_read_for_tx:
                    desired |= selectors.EVENT_READ
                if want_write or want_write_for_rx or (tx_buf and not want_read_for_tx):
                    desired |= selectors.EVENT_WRITE

                if desired != sock_events:
                    if sock_events:
                        sel.unregister(self._sock)
                    if desired:
                        sel.register(self._sock, desired, data="tls")
                    sock_events = desired

                for key, _ in sel.select(timeout=0.5):
                    if key.data == "wake":
                        self._drain_wake()
        finally:
            self.closed.set()
            with suppress(Exception):
                sel.close()
