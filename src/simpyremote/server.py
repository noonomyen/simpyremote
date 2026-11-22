import hmac
import json
import os
import queue
import secrets
import site
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from contextlib import suppress
from typing import Any

from .config import DEFAULT_BIND, DEFAULT_PORT, resolve_server_secret
from .io_pump import (
    ManagedProcess,
    clamp_terminal_size,
    default_shell_argv,
    deliver_signal_to_process,
    spawn_process,
)
from .proto import (
    FRAME_CONTROL,
    FRAME_ERROR,
    FRAME_EXEC_CMD,
    FRAME_EXEC_PY,
    FRAME_EXIT,
    FRAME_FILE_GET,
    FRAME_FILE_PUT,
    FRAME_RESIZE,
    FRAME_RETURN,
    FRAME_SIGNAL,
    FRAME_STARTED,
    FRAME_STDERR,
    FRAME_STDIN,
    FRAME_STDIN_EOF,
    FRAME_STDOUT,
    FramedTLSSession,
    recv_frame,
    send_frame,
    send_json,
)
from .tls import (
    HANDSHAKE_TIMEOUT,
    build_server_ssl_context,
    derive_psk,
    handshake_with_deadline,
    warn_if_weak_secret,
)
from .transfer import server_handle_file_get, server_handle_file_put

MAX_CONCURRENT_SESSIONS = 64
INITIAL_FRAME_TIMEOUT = 10.0
TRANSFER_IDLE_TIMEOUT = 120.0
WORKER_CONNECT_TIMEOUT = 30.0
MAX_PENDING_STDIN_BYTES = 4 * 1024 * 1024
_ERROR_SEND_TIMEOUT = 5.0
_CTL_AUTH_TIMEOUT = 2.0
_CTL_MAX_TOKEN_BYTES = 128


def _send_error_bounded(tls_sock: ssl.SSLSocket, message: str) -> None:
    with suppress(OSError):
        tls_sock.setblocking(True)
        tls_sock.settimeout(_ERROR_SEND_TIMEOUT)
        send_json(tls_sock, FRAME_ERROR, {"error": message})


def _clean_child_env(base_env: dict[str, str] | None, *, is_worker: bool) -> dict[str, str]:
    env = (os.environ if base_env is None else base_env).copy()
    env.pop("SIMPYREMOTE_SECRET", None)
    if not is_worker and getattr(sys, "frozen", False) and sys.platform != "win32":
        orig_ld = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig_ld is not None:
            env["LD_LIBRARY_PATH"] = orig_ld
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return env


def _worker_cmd_and_env() -> tuple[list[str], dict[str, str]]:
    env = _clean_child_env(None, is_worker=True)
    if getattr(sys, "frozen", False):
        return [sys.executable, "--_worker"], env
    if globals().get("_AMALGAMATED") or not __package__:
        return [sys.executable, "-P", os.path.abspath(__file__), "--_worker"], env
    pkg_parent = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    site_dirs: set[str] = set()
    with suppress(Exception):
        for p in site.getsitepackages():
            site_dirs.add(os.path.normcase(os.path.abspath(p)))
    with suppress(Exception):
        user_site = site.getusersitepackages()
        if user_site:
            site_dirs.add(os.path.normcase(os.path.abspath(user_site)))
    if os.path.normcase(pkg_parent) not in site_dirs:
        parts = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
        if pkg_parent not in parts:
            parts.insert(0, pkg_parent)
            env["PYTHONPATH"] = os.pathsep.join(parts)
    return [sys.executable, "-P", "-m", "simpyremote", "--_worker"], env


def _pump_reader(
    read_fn: Callable[[int], bytes],
    session: FramedTLSSession,
    frame_type: int,
) -> None:
    discarding = False
    try:
        while True:
            chunk = read_fn(4096)
            if not chunk:
                break
            if not discarding and not session.enqueue_frame(frame_type, chunk):
                discarding = True
    except OSError:
        pass


def _stdin_writer_loop(
    proc: ManagedProcess,
    stdin_q: queue.SimpleQueue[bytes | None],
    stdin_lock: threading.Lock,
    pending_bytes: list[int],
) -> None:
    try:
        while True:
            chunk = stdin_q.get()
            if chunk is None:
                break
            with stdin_lock:
                pending_bytes[0] = max(0, pending_bytes[0] - len(chunk))
            try:
                proc.write_stdin(chunk)
            except OSError:
                break
    finally:
        proc.close_stdin()


def _abort_worker(
    proc: ManagedProcess,
    tls_sock: ssl.SSLSocket,
    message: str,
) -> None:
    deliver_signal_to_process(proc, "KILL")
    with suppress(OSError, subprocess.TimeoutExpired):
        proc.wait(timeout=5.0)
    proc.close_io()
    _send_error_bounded(tls_sock, message)


def _setup_worker_control(
    proc: ManagedProcess,
    ctl_srv: socket.socket,
    ctl_token: str,
    job_payload: bytes,
    mode: str,
    tls_sock: ssl.SSLSocket,
) -> tuple[bool, list[bytes], threading.Thread | None]:
    ctl_result: list[bytes] = []
    ctl_conn: socket.socket | None = None
    deadline = time.monotonic() + WORKER_CONNECT_TIMEOUT

    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _abort_worker(proc, tls_sock, "Worker failed to connect control channel (timeout)")
                return False, ctl_result, None
            rc_now = proc.poll()
            if rc_now is not None:
                _abort_worker(
                    proc,
                    tls_sock,
                    f"Worker exited prematurely (code {rc_now}) before control handshake",
                )
                return False, ctl_result, None
            ctl_srv.settimeout(min(remaining, 0.5))
            try:
                candidate, _ = ctl_srv.accept()
            except TimeoutError:
                continue
            try:
                candidate.settimeout(_CTL_AUTH_TIMEOUT)
                tok_frame = recv_frame(candidate, max_size=_CTL_MAX_TOKEN_BYTES)
                if tok_frame is None or not hmac.compare_digest(
                    tok_frame[1].decode("utf-8", errors="replace"), ctl_token
                ):
                    candidate.close()
                    continue
                candidate.settimeout(None)
                send_frame(candidate, FRAME_CONTROL, job_payload)
                ctl_conn = candidate
                break
            except (OSError, ValueError):
                with suppress(OSError):
                    candidate.close()
                continue
    finally:
        with suppress(OSError):
            ctl_srv.close()

    assert ctl_conn is not None
    if mode != "call":
        with suppress(OSError):
            ctl_conn.close()
        return True, ctl_result, None

    def _wait_ctl_return() -> None:
        try:
            res_frame = recv_frame(ctl_conn)
            if res_frame is not None:
                ctl_result.append(res_frame[1])
        except (OSError, ValueError):
            pass
        finally:
            with suppress(OSError):
                ctl_conn.close()

    ctl_thread = threading.Thread(target=_wait_ctl_return, daemon=True)
    ctl_thread.start()
    return True, ctl_result, ctl_thread


def _run_process_session(
    tls_sock: ssl.SSLSocket,
    cmd: list[str],
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    *,
    job_payload: bytes | None = None,
    mode: str = "run",
    use_pty: bool = False,
    cols: int = 80,
    rows: int = 24,
    term: str | None = None,
    close_stdin: bool = False,
) -> None:
    is_worker = job_payload is not None
    proc_env = _clean_child_env(env, is_worker=is_worker)
    ctl_srv: socket.socket | None = None
    ctl_token = ""

    if is_worker:
        ctl_srv = socket.create_server(("127.0.0.1", 0), backlog=4)
        ctl_port = ctl_srv.getsockname()[1]
        ctl_token = secrets.token_hex(16)
        proc_env["SIMPYREMOTE_CTL"] = f"127.0.0.1:{ctl_port}:{ctl_token}"

    try:
        proc = spawn_process(
            cmd,
            env=proc_env,
            cwd=cwd,
            use_pty=use_pty and not is_worker,
            cols=cols,
            rows=rows,
            term=term,
        )
    except Exception as exc:
        if ctl_srv is not None:
            with suppress(OSError):
                ctl_srv.close()
        _send_error_bounded(tls_sock, f"Failed to spawn process: {exc}")
        return

    ctl_result: list[bytes] = []
    ctl_thread: threading.Thread | None = None
    if ctl_srv is not None and job_payload is not None:
        ok, ctl_result, ctl_thread = _setup_worker_control(
            proc, ctl_srv, ctl_token, job_payload, mode, tls_sock
        )
        if not ok:
            return

    session = FramedTLSSession(tls_sock)
    stdin_q: queue.SimpleQueue[bytes | None] = queue.SimpleQueue()
    stdin_lock = threading.Lock()
    pending_stdin = [0]
    stdin_closed = threading.Event()

    def _close_stdin_queue() -> None:
        if not stdin_closed.is_set():
            stdin_closed.set()
            stdin_q.put_nowait(None)

    if close_stdin:
        _close_stdin_queue()

    t_in = threading.Thread(
        target=_stdin_writer_loop,
        args=(proc, stdin_q, stdin_lock, pending_stdin),
        daemon=True,
    )
    t_out = threading.Thread(
        target=_pump_reader,
        args=(proc.read_stdout, session, FRAME_STDOUT),
        daemon=True,
    )
    t_err: threading.Thread | None = None
    if proc.has_stderr:
        t_err = threading.Thread(
            target=_pump_reader,
            args=(proc.read_stderr, session, FRAME_STDERR),
            daemon=True,
        )

    def _wait_process_and_finish() -> None:
        rc = proc.wait()
        t_out.join()
        if t_err is not None:
            t_err.join()
        _close_stdin_queue()
        t_in.join(timeout=1.0)
        proc.close_io()
        if ctl_thread is not None:
            ctl_thread.join()
            if ctl_result:
                session.enqueue_frame(FRAME_RETURN, ctl_result[0])
        session.enqueue_json(FRAME_EXIT, {"returncode": rc})
        session.finish_tx()

    t_wait = threading.Thread(target=_wait_process_and_finish, daemon=True)

    def _on_frame(msg_type: int, payload: bytes) -> bool:
        if msg_type == FRAME_STDIN:
            if not stdin_closed.is_set():
                with stdin_lock:
                    if pending_stdin[0] + len(payload) > MAX_PENDING_STDIN_BYTES:
                        _close_stdin_queue()
                        session.send_from_loop(
                            FRAME_ERROR,
                            json.dumps({"error": "Remote stdin buffer limit exceeded"}).encode(
                                "utf-8"
                            ),
                        )
                        session.finish_tx()
                        return True
                    pending_stdin[0] += len(payload)
                stdin_q.put_nowait(payload)
        elif msg_type == FRAME_STDIN_EOF:
            _close_stdin_queue()
        elif msg_type == FRAME_SIGNAL:
            sig_name = payload.decode("utf-8", errors="replace").strip() or "INT"
            deliver_signal_to_process(proc, sig_name)
        elif msg_type == FRAME_RESIZE:
            try:
                info = json.loads(payload.decode("utf-8"))
                c, r = clamp_terminal_size(
                    int(info.get("cols") or 80), int(info.get("rows") or 24)
                )
            except (ValueError, TypeError, AttributeError):
                return True
            proc.resize(c, r)
        return True

    def _on_eof() -> bool:
        _close_stdin_queue()
        return False

    try:
        session.enqueue_json(FRAME_STARTED, {"pid": proc.pid, "pty": proc.is_pty})
        t_in.start()
        t_out.start()
        if t_err is not None:
            t_err.start()
        t_wait.start()
        session.run(_on_frame, on_eof=_on_eof)
    except (OSError, ValueError):
        _close_stdin_queue()
    finally:
        session.closed.set()
        _close_stdin_queue()
        if t_in.is_alive():
            t_in.join(timeout=0.5)
        if proc.poll() is not None and t_wait.is_alive():
            t_wait.join(timeout=1.0)
        session.close()


def _handle_client(
    raw_sock: socket.socket,
    peer: tuple[Any, ...],
    ssl_ctx: ssl.SSLContext,
    sem: threading.BoundedSemaphore,
) -> None:
    tls_sock: ssl.SSLSocket | None = None
    try:
        with suppress(OSError):
            raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        tls_sock = handshake_with_deadline(
            raw_sock, ssl_ctx, server_side=True, timeout=HANDSHAKE_TIMEOUT
        )
        tls_sock.settimeout(INITIAL_FRAME_TIMEOUT)
        first = recv_frame(tls_sock)
        if first is None:
            return
        tls_sock.settimeout(None)

        msg_type, payload = first
        if msg_type == FRAME_EXEC_CMD:
            req = json.loads(payload.decode("utf-8"))
            raw_argv = req.get("argv")
            if raw_argv is not None and not isinstance(raw_argv, list):
                raise ValueError("Invalid argv: expected a list of strings")
            argv = [str(x) for x in raw_argv or []] or default_shell_argv()
            cols, rows = clamp_terminal_size(
                int(req.get("cols") or 80), int(req.get("rows") or 24)
            )
            term_val = req.get("term")
            term = str(term_val) if isinstance(term_val, str) and term_val else None
            _run_process_session(
                tls_sock,
                argv,
                cwd=req.get("cwd"),
                mode="run",
                use_pty=bool(req.get("pty", False)),
                cols=cols,
                rows=rows,
                term=term,
                close_stdin=bool(req.get("close_stdin", False)),
            )
        elif msg_type == FRAME_EXEC_PY:
            job = json.loads(payload.decode("utf-8"))
            cmd, env = _worker_cmd_and_env()
            _run_process_session(
                tls_sock,
                cmd,
                env=env,
                cwd=job.get("cwd"),
                job_payload=payload,
                mode=str(job.get("mode", "run")),
                close_stdin=bool(job.get("close_stdin", False)),
            )
        elif msg_type == FRAME_FILE_PUT:
            tls_sock.settimeout(TRANSFER_IDLE_TIMEOUT)
            server_handle_file_put(tls_sock, json.loads(payload.decode("utf-8")))
        elif msg_type == FRAME_FILE_GET:
            tls_sock.settimeout(TRANSFER_IDLE_TIMEOUT)
            server_handle_file_get(tls_sock, json.loads(payload.decode("utf-8")))
        else:
            _send_error_bounded(tls_sock, f"Unknown initial frame: {msg_type}")
    except (ssl.SSLError, TimeoutError) as exc:
        print(f"[simpyremote] auth/tls rejected from {peer[0]}: {exc}", file=sys.stderr)
    except Exception as exc:
        if tls_sock is not None:
            _send_error_bounded(tls_sock, str(exc))
    finally:
        with suppress(OSError):
            (tls_sock or raw_sock).close()
        sem.release()


def _resolve_bind_family(host: str, port: int) -> tuple[socket.AddressFamily, bool]:
    if host == "::":
        return socket.AF_INET6, socket.has_dualstack_ipv6()
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if infos:
            return infos[0][0], False
    except OSError:
        pass
    return (socket.AF_INET6 if ":" in host else socket.AF_INET), False


def serve(
    host: str = DEFAULT_BIND,
    port: int = DEFAULT_PORT,
    pre_auth: str | None = None,
    *,
    stop_event: threading.Event | None = None,
    on_listening: Any = None,
    ignore_warnings: bool = False,
) -> None:
    """Run the TLS 1.3 PSK remote execution server."""
    if not (0 <= port <= 65535):
        raise ValueError(f"Invalid bind port: {port}")
    secret, generated = resolve_server_secret(pre_auth)
    if not ignore_warnings:
        warn_if_weak_secret(secret)
    ssl_ctx = build_server_ssl_context(derive_psk(secret))
    sem = threading.BoundedSemaphore(MAX_CONCURRENT_SESSIONS)

    family, dualstack = _resolve_bind_family(host, port)
    with socket.create_server(
        (host, port),
        family=family,
        backlog=64,
        dualstack_ipv6=dualstack,
    ) as srv_sock:
        srv_sock.settimeout(0.5)
        bound_port = srv_sock.getsockname()[1]
        display_addr = f"[{host}]:{bound_port}" if ":" in host else f"{host}:{bound_port}"
        if on_listening is not None:
            on_listening(host, bound_port, secret, generated)
        elif generated:
            print(
                f"[simpyremote] listening on {display_addr} (TLS 1.3 PSK, generated secret={secret})",
                file=sys.stderr,
                flush=True,
            )
        else:
            print(
                f"[simpyremote] listening on {display_addr} (TLS 1.3 PSK, configured secret)",
                file=sys.stderr,
                flush=True,
            )

        try:
            while stop_event is None or not stop_event.is_set():
                try:
                    conn, peer = srv_sock.accept()
                except TimeoutError:
                    continue
                if not sem.acquire(blocking=False):
                    conn.close()
                    continue
                try:
                    threading.Thread(
                        target=_handle_client,
                        args=(conn, peer, ssl_ctx, sem),
                        daemon=True,
                    ).start()
                except Exception:
                    with suppress(OSError):
                        conn.close()
                    sem.release()
                    raise
        except KeyboardInterrupt:
            pass
