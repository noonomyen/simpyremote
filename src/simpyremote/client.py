import codecs
import io
import json
import os
import ssl
import sys
from collections.abc import Callable
from contextlib import ExitStack, suppress
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

from .config import ClientConfig, resolve_client_config
from .io_pump import (
    StdinForwarder,
    interrupt_guard,
    raw_terminal_mode,
    stream_is_tty,
    terminal_size,
    winch_guard,
)
from .proto import (
    FRAME_ERROR,
    FRAME_EXEC_CMD,
    FRAME_EXEC_PY,
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_RETURN,
    FRAME_SIGNAL,
    FRAME_STARTED,
    FRAME_STDERR,
    FRAME_STDOUT,
    FramedTLSSession,
    decode_error_payload,
)
from .serialize import RemoteError, decode_data, serialize_callable
from .tls import build_client_ssl_context, connect_tls, derive_psk, warn_if_weak_secret
from .transfer import client_pull, client_push


def _write_stream(
    stream: Any,
    data: bytes,
    decoder: codecs.IncrementalDecoder | None = None,
) -> None:
    if not data or stream is None:
        return
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        buf.write(data)
        buf.flush()
        return
    if isinstance(stream, io.RawIOBase):
        view = memoryview(data)
        while view:
            written = stream.write(view)
            if written is None or written <= 0:
                break
            view = view[written:]
        stream.flush()
        return
    if isinstance(stream, io.BufferedIOBase) or "b" in str(getattr(stream, "mode", "")):
        stream.write(data)
        stream.flush()
        return
    text = (
        decoder.decode(data)
        if decoder is not None
        else data.decode("utf-8", errors="replace")
    )
    if text:
        stream.write(text)
        stream.flush()


def _flush_text_decoder(stream: Any, decoder: codecs.IncrementalDecoder) -> None:
    if stream is None or getattr(stream, "buffer", None) is not None:
        return
    if isinstance(stream, (io.RawIOBase, io.BufferedIOBase)) or "b" in str(
        getattr(stream, "mode", "")
    ):
        return
    tail = decoder.decode(b"", final=True)
    if tail:
        stream.write(tail)
        stream.flush()


class Client:
    """Remote client bound to a resolved target and TLS 1.3 PSK secret."""

    def __init__(
        self,
        remote: str | None = None,
        port: int | None = None,
        auth: str | None = None,
        *,
        config: ClientConfig | None = None,
        ignore_warnings: bool | None = None,
    ) -> None:
        resolved = config or resolve_client_config(
            remote=remote,
            port=port,
            auth=auth,
            ignore_warnings=ignore_warnings,
        )
        if config is not None and ignore_warnings is not None:
            resolved = replace(resolved, ignore_warnings=bool(ignore_warnings))
        self.config = resolved
        if not self.config.ignore_warnings:
            warn_if_weak_secret(self.config.secret)
        self._ssl_ctx: ssl.SSLContext | None = None

    def _get_ssl_context(self) -> ssl.SSLContext:
        if self._ssl_ctx is None:
            self._ssl_ctx = build_client_ssl_context(derive_psk(self.config.secret))
        return self._ssl_ctx

    def _connect(self) -> ssl.SSLSocket:
        return connect_tls(self.config.addr, self.config.port, self._get_ssl_context())

    def _stream_session(
        self,
        initial_type: int,
        initial_obj: dict[str, Any],
        *,
        forward_stdin: bool = True,
        request_pty: bool = False,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> tuple[int, dict[str, Any] | None]:
        in_stream = sys.stdin if stdin is None else stdin
        out_stream = sys.stdout if stdout is None else stdout
        err_stream = sys.stderr if stderr is None else stderr
        out_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        err_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        tls_sock = self._connect()
        session = FramedTLSSession(tls_sock)
        remote_pid: int | None = None
        detached = False
        got_exit = False
        return_payload: dict[str, Any] | None = None
        exit_code = 1
        stdin_pump: StdinForwarder | None = None
        stack = ExitStack()

        def _start_stdin_pump(pty_active: bool) -> None:
            nonlocal stdin_pump
            if forward_stdin and stdin_pump is None:
                pump = StdinForwarder(session, stdin_stream=in_stream, pty_mode=pty_active)
                pump.start()
                stdin_pump = pump
                stack.callback(pump.stop)

        def _on_urgent(event: Any) -> bool:
            nonlocal detached
            if event == "INT":
                session.send_from_loop(FRAME_SIGNAL, b"INT")
                pid_hint = f" (remote pid={remote_pid})" if remote_pid is not None else ""
                _write_stream(
                    err_stream,
                    f"\n[simpyremote] sent SIGINT{pid_hint}; press Ctrl+C again to detach\n".encode(),
                    err_decoder,
                )
                return True
            if event == "RESIZE":
                cols, rows = terminal_size()
                session.send_from_loop(
                    FRAME_RESIZE,
                    json.dumps({"cols": cols, "rows": rows}).encode("utf-8"),
                )
                return True
            if event == "DETACH":
                detached = True
                return False
            return True

        def _on_frame(msg_type: int, payload: bytes) -> bool:
            nonlocal remote_pid, return_payload, exit_code, got_exit
            if msg_type == FRAME_STARTED:
                info = json.loads(payload.decode("utf-8"))
                remote_pid = int(info["pid"])
                pty_active = bool(info.get("pty", False))
                if pty_active:
                    stack.enter_context(raw_terminal_mode(in_stream, out_stream))
                    stack.enter_context(
                        winch_guard(lambda: session.enqueue_urgent("RESIZE"))
                    )
                _start_stdin_pump(pty_active)
            elif msg_type == FRAME_STDOUT:
                _write_stream(out_stream, payload, out_decoder)
            elif msg_type == FRAME_STDERR:
                _write_stream(err_stream, payload, err_decoder)
            elif msg_type == FRAME_RETURN:
                return_payload = json.loads(payload.decode("utf-8"))
            elif msg_type == FRAME_EXIT:
                info = json.loads(payload.decode("utf-8"))
                exit_code = int(info["returncode"])
                got_exit = True
                return False
            elif msg_type == FRAME_ERROR:
                raise RemoteError(decode_error_payload(payload))
            else:
                raise RuntimeError(f"Unknown frame type from server: {msg_type}")
            return True

        def _on_eof() -> bool:
            return False

        try:
            session.enqueue_json(initial_type, initial_obj)
            with stack:
                stack.enter_context(
                    interrupt_guard(
                        lambda: session.enqueue_urgent("INT"),
                        lambda: session.enqueue_urgent("DETACH"),
                    )
                )
                if forward_stdin and not request_pty:
                    _start_stdin_pump(False)
                session.run(_on_frame, on_eof=_on_eof, on_urgent=_on_urgent)

            _flush_text_decoder(out_stream, out_decoder)
            _flush_text_decoder(err_stream, err_decoder)
            if detached:
                pid_hint = f" (remote pid={remote_pid})" if remote_pid is not None else ""
                _write_stream(
                    err_stream,
                    f"\n[simpyremote] detaching client{pid_hint}\n".encode(),
                )
                return 130, None
            if not got_exit:
                raise EOFError("Remote server closed connection unexpectedly")
            return exit_code, return_payload
        finally:
            session.closed.set()
            stack.close()
            session.close()
            with suppress(OSError):
                tls_sock.close()

    def run_cmd(
        self,
        argv: list[str] | None = None,
        *,
        cwd: str | None = None,
        pty: bool | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> int:
        """Execute a remote command (or server's default shell if argv is None)."""
        in_stream = sys.stdin if stdin is None else stdin
        out_stream = sys.stdout if stdout is None else stdout
        use_pty = (
            stream_is_tty(in_stream) and stream_is_tty(out_stream)
            if pty is None
            else bool(pty)
        )
        req: dict[str, Any] = {
            "argv": list(argv) if argv else [],
            "cwd": cwd,
            "pty": use_pty,
        }
        if use_pty:
            cols, rows = terminal_size()
            req["cols"] = cols
            req["rows"] = rows
            req["term"] = os.environ.get("TERM") or "xterm-256color"
        rc, _ = self._stream_session(
            FRAME_EXEC_CMD,
            req,
            forward_stdin=True,
            request_pty=use_pty,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )
        return rc

    def run(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> int:
        """Serialize fn and run it in a remote process with attached stdio, returning exit code."""
        return self.run_with(fn, args=args, kwargs=kwargs)

    def run_with(
        self,
        fn: Callable[..., Any],
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        serializer: str = "json",
        cwd: str | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> int:
        """Execute fn in a remote process with explicit stdio and serializer options."""
        job = serialize_callable(
            fn,
            args,
            kwargs or {},
            mode="run",
            serializer=serializer,
        )
        if cwd is not None:
            job["cwd"] = cwd
        rc, _ = self._stream_session(
            FRAME_EXEC_PY,
            job,
            forward_stdin=True,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )
        return rc

    def call[T](
        self,
        fn: Callable[..., T],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute fn in a fresh remote process and return its serialized return value."""
        return self.call_with(fn, args=args, kwargs=kwargs)

    def call_with[T](
        self,
        fn: Callable[..., T],
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        serializer: str = "json",
        forward_stdin: bool = False,
        cwd: str | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> T:
        """Execute fn in a fresh remote process with explicit RPC options."""
        job = serialize_callable(
            fn,
            args,
            kwargs or {},
            mode="call",
            serializer=serializer,
        )
        if cwd is not None:
            job["cwd"] = cwd
        rc, ret = self._stream_session(
            FRAME_EXEC_PY,
            job,
            forward_stdin=forward_stdin,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )
        if ret is None:
            raise RemoteError(f"Remote call exited with status {rc} without a return payload")
        if not ret.get("ok"):
            tb = str(ret.get("traceback", ""))
            err = str(ret.get("error", "Remote call failed"))
            exc_type = str(ret.get("exc_type", "RemoteError"))
            msg = f"{exc_type}: {err}"
            if tb:
                msg = f"{msg}\n{tb.rstrip()}"
            raise RemoteError(msg, remote_traceback=tb, exc_type=exc_type)
        used_ser = str(ret.get("serializer", "json"))
        if used_ser != serializer:
            raise RemoteError(
                f"Serializer mismatch: requested {serializer!r}, server returned {used_ser!r}"
            )
        return cast(T, decode_data(ret.get("value"), serializer))

    def push(
        self,
        local_src: str | os.PathLike[str],
        remote_dst: str,
        *,
        recursive: bool = False,
    ) -> tuple[str, int]:
        """Upload a local file or directory to the server."""
        with self._connect() as tls_sock:
            return client_push(tls_sock, local_src, remote_dst, recursive=recursive)

    def pull(
        self,
        remote_src: str,
        local_dst: str | os.PathLike[str],
        *,
        recursive: bool = False,
    ) -> tuple[Path, int]:
        """Download a remote file or directory from the server."""
        with self._connect() as tls_sock:
            return client_pull(tls_sock, remote_src, local_dst, recursive=recursive)


def run(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> int:
    """Run fn in a remote process using .simpyremote / env configuration."""
    return Client().run(fn, *args, **kwargs)


def call[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Call fn in a stateless remote process and return its serialized result."""
    return Client().call(fn, *args, **kwargs)


def push(
    local_src: str | os.PathLike[str],
    remote_dst: str,
    *,
    recursive: bool = False,
) -> tuple[str, int]:
    """Upload a local file or directory using .simpyremote / env configuration."""
    return Client().push(local_src, remote_dst, recursive=recursive)


def pull(
    remote_src: str,
    local_dst: str | os.PathLike[str],
    *,
    recursive: bool = False,
) -> tuple[Path, int]:
    """Download a remote file or directory using .simpyremote / env configuration."""
    return Client().pull(remote_src, local_dst, recursive=recursive)
