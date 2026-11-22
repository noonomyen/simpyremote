import codecs
import io
import json
import os
import ssl
import subprocess
import sys
from collections.abc import Callable, Sequence
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

DEVNULL = subprocess.DEVNULL


def _is_devnull(stream: Any) -> bool:
    return stream is False or (
        isinstance(stream, int)
        and not isinstance(stream, bool)
        and stream == subprocess.DEVNULL
    )


def _normalize_stdin(stdin: Any) -> tuple[Any, bool]:
    if _is_devnull(stdin):
        return None, False
    if stdin is None:
        return sys.stdin, True
    if isinstance(stdin, (bytes, bytearray, memoryview)):
        return io.BytesIO(bytes(stdin)), True
    if isinstance(stdin, str):
        return io.BytesIO(stdin.encode("utf-8")), True
    if hasattr(stdin, "read"):
        if getattr(stdin, "closed", False):
            return None, False
        readable = getattr(stdin, "readable", None)
        if callable(readable):
            try:
                if not readable():
                    raise TypeError("stdin stream must be readable")
            except ValueError:
                return None, False
        return stdin, True
    raise TypeError(
        f"stdin must be None, DEVNULL, False, bytes, str, or a readable stream, got {type(stdin).__name__}"
    )


def _normalize_cwd(cwd: str | None) -> str | None:
    if cwd is not None and not isinstance(cwd, str):
        raise TypeError(f"cwd must be a remote path str or None, got {type(cwd).__name__}")
    return cwd


def _normalize_output_stream(stream: Any, name: str, default: Any) -> Any:
    if _is_devnull(stream):
        return None
    if stream is None:
        return default
    if hasattr(stream, "write"):
        return stream
    raise TypeError(
        f"{name} must be None, DEVNULL, False, or a writable stream, got {type(stream).__name__}"
    )


def _exec_runner(argv: list[str]) -> int:
    import os
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)
    return subprocess.run(argv, env=env).returncode


def SHELL_AUTO(cmd: str) -> int:
    """Detect the remote OS shell and execute cmd."""
    import base64
    import os
    import shutil
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)

    if sys.platform == "win32":
        is_wine = False
        try:
            import ctypes

            is_wine = hasattr(ctypes.WinDLL("ntdll"), "wine_get_version")
        except OSError:
            pass
        ps = (
            shutil.which("pwsh")
            if is_wine
            else (shutil.which("powershell.exe") or shutil.which("pwsh"))
        )
        if ps:
            encoded = base64.b64encode((cmd or " ").encode("utf-16le")).decode("ascii")
            return subprocess.run(
                [ps, "-NoLogo", "-NoProfile", "-OutputFormat", "Text", "-EncodedCommand", encoded],
                env=env,
            ).returncode
        if "\n" in cmd or "\r" in cmd:
            raise ValueError(
                "cmd.exe only supports single-line commands; install PowerShell for multiline scripts"
            )
        comspec = (os.environ.get("COMSPEC") or "cmd.exe").strip('"')
        return subprocess.run(f'"{comspec}" /d /s /c "{cmd}"', env=env).returncode

    posix_shells = {"sh", "bash", "dash", "ash", "zsh", "ksh", "mksh"}
    env_shell = os.environ.get("SHELL", "")
    if env_shell and os.path.basename(env_shell) in posix_shells and shutil.which(env_shell):
        return subprocess.run([env_shell, "-c", cmd], env=env).returncode
    sh = shutil.which("sh") or "/bin/sh"
    return subprocess.run([sh, "-c", cmd], env=env).returncode


def SHELL_SH(cmd: str) -> int:
    """Execute cmd via POSIX sh -c."""
    import os
    import shutil
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)

    sh = shutil.which("sh") or ("sh" if sys.platform == "win32" else "/bin/sh")
    return subprocess.run([sh, "-c", cmd], env=env).returncode


def SHELL_BASH(cmd: str) -> int:
    """Execute cmd via bash -c."""
    import os
    import shutil
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)

    bash = shutil.which("bash") or "bash"
    return subprocess.run([bash, "-c", cmd], env=env).returncode


def SHELL_PWSH(cmd: str) -> int:
    """Execute cmd via PowerShell Core (pwsh) using -EncodedCommand."""
    import base64
    import os
    import shutil
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)

    pwsh = shutil.which("pwsh") or "pwsh"
    encoded = base64.b64encode((cmd or " ").encode("utf-16le")).decode("ascii")
    return subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-OutputFormat", "Text", "-EncodedCommand", encoded],
        env=env,
    ).returncode


def SHELL_POWERSHELL(cmd: str) -> int:
    """Execute cmd via Windows PowerShell using -EncodedCommand."""
    import base64
    import os
    import shutil
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)

    ps = shutil.which("powershell.exe") or "powershell.exe"
    encoded = base64.b64encode((cmd or " ").encode("utf-16le")).decode("ascii")
    return subprocess.run(
        [ps, "-NoLogo", "-NoProfile", "-OutputFormat", "Text", "-EncodedCommand", encoded],
        env=env,
    ).returncode


def SHELL_CMD(cmd: str) -> int:
    """Execute cmd via Windows cmd.exe."""
    import os
    import subprocess
    import sys

    env = None
    if getattr(sys, "frozen", False) and sys.platform != "win32":
        env = os.environ.copy()
        orig = env.pop("LD_LIBRARY_PATH_ORIG", None)
        if orig is not None:
            env["LD_LIBRARY_PATH"] = orig
        else:
            env.pop("LD_LIBRARY_PATH", None)

    comspec = (os.environ.get("COMSPEC") or "cmd.exe").strip('"')
    if sys.platform == "win32":
        if "\n" in cmd or "\r" in cmd:
            raise ValueError(
                "SHELL_CMD only supports single-line commands; use SHELL_POWERSHELL or SHELL_PWSH"
            )
        return subprocess.run(f'"{comspec}" /d /s /c "{cmd}"', env=env).returncode
    return subprocess.run([comspec, "/d", "/c", cmd], env=env).returncode


def _flush_if_present(target: Any) -> None:
    flush = getattr(target, "flush", None)
    if callable(flush):
        flush()


def _write_stream(
    stream: Any,
    data: bytes,
    decoder: codecs.IncrementalDecoder | None = None,
) -> None:
    if not data or stream is None:
        return
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        _flush_if_present(stream)
        buf.write(data)
        _flush_if_present(buf)
        return
    if isinstance(stream, io.RawIOBase):
        view = memoryview(data)
        while view:
            written = stream.write(view)
            if written is None or written <= 0:
                break
            view = view[written:]
        _flush_if_present(stream)
        return
    if isinstance(stream, io.BufferedIOBase) or "b" in str(getattr(stream, "mode", "")):
        stream.write(data)
        _flush_if_present(stream)
        return
    text = (
        decoder.decode(data)
        if decoder is not None
        else data.decode("utf-8", errors="replace")
    )
    if text:
        stream.write(text)
        _flush_if_present(stream)


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
        _flush_if_present(stream)


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
        in_stream, stdin_enabled = _normalize_stdin(stdin)
        out_stream = _normalize_output_stream(stdout, "stdout", sys.stdout)
        err_stream = _normalize_output_stream(stderr, "stderr", sys.stderr)
        effective_forward_stdin = bool(forward_stdin) and stdin_enabled
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
            if effective_forward_stdin and stdin_pump is None:
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
                if pty_active and effective_forward_stdin:
                    stack.enter_context(raw_terminal_mode(in_stream, out_stream))
                    stack.enter_context(
                        winch_guard(lambda: session.enqueue_urgent("RESIZE"))
                    )
                if effective_forward_stdin:
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
                if effective_forward_stdin and not request_pty:
                    _start_stdin_pump(False)
                session.run(_on_frame, on_eof=_on_eof, on_urgent=_on_urgent)

            if detached:
                pid_hint = f" (remote pid={remote_pid})" if remote_pid is not None else ""
                _write_stream(
                    err_stream,
                    f"\n[simpyremote] detaching client{pid_hint}\n".encode(),
                    err_decoder,
                )
                return 130, None
            if not got_exit:
                raise EOFError("Remote server closed connection unexpectedly")
            return exit_code, return_payload
        finally:
            with suppress(Exception):
                _flush_text_decoder(out_stream, out_decoder)
            with suppress(Exception):
                _flush_text_decoder(err_stream, err_decoder)
            session.closed.set()
            stack.close()
            session.close()
            with suppress(OSError):
                tls_sock.close()

    def run_cmd(
        self,
        argv: Sequence[str] | None = None,
        *,
        cwd: str | None = None,
        pty: bool | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        forward_stdin: bool = True,
    ) -> int:
        """Execute a remote command (or server's default shell if argv is None)."""
        if argv is not None and (
            isinstance(argv, (str, bytes, bytearray, memoryview))
            or not isinstance(argv, Sequence)
        ):
            raise TypeError("argv must be None or a sequence of strings, not str or bytes")
        cwd = _normalize_cwd(cwd)
        in_stream, stdin_enabled = _normalize_stdin(stdin)
        out_stream = _normalize_output_stream(stdout, "stdout", sys.stdout)
        _normalize_output_stream(stderr, "stderr", sys.stderr)
        use_pty = (
            bool(forward_stdin)
            and stdin_enabled
            and stream_is_tty(in_stream)
            and stream_is_tty(out_stream)
            if pty is None
            else bool(pty)
        )
        req: dict[str, Any] = {
            "argv": [str(x) for x in argv] if argv else [],
            "cwd": cwd,
            "pty": use_pty,
        }
        if not (bool(forward_stdin) and stdin_enabled):
            req["close_stdin"] = True
        if use_pty:
            cols, rows = terminal_size()
            req["cols"] = cols
            req["rows"] = rows
            req["term"] = os.environ.get("TERM") or "xterm-256color"
        rc, _ = self._stream_session(
            FRAME_EXEC_CMD,
            req,
            forward_stdin=forward_stdin,
            request_pty=use_pty,
            stdin=in_stream if stdin_enabled else False,
            stdout=stdout,
            stderr=stderr,
        )
        return rc

    def run_shell(
        self,
        cmd: str,
        *,
        shell: Callable[[str], Any] | None = None,
        cwd: str | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        forward_stdin: bool = True,
    ) -> int:
        """Execute a shell command string on the remote host via the call protocol."""
        if not isinstance(cmd, str):
            raise TypeError(f"cmd must be str, got {type(cmd).__name__}")
        runner = SHELL_AUTO if shell is None else shell
        if not callable(runner):
            raise TypeError(f"shell must be callable or None, got {type(runner).__name__}")
        rc = self.call_with(
            runner,
            args=(cmd,),
            cwd=cwd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            forward_stdin=forward_stdin,
        )
        return 0 if rc is None else int(rc)

    def run_exec(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
        forward_stdin: bool = True,
    ) -> int:
        """Execute an argv sequence directly without a shell via the call protocol."""
        if isinstance(argv, (str, bytes, bytearray, memoryview)) or not isinstance(
            argv, Sequence
        ):
            raise TypeError("argv must be a sequence of strings, not str or bytes")
        argv_list = [str(x) for x in argv]
        if not argv_list:
            raise ValueError("argv must not be empty")
        rc = self.call_with(
            _exec_runner,
            args=(argv_list,),
            cwd=cwd,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            forward_stdin=forward_stdin,
        )
        return 0 if rc is None else int(rc)

    def capture_shell(
        self,
        cmd: str,
        *,
        shell: Callable[[str], Any] | None = None,
        cwd: str | None = None,
        stdin: Any = DEVNULL,
        forward_stdin: bool = True,
    ) -> tuple[int, str, str]:
        """Run a shell command and return (returncode, stdout_text, stderr_text)."""
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = self.run_shell(
            cmd,
            shell=shell,
            cwd=cwd,
            stdin=stdin,
            stdout=out_buf,
            stderr=err_buf,
            forward_stdin=forward_stdin,
        )
        return rc, out_buf.getvalue(), err_buf.getvalue()

    def capture_exec(
        self,
        argv: Sequence[str],
        *,
        cwd: str | None = None,
        stdin: Any = DEVNULL,
        forward_stdin: bool = True,
    ) -> tuple[int, str, str]:
        """Execute an argv sequence directly and return (returncode, stdout_text, stderr_text)."""
        out_buf = io.StringIO()
        err_buf = io.StringIO()
        rc = self.run_exec(
            argv,
            cwd=cwd,
            stdin=stdin,
            stdout=out_buf,
            stderr=err_buf,
            forward_stdin=forward_stdin,
        )
        return rc, out_buf.getvalue(), err_buf.getvalue()

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
        forward_stdin: bool | None = None,
        cwd: str | None = None,
        stdin: Any = None,
        stdout: Any = None,
        stderr: Any = None,
    ) -> T:
        """Execute fn in a fresh remote process with explicit RPC options."""
        cwd = _normalize_cwd(cwd)
        in_stream, stdin_enabled = _normalize_stdin(stdin)
        _normalize_output_stream(stdout, "stdout", sys.stdout)
        _normalize_output_stream(stderr, "stderr", sys.stderr)
        effective_forward_stdin = (
            stdin is not None and stdin_enabled
            if forward_stdin is None
            else bool(forward_stdin) and stdin_enabled
        )
        job = serialize_callable(
            fn,
            args,
            kwargs or {},
            mode="call",
            serializer=serializer,
        )
        if cwd is not None:
            job["cwd"] = cwd
        if not effective_forward_stdin:
            job["close_stdin"] = True
        rc, ret = self._stream_session(
            FRAME_EXEC_PY,
            job,
            forward_stdin=effective_forward_stdin,
            stdin=in_stream if stdin_enabled else False,
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


def run_shell(
    cmd: str,
    *,
    shell: Callable[[str], Any] | None = None,
    cwd: str | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    forward_stdin: bool = True,
) -> int:
    """Execute a shell command string on the remote host using .simpyremote / env configuration."""
    return Client().run_shell(
        cmd,
        shell=shell,
        cwd=cwd,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        forward_stdin=forward_stdin,
    )


def run_exec(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
    forward_stdin: bool = True,
) -> int:
    """Execute an argv sequence directly without a shell using .simpyremote / env configuration."""
    return Client().run_exec(
        argv,
        cwd=cwd,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
        forward_stdin=forward_stdin,
    )


def capture_shell(
    cmd: str,
    *,
    shell: Callable[[str], Any] | None = None,
    cwd: str | None = None,
    stdin: Any = DEVNULL,
    forward_stdin: bool = True,
) -> tuple[int, str, str]:
    """Run a shell command using .simpyremote / env config and return (rc, stdout, stderr)."""
    return Client().capture_shell(
        cmd,
        shell=shell,
        cwd=cwd,
        stdin=stdin,
        forward_stdin=forward_stdin,
    )


def capture_exec(
    argv: Sequence[str],
    *,
    cwd: str | None = None,
    stdin: Any = DEVNULL,
    forward_stdin: bool = True,
) -> tuple[int, str, str]:
    """Execute an argv sequence using .simpyremote / env config and return (rc, stdout, stderr)."""
    return Client().capture_exec(
        argv,
        cwd=cwd,
        stdin=stdin,
        forward_stdin=forward_stdin,
    )


def call[T](fn: Callable[..., T], *args: Any, **kwargs: Any) -> T:
    """Call fn in a stateless remote process and return its serialized result."""
    return Client().call(fn, *args, **kwargs)


def call_with[T](
    fn: Callable[..., T],
    *,
    args: tuple[Any, ...] = (),
    kwargs: dict[str, Any] | None = None,
    serializer: str = "json",
    forward_stdin: bool | None = None,
    cwd: str | None = None,
    stdin: Any = None,
    stdout: Any = None,
    stderr: Any = None,
) -> T:
    """Execute fn with explicit RPC options using .simpyremote / env configuration."""
    return Client().call_with(
        fn,
        args=args,
        kwargs=kwargs,
        serializer=serializer,
        forward_stdin=forward_stdin,
        cwd=cwd,
        stdin=stdin,
        stdout=stdout,
        stderr=stderr,
    )


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
