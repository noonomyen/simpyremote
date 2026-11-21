import ctypes
import errno
import io
import os
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from typing import Any

from .proto import FRAME_STDIN, FRAME_STDIN_EOF, FramedTLSSession

_DOUBLE_INT_WINDOW = 1.5
_STDIN_CHUNK_SIZE = 65536
_WIN_FILE_TYPE_CHAR = 2
_WIN_FILE_TYPE_PIPE = 3
_WIN_WAIT_OBJECT_0 = 0
_WIN_INFINITE = 0xFFFFFFFF
_WIN_STARTF_USESTDHANDLES = 0x00000100
_WIN_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_WIN_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_WIN_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
_WIN_ENABLE_PROCESSED_INPUT = 0x0001
_WIN_ENABLE_LINE_INPUT = 0x0002
_WIN_ENABLE_ECHO_INPUT = 0x0004
_WIN_ENABLE_WINDOW_INPUT = 0x0008
_WIN_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_WIN_KEY_EVENT = 0x0001
_WIN_WINDOW_BUFFER_SIZE_EVENT = 0x0004
_WIN_VK_VT_MAP: dict[int, bytes] = {
    0x21: b"\x1b[5~",
    0x22: b"\x1b[6~",
    0x23: b"\x1b[F",
    0x24: b"\x1b[H",
    0x25: b"\x1b[D",
    0x26: b"\x1b[A",
    0x27: b"\x1b[C",
    0x28: b"\x1b[B",
    0x2D: b"\x1b[2~",
    0x2E: b"\x1b[3~",
    0x70: b"\x1bOP",
    0x71: b"\x1bOQ",
    0x72: b"\x1bOR",
    0x73: b"\x1bOS",
    0x74: b"\x1b[15~",
    0x75: b"\x1b[17~",
    0x76: b"\x1b[18~",
    0x77: b"\x1b[19~",
    0x78: b"\x1b[20~",
    0x79: b"\x1b[21~",
    0x7A: b"\x1b[23~",
    0x7B: b"\x1b[24~",
}


class _WinCoord(ctypes.Structure):
    _fields_ = [("X", ctypes.c_short), ("Y", ctypes.c_short)]


def default_shell_argv() -> list[str]:
    """Return the default interactive shell command for the host OS."""
    if sys.platform == "win32":
        ps = shutil.which("powershell.exe")
        if ps:
            return [ps, "-NoLogo"]
        return [os.environ.get("COMSPEC") or "cmd.exe"]
    return [os.environ.get("SHELL") or "/bin/sh"]


def stream_is_tty(stream: Any) -> bool:
    """Return True if stream is attached to an interactive terminal."""
    if stream is None:
        return False
    isatty = getattr(stream, "isatty", None)
    if not callable(isatty):
        return False
    try:
        return bool(isatty())
    except (OSError, ValueError):
        return False


def clamp_terminal_size(cols: int, rows: int) -> tuple[int, int]:
    """Clamp terminal dimensions to sane bounds."""
    return max(1, min(1000, int(cols))), max(1, min(1000, int(rows)))


def terminal_size() -> tuple[int, int]:
    """Return the current local terminal (cols, rows)."""
    sz = shutil.get_terminal_size(fallback=(80, 24))
    return clamp_terminal_size(sz.columns, sz.lines)


def spawn_kwargs_for_process_group() -> dict[str, Any]:
    """Return platform-specific Popen flags to isolate child process signals."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def deliver_signal_to_process(proc: Any, sig_name: str) -> None:
    """Deliver INT, TERM, or KILL to a spawned child process or managed process."""
    if hasattr(proc, "deliver_signal"):
        proc.deliver_signal(sig_name)
        return
    if proc.poll() is not None:
        return
    name = sig_name.upper()
    if sys.platform == "win32":
        if name == "INT":
            try:
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            except (OSError, ValueError):
                proc.terminate()
        elif name in ("TERM", "KILL"):
            proc.kill() if name == "KILL" else proc.terminate()
        return

    sig_map = {
        "INT": signal.SIGINT,
        "TERM": signal.SIGTERM,
        "KILL": signal.SIGKILL,
    }
    sig = sig_map.get(name, signal.SIGINT)
    try:
        os.killpg(proc.pid, sig)
    except ProcessLookupError:
        pass
    except OSError:
        with suppress(OSError):
            proc.send_signal(sig)


class PipeProcess:
    """Uniform process wrapper backed by standard OS pipes."""

    is_pty = False
    has_stderr = True

    def __init__(self, popen: subprocess.Popen[bytes]) -> None:
        self._popen = popen
        self.pid = popen.pid

    def write_stdin(self, data: bytes) -> None:
        if self._popen.stdin is not None and not self._popen.stdin.closed:
            self._popen.stdin.write(data)
            self._popen.stdin.flush()

    def close_stdin(self) -> None:
        if self._popen.stdin is not None and not self._popen.stdin.closed:
            with suppress(OSError):
                self._popen.stdin.close()

    def read_stdout(self, size: int = 4096) -> bytes:
        assert self._popen.stdout is not None
        return self._popen.stdout.read(size)

    def read_stderr(self, size: int = 4096) -> bytes:
        assert self._popen.stderr is not None
        return self._popen.stderr.read(size)

    def resize(self, cols: int, rows: int) -> None:
        return

    def deliver_signal(self, sig_name: str) -> None:
        deliver_signal_to_process(self._popen, sig_name)

    def poll(self) -> int | None:
        return self._popen.poll()

    def wait(self, timeout: float | None = None) -> int:
        return self._popen.wait(timeout=timeout)

    def close_io(self) -> None:
        for pipe in (self._popen.stdin, self._popen.stdout, self._popen.stderr):
            if pipe is not None:
                with suppress(OSError):
                    pipe.close()


class PosixPtyProcess:
    """Uniform process wrapper backed by a POSIX pseudoterminal."""

    is_pty = True
    has_stderr = False

    def __init__(
        self,
        master_fd: int,
        pid: int,
        popen: subprocess.Popen[bytes] | None = None,
    ) -> None:
        self._master_fd: int | None = master_fd
        self.pid = pid
        self._popen = popen
        self._returncode: int | None = None
        self._wait_lock = threading.Lock()

    def write_stdin(self, data: bytes) -> None:
        fd = self._master_fd
        if fd is None:
            return
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                break
            view = view[written:]

    def close_stdin(self) -> None:
        return

    def read_stdout(self, size: int = 4096) -> bytes:
        fd = self._master_fd
        if fd is None:
            return b""
        try:
            return os.read(fd, size)
        except OSError as exc:
            if exc.errno in (errno.EIO, errno.EBADF):
                return b""
            raise

    def read_stderr(self, size: int = 4096) -> bytes:
        return b""

    def resize(self, cols: int, rows: int) -> None:
        fd = self._master_fd
        if fd is None or os.name != "posix":
            return
        import fcntl
        import termios

        c, r = clamp_terminal_size(cols, rows)
        with suppress(OSError):
            fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))

    def deliver_signal(self, sig_name: str) -> None:
        if self.poll() is not None:
            return
        sig_map = {
            "INT": signal.SIGINT,
            "TERM": signal.SIGTERM,
            "KILL": signal.SIGKILL,
        }
        sig = sig_map.get(sig_name.upper(), signal.SIGINT)
        try:
            os.killpg(self.pid, sig)
        except ProcessLookupError:
            pass
        except OSError:
            with suppress(OSError):
                os.kill(self.pid, sig)

    def poll(self) -> int | None:
        if self._popen is not None:
            return self._popen.poll()
        if self._returncode is not None:
            return self._returncode
        if not self._wait_lock.acquire(blocking=False):
            return self._returncode
        try:
            if self._returncode is not None:
                return self._returncode
            try:
                wpid, status = os.waitpid(self.pid, os.WNOHANG)
            except ChildProcessError:
                self._returncode = 0
                return self._returncode
            if wpid != 0:
                self._returncode = os.waitstatus_to_exitcode(status)
            return self._returncode
        finally:
            self._wait_lock.release()

    def wait(self, timeout: float | None = None) -> int:
        if self._popen is not None:
            return self._popen.wait(timeout=timeout)
        with self._wait_lock:
            if self._returncode is not None:
                return self._returncode
            if timeout is None:
                try:
                    _, status = os.waitpid(self.pid, 0)
                    self._returncode = os.waitstatus_to_exitcode(status)
                except ChildProcessError:
                    self._returncode = 0
                return self._returncode
            deadline = time.monotonic() + timeout
            while True:
                try:
                    wpid, status = os.waitpid(self.pid, os.WNOHANG)
                except ChildProcessError:
                    self._returncode = 0
                    return self._returncode
                if wpid != 0:
                    self._returncode = os.waitstatus_to_exitcode(status)
                    return self._returncode
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(str(self.pid), timeout)
                time.sleep(min(0.02, remaining))

    def close_io(self) -> None:
        fd = self._master_fd
        if fd is not None:
            self._master_fd = None
            with suppress(OSError):
                os.close(fd)


class WinConPtyProcess:
    """Uniform process wrapper backed by Windows ConPTY."""

    is_pty = True
    has_stderr = False

    def __init__(
        self,
        k32: Any,
        hpc: ctypes.c_void_p,
        h_process: Any,
        pid: int,
        in_fd: int,
        out_fd: int,
    ) -> None:
        self._k32 = k32
        self._hpc: ctypes.c_void_p | None = hpc
        self._h_process: Any = h_process
        self.pid = pid
        self._in_fd: int | None = in_fd
        self._out_fd: int | None = out_fd
        self._returncode: int | None = None
        self._lock = threading.Lock()
        self._in_lock = threading.Lock()

    def write_stdin(self, data: bytes) -> None:
        with self._in_lock:
            fd = self._in_fd
            if fd is None:
                return
            view = memoryview(data)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    break
                view = view[written:]

    def close_stdin(self) -> None:
        return

    def read_stdout(self, size: int = 4096) -> bytes:
        fd = self._out_fd
        if fd is None:
            return b""
        try:
            return os.read(fd, size)
        except OSError:
            return b""

    def read_stderr(self, size: int = 4096) -> bytes:
        return b""

    def resize(self, cols: int, rows: int) -> None:
        if sys.platform != "win32":
            return
        with self._lock:
            if self._hpc is None:
                return
            c, r = clamp_terminal_size(cols, rows)
            with suppress(OSError):
                self._k32.ResizePseudoConsole(self._hpc, _WinCoord(c, r))

    def deliver_signal(self, sig_name: str) -> None:
        if self.poll() is not None:
            return
        name = sig_name.upper()
        if name == "INT":
            with suppress(OSError):
                self.write_stdin(b"\x03")
        elif name in ("TERM", "KILL"):
            with self._lock:
                if self._h_process is not None:
                    with suppress(OSError):
                        self._k32.TerminateProcess(self._h_process, 1)

    def _close_conpty(self) -> None:
        with self._lock:
            hpc = self._hpc
            self._hpc = None
        if hpc is not None:
            with suppress(OSError):
                self._k32.ClosePseudoConsole(hpc)

    def poll(self) -> int | None:
        from ctypes import wintypes

        exited = False
        with self._lock:
            if self._returncode is not None:
                return self._returncode
            if self._h_process is None:
                return 0
            rc = int(self._k32.WaitForSingleObject(self._h_process, 0))
            if rc == _WIN_WAIT_OBJECT_0:
                code = wintypes.DWORD(0)
                self._k32.GetExitCodeProcess(self._h_process, ctypes.byref(code))
                self._returncode = int(code.value)
                exited = True
            result = self._returncode
        if exited:
            self._close_conpty()
        return result

    def wait(self, timeout: float | None = None) -> int:
        from ctypes import wintypes

        with self._lock:
            if self._returncode is not None:
                cached = self._returncode
                h_proc = None
            else:
                cached = None
                h_proc = self._h_process
        if cached is not None:
            self._close_conpty()
            return cached
        if h_proc is None:
            self._close_conpty()
            return 0

        ms = _WIN_INFINITE if timeout is None else max(0, int(timeout * 1000))
        rc = int(self._k32.WaitForSingleObject(h_proc, ms))
        if rc != _WIN_WAIT_OBJECT_0:
            raise subprocess.TimeoutExpired(str(self.pid), timeout or 0.0)
        with self._lock:
            if self._returncode is None:
                if self._h_process is not None:
                    code = wintypes.DWORD(0)
                    self._k32.GetExitCodeProcess(self._h_process, ctypes.byref(code))
                    self._returncode = int(code.value)
                else:
                    self._returncode = 0
            final_rc = self._returncode
        self._close_conpty()
        return final_rc

    def close_io(self) -> None:
        self._close_conpty()
        with self._in_lock:
            in_fd = self._in_fd
            self._in_fd = None
        if in_fd is not None:
            with suppress(OSError):
                os.close(in_fd)
        out_fd = self._out_fd
        self._out_fd = None
        if out_fd is not None:
            with suppress(OSError):
                os.close(out_fd)
        with self._lock:
            h = self._h_process
            self._h_process = None
        if h is not None:
            with suppress(OSError):
                self._k32.CloseHandle(h)


type ManagedProcess = PipeProcess | PosixPtyProcess | WinConPtyProcess


def _is_wine() -> bool:
    if sys.platform != "win32":
        return False
    try:
        ntdll = ctypes.WinDLL("ntdll")
        return hasattr(ntdll, "wine_get_version")
    except OSError:
        return False


def _spawn_posix_pty(
    cmd: list[str],
    env: dict[str, str],
    cwd: str | None,
    cols: int,
    rows: int,
) -> PosixPtyProcess:
    import fcntl
    import pty
    import termios

    master_fd, slave_fd = pty.openpty()
    c, r = clamp_terminal_size(cols, rows)
    try:
        fcntl.ioctl(slave_fd, termios.TIOCSWINSZ, struct.pack("HHHH", r, c, 0, 0))
        if cwd is None and hasattr(os, "posix_spawnp"):
            slave_name = os.ttyname(slave_fd)
            restore_sigs = [
                sig
                for sig in (
                    getattr(signal, "SIGPIPE", None),
                    getattr(signal, "SIGXFSZ", None),
                )
                if sig is not None
            ]
            file_actions: list[tuple[Any, ...]] = [
                (os.POSIX_SPAWN_CLOSE, master_fd),
                (os.POSIX_SPAWN_CLOSE, slave_fd),
                (os.POSIX_SPAWN_OPEN, 0, slave_name, os.O_RDWR, 0),
                (os.POSIX_SPAWN_DUP2, 0, 1),
                (os.POSIX_SPAWN_DUP2, 0, 2),
            ]
            try:
                pid = os.posix_spawnp(
                    cmd[0],
                    cmd,
                    env,
                    setsid=True,
                    setsigdef=restore_sigs,
                    file_actions=file_actions,
                )
            except NotImplementedError:
                pass
            else:
                os.close(slave_fd)
                return PosixPtyProcess(master_fd, pid)

        def _setup_ctty() -> None:
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        popen = subprocess.Popen(
            cmd,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            env=env,
            cwd=cwd,
            close_fds=True,
            preexec_fn=_setup_ctty,
        )
        os.close(slave_fd)
        return PosixPtyProcess(master_fd, popen.pid, popen=popen)
    except Exception:
        with suppress(OSError):
            os.close(slave_fd)
        with suppress(OSError):
            os.close(master_fd)
        raise


def _spawn_windows_conpty(
    cmd: list[str],
    env: dict[str, str],
    cwd: str | None,
    cols: int,
    rows: int,
) -> WinConPtyProcess | None:
    if sys.platform != "win32" or _is_wine():
        return None
    import msvcrt
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not hasattr(k32, "CreatePseudoConsole"):
        return None

    class _StartupInfoW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _StartupInfoExW(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", _StartupInfoW),
            ("lpAttributeList", ctypes.c_void_p),
        ]

    class _ProcessInfo(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    k32.CreatePipe.argtypes = [
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(wintypes.HANDLE),
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    k32.CreatePipe.restype = wintypes.BOOL
    k32.CreatePseudoConsole.argtypes = [
        _WinCoord,
        wintypes.HANDLE,
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    k32.CreatePseudoConsole.restype = ctypes.c_long
    k32.ResizePseudoConsole.argtypes = [ctypes.c_void_p, _WinCoord]
    k32.ResizePseudoConsole.restype = ctypes.c_long
    k32.ClosePseudoConsole.argtypes = [ctypes.c_void_p]
    k32.InitializeProcThreadAttributeList.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    k32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    k32.UpdateProcThreadAttribute.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    k32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    k32.DeleteProcThreadAttributeList.argtypes = [ctypes.c_void_p]
    k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPWSTR,
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.BOOL,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(_StartupInfoExW),
        ctypes.POINTER(_ProcessInfo),
    ]
    k32.CreateProcessW.restype = wintypes.BOOL
    k32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    k32.WaitForSingleObject.restype = wintypes.DWORD
    k32.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    k32.TerminateProcess.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    k32.CloseHandle.restype = wintypes.BOOL

    in_r = wintypes.HANDLE()
    in_w = wintypes.HANDLE()
    out_r = wintypes.HANDLE()
    out_w = wintypes.HANDLE()
    if not k32.CreatePipe(ctypes.byref(in_r), ctypes.byref(in_w), None, 0):
        return None
    if not k32.CreatePipe(ctypes.byref(out_r), ctypes.byref(out_w), None, 0):
        k32.CloseHandle(in_r)
        k32.CloseHandle(in_w)
        return None

    c, r = clamp_terminal_size(cols, rows)
    hpc = ctypes.c_void_p()
    hr = k32.CreatePseudoConsole(_WinCoord(c, r), in_r, out_w, 0, ctypes.byref(hpc))
    k32.CloseHandle(in_r)
    k32.CloseHandle(out_w)
    if hr != 0:
        k32.CloseHandle(in_w)
        k32.CloseHandle(out_r)
        return None

    attr_size = ctypes.c_size_t(0)
    k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(attr_size))
    attr_buf = ctypes.create_string_buffer(attr_size.value)
    if not k32.InitializeProcThreadAttributeList(attr_buf, 1, 0, ctypes.byref(attr_size)):
        k32.ClosePseudoConsole(hpc)
        k32.CloseHandle(in_w)
        k32.CloseHandle(out_r)
        return None

    if not k32.UpdateProcThreadAttribute(
        attr_buf,
        0,
        _WIN_PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        hpc,
        ctypes.sizeof(ctypes.c_void_p),
        None,
        None,
    ):
        k32.DeleteProcThreadAttributeList(attr_buf)
        k32.ClosePseudoConsole(hpc)
        k32.CloseHandle(in_w)
        k32.CloseHandle(out_r)
        return None

    si = _StartupInfoExW()
    si.StartupInfo.cb = ctypes.sizeof(_StartupInfoExW)
    si.StartupInfo.dwFlags = _WIN_STARTF_USESTDHANDLES
    si.lpAttributeList = ctypes.addressof(attr_buf)
    pi = _ProcessInfo()

    cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline(cmd))
    sorted_env = sorted(env.items(), key=lambda kv: kv[0].upper())
    env_text = "\x00".join(f"{k}={v}" for k, v in sorted_env) + "\x00\x00"
    env_buf = ctypes.create_string_buffer(env_text.encode("utf-16-le"))
    ok = k32.CreateProcessW(
        None,
        cmdline,
        None,
        None,
        False,
        _WIN_EXTENDED_STARTUPINFO_PRESENT | _WIN_CREATE_UNICODE_ENVIRONMENT,
        env_buf,
        cwd,
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    err = ctypes.get_last_error()
    k32.DeleteProcThreadAttributeList(attr_buf)
    if not ok:
        k32.ClosePseudoConsole(hpc)
        k32.CloseHandle(in_w)
        k32.CloseHandle(out_r)
        raise ctypes.WinError(err)

    k32.CloseHandle(pi.hThread)
    in_fd: int | None = None
    try:
        in_fd = msvcrt.open_osfhandle(int(in_w.value), os.O_WRONLY | os.O_BINARY)
        out_fd = msvcrt.open_osfhandle(int(out_r.value), os.O_RDONLY | os.O_BINARY)
    except Exception:
        if in_fd is not None:
            with suppress(OSError):
                os.close(in_fd)
        else:
            k32.CloseHandle(in_w)
        k32.CloseHandle(out_r)
        k32.ClosePseudoConsole(hpc)
        k32.TerminateProcess(pi.hProcess, 1)
        k32.CloseHandle(pi.hProcess)
        raise
    return WinConPtyProcess(k32, hpc, pi.hProcess, int(pi.dwProcessId), in_fd, out_fd)


def spawn_process(
    cmd: list[str],
    *,
    env: dict[str, str],
    cwd: str | None = None,
    use_pty: bool = False,
    cols: int = 80,
    rows: int = 24,
    term: str | None = None,
) -> ManagedProcess:
    """Spawn a child process attached to a PTY when requested and supported, or OS pipes."""
    if use_pty:
        if os.name == "posix":
            pty_env = env.copy()
            pty_env["TERM"] = term or pty_env.get("TERM") or "xterm-256color"
            return _spawn_posix_pty(cmd, pty_env, cwd, cols, rows)
        if sys.platform == "win32":
            conpty_proc = _spawn_windows_conpty(cmd, env, cwd, cols, rows)
            if conpty_proc is not None:
                return conpty_proc

    popen = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0,
        env=env,
        cwd=cwd,
        **spawn_kwargs_for_process_group(),
    )
    return PipeProcess(popen)


@contextmanager
def raw_terminal_mode(
    stdin_stream: Any,
    stdout_stream: Any,
) -> Iterator[bool]:
    """Place the local terminal into raw VT mode for PTY sessions and always restore it."""
    if not stream_is_tty(stdin_stream):
        yield False
        return
    try:
        in_fd = stdin_stream.fileno()
    except (AttributeError, OSError, io.UnsupportedOperation):
        yield False
        return

    if os.name == "posix":
        import termios
        import tty

        try:
            old_attrs = termios.tcgetattr(in_fd)
        except OSError:
            yield False
            return
        tty.setraw(in_fd)
        try:
            yield True
        finally:
            with suppress(OSError):
                termios.tcsetattr(in_fd, termios.TCSADRAIN, old_attrs)
        return

    if sys.platform == "win32":
        import msvcrt
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        k32.GetConsoleMode.restype = wintypes.BOOL
        k32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k32.SetConsoleMode.restype = wintypes.BOOL

        h_in = wintypes.HANDLE(msvcrt.get_osfhandle(in_fd))
        old_in = wintypes.DWORD(0)
        if not k32.GetConsoleMode(h_in, ctypes.byref(old_in)):
            yield False
            return

        new_in = (
            old_in.value
            & ~(
                _WIN_ENABLE_PROCESSED_INPUT
                | _WIN_ENABLE_LINE_INPUT
                | _WIN_ENABLE_ECHO_INPUT
            )
        ) | _WIN_ENABLE_WINDOW_INPUT
        if not k32.SetConsoleMode(h_in, new_in):
            yield False
            return

        h_out: Any = None
        old_out = wintypes.DWORD(0)
        if stream_is_tty(stdout_stream):
            with suppress(AttributeError, OSError, io.UnsupportedOperation):
                out_fd = stdout_stream.fileno()
                cand = wintypes.HANDLE(msvcrt.get_osfhandle(out_fd))
                if k32.GetConsoleMode(cand, ctypes.byref(old_out)):
                    if k32.SetConsoleMode(
                        cand, old_out.value | _WIN_ENABLE_VIRTUAL_TERMINAL_PROCESSING
                    ):
                        h_out = cand

        try:
            yield True
        finally:
            with suppress(OSError):
                k32.SetConsoleMode(h_in, old_in.value)
            if h_out is not None:
                with suppress(OSError):
                    k32.SetConsoleMode(h_out, old_out.value)
        return

    yield False


class _PtyEscapeFilter:
    """Detect SSH-style '~.' detach escape sequence at the start of a line."""

    def __init__(self) -> None:
        self._at_line_start = True
        self._saw_tilde = False

    def feed(self, chunk: bytes) -> tuple[bytes, bool]:
        out = bytearray()
        for b in chunk:
            if self._saw_tilde:
                self._saw_tilde = False
                if b == 0x2E:
                    return bytes(out), True
                if b == 0x7E:
                    out.append(0x7E)
                    self._at_line_start = False
                else:
                    out.append(0x7E)
                    out.append(b)
                    self._at_line_start = b in (0x0A, 0x0D)
            elif self._at_line_start and b == 0x7E:
                self._saw_tilde = True
                self._at_line_start = False
            else:
                out.append(b)
                self._at_line_start = b in (0x0A, 0x0D)
        return bytes(out), False


class StdinForwarder:
    """Non-leaking cross-platform stdin pump feeding a FramedTLSSession."""

    def __init__(
        self,
        session: FramedTLSSession,
        stdin_stream: Any = None,
        *,
        pty_mode: bool = False,
    ) -> None:
        self._session = session
        self._stdin = sys.stdin if stdin_stream is None else stdin_stream
        self._pty_mode = pty_mode
        self._escape = _PtyEscapeFilter() if pty_mode else None
        self._stop_event = threading.Event()
        self._stop_r: int | None = None
        self._stop_w: int | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start background forwarding of stdin."""
        if os.name == "posix" and self._stop_r is None:
            self._stop_r, self._stop_w = os.pipe()
        self._thread = threading.Thread(target=self._run, daemon=True)
        try:
            self._thread.start()
        except Exception:
            self._thread = None
            for fd_attr in ("_stop_r", "_stop_w"):
                fd = getattr(self, fd_attr)
                if fd is not None:
                    setattr(self, fd_attr, None)
                    with suppress(OSError):
                        os.close(fd)
            raise

    def stop(self) -> None:
        """Signal the stdin forwarder to exit and release resources."""
        self._stop_event.set()
        stop_w = self._stop_w
        if stop_w is not None:
            self._stop_w = None
            with suppress(OSError):
                os.write(stop_w, b"x")
            with suppress(OSError):
                os.close(stop_w)
        if self._thread is not None:
            self._thread.join(timeout=0.5)
        elif self._stop_r is not None:
            stop_r = self._stop_r
            self._stop_r = None
            with suppress(OSError):
                os.close(stop_r)

    def _send_eof(self) -> None:
        self._session.enqueue_frame(FRAME_STDIN_EOF)

    def _send_chunk(self, chunk: bytes) -> bool:
        if self._escape is not None:
            chunk, detach = self._escape.feed(chunk)
            if chunk and not self._session.enqueue_frame(FRAME_STDIN, chunk):
                return False
            if detach:
                self._session.enqueue_urgent("DETACH")
                return False
            return True
        return self._session.enqueue_frame(FRAME_STDIN, chunk)

    def _forward_fd_once(self, fd: int, size: int = 4096) -> bool:
        try:
            chunk = os.read(fd, size)
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not chunk:
            self._send_eof()
            return False
        return self._send_chunk(chunk)

    def _run_stream_fallback(self) -> None:
        raw_buf = getattr(self._stdin, "buffer", self._stdin)
        if hasattr(raw_buf, "read"):
            while not self._stop_event.is_set():
                try:
                    chunk = raw_buf.read(_STDIN_CHUNK_SIZE)
                except (OSError, ValueError):
                    break
                if not chunk:
                    break
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                for offset in range(0, len(chunk), _STDIN_CHUNK_SIZE):
                    if not self._send_chunk(chunk[offset : offset + _STDIN_CHUNK_SIZE]):
                        return
        self._send_eof()

    def _run(self) -> None:
        stop_r = self._stop_r
        self._stop_r = None
        try:
            if self._stdin is None:
                self._send_eof()
                return
            try:
                fd = self._stdin.fileno()
            except (AttributeError, OSError, io.UnsupportedOperation):
                self._run_stream_fallback()
                return

            if sys.platform == "win32":
                self._run_windows(fd)
            else:
                self._run_posix(fd, stop_r)
        finally:
            if stop_r is not None:
                with suppress(OSError):
                    os.close(stop_r)

    def _run_posix(self, fd: int, stop_r: int | None) -> None:
        assert stop_r is not None
        sel = selectors.DefaultSelector()
        try:
            sel.register(stop_r, selectors.EVENT_READ, data="stop")
            try:
                sel.register(fd, selectors.EVENT_READ, data="stdin")
            except (OSError, ValueError):
                while not self._stop_event.is_set():
                    if not self._forward_fd_once(fd):
                        break
                return

            while not self._stop_event.is_set():
                try:
                    ready = sel.select()
                except (OSError, ValueError):
                    break
                keys = {key.data for key, _ in ready}
                if "stop" in keys or self._stop_event.is_set():
                    break
                if "stdin" in keys and not self._forward_fd_once(fd):
                    break
        finally:
            with suppress(Exception):
                sel.close()

    def _run_windows(self, fd: int) -> None:
        if sys.platform != "win32":
            return
        import msvcrt
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetFileType.argtypes = [wintypes.HANDLE]
        kernel32.GetFileType.restype = wintypes.DWORD
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.GetConsoleMode.restype = wintypes.BOOL
        kernel32.PeekNamedPipe.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.PeekNamedPipe.restype = wintypes.BOOL
        kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.WaitForSingleObject.restype = wintypes.DWORD
        kernel32.ReadConsoleInputW.argtypes = [
            wintypes.HANDLE,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
        ]
        kernel32.ReadConsoleInputW.restype = wintypes.BOOL

        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        file_type = int(kernel32.GetFileType(handle))
        console_mode = wintypes.DWORD(0)
        is_console = bool(kernel32.GetConsoleMode(handle, ctypes.byref(console_mode)))

        prev_mode: int | None = None
        if not is_console:
            with suppress(OSError):
                prev_mode = msvcrt.setmode(fd, os.O_BINARY)

        try:
            if file_type == _WIN_FILE_TYPE_PIPE:
                avail = wintypes.DWORD(0)
                while not self._stop_event.is_set():
                    ok = kernel32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None)
                    if not ok:
                        self._send_eof()
                        return
                    if avail.value > 0:
                        if not self._forward_fd_once(fd, min(4096, int(avail.value))):
                            return
                    else:
                        self._stop_event.wait(0.02)
                return

            if file_type == _WIN_FILE_TYPE_CHAR:
                if not is_console:
                    self._send_eof()
                    return
                if self._pty_mode:
                    rec_buf = ctypes.create_string_buffer(20)
                    rec_read = wintypes.DWORD(0)
                    high_surrogate: int | None = None
                    while not self._stop_event.is_set():
                        wait_rc = kernel32.WaitForSingleObject(handle, 50)
                        if wait_rc != _WIN_WAIT_OBJECT_0:
                            continue
                        if (
                            not kernel32.ReadConsoleInputW(
                                handle, rec_buf, 1, ctypes.byref(rec_read)
                            )
                            or rec_read.value == 0
                        ):
                            self._stop_event.wait(0.02)
                            continue
                        ev_type = struct.unpack_from("<H", rec_buf.raw, 0)[0]
                        if ev_type == _WIN_WINDOW_BUFFER_SIZE_EVENT:
                            self._session.enqueue_urgent("RESIZE")
                            continue
                        if ev_type != _WIN_KEY_EVENT:
                            continue
                        key_down, repeat, vk, _scan, uchar = struct.unpack_from(
                            "<IHHHH", rec_buf.raw, 4
                        )
                        if not key_down:
                            continue
                        count = max(1, repeat)
                        if uchar != 0:
                            if 0xD800 <= uchar <= 0xDBFF:
                                high_surrogate = uchar
                                continue
                            if 0xDC00 <= uchar <= 0xDFFF and high_surrogate is not None:
                                codepoint = (
                                    0x10000
                                    + ((high_surrogate - 0xD800) << 10)
                                    + (uchar - 0xDC00)
                                )
                                high_surrogate = None
                                data = chr(codepoint).encode("utf-8") * count
                            else:
                                high_surrogate = None
                                data = chr(uchar).encode("utf-8") * count
                        else:
                            high_surrogate = None
                            seq = _WIN_VK_VT_MAP.get(vk)
                            if seq is None:
                                continue
                            data = seq * count
                        if not self._send_chunk(data):
                            return
                    return

                while not self._stop_event.is_set():
                    wait_rc = kernel32.WaitForSingleObject(handle, 50)
                    if wait_rc == _WIN_WAIT_OBJECT_0:
                        if msvcrt.kbhit():
                            if not self._forward_fd_once(fd):
                                return
                        else:
                            self._stop_event.wait(0.02)
                return

            while not self._stop_event.is_set():
                if not self._forward_fd_once(fd):
                    return
        finally:
            if prev_mode is not None:
                with suppress(OSError):
                    msvcrt.setmode(fd, prev_mode)


@contextmanager
def winch_guard(on_resize: Callable[[], None]) -> Iterator[None]:
    """Intercept SIGWINCH on POSIX main thread to forward terminal resize events."""
    if (
        threading.current_thread() is not threading.main_thread()
        or not hasattr(signal, "SIGWINCH")
    ):
        yield
        return

    def _handler(_signum: int, _frame: Any) -> None:
        on_resize()

    prev = signal.getsignal(signal.SIGWINCH)
    signal.signal(signal.SIGWINCH, _handler)
    try:
        yield
    finally:
        if prev is not None:
            signal.signal(signal.SIGWINCH, prev)


@contextmanager
def interrupt_guard(
    on_first: Callable[[], None],
    on_second: Callable[[], None],
) -> Iterator[None]:
    """Temporarily intercept SIGINT/SIGBREAK on the main thread with double-press escalation."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    last_int = 0.0

    def _handler(_signum: int, _frame: Any) -> None:
        nonlocal last_int
        now = time.monotonic()
        if last_int and (now - last_int) <= _DOUBLE_INT_WINDOW:
            on_second()
        else:
            last_int = now
            on_first()

    prev_int = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, _handler)
    prev_break = None
    has_break = sys.platform == "win32" and hasattr(signal, "SIGBREAK")
    if has_break:
        prev_break = signal.getsignal(signal.SIGBREAK)
        signal.signal(signal.SIGBREAK, _handler)
    try:
        yield
    finally:
        if prev_int is not None:
            signal.signal(signal.SIGINT, prev_int)
        if has_break and prev_break is not None:
            signal.signal(signal.SIGBREAK, prev_break)
