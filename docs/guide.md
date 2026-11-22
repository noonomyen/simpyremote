# simpyremote Documentation

For internal protocol framing, concurrency design, and sequence diagrams, see [docs/architecture.md](architecture.md).

## Concept & Design Philosophy

`simpyremote` (Simple Python Remote) is a lightweight remote execution tool designed around one simple idea: give you direct remote command execution, Python function execution, and file transfer over a single shared secret without SSH setup, certificates, or heavy orchestration frameworks.

Key design principles:

- **Zero external runtime dependencies**: Built 100% on Python 3.14+ standard library (`ssl`, `hashlib.scrypt`, `pty`/`ctypes`, `selectors`, `ast`, `tarfile`).
- **Stateless per-invocation isolation**: Every CLI command, `run()`, and `call()` opens a dedicated TLS 1.3 PSK session, spawns a fresh OS child process on the server, holds the connection until the process exits and output finishes draining, and cleans up immediately.
- **Realtime interactive PTY when human, clean pipes when scripted**: Interactive terminal invocations automatically allocate a real pseudoterminal (POSIX `pty.openpty` / Windows ConPTY) so shells and REPLs (`python`, `bash`, `powershell.exe`, `vim`) behave natively in realtime. Redirected/piped invocations and Python `run()`/`call()` use 8-bit clean separated `stdout`/`stderr` pipes.
- **Deploy anywhere**: Run directly from `src/simpyremote`, distribute a single amalgamated `simpyremote.py` file, or bundle into a standalone PyInstaller `ELF` / `.exe`.

## Configuration & Precedence

Client connection settings are resolved in strict priority order:

1. Explicit CLI flags (`--remote`, `--port`, `--auth`) or `Client(remote=..., port=..., auth=...)` arguments.
2. `SIMPYREMOTE_SECRET` environment variable (for the secret).
3. Config file:
   - `SIMPYREMOTE_CONFIG` environment variable (if set; fails if the file does not exist).
   - `./.simpyremote` in the current working directory.

Server secret resolution order:

1. `--pre-auth <secret>` CLI flag.
2. `SIMPYREMOTE_SECRET` environment variable.
3. Auto-generated 32-character cryptographically random `[A-Za-z0-9]` secret (printed to stderr only when auto-generated).

Example `.simpyremote` file:

```ini
addr=192.168.0.100
port=2222
secret=your_shared_secret_here
# Optional: suppress non-fatal warnings (short secret, .simpyremote permissions)
ignore_warnings=true
```

On POSIX systems, `.simpyremote` files owned by another user or writable by group/others are ignored, and files readable by group/others emit a warning recommending `chmod 600` (unless `ignore_warnings=true` or `--ignore-warnings` is set). Note that `.simpyremote` is only consulted when target or secret is omitted (pass `--ignore-warnings` when supplying both `--remote` and `--auth` or `SIMPYREMOTE_SECRET`).

## CLI Reference

### Server Mode

```bash
simpyremote --server [HOST] [--port PORT] [--pre-auth SECRET] [--ignore-warnings]
```

- `--server [HOST]`: Bind host/IP only (never `HOST:PORT`; defaults to `127.0.0.1` if `--server` is passed without a value; use `0.0.0.0` for all IPv4 interfaces or `::` for dual-stack IPv6/IPv4).
- `--port PORT`: TCP port (`0..65535`, default `2222`; `0` picks an ephemeral OS port).
- `--pre-auth SECRET`: Pre-shared secret (overrides `SIMPYREMOTE_SECRET`).
- `--ignore-warnings`: Suppress non-fatal security warnings (short secret, `.simpyremote` permissions).

### Client Mode

```bash
simpyremote [--remote HOST[:PORT]] [--port PORT] [--auth SECRET] [--ignore-warnings] [-t | -T] [-- COMMAND [ARGS...]]
simpyremote [--remote HOST[:PORT]] [--port PORT] [--auth SECRET] [--ignore-warnings] [-r] --push LOCAL REMOTE
simpyremote [--remote HOST[:PORT]] [--port PORT] [--auth SECRET] [--ignore-warnings] [-r] --pull REMOTE LOCAL
```

- `--remote HOST[:PORT]`: Server address (supports IPv4, hostname, and bracketed IPv6 like `[::1]:2222`).
- `--port PORT`: Port override (`1..65535`).
- `--auth SECRET`: Authentication secret override.
- `--ignore-warnings`: Suppress non-fatal security warnings (short secret, `.simpyremote` permissions).
- `-t` / `--pty`: Force pseudo-terminal allocation.
- `-T` / `--no-pty`: Disable pseudo-terminal allocation and force raw pipes.
- `-- COMMAND [ARGS...]`: `--` is mandatory before any remote command; everything after the first `--` is forwarded verbatim as the remote command argv. If omitted (and neither `--push` nor `--pull` is given), the server opens its default shell (`$SHELL` / `/bin/sh` on POSIX, `powershell.exe -NoLogo` / `cmd.exe` on Windows).
- `--push LOCAL REMOTE`: Upload a local file (auto-creates missing parent directories; trailing `/` places the file inside that directory) or directory with `-r`/`--recursive` (always nests the source directory basename inside `REMOTE`, e.g. `-r --push ./mydir /tmp/dest` creates `/tmp/dest/mydir/...`).
- `--pull REMOTE LOCAL`: Download a remote file or directory with the same destination semantics.

### Distribution Modes

- **Installed package**: Use `simpyremote ...` and `from simpyremote import ...`.
- **Standalone binary** (`dist/simpyremote` / `dist/simpyremote.exe`): Self-contained CLI client and server (including serving remote Python workers); cannot be imported from Python.
- **Single-file Python** (`dist/simpyremote.py`, requires Python 3.14+): Run CLI via `python dist/simpyremote.py ...` or import via `PYTHONPATH=dist`.

### Signals, EOF, and Detaching

- **PTY mode (default on interactive terminal)**:
  - `Ctrl+C` (`\x03`), `Ctrl+D` (`\x04`), arrow keys, tab completion, colors, and terminal resize (`SIGWINCH` / Windows console buffer resize) work in realtime.
  - Press `Enter` followed by `~.` to detach the client if a remote process hangs (prints the remote PID so you can inspect or kill it from another session). Type `~~` at the start of a line to send a literal `~`.
- **Pipe mode (`-T`, redirected I/O, or Python `run()`)**:
  - `Ctrl+D` (`Ctrl+Z` then `Enter` on Windows console) sends EOF to remote `stdin`.
  - First `Ctrl+C` sends `SIGINT` (POSIX process group) or `CTRL_BREAK_EVENT` (Windows) to the remote process.
  - Pressing `Ctrl+C` twice within 1.5 seconds detaches the client and reports the remote PID.
  - Server-side unconsumed `stdin` buffering is capped at 4 MiB (`MAX_PENDING_STDIN_BYTES`) to prevent unbounded RAM growth when piping large data to a slow-reading process.

## Python API Guide

### Quick Helpers (Using `.simpyremote` / Env)

```python
from simpyremote import RemoteError, call, pull, push, run

def greet(name: str) -> None:
    print(f"hello {name} from {__name__}")

rc = run(greet, "world")

def disk_usage(path: str) -> dict[str, int]:
    import shutil
    u = shutil.disk_usage(path)
    return {"total": u.total, "used": u.used, "free": u.free}

try:
    stats = call(disk_usage, "/")
except RemoteError as exc:
    print(exc.exc_type, exc.remote_traceback)

push("./payload.bin", "/tmp/payload.bin")
pull("/var/log/app.log", "./logs/")
```

### Explicit Client & Advanced Options

Use `Client` to specify connection details in code, reuse the derived PSK/SSL context across calls, or pass execution options without colliding with function keyword arguments:

```python
import io
from simpyremote import Client, serve

client = Client(remote="192.168.0.100:2222", auth="example_shared_secret_123456", ignore_warnings=None)

# Run an OS command (stdout/stderr accept BytesIO, binary files, StringIO, or TextIOWrapper)
buf = io.BytesIO()
rc = client.run_cmd(["uname", "-a"], cwd="/tmp", pty=False, stdout=buf)

# Run a Python function with custom stdio or working directory
rc = client.run_with(greet, args=("world",), cwd="/tmp", stdout=io.StringIO())

# Stateless RPC with explicit JSON or opt-in pickle serialization
res = client.call_with(disk_usage, args=("/",), cwd="/tmp")
raw_obj = client.call_with(lambda: (b"bytes", {1, 2}), serializer="pickle")

# File and recursive directory transfers
remote_path, nbytes = client.push("./folder", "/tmp/dest", recursive=True)
local_path, nbytes = client.pull("/tmp/dest/folder", "./local_dest", recursive=True)

# Embed a server in Python (port=0 picks an ephemeral port)
# serve(host="127.0.0.1", port=2222, pre_auth=None, stop_event=ev, on_listening=cb, ignore_warnings=False)
```

### How Function Serialization Works

1. **Source extraction (default)**: `inspect.getsource()` + AST parsing extracts the function body, strips decorators, supports single-expression `lambda`s and recursive functions, and captures top-level `import mod` / `import mod as alias` plus JSON-primitive globals/nonlocals. Note that `from mod import Symbol` and calls to sibling top-level helper functions are not captured; place `from ... import ...` and helper `def`s inside the function itself. This works across Linux <-> Windows and Python 3.14 <-> 3.15.
2. **Bytecode fallback**: Dynamically created functions (e.g. via `exec()`) fall back to `marshal` bytecode with reconstructed closure cells. Bytecode fallback requires the same Python minor version on both sides (e.g. 3.14 <-> 3.14).
3. **Builtins**: Module-level builtins such as `os.getcwd` are sent by module + qualname, with `posix`/`nt` automatically normalized to `os` for cross-OS calls.
4. **Constraints**:
   - Only synchronous non-generator functions are supported (`async def`, generators, and async generators are rejected; run `asyncio.run(...)` inside a regular function instead).
   - Remote workers run with `python -P` (safe path), so the remote working directory is not automatically added to `sys.path`.
   - `call()` is strictly stateless: `os.chdir()`, globals, and environment changes do not carry over between calls. Batch loops inside a single `call()` rather than calling `call()` in a tight loop.

## Security Model

- **Mutual-auth TLS 1.3 External PSK**: The shared secret is stretched with `hashlib.scrypt` (`N=16384, r=8, p=1`, 32-byte key) and used exclusively for TLS 1.3 PSK (`OP_NO_TICKET` enabled). The client enforces `verify_mode = ssl.CERT_REQUIRED` with zero loaded CAs plus post-handshake verification (`version() == "TLSv1.3"` and `getpeercert(binary_form=True) is None`), preventing certificate-downgrade MITM attacks.
- **Strict serializer enforcement**: `call()` defaults to JSON and rejects any response attempting to switch serializers (e.g. a server returning `serializer="pickle"` to a JSON call).
- **Secret isolation**: The server strips `SIMPYREMOTE_SECRET` from all spawned child process environments and never logs configured secrets.
- **Safe file transfers**: All transfers verify byte count and SHA-256 before committing. Single files use atomic `os.replace()` and reject path traversal names (`..`, `/`, `\`, drive prefixes, escaping symlinks) while masking POSIX permissions with `0o755` (never world-writable). Directory transfers validate every archive member, symlink, and hardlink stays within the target folder and extract using Python's `tarfile` `filter="data"`.
- **Operational guidance**: Anyone with the shared secret can execute arbitrary commands as the server OS user. Use a strong 32-character secret, bind to `127.0.0.1` or a trusted private network/VPN when possible, protect `.simpyremote` with `chmod 600`, and avoid running `simpyremote` inside untrusted repositories that may contain a `.simpyremote` file.
