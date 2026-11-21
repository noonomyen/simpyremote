---
name: simpyremote
description: Execute remote commands, interactive PTY shells/REPLs, Python functions (run/call), and streaming file transfers (push/pull) across Linux and Windows targets over mutual-auth TLS 1.3 PSK using simpyremote. Use when interacting with a remote host via CLI or Python scripts where .simpyremote, SIMPYREMOTE_SECRET, or --remote/--auth credentials are available.
---

# simpyremote Agent Skill

## Core Concept & Mental Model

`simpyremote` (Simple Python Remote) is a zero-dependency, composable remote execution primitive over mutual-authentication TLS 1.3 External PSK (Python 3.14+ or standalone ELF/EXE).

Keep four architectural principles in mind when using it:

1. **No heavy orchestration layer**: `simpyremote` intentionally avoids high-level state machines or agent-specific wrappers. Compose standard OS commands and plain Python functions directly.
2. **One invocation = one isolated OS process**: Every CLI command, `run(fn)`, and `call(fn)` opens a fresh TLS 1.3 PSK session, spawns a fresh child process on the remote host, holds the session until the process exits and output drains, and returns the exit code or return value. No remote interpreter state persists between invocations.
3. **Auto-PTY vs clean pipes**: CLI commands automatically allocate a realtime pseudoterminal (POSIX `pty.openpty` / Windows ConPTY) when attached to an interactive terminal, and use 8-bit clean separated `stdout`/`stderr` pipes when stdin/stdout is redirected (or forced with `-T`/`--no-pty`). Python `run()` and `call()` always use separated pipes with line-buffered remote stdio.
4. **Single shared secret = mutual TLS 1.3 auth**: Both sides derive a 32-byte key from the secret via `scrypt` and authenticate using TLS 1.3 External PSK (X.509 certificate handshakes are rejected). Anyone holding the secret has full command execution as the server user.

## Invocation & Distribution Modes

`simpyremote` can be invoked in three equivalent forms:

- **Installed package**: CLI `simpyremote ...` and Python `from simpyremote import ...`.
- **Standalone compiled binary** (`./simpyremote` or `simpyremote.exe`): Full CLI client and server (including serving remote Python `run()`/`call()` workers), with no Python install needed on the target. Cannot be `import`ed as a Python module.
- **Single-file Python script** (`simpyremote.py`, requires Python 3.14+): Run CLI via `python /path/to/simpyremote.py ...`, or import its Python API by adding its parent directory to `PYTHONPATH` / `sys.path` (`PYTHONPATH=/path/to/dir python -c "from simpyremote import Client"`).

## Primitives & API Reference

### 1. CLI Commands & Interactive Shells

```bash
# Start server (default bind is 127.0.0.1, default port is 2222; auto-generates 32-char secret if omitted)
simpyremote --server
simpyremote --server 0.0.0.0 --port 2222
SIMPYREMOTE_SECRET=<secret> simpyremote --server 127.0.0.1 --port 2222
simpyremote --server 127.0.0.1 --port 2222 --pre-auth <secret>

# Run remote command (explicit target or via .simpyremote; '--' is mandatory before the command)
simpyremote --remote 192.168.0.100:2222 --auth <secret> -- <cmd...>
simpyremote --remote 192.168.0.100 --port 2222 --auth <secret> -- uname -a
simpyremote -- powershell.exe -Command Get-Date

# Open default remote shell or interactive REPL (auto-PTY on TTY)
simpyremote
simpyremote -- python

# Force PTY (-t / --pty) or force raw pipes (-T / --no-pty)
simpyremote -t -- bash
simpyremote -T -- python -c "print('clean')"

# File and directory transfer (-r / --recursive)
simpyremote --push ./local.bin /tmp/remote.bin
simpyremote --pull /var/log/app.log ./app.log
simpyremote -r --push ./local_dir /tmp/dest
simpyremote -r --pull /remote/dir ./local_dest
```

Important CLI rules:

- `--server [HOST]` accepts a bare host/IP only (never `HOST:PORT`); pass `--port` separately (`--port 0` binds an ephemeral port). Default host is `127.0.0.1`, default port is `2222`.
- `--remote` accepts `HOST[:PORT]` (or `[ipv6][:PORT]`), optionally overridden by `--port`.
- `--` is **mandatory** before any remote command, even if the command has no flags.
- There is no CLI `--cwd` or `--config` flag; use `Client.run_cmd(..., cwd=...)` (or `sh -c 'cd ... && ...'`) and `SIMPYREMOTE_CONFIG=/path/to/rc`.
- CLI exit codes: remote command's exit code on execution, `0` on successful transfer, `1` on auth/runtime/network/remote error, `2` on invalid CLI flags or missing config, and `130` on client interrupt/detach.

### 2. Python API

Top-level helpers read `.simpyremote` / `SIMPYREMOTE_SECRET`:

```python
from simpyremote import Client, RemoteError, call, pull, push, run, serve
```

- `run(fn, *args, **kwargs) -> int`: Serializes `fn`, executes it in an isolated remote OS process with `__name__ == "__main__"` and live `stdin`/`stdout`/`stderr`, and returns the process exit code.
- `call(fn, *args, **kwargs) -> T`: Executes `fn` in a fresh stateless remote process and returns its JSON-serialized return value. `stdout`/`stderr` still stream live without corrupting the return payload. Remote exceptions raise `RemoteError` (`exc.exc_type`, `exc.remote_traceback`).
- `push(local_src, remote_dst, *, recursive=False) -> tuple[str, int]`: Streams a file (64 KiB chunks, SHA-256 verified, atomic `os.replace`) or directory (`tarfile` archive verified before extraction with `filter="data"` and strict target-directory scoping). Returns `(saved_remote_path, bytes_transferred)`.
- `pull(remote_src, local_dst, *, recursive=False) -> tuple[Path, int]`: Downloads a file or directory with the same integrity and path-safety checks. Returns `(saved_local_path, bytes_transferred)`.
- `serve(host="127.0.0.1", port=2222, pre_auth=None, *, stop_event=None, on_listening=None) -> None`: Starts an embedded server in Python (`port=0` picks an ephemeral port; `on_listening(host, bound_port, secret, was_generated)` fires once listening; set `stop_event` to stop cleanly).

Use `Client` when specifying target overrides or advanced options without colliding with `fn`'s `**kwargs`:

```python
client = Client(remote="192.168.0.100:2222", auth="example_shared_secret_123456")
# or Client(remote="192.168.0.100", port=2222, auth="example_shared_secret_123456")

rc = client.run_cmd(["uname", "-a"], cwd="/tmp", pty=False, stdin=..., stdout=..., stderr=...)
rc = client.run_cmd()  # argv=None opens the server's default shell
rc = client.run(fn, *args, **kwargs)
rc = client.run_with(fn, args=(1,), kwargs={"k": "v"}, cwd="/tmp", serializer="json", stdin=..., stdout=..., stderr=...)
val = client.call(fn, *args, **kwargs)
val = client.call_with(fn, args=(1,), kwargs={"k": "v"}, cwd="/tmp", serializer="json", forward_stdin=False, stdin=..., stdout=..., stderr=...)
val_bin = client.call_with(fn_returning_bytes, serializer="pickle")
remote_path, nbytes = client.push("./local.bin", "/tmp/remote.bin", recursive=False)
local_path, nbytes = client.pull("/tmp/remote.bin", "./out.bin", recursive=False)
```

Stream parameters (`stdin`, `stdout`, `stderr`): `stdout` and `stderr` accept binary streams (`io.BytesIO`, `open(..., "wb")`), text wrappers with a `.buffer` (`io.TextIOWrapper`, `open(..., "w")`), and plain text streams (`io.StringIO`, using incremental UTF-8 decoding). Note that server-side unconsumed `stdin` is capped at 4 MiB (`MAX_PENDING_STDIN_BYTES`); piping >4 MiB into a remote process that does not drain stdin aborts the session with a `RemoteError`.

### 3. File & Directory Transfer Semantics

- **Single files**: Missing parent directories are created automatically. If the destination ends with `/` (or `\`) or is an existing directory, the source filename is placed inside it.
- **Directories (`-r` / `recursive=True`)**: Always nests the source directory's basename **inside** the destination directory, even if the destination does not yet exist (unlike `cp -r` / `scp -r`). For example, `-r --push ./mydir /tmp/dest` creates `/tmp/dest/mydir/...`, and `-r --pull /remote/mydir ./out` creates `./out/mydir/...`.

## Configuration Precedence

- **Client**: CLI flags (`--remote`, `--port`, `--auth`) > `SIMPYREMOTE_SECRET` env var > config file (`SIMPYREMOTE_CONFIG` env var, else trusted `./.simpyremote`, else trusted `~/.simpyremote`).
- **Server**: `--pre-auth` > `SIMPYREMOTE_SECRET` > auto-generated 32-char `[A-Za-z0-9]` secret (printed to stderr only when auto-generated; configured secrets are redacted in logs).

`.simpyremote` format:

```ini
addr=192.168.0.100
port=2222
secret=example_shared_secret_123456
```

On POSIX, `./.simpyremote` and `~/.simpyremote` are ignored if owned by another user or writable by group/others (`chmod 666`), while group/other-readable files (`chmod 644`) emit a warning to stderr and still load. Use `chmod 600 .simpyremote`.

## Choosing the Right Primitive

| Goal | Primitive | Why |
| :--- | :--- | :--- |
| Run an existing OS binary, shell pipeline, or tool | `simpyremote -- <cmd>` or `Client.run_cmd` | Direct process execution, no Python serialization overhead. |
| Interactive shell, REPL, debugger, or TUI | `simpyremote` / `simpyremote -- <repl>` | Auto-PTY delivers raw keystrokes, colors, and resize events in realtime. |
| Query remote state and get structured Python data back | `call(fn, ...)` | Returns typed JSON data (dicts/lists/strings/ints) cleanly separated from stdout/stderr. |
| Run a long-lived Python script with live output/stdin | `run(fn, ...)` | Streams live line-buffered stdio, supports stdin, returns exit code. |
| Move files or directory trees | `push` / `pull` or `--push` / `--pull` | Chunked 64 KiB streaming with SHA-256 verification and traversal guards. |

## Recommended Usage Patterns for Agents

### Pattern 1: Inspect Remotely, Pull Selectively

Instead of pulling whole directories or parsing messy shell output, run a small Python inspection function via `call()` and only transfer matching files:

```python
from simpyremote import call, pull

def find_recent_logs(root: str, limit: int = 5) -> list[str]:
    from pathlib import Path
    files = sorted(Path(root).glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    return [str(p) for p in files[:limit]]

for remote_path in call(find_recent_logs, "/var/log/app"):
    pull(remote_path, "./collected/")
```

### Pattern 2: Batch Work Inside One `call()`

Each `call()` performs a TLS 1.3 handshake and spawns a new remote worker process (and if the server is a PyInstaller `--onefile` binary, each worker unpacks its bundle). Never call `call()` inside a tight loop; move the loop inside the remote function:

```python
def stat_all(paths: list[str]) -> dict[str, int | None]:
    import os
    return {p: (os.path.getsize(p) if os.path.exists(p) else None) for p in paths}

sizes = call(stat_all, ["/etc/hosts", "/etc/hostname"])
```

### Pattern 3: Non-Interactive / Binary-Clean Automation

When running CLI commands from an agent harness or capturing binary output, pass `-T` (or `pty=False` with `stdout=io.BytesIO()` in `Client.run_cmd`) to guarantee raw pipes with no ANSI escape codes or `\r\n` translation.

### Pattern 4: Recovering from Hung Remote Processes

- In **PTY mode**: `Ctrl+C` forwards `\x03` to the remote PTY foreground group; if the remote process ignores it, press `Enter` then `~.` to detach cleanly.
- In **pipe mode** (`-T` or `run()`): first `Ctrl+C` sends `SIGINT` (POSIX process group) or `CTRL_BREAK_EVENT` (Windows); pressing `Ctrl+C` twice within 1.5s detaches and prints `(remote pid=...)`.
- After detaching, launch a second `simpyremote` invocation to inspect or terminate that PID (e.g. `simpyremote -- kill -9 <pid>` on POSIX or `simpyremote -- taskkill /PID <pid> /F` on Windows).

### Pattern 5: Cross-OS Workflows (Linux <-> Windows)

- Always pass remote paths as raw strings (`r"C:\Users\app\out.bin"` or `"/var/log/app.log"`). Never construct remote paths with local `pathlib.Path`.
- Remote functions serialized from source (`def fn(...): ...`) work across Linux <-> Windows and Python 3.14 <-> 3.15. Builtins like `os.getcwd` are automatically normalized across `posix`/`nt`.

## Serialization Rules & Constraints

1. **Function serialization**: `simpyremote` extracts AST source via `inspect.getsource()` by default (supports single-expression lambdas and recursive functions). If source is unavailable (e.g. `exec`-generated functions), it falls back to `marshal` bytecode, which requires matching client/server Python minor versions (`3.14` <-> `3.14`).
2. **Imports & helper functions**: Only top-level `import mod` and `import mod as alias` are captured automatically. **`from mod import Symbol` and calls to sibling top-level helper functions are NOT captured** and will fail remotely with `RemoteError: NameError`. Put `from ... import ...` statements and nested helper `def`s **inside** `fn`.
3. **Closures & globals**: JSON-primitive globals/nonlocals are captured in both modes; non-JSON values (e.g. `Path`, `set`, custom objects) are silently omitted under default `serializer="json"` (causing remote `NameError`) unless passed as arguments or using `serializer="pickle"`.
4. **Decorators**: Pass-through decorators and `@functools.wraps` functions work, but wrapper logic is bypassed when decorators are stripped/unwrapped. Plain non-`wraps` wrapper decorators fail remotely.
5. **Synchronous functions only**: `async def` coroutines, generators, and async generators are rejected with `TypeError`; wrap `asyncio.run(...)` inside a regular `def` function instead.
6. **JSON by default, pickle opt-in**: `call()` uses JSON by default and rejects any server response whose serializer does not match what the client requested. Only pass `serializer="pickle"` to `Client.call_with()` when both sides are trusted and you need non-JSON Python types (e.g. `bytes`, `set`, `tuple`).
7. **Worker safe-path mode (`python -P`)**: Remote workers run with `-P`, so the remote working directory is not auto-added to `sys.path`. If a remote function needs to import local modules from the remote CWD, add `sys.path.insert(0, ".")` inside the function.
8. **Statelessness**: `os.chdir()`, environment edits, and global variables inside `call()` disappear as soon as the call returns. Always pass explicit paths or `cwd=...`.

## Troubleshooting & Diagnostics

- **Auto-generated secret log format (stderr)**: `[simpyremote] listening on <host>:<port> (TLS 1.3 PSK, generated secret=<32-char>)`. Configured secrets print `configured secret` instead of the secret value.
- **Wrong secret**: Fails during TLS handshake with `[SSL: TLSV1_ALERT_DECRYPT_ERROR]` (exit code `1`), not an application-level message.
- **Short secret warning**: Secrets shorter than 16 characters emit a warning to stderr on both client and server; use >=16-char (ideally 32-char) secrets to keep stderr clean.

## Security & Secret Hygiene

- Prefer `.simpyremote` (`chmod 600`) or `SIMPYREMOTE_SECRET` environment variable over `--auth` / `--pre-auth` flags (CLI arguments can appear in local process listings).
- Never commit `.simpyremote` files or print secrets in logs/prompts.
- Do not run `simpyremote` blindly inside untrusted repositories that could contain a crafted `./.simpyremote` file.
- Server automatically strips `SIMPYREMOTE_SECRET` from child process environments.
