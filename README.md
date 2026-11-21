# simpyremote - Simple Python Remote

A lightweight remote shell, Python function runner, and file transfer tool using a single shared secret over TLS 1.3 (Python 3.14 / 3.15).

## What It Does

- Run commands or open a realtime interactive shell/REPL on a remote machine (automatically allocates a PTY when used from a terminal, and uses clean raw pipes when redirected).
- Send a Python function from your script to run on the remote machine (`run` for live terminal I/O, `call` to get the return value back).
- Upload and download files or folders (`push` / `pull`).
- Runs from source (`src/simpyremote`), as a single `.py` file (`dist/simpyremote.py`), or as a standalone PyInstaller executable (`ELF` / `.exe`) with zero external runtime dependencies.

## Install

```bash
pip install .
```

Or run directly without installing using `python dist/simpyremote.py` (see [Build & Test](#build--test)).

## Usage

### 1. Start the Server

On the target machine:

```bash
# Auto-generate a random 32-character secret
simpyremote --server 0.0.0.0 --port 2222

# Or set your own secret
SIMPYREMOTE_SECRET=mysecret simpyremote --server 0.0.0.0 --port 2222
# or
simpyremote --server 0.0.0.0 --port 2222 --pre-auth mysecret
```

### 2. Configure Client (`.simpyremote`)

Optionally save your connection details in `./.simpyremote` or `~/.simpyremote`:

```ini
addr=192.168.0.100
port=2222
secret=mysecret
```

CLI flags (`--remote`, `--auth`) override `.simpyremote`.

### 3. Run Commands & Transfer Files

```bash
# Run a command with explicit target
simpyremote --remote 192.168.0.100:2222 --auth mysecret -- powershell.exe -Command Get-Date

# Run a command using .simpyremote
simpyremote -- uname -a

# Open a remote shell or interactive REPL (auto-PTY)
simpyremote
simpyremote -- python

# Force PTY (-t) or raw pipes (-T)
simpyremote -T -- uname -a

# Copy files and directories
simpyremote --push ./local.bin /tmp/remote.bin
simpyremote --pull /var/log/app.log ./app.log
simpyremote -r --push ./my_folder /tmp/dest
```

In interactive PTY mode, `Ctrl+C`, `Ctrl+D`, tab completion, arrow keys, and terminal resize work in realtime; press `Enter` then `~.` to detach if a remote process hangs. In pipe mode (`-T` or `run()`), use `Ctrl+D` (`Ctrl+Z` then `Enter` on Windows) for EOF and `Ctrl+C` to interrupt (press twice quickly to detach).

### 4. Use from Python (`run`, `call`, `push`, `pull`)

```python
from simpyremote import call, pull, push, run

def hello():
    print(__name__)

# Runs on the remote machine with live stdio and returns exit code
run(hello)

# Runs in a fresh remote process and returns the function's return value
def list_logs(path):
    import os
    return [f for f in os.listdir(path) if f.endswith(".log")]

for name in call(list_logs, "/var/log"):
    pull(f"/var/log/{name}", f"./logs/{name}")
```

To specify a target in code without `.simpyremote`:

```python
from simpyremote import Client

c = Client(remote="192.168.0.100:2222", auth="mysecret")
c.call(list_logs, "/var/log")
```

Note on `call()`: each `call()` spawns a new remote process and exits when finished, so changes like `os.chdir()` or globals do not carry over to the next `call()`.

See [docs/guide.md](docs/guide.md) for the full CLI/API reference, serialization rules, and security model, and [docs/architecture.md](docs/architecture.md) for protocol and internal design diagrams.

## Security Notes

- Anyone who knows the shared secret has full command execution as the server user. Prefer the auto-generated 32-character secret or a long random secret.
- Restrict `.simpyremote` permissions (`chmod 600 .simpyremote`) and do not run `simpyremote` blindly inside untrusted repositories that might contain a `.simpyremote` file.

## Build & Test

```bash
# Generate single-file script (dist/simpyremote.py)
python scripts/build_single.py

# Build standalone binary with PyInstaller (requires pyinstaller installed)
pyinstaller --onefile --clean --name simpyremote --distpath ./dist --workpath ./build --specpath ./build ./dist/simpyremote.py

# Run tests locally
python -m unittest discover -s tests -v

# Run tests in Docker (Linux + Wine Windows Python 3.14 & 3.15)
./scripts/test_docker.sh --build
```
