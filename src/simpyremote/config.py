import os
import secrets
import stat
import string
import sys
from dataclasses import dataclass
from pathlib import Path

DEFAULT_PORT = 2222
DEFAULT_BIND = "127.0.0.1"
SECRET_LEN = 32
SECRET_ALPHABET = string.ascii_letters + string.digits
RC_FILENAME = ".simpyremote"


@dataclass(frozen=True, slots=True)
class ClientConfig:
    """Resolved client connection settings."""

    addr: str
    port: int
    secret: str


def validate_port(port: int) -> int:
    """Validate that port is within the TCP range 1..65535."""
    if not (1 <= port <= 65535):
        raise ValueError(f"Invalid port: {port}")
    return port


def generate_secret(length: int = SECRET_LEN) -> str:
    """Generate a cryptographically random A-Za-z0-9 secret."""
    return "".join(secrets.choice(SECRET_ALPHABET) for _ in range(length))


def parse_remote_spec(spec: str, fallback_port: int = DEFAULT_PORT) -> tuple[str, int]:
    """Parse host[:port] or [ipv6][:port] into (host, port)."""
    spec = spec.strip()
    if not spec:
        raise ValueError("Empty remote address")
    if spec.startswith("["):
        end = spec.find("]")
        if end == -1:
            raise ValueError(f"Invalid IPv6 address: {spec!r}")
        host = spec[1:end].strip()
        if not host:
            raise ValueError(f"Empty remote host: {spec!r}")
        rest = spec[end + 1 :]
        if rest.startswith(":"):
            return host, validate_port(int(rest[1:]))
        if rest:
            raise ValueError(f"Invalid remote address: {spec!r}")
        return host, validate_port(fallback_port)
    if spec.count(":") == 1:
        host, port_str = spec.rsplit(":", 1)
        host = host.strip()
        if not host:
            raise ValueError(f"Empty remote host: {spec!r}")
        return host, validate_port(int(port_str))
    return spec, validate_port(fallback_port)


def _is_trusted_rc_file(path: Path) -> bool:
    if os.name != "posix":
        return True
    try:
        st = path.stat()
    except OSError:
        return False
    if st.st_uid != os.geteuid():
        print(
            f"[simpyremote] ignoring {path}: owned by another user (use SIMPYREMOTE_CONFIG to override)",
            file=sys.stderr,
        )
        return False
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        print(
            f"[simpyremote] ignoring {path}: writable by group/others; run chmod 600",
            file=sys.stderr,
        )
        return False
    return True


def find_config_file() -> Path | None:
    """Locate .simpyremote from env override, trusted CWD, or user home."""
    env_path = os.environ.get("SIMPYREMOTE_CONFIG")
    if env_path:
        p = Path(env_path).expanduser()
        if not p.is_file():
            raise FileNotFoundError(f"SIMPYREMOTE_CONFIG file not found: {p}")
        return p
    cwd_candidate = Path.cwd() / RC_FILENAME
    if cwd_candidate.is_file() and _is_trusted_rc_file(cwd_candidate):
        return cwd_candidate
    try:
        home_candidate = Path.home() / RC_FILENAME
    except RuntimeError:
        return None
    if home_candidate.is_file() and _is_trusted_rc_file(home_candidate):
        return home_candidate
    return None


def _warn_insecure_file_perms(path: Path) -> None:
    if os.name != "posix":
        return
    try:
        mode = path.stat().st_mode
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            print(
                f"[simpyremote] warning: {path} is readable by group/others; recommend chmod 600",
                file=sys.stderr,
            )
    except OSError:
        pass


def load_rc_file(path: Path) -> dict[str, str]:
    """Parse key=value entries from a .simpyremote file."""
    _warn_insecure_file_perms(path)
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid line in {path}: {raw_line!r}")
        key, val = line.split("=", 1)
        key = key.strip().lower()
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        data[key] = val
    return data


def resolve_client_config(
    remote: str | None = None,
    port: int | None = None,
    auth: str | None = None,
) -> ClientConfig:
    """Resolve client address, port, and secret with CLI > env > .simpyremote precedence."""
    explicit_secret = auth or os.environ.get("SIMPYREMOTE_SECRET")
    rc: dict[str, str] = {}
    if not (remote and explicit_secret):
        rc_path = find_config_file()
        if rc_path:
            rc = load_rc_file(rc_path)

    if remote:
        fallback = validate_port(port) if port is not None else DEFAULT_PORT
        addr, parsed_port = parse_remote_spec(remote, fallback_port=fallback)
        final_port = validate_port(port) if port is not None else parsed_port
    elif rc.get("addr"):
        rc_port = validate_port(int(rc["port"])) if rc.get("port") else DEFAULT_PORT
        fallback = validate_port(port) if port is not None else rc_port
        addr, parsed_port = parse_remote_spec(rc["addr"], fallback_port=fallback)
        final_port = validate_port(port) if port is not None else parsed_port
    else:
        raise ValueError(
            "Missing remote target: pass --remote host:port or configure .simpyremote"
        )

    secret = explicit_secret or rc.get("secret")
    if not secret:
        raise ValueError(
            "Missing auth secret: pass --auth, set SIMPYREMOTE_SECRET, or configure .simpyremote"
        )
    return ClientConfig(addr=addr, port=validate_port(final_port), secret=secret)


def resolve_server_secret(pre_auth: str | None = None) -> tuple[str, bool]:
    """Resolve server secret from CLI, env, or generate a fresh 32-char secret."""
    if pre_auth:
        return pre_auth, False
    env_secret = os.environ.get("SIMPYREMOTE_SECRET")
    if env_secret:
        return env_secret, False
    return generate_secret(), True


def split_argv_at_double_dash(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """Split CLI arguments at the first '--' separator."""
    if "--" not in argv:
        return argv, None
    idx = argv.index("--")
    return argv[:idx], argv[idx + 1 :]
