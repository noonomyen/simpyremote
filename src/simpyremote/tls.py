import hashlib
import selectors
import socket
import ssl
import sys
import time
from contextlib import suppress
from functools import lru_cache

PSK_IDENTITY = "simpyremote-v1"
HANDSHAKE_TIMEOUT = 5.0
CONNECT_TIMEOUT = 10.0
_SCRYPT_SALT = b"simpyremote-tls13-psk-v1"


def ensure_tls_psk_support() -> None:
    """Verify the Python runtime supports TLS 1.3 PSK callbacks and scrypt."""
    if not (
        hasattr(ssl.SSLContext, "set_psk_client_callback")
        and hasattr(ssl.SSLContext, "set_psk_server_callback")
    ):
        raise RuntimeError(
            "simpyremote requires Python 3.14+ (or PyInstaller build) for native TLS 1.3 PSK"
        )
    if not getattr(ssl, "HAS_TLSv1_3", False):
        raise RuntimeError("OpenSSL in this Python build does not support TLS 1.3")
    if not hasattr(hashlib, "scrypt"):
        raise RuntimeError("OpenSSL in this Python build does not support hashlib.scrypt")


def warn_if_weak_secret(secret: str) -> None:
    """Warn on stderr when a custom secret is short and vulnerable to offline guessing."""
    if len(secret) < 16:
        print(
            "[simpyremote] warning: secret is shorter than 16 chars; "
            "consider using a 32-char random secret to resist offline binder attacks",
            file=sys.stderr,
        )


@lru_cache(maxsize=16)
def derive_psk(secret: str) -> bytes:
    """Derive and cache a 32-byte TLS 1.3 PSK from the shared secret."""
    ensure_tls_psk_support()
    return hashlib.scrypt(
        secret.encode("utf-8"),
        salt=_SCRYPT_SALT,
        n=16384,
        r=8,
        p=1,
        dklen=32,
    )


def build_server_ssl_context(psk: bytes) -> ssl.SSLContext:
    """Create a TLS 1.3 server context authenticating clients via PSK."""
    ensure_tls_psk_support()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TICKET
    ctx.set_psk_server_callback(lambda identity: psk if identity == PSK_IDENTITY else b"")
    return ctx


def build_client_ssl_context(psk: bytes) -> ssl.SSLContext:
    """Create a TLS 1.3 client context enforcing PSK-only mutual auth (rejects any X.509 cert)."""
    ensure_tls_psk_support()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.options |= ssl.OP_NO_TICKET
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.set_psk_client_callback(lambda hint: (PSK_IDENTITY, psk))
    return ctx


def handshake_with_deadline(
    raw_sock: socket.socket,
    ssl_ctx: ssl.SSLContext,
    *,
    server_side: bool,
    timeout: float = HANDSHAKE_TIMEOUT,
) -> ssl.SSLSocket:
    """Wrap raw_sock and complete TLS 1.3 PSK handshake within a wall-clock deadline."""
    raw_sock.setblocking(False)
    tls_sock = ssl_ctx.wrap_socket(
        raw_sock,
        server_side=server_side,
        do_handshake_on_connect=False,
    )
    deadline = time.monotonic() + timeout
    sel = selectors.DefaultSelector()
    try:
        while True:
            try:
                tls_sock.do_handshake()
                break
            except ssl.SSLWantReadError:
                ev = selectors.EVENT_READ
            except ssl.SSLWantWriteError:
                ev = selectors.EVENT_WRITE
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("TLS handshake timed out")
            sel.register(tls_sock, ev)
            try:
                ready = sel.select(timeout=remaining)
            finally:
                sel.unregister(tls_sock)
            if not ready:
                raise TimeoutError("TLS handshake timed out")

        if tls_sock.version() != "TLSv1.3":
            raise ssl.SSLError(f"Unexpected TLS version: {tls_sock.version()!r}")
        if tls_sock.getpeercert(binary_form=True) is not None:
            raise ssl.SSLError("Certificate-based handshake rejected; TLS 1.3 PSK required")

        tls_sock.setblocking(True)
        tls_sock.settimeout(None)
        return tls_sock
    except BaseException:
        with suppress(OSError):
            tls_sock.close()
        raise
    finally:
        with suppress(Exception):
            sel.close()


def connect_tls(
    addr: str,
    port: int,
    ssl_ctx: ssl.SSLContext,
    timeout: float = CONNECT_TIMEOUT,
) -> ssl.SSLSocket:
    """Connect TCP and complete the TLS 1.3 PSK handshake."""
    raw_sock = socket.create_connection((addr, port), timeout=timeout)
    with suppress(OSError):
        raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        return handshake_with_deadline(
            raw_sock, ssl_ctx, server_side=False, timeout=timeout
        )
    except BaseException:
        with suppress(OSError):
            raw_sock.close()
        raise
