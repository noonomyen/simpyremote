import hashlib
import io
import json
import os
import posixpath
import shutil
import socket
import tarfile
import tempfile
import threading
from contextlib import suppress
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .proto import (
    FRAME_ERROR,
    FRAME_FILE_DATA,
    FRAME_FILE_DONE,
    FRAME_FILE_GET,
    FRAME_FILE_PUT,
    decode_error_payload,
    recv_frame,
    send_frame,
    send_json,
)

TRANSFER_CHUNK_SIZE = 65536


class _FrameChunkWriter(io.RawIOBase):
    """Stream file or tarfile bytes as FRAME_FILE_DATA chunks with running SHA-256."""

    def __init__(self, sock: socket.socket, lock: threading.Lock | None) -> None:
        self._sock = sock
        self._lock = lock
        self.hasher = hashlib.sha256()
        self.total_bytes = 0

    def writable(self) -> bool:
        return True

    def write(self, b: bytes | bytearray | memoryview) -> int:
        data = bytes(b)
        if not data:
            return 0
        for offset in range(0, len(data), TRANSFER_CHUNK_SIZE):
            chunk = data[offset : offset + TRANSFER_CHUNK_SIZE]
            self.hasher.update(chunk)
            self.total_bytes += len(chunk)
            send_frame(self._sock, FRAME_FILE_DATA, chunk, lock=self._lock)
        return len(data)


def _sanitize_leaf_name(raw_name: Any) -> str:
    name = str(raw_name or "")
    if not name or name in (".", "..") or "\x00" in name or "/" in name or "\\" in name:
        raise ValueError(f"Unsafe transfer filename: {raw_name!r}")
    win = PureWindowsPath(name)
    pos = PurePosixPath(name)
    if win.drive or win.root or pos.root or win.parts != (name,) or pos.parts != (name,):
        raise ValueError(f"Unsafe transfer filename: {raw_name!r}")
    return name


def _is_explicit_dir_target(raw_dst: str, resolved: Path) -> bool:
    return raw_dst.endswith(("/", "\\")) or resolved.is_dir()


def _resolve_dest_file(raw_dst: str, src_name: str) -> Path:
    safe_name = _sanitize_leaf_name(src_name)
    dst = Path(raw_dst).expanduser()
    if _is_explicit_dir_target(raw_dst, dst):
        base = dst.resolve()
        candidate = (base / safe_name).resolve()
        if not candidate.is_relative_to(base):
            raise ValueError(f"Transfer destination escapes base directory: {src_name!r}")
        return dst / safe_name
    return dst


def _logical_leaf_name(raw_src: str | os.PathLike[str], resolved: Path) -> str:
    raw_name = Path(raw_src).expanduser().name
    candidate = raw_name if raw_name not in ("", ".", "..") else resolved.name
    return _sanitize_leaf_name(candidate)


def _stream_source_to_frames(
    sock: socket.socket,
    src_path: Path,
    *,
    arcname: str | None = None,
    lock: threading.Lock | None = None,
) -> tuple[int, str]:
    writer = _FrameChunkWriter(sock, lock)
    if src_path.is_dir():
        with tarfile.open(fileobj=writer, mode="w|") as tar:
            tar.add(src_path, arcname=arcname or src_path.name)
    else:
        with src_path.open("rb") as f:
            shutil.copyfileobj(f, writer, TRANSFER_CHUNK_SIZE)
    return writer.total_bytes, writer.hasher.hexdigest()


def _prepare_dest(
    raw_dst: str,
    meta: dict[str, Any],
) -> tuple[bool, Path, Path, Path, str]:
    is_dir = bool(meta.get("is_dir", False))
    safe_name = _sanitize_leaf_name(meta.get("name"))
    if is_dir:
        dst_dir = Path(raw_dst).expanduser()
        dst_dir.mkdir(parents=True, exist_ok=True)
        base = dst_dir.resolve()
        final_target = dst_dir / safe_name
        if not final_target.resolve().is_relative_to(base):
            raise ValueError(f"Transfer destination escapes base directory: {safe_name!r}")
        final_target.mkdir(parents=True, exist_ok=True)
        return True, dst_dir, final_target, final_target, safe_name
    dst_file = _resolve_dest_file(raw_dst, safe_name)
    dst_file.parent.mkdir(parents=True, exist_ok=True)
    return False, dst_file.parent, dst_file, dst_file, safe_name


def _prepare_tar_members(tar: tarfile.TarFile, safe_name: str) -> list[tarfile.TarInfo]:
    prepared: list[tarfile.TarInfo] = []
    seen_symlinks: set[str] = set()
    for member in tar.getmembers():
        if not member.name or "\x00" in member.name or "\\" in member.name:
            raise ValueError(f"Unsafe archive member path: {member.name!r}")
        parts = PurePosixPath(member.name).parts
        if not parts or parts[0] != safe_name or ".." in parts:
            raise ValueError(
                f"Archive member escapes target directory {safe_name!r}: {member.name!r}"
            )
        if len(parts) == 1:
            if not member.isdir():
                raise ValueError(f"Unsafe archive root entry: {member.name!r}")
            continue
        rel_parts = parts[1:]
        for depth in range(1, len(rel_parts)):
            if posixpath.join(*rel_parts[:depth]) in seen_symlinks:
                raise ValueError(
                    f"Archive member traverses through symlink: {member.name!r}"
                )
        rel_name = posixpath.join(*rel_parts)
        if member.islnk():
            if not member.linkname or "\x00" in member.linkname or "\\" in member.linkname:
                raise ValueError(f"Unsafe archive link target: {member.linkname!r}")
            link_parts = PurePosixPath(member.linkname).parts
            if len(link_parts) < 2 or link_parts[0] != safe_name or ".." in link_parts:
                raise ValueError(
                    f"Archive hardlink escapes target directory {safe_name!r}: {member.linkname!r}"
                )
            member.linkname = posixpath.join(*link_parts[1:])
        elif member.issym():
            if not member.linkname or "\x00" in member.linkname or "\\" in member.linkname:
                raise ValueError(f"Unsafe archive symlink target: {member.linkname!r}")
            if member.linkname.startswith("/"):
                raise ValueError(
                    f"Archive symlink escapes target directory {safe_name!r}: {member.linkname!r}"
                )
            resolved = posixpath.normpath(
                posixpath.join(posixpath.dirname(rel_name), member.linkname)
            )
            if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
                raise ValueError(
                    f"Archive symlink escapes target directory {safe_name!r}: {member.linkname!r}"
                )
            seen_symlinks.add(rel_name)
        member.name = rel_name
        prepared.append(member)
    return prepared


def _receive_stream_to_dest(
    sock: socket.socket,
    raw_dst: str,
    meta: dict[str, Any],
    *,
    send_ready_ack: bool = False,
) -> tuple[Path, int]:
    is_dir, tmp_dir, dst_target, final_target, safe_name = _prepare_dest(raw_dst, meta)
    mode = meta.get("mode")

    hasher = hashlib.sha256()
    received = 0
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=tmp_dir, prefix=".simpyremote.", delete=False
        ) as tmp:
            tmp_path = Path(tmp.name)
            if send_ready_ack:
                send_json(sock, FRAME_FILE_PUT, {"ready": True})
            while True:
                frame = recv_frame(sock)
                if frame is None:
                    raise EOFError("Connection closed before FILE_DONE")
                msg_type, payload = frame
                if msg_type == FRAME_FILE_DATA:
                    tmp.write(payload)
                    hasher.update(payload)
                    received += len(payload)
                elif msg_type == FRAME_FILE_DONE:
                    done = json.loads(payload.decode("utf-8"))
                    expected_size = int(done["size"])
                    expected_sha = str(done["sha256"])
                    if received != expected_size or hasher.hexdigest() != expected_sha:
                        raise ValueError(
                            f"Transfer integrity mismatch: size {received}/{expected_size}"
                        )
                    break
                elif msg_type == FRAME_ERROR:
                    raise RuntimeError(decode_error_payload(payload))
                else:
                    raise RuntimeError(f"Unexpected frame type during transfer: {msg_type}")

        if is_dir:
            with tarfile.open(tmp_path, mode="r:") as tar:
                members = _prepare_tar_members(tar, safe_name)
                tar.extractall(path=dst_target, members=members, filter="data")
            tmp_path.unlink(missing_ok=True)
            tmp_path = None
            return final_target, received

        if os.name == "posix" and isinstance(mode, int) and not isinstance(mode, bool):
            with suppress(OSError):
                os.chmod(tmp_path, mode & 0o755)
        os.replace(tmp_path, dst_target)
        tmp_path = None
        return dst_target, received
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def client_push(
    sock: socket.socket,
    local_src: str | os.PathLike[str],
    remote_dst: str,
    *,
    recursive: bool = False,
) -> tuple[str, int]:
    """Upload a local file or directory to the remote server."""
    src_path = Path(local_src).expanduser().resolve()
    if not src_path.exists():
        raise FileNotFoundError(f"Local path not found: {src_path}")
    is_dir = src_path.is_dir()
    if is_dir and not recursive:
        raise IsADirectoryError(f"{src_path} is a directory; pass recursive=True / -r")
    safe_name = _logical_leaf_name(local_src, src_path)

    mode = src_path.stat().st_mode if not is_dir else None
    send_json(
        sock,
        FRAME_FILE_PUT,
        {
            "dst": remote_dst,
            "name": safe_name,
            "is_dir": is_dir,
            "mode": mode,
        },
    )
    ready = recv_frame(sock)
    if ready is None:
        raise EOFError("Server closed connection before accepting upload")
    if ready[0] == FRAME_ERROR:
        raise RuntimeError(decode_error_payload(ready[1]))
    if ready[0] != FRAME_FILE_PUT:
        raise RuntimeError(f"Unexpected server reply before upload: {ready[0]}")

    total, sha256_hex = _stream_source_to_frames(sock, src_path, arcname=safe_name)
    send_json(sock, FRAME_FILE_DONE, {"size": total, "sha256": sha256_hex})

    reply = recv_frame(sock)
    if reply is None:
        raise EOFError("Server closed connection before acknowledging upload")
    msg_type, payload = reply
    if msg_type == FRAME_ERROR:
        raise RuntimeError(decode_error_payload(payload))
    if msg_type != FRAME_FILE_DONE:
        raise RuntimeError(f"Unexpected server reply: {msg_type}")
    ack = json.loads(payload.decode("utf-8"))
    return str(ack["path"]), int(ack["size"])


def client_pull(
    sock: socket.socket,
    remote_src: str,
    local_dst: str | os.PathLike[str],
    *,
    recursive: bool = False,
) -> tuple[Path, int]:
    """Download a remote file or directory from the server."""
    send_json(
        sock,
        FRAME_FILE_GET,
        {"src": remote_src, "recursive": recursive},
    )
    first = recv_frame(sock)
    if first is None:
        raise EOFError("Server closed connection before sending file metadata")
    msg_type, payload = first
    if msg_type == FRAME_ERROR:
        raise RuntimeError(decode_error_payload(payload))
    if msg_type != FRAME_FILE_GET:
        raise RuntimeError(f"Unexpected server reply: {msg_type}")
    meta = json.loads(payload.decode("utf-8"))
    return _receive_stream_to_dest(sock, os.fspath(local_dst), meta)


def server_handle_file_put(sock: socket.socket, meta: dict[str, Any]) -> None:
    """Receive an uploaded file/directory from a client and send DONE ack."""
    try:
        saved_path, received = _receive_stream_to_dest(
            sock, str(meta["dst"]), meta, send_ready_ack=True
        )
        send_json(sock, FRAME_FILE_DONE, {"path": str(saved_path), "size": received})
    except Exception as exc:
        with suppress(OSError):
            send_json(sock, FRAME_ERROR, {"error": str(exc)})


def server_handle_file_get(sock: socket.socket, req: dict[str, Any]) -> None:
    """Stream a requested file/directory back to a client."""
    try:
        raw_src = str(req["src"])
        src_path = Path(raw_src).expanduser().resolve()
        if not src_path.exists():
            raise FileNotFoundError(f"Remote path not found: {src_path}")
        is_dir = src_path.is_dir()
        if is_dir and not req.get("recursive", False):
            raise IsADirectoryError(
                f"Remote path {src_path} is a directory; pass recursive=True / -r"
            )
        safe_name = _logical_leaf_name(raw_src, src_path)
        mode = src_path.stat().st_mode if not is_dir else None
        send_json(
            sock,
            FRAME_FILE_GET,
            {"name": safe_name, "is_dir": is_dir, "mode": mode},
        )
        total, sha256_hex = _stream_source_to_frames(sock, src_path, arcname=safe_name)
        send_json(sock, FRAME_FILE_DONE, {"size": total, "sha256": sha256_hex})
    except Exception as exc:
        with suppress(OSError):
            send_json(sock, FRAME_ERROR, {"error": str(exc)})
