import ast
import base64
import importlib
import inspect
import json
import marshal
import os
import pickle
import signal
import socket
import sys
import textwrap
import traceback
import types
from contextlib import suppress
from typing import Any

from .proto import FRAME_CONTROL, recv_frame, send_frame, send_json

_SKIP_GLOBAL_BINDINGS = frozenset(
    {"__name__", "__package__", "__file__", "__spec__", "__builtins__", "__doc__", "__cached__"}
)


class RemoteError(RuntimeError):
    """Raised on the client when a remote call() fails."""

    def __init__(self, message: str, remote_traceback: str = "", exc_type: str = ""):
        super().__init__(message)
        self.remote_traceback = remote_traceback
        self.exc_type = exc_type


def encode_data(obj: Any, serializer: str) -> Any:
    """Encode an object using json (passthrough) or base64-wrapped pickle."""
    if serializer == "json":
        json.dumps(obj)
        return obj
    if serializer == "pickle":
        return base64.b64encode(pickle.dumps(obj)).decode("ascii")
    raise ValueError(f"Unsupported serializer: {serializer!r}")


def decode_data(raw: Any, serializer: str) -> Any:
    """Decode an object previously encoded with encode_data."""
    if serializer == "json":
        return raw
    if serializer == "pickle":
        return pickle.loads(base64.b64decode(raw.encode("ascii")))
    raise ValueError(f"Unsupported serializer: {serializer!r}")


def _is_json_primitive(val: Any, _seen: set[int] | None = None) -> bool:
    if val is None or isinstance(val, (bool, int, float, str)):
        return True
    if isinstance(val, (list, tuple, dict)):
        seen = set() if _seen is None else _seen
        obj_id = id(val)
        if obj_id in seen:
            return False
        seen.add(obj_id)
        try:
            if isinstance(val, dict):
                return all(
                    isinstance(k, str) and _is_json_primitive(v, seen)
                    for k, v in val.items()
                )
            return all(_is_json_primitive(item, seen) for item in val)
        finally:
            seen.remove(obj_id)
    return False


def _extract_source(fn: Any) -> tuple[str, str]:
    raw_src = textwrap.dedent(inspect.getsource(fn))
    tree = ast.parse(raw_src)
    func_name = getattr(fn, "__name__", "_remote_fn")
    if len(tree.body) == 1 and isinstance(tree.body[0], ast.FunctionDef):
        tree.body[0].decorator_list = []
        return ast.unparse(tree), tree.body[0].name
    if func_name == "<lambda>":
        lambdas = [node for node in ast.walk(tree) if isinstance(node, ast.Lambda)]
        if len(lambdas) == 1:
            lam = lambdas[0]
            fn_def = ast.FunctionDef(
                name="_remote_lambda",
                args=lam.args,
                body=[ast.Return(value=lam.body)],
                decorator_list=[],
                lineno=1,
                col_offset=0,
            )
            ast.fix_missing_locations(fn_def)
            return ast.unparse(fn_def), "_remote_lambda"
        raise ValueError("Cannot unambiguously extract lambda source")
    return raw_src, func_name


def _collect_closure_env(fn: Any, serializer: str) -> tuple[list[list[str]], dict[str, Any]]:
    imports: list[list[str]] = []
    bindings: dict[str, Any] = {}
    try:
        cv = inspect.getclosurevars(fn)
    except Exception:
        return imports, bindings

    def _capture(name: str, val: Any) -> None:
        if _is_json_primitive(val):
            bindings[name] = encode_data(val, serializer)
        elif serializer == "pickle":
            with suppress(Exception):
                bindings[name] = encode_data(val, "pickle")

    for name, val in cv.globals.items():
        if name in _SKIP_GLOBAL_BINDINGS or val is fn:
            continue
        if isinstance(val, types.ModuleType):
            imports.append([name, val.__name__])
        else:
            _capture(name, val)
    for name, val in cv.nonlocals.items():
        if val is fn:
            continue
        if isinstance(val, types.ModuleType):
            imports.append([name, val.__name__])
        else:
            _capture(name, val)
    return imports, bindings


def serialize_callable(
    fn: Any,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    *,
    mode: str = "run",
    serializer: str = "json",
) -> dict[str, Any]:
    """Serialize a Python callable, its captured bindings, and arguments."""
    if not callable(fn):
        raise TypeError(f"Expected callable, got {type(fn).__name__}")
    if isinstance(fn, types.MethodType):
        raise TypeError("Bound methods are not supported; pass a standalone function")
    if (
        inspect.iscoroutinefunction(fn)
        or inspect.isgeneratorfunction(fn)
        or inspect.isasyncgenfunction(fn)
    ):
        raise TypeError("Remote execution only supports synchronous non-generator callables")
    if serializer not in ("json", "pickle"):
        raise ValueError(f"Unsupported serializer: {serializer!r}")

    payload: dict[str, Any] = {
        "mode": mode,
        "serializer": serializer,
        "args": encode_data(list(args), serializer),
        "kwargs": encode_data(kwargs, serializer),
        "py_ver": list(sys.version_info[:2]),
    }

    mod_name = getattr(fn, "__module__", None)
    bound_self = getattr(fn, "__self__", None)
    if (
        isinstance(fn, types.BuiltinFunctionType)
        and isinstance(mod_name, str)
        and (bound_self is None or isinstance(bound_self, types.ModuleType))
    ):
        if mod_name in ("posix", "nt"):
            mod_name = "os"
        payload["kind"] = "builtin"
        payload["module"] = mod_name
        payload["qualname"] = fn.__qualname__
        return payload

    try:
        src_text, extracted_name = _extract_source(fn)
        unwrapped = inspect.unwrap(fn)
        imports, bindings = _collect_closure_env(unwrapped, serializer)
        payload["kind"] = "source"
        payload["source"] = src_text
        payload["func_name"] = extracted_name
        payload["imports"] = imports
        payload["bindings"] = bindings
        return payload
    except (OSError, TypeError, IndentationError, SyntaxError, ValueError):
        code = getattr(fn, "__code__", None)
        if code is None:
            raise TypeError(
                f"Cannot serialize callable {fn!r}: source unavailable and no __code__"
            )
        imports, bindings = _collect_closure_env(fn, serializer)
        payload["kind"] = "code"
        payload["func_name"] = getattr(fn, "__name__", "_remote_fn")
        payload["imports"] = imports
        payload["bindings"] = bindings
        payload["code_b64"] = base64.b64encode(marshal.dumps(code)).decode("ascii")
        defaults = getattr(fn, "__defaults__", None)
        kwdefaults = getattr(fn, "__kwdefaults__", None)
        if defaults is not None:
            payload["defaults"] = encode_data(list(defaults), serializer)
        if kwdefaults is not None:
            payload["kwdefaults"] = encode_data(kwdefaults, serializer)
        return payload


def _build_callable_from_job(job: dict[str, Any]) -> Any:
    kind = job["kind"]
    serializer = str(job.get("serializer", "json"))
    if kind == "builtin":
        obj: Any = importlib.import_module(job["module"])
        for attr in job["qualname"].split("."):
            obj = getattr(obj, attr)
        return obj

    ns: dict[str, Any] = {"__name__": "__main__"}
    for alias, mod_name in job.get("imports", ()):
        ns[alias] = importlib.import_module(mod_name)
    for name, val in job.get("bindings", {}).items():
        ns[name] = decode_data(val, serializer)

    if kind == "source":
        compiled = compile(job["source"], "<simpyremote>", "exec")
        exec(compiled, ns)
        return ns[job["func_name"]]

    if kind == "code":
        client_ver = tuple(job["py_ver"])
        server_ver = sys.version_info[:2]
        if client_ver != server_ver:
            raise RuntimeError(
                f"Bytecode fallback requires matching Python minor version: "
                f"client={client_ver[0]}.{client_ver[1]}, server={server_ver[0]}.{server_ver[1]}"
            )
        code = marshal.loads(base64.b64decode(job["code_b64"].encode("ascii")))
        defaults = tuple(decode_data(job["defaults"], serializer)) if "defaults" in job else None
        closure: tuple[types.CellType, ...] | None = None
        if code.co_freevars:
            missing = [name for name in code.co_freevars if name not in ns]
            if missing:
                raise RuntimeError(f"Unserializable closure variables: {', '.join(missing)}")
            closure = tuple(types.CellType(ns[name]) for name in code.co_freevars)
        rebuilt = types.FunctionType(code, ns, job["func_name"], defaults, closure)
        if "kwdefaults" in job:
            rebuilt.__kwdefaults__ = dict(decode_data(job["kwdefaults"], serializer))
        return rebuilt

    raise ValueError(f"Unknown job kind: {kind!r}")


def _configure_worker_streams_and_signals() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconf = getattr(stream, "reconfigure", None)
        if callable(reconf):
            with suppress(Exception):
                reconf(line_buffering=True, write_through=True)
    if sys.platform == "win32" and hasattr(signal, "SIGBREAK"):
        def _on_break(_signum: int, _frame: Any) -> None:
            raise KeyboardInterrupt

        signal.signal(signal.SIGBREAK, _on_break)


def _send_worker_error(
    ctl_sock: socket.socket,
    mode: str,
    exc_type: str,
    message: str,
    *,
    print_tb: bool = False,
) -> None:
    if mode == "call":
        send_json(
            ctl_sock,
            FRAME_CONTROL,
            {
                "ok": False,
                "exc_type": exc_type,
                "error": message,
                "traceback": traceback.format_exc(),
            },
        )
    elif print_tb:
        traceback.print_exc(file=sys.stderr)


def run_worker_from_ctl() -> int:
    """Execute a serialized Python job in an isolated worker process."""
    _configure_worker_streams_and_signals()
    ctl_spec = os.environ.pop("SIMPYREMOTE_CTL", "")
    if not ctl_spec:
        print("[simpyremote] missing SIMPYREMOTE_CTL", file=sys.stderr)
        return 2
    host, port_str, token = ctl_spec.rsplit(":", 2)

    with socket.create_connection((host, int(port_str)), timeout=10.0) as ctl_sock:
        ctl_sock.settimeout(None)
        send_frame(ctl_sock, FRAME_CONTROL, token.encode("utf-8"))
        job_frame = recv_frame(ctl_sock)
        if job_frame is None:
            raise EOFError("Control channel closed before receiving job")
        job = json.loads(job_frame[1].decode("utf-8"))

        mode = str(job.get("mode", "run"))
        serializer = str(job.get("serializer", "json"))

        try:
            args = tuple(decode_data(job["args"], serializer))
            kwargs = dict(decode_data(job["kwargs"], serializer))
            fn = _build_callable_from_job(job)
            result = fn(*args, **kwargs)
        except KeyboardInterrupt:
            _send_worker_error(
                ctl_sock,
                mode,
                "KeyboardInterrupt",
                "Remote execution interrupted",
                print_tb=True,
            )
            return 130
        except SystemExit as exc:
            code = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
            if mode != "call" and exc.code is not None and not isinstance(exc.code, int):
                print(exc.code, file=sys.stderr)
            _send_worker_error(
                ctl_sock,
                mode,
                "SystemExit",
                f"Remote function called sys.exit({exc.code!r})",
            )
            return code
        except Exception as exc:
            _send_worker_error(
                ctl_sock,
                mode,
                type(exc).__name__,
                str(exc),
                print_tb=True,
            )
            return 1

        if mode == "call":
            try:
                encoded = encode_data(result, serializer)
                send_json(
                    ctl_sock,
                    FRAME_CONTROL,
                    {"ok": True, "serializer": serializer, "value": encoded},
                )
            except Exception as exc:
                _send_worker_error(
                    ctl_sock,
                    mode,
                    type(exc).__name__,
                    f"Failed to serialize or send return value: {exc}",
                )
                return 1
        return 0
