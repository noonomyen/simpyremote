import base64
import codecs
import functools
import io
import json
import math
import os
import pickle
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from simpyremote import (
    DEVNULL,
    SHELL_AUTO,
    SHELL_BASH,
    SHELL_CMD,
    SHELL_POWERSHELL,
    SHELL_PWSH,
    SHELL_SH,
    Client,
    RemoteError,
    call,
    call_with,
    capture_exec,
    capture_shell,
    pull,
    push,
    run_exec,
    run_shell,
    serve,
)
from simpyremote.cli import main as cli_main
from simpyremote.client import _flush_text_decoder, _write_stream
from simpyremote.config import (
    ClientConfig,
    generate_secret,
    parse_remote_spec,
    resolve_client_config,
    resolve_server_secret,
    split_argv_at_double_dash,
)
from simpyremote.io_pump import _is_wine, _PtyEscapeFilter
from simpyremote.proto import (
    FRAME_EXEC_CMD,
    FRAME_EXEC_PY,
    FRAME_EXIT,
    FRAME_RESIZE,
    FRAME_RETURN,
    FRAME_SIGNAL,
    FRAME_STARTED,
    FRAME_STDIN,
    FRAME_STDOUT,
    recv_frame,
    send_frame,
    send_json,
)
from simpyremote.serialize import (
    _build_callable_from_job,
    _is_json_primitive,
    serialize_callable,
)
from simpyremote.server import _clean_child_env
from simpyremote.tls import (
    build_client_ssl_context,
    build_server_ssl_context,
    connect_tls,
    derive_psk,
    handshake_with_deadline,
)
from simpyremote.transfer import (
    _prepare_tar_members,
    _raise_transfer_error,
    _resolve_dest_file,
    _sanitize_leaf_name,
)

_WRAP_SCALE = 3


def _noop_wrap(fn):
    @functools.wraps(fn)
    def _inner(*args, **kwargs):
        return fn(*args, **kwargs)

    return _inner


@_noop_wrap
def _wrapped_math_fn(n: int) -> int:
    return math.isqrt(n) * _WRAP_SCALE


def _recursive_fact(n: int) -> int:
    return 1 if n <= 1 else n * _recursive_fact(n - 1)


class SimpyRemoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self._stop = threading.Event()
        self._ready = threading.Event()
        self.port = 0
        self.secret = ""

        def _on_listen(_host: str, port: int, secret: str, _generated: bool) -> None:
            self.port = port
            self.secret = secret
            self._ready.set()

        self._srv_thread = threading.Thread(
            target=serve,
            kwargs={
                "host": "127.0.0.1",
                "port": 0,
                "pre_auth": None,
                "stop_event": self._stop,
                "on_listening": _on_listen,
            },
            daemon=True,
        )
        self._srv_thread.start()
        self.assertTrue(self._ready.wait(timeout=5.0))
        self.client = Client(remote=f"127.0.0.1:{self.port}", auth=self.secret)

    def tearDown(self) -> None:
        self._stop.set()
        self._srv_thread.join(timeout=3.0)

    def test_secret_generation_and_split(self) -> None:
        self.assertEqual(len(self.secret), 32)
        self.assertTrue(self.secret.isalnum())
        s = generate_secret()
        self.assertEqual(len(s), 32)
        cli, cmd = split_argv_at_double_dash(
            ["--remote", "1.2.3.4:2222", "--", "python3", "--help"]
        )
        self.assertEqual(cli, ["--remote", "1.2.3.4:2222"])
        self.assertEqual(cmd, ["python3", "--help"])
        for bad in ("", ":2222", "[]", "[]:2222"):
            with self.assertRaises(ValueError):
                parse_remote_spec(bad)

    def test_rc_file_and_cli_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = Path(tmp) / ".simpyremote"
            rc.write_text("addr=10.0.0.5\nport=3333\nsecret=rcsecret1234567890\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(rc, 0o600)
            old_cwd = os.getcwd()
            old_env = os.environ.pop("SIMPYREMOTE_SECRET", None)
            old_cfg = os.environ.pop("SIMPYREMOTE_CONFIG", None)
            try:
                os.chdir(tmp)
                cfg = resolve_client_config()
                self.assertEqual(
                    (cfg.addr, cfg.port, cfg.secret),
                    ("10.0.0.5", 3333, "rcsecret1234567890"),
                )
                over = resolve_client_config(
                    remote="192.168.0.100", auth="override_secret_1234"
                )
                self.assertEqual(
                    (over.addr, over.port, over.secret),
                    ("192.168.0.100", 2222, "override_secret_1234"),
                )
                if os.name == "posix":
                    os.chmod(rc, 0o666)
                    with self.assertRaises(ValueError):
                        resolve_client_config()
            finally:
                os.chdir(old_cwd)
                if old_env is not None:
                    os.environ["SIMPYREMOTE_SECRET"] = old_env
                if old_cfg is not None:
                    os.environ["SIMPYREMOTE_CONFIG"] = old_cfg

    def test_ignore_warnings_flag_and_rc(self) -> None:
        err_default = io.StringIO()
        with redirect_stderr(err_default):
            Client(remote="127.0.0.1:2222", auth="short")
        self.assertIn("secret is shorter than 16 chars", err_default.getvalue())

        err_api = io.StringIO()
        with redirect_stderr(err_api):
            c_api = Client(remote="127.0.0.1:2222", auth="short", ignore_warnings=True)
        self.assertTrue(c_api.config.ignore_warnings)
        self.assertEqual(err_api.getvalue(), "")

        err_cfg_override = io.StringIO()
        with redirect_stderr(err_cfg_override):
            c_cfg = Client(
                config=ClientConfig("127.0.0.1", 2222, "short", ignore_warnings=False),
                ignore_warnings=True,
            )
        self.assertTrue(c_cfg.config.ignore_warnings)
        self.assertEqual(err_cfg_override.getvalue(), "")

        def _serve_short(ignore_warnings: bool) -> tuple[str, int]:
            stop = threading.Event()
            err_srv = io.StringIO()
            bound: list[int] = []

            def _on_listen(_h: str, p: int, _s: str, _g: bool) -> None:
                bound.append(p)
                stop.set()

            def _run() -> None:
                with redirect_stderr(err_srv):
                    serve(
                        host="127.0.0.1",
                        port=0,
                        pre_auth="short",
                        stop_event=stop,
                        on_listening=_on_listen,
                        ignore_warnings=ignore_warnings,
                    )

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            t.join(timeout=3.0)
            self.assertFalse(t.is_alive())
            return err_srv.getvalue(), bound[0]

        srv_warn_err, _ = _serve_short(False)
        self.assertIn("secret is shorter than 16 chars", srv_warn_err)
        srv_quiet_err, _ = _serve_short(True)
        self.assertEqual(srv_quiet_err, "")

        cli_entry = "import sys; from simpyremote.cli import main; sys.exit(main())"
        sub_env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src")}

        srv_warn_proc = subprocess.Popen(
            [sys.executable, "-c", cli_entry, "--server", "127.0.0.1", "--port", "0", "--pre-auth", "short"],
            env=sub_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert srv_warn_proc.stderr is not None
            warn_line = srv_warn_proc.stderr.readline()
            self.assertIn("secret is shorter than 16 chars", warn_line)
        finally:
            srv_warn_proc.terminate()
            srv_warn_proc.wait(timeout=5)
            if srv_warn_proc.stdout is not None:
                srv_warn_proc.stdout.close()
            if srv_warn_proc.stderr is not None:
                srv_warn_proc.stderr.close()

        srv_proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                cli_entry,
                "--server",
                "127.0.0.1",
                "--port",
                "0",
                "--pre-auth",
                "short",
                "--ignore-warnings",
            ],
            env=sub_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert srv_proc.stderr is not None
            first_line = srv_proc.stderr.readline()
            self.assertIn("listening on 127.0.0.1:", first_line)
            self.assertNotIn("warning:", first_line)
            short_port = int(first_line.split("127.0.0.1:", 1)[1].split(" ", 1)[0])

            cli_res = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    cli_entry,
                    "--remote",
                    f"127.0.0.1:{short_port}",
                    "--auth",
                    "short",
                    "--ignore-warnings",
                    "--",
                    sys.executable,
                    "-c",
                    "print('ok')",
                ],
                env=sub_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(cli_res.returncode, 0)
            self.assertEqual(cli_res.stdout.strip(), "ok")
            self.assertEqual(cli_res.stderr, "")
        finally:
            srv_proc.terminate()
            srv_proc.wait(timeout=5)
            if srv_proc.stdout is not None:
                srv_proc.stdout.close()
            if srv_proc.stderr is not None:
                srv_proc.stderr.close()

        with tempfile.TemporaryDirectory() as tmp:
            rc_path = Path(tmp) / ".simpyremote"
            if os.name == "posix":
                rc_path.write_text("", encoding="utf-8")
                os.chmod(rc_path, 0o644)

            old_cfg = os.environ.get("SIMPYREMOTE_CONFIG")
            old_sec = os.environ.pop("SIMPYREMOTE_SECRET", None)
            try:
                os.environ["SIMPYREMOTE_CONFIG"] = str(rc_path)

                for truthy in ("true", "1", "yes", "on"):
                    rc_path.write_text(
                        f"addr=127.0.0.1\nport={self.port}\nsecret=short\nignore_warnings={truthy}\n",
                        encoding="utf-8",
                    )
                    err_rc = io.StringIO()
                    with redirect_stderr(err_rc):
                        c = Client()
                    self.assertTrue(c.config.ignore_warnings)
                    self.assertEqual(err_rc.getvalue(), "")

                err_override = io.StringIO()
                with redirect_stderr(err_override):
                    Client(ignore_warnings=False)
                self.assertIn("secret is shorter than 16 chars", err_override.getvalue())
                if os.name == "posix":
                    self.assertIn("readable by group/others", err_override.getvalue())

                for falsy in ("false", "0", "no", "off"):
                    rc_path.write_text(
                        f"addr=127.0.0.1\nport={self.port}\nsecret=short\nignore_warnings={falsy}\n",
                        encoding="utf-8",
                    )
                    err_false = io.StringIO()
                    with redirect_stderr(err_false):
                        c_false = Client()
                    self.assertFalse(c_false.config.ignore_warnings)
                    self.assertIn("secret is shorter than 16 chars", err_false.getvalue())

                err_cli_over = io.StringIO()
                with redirect_stderr(err_cli_over):
                    c_cli_over = Client(ignore_warnings=True)
                self.assertTrue(c_cli_over.config.ignore_warnings)
                self.assertEqual(err_cli_over.getvalue(), "")

                rc_path.write_text(
                    "addr=127.0.0.1\nport=2222\nsecret=short\nignore_warnings=maybe\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ValueError):
                    resolve_client_config()

                if os.name == "posix":
                    os.environ.pop("SIMPYREMOTE_CONFIG", None)
                    os.chmod(rc_path, 0o666)
                    rc_path.write_text(
                        "addr=127.0.0.1\nport=2222\nsecret=short\nignore_warnings=true\n",
                        encoding="utf-8",
                    )
                    old_cwd = os.getcwd()
                    try:
                        os.chdir(tmp)
                        err_untrusted = io.StringIO()
                        with redirect_stderr(err_untrusted), self.assertRaises(ValueError):
                            resolve_client_config(ignore_warnings=True)
                        self.assertIn("ignoring", err_untrusted.getvalue())
                    finally:
                        os.chdir(old_cwd)
            finally:
                if old_cfg is None:
                    os.environ.pop("SIMPYREMOTE_CONFIG", None)
                else:
                    os.environ["SIMPYREMOTE_CONFIG"] = old_cfg
                if old_sec is not None:
                    os.environ["SIMPYREMOTE_SECRET"] = old_sec

    def test_server_secret_precedence(self) -> None:
        old = os.environ.get("SIMPYREMOTE_SECRET")
        try:
            os.environ["SIMPYREMOTE_SECRET"] = "env_secret_1234567890"
            sec, gen = resolve_server_secret()
            self.assertEqual((sec, gen), ("env_secret_1234567890", False))
            sec2, gen2 = resolve_server_secret("cli_secret_1234567890")
            self.assertEqual((sec2, gen2), ("cli_secret_1234567890", False))
        finally:
            if old is None:
                os.environ.pop("SIMPYREMOTE_SECRET", None)
            else:
                os.environ["SIMPYREMOTE_SECRET"] = old

    def test_tls_rejects_wrong_secret(self) -> None:
        bad_client = Client(remote=f"127.0.0.1:{self.port}", auth="wrong_secret_1234567890")
        with self.assertRaises(ssl.SSLError):
            bad_client.run_cmd([sys.executable, "-c", "print(1)"])

    def test_tls_rejects_cert_downgrade_mitm(self) -> None:
        cli_ctx = build_client_ssl_context(derive_psk(self.secret))
        self.assertEqual(cli_ctx.verify_mode, ssl.CERT_REQUIRED)
        self.assertEqual(cli_ctx.cert_store_stats()["x509_ca"], 0)
        openssl_bin = shutil.which("openssl")
        if openssl_bin is None:
            return
        with tempfile.TemporaryDirectory() as tmp:
            cert = Path(tmp) / "mitm.crt"
            key = Path(tmp) / "mitm.key"
            subprocess.run(
                [
                    openssl_bin,
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-keyout",
                    str(key),
                    "-out",
                    str(cert),
                    "-days",
                    "1",
                    "-nodes",
                    "-subj",
                    "/CN=mitm.example.com",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            mitm_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            mitm_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            mitm_ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))

            with socket.create_server(("127.0.0.1", 0)) as srv:
                mitm_port = srv.getsockname()[1]

                def _mitm_accept() -> None:
                    conn, _ = srv.accept()
                    try:
                        with mitm_ctx.wrap_socket(conn, server_side=True):
                            pass
                    except OSError:
                        pass
                    finally:
                        conn.close()

                t = threading.Thread(target=_mitm_accept, daemon=True)
                t.start()
                with self.assertRaises(ssl.SSLError):
                    connect_tls("127.0.0.1", mitm_port, cli_ctx)
                t.join(timeout=3.0)

    def test_call_rejects_serializer_mismatch_pickle_downgrade(self) -> None:
        psk = derive_psk(self.secret)
        srv_ctx = build_server_ssl_context(psk)
        evil_payload = base64.b64encode(pickle.dumps({"pwn": True})).decode("ascii")

        with socket.create_server(("127.0.0.1", 0)) as srv:
            fake_port = srv.getsockname()[1]

            def _fake_srv() -> None:
                conn, _ = srv.accept()
                try:
                    with handshake_with_deadline(conn, srv_ctx, server_side=True) as tls:
                        first = recv_frame(tls)
                        assert first is not None and first[0] == FRAME_EXEC_PY
                        send_json(tls, FRAME_STARTED, {"pid": 1})
                        send_json(
                            tls,
                            FRAME_RETURN,
                            {"ok": True, "serializer": "pickle", "value": evil_payload},
                        )
                        send_json(tls, FRAME_EXIT, {"returncode": 0})
                finally:
                    conn.close()

            t = threading.Thread(target=_fake_srv, daemon=True)
            t.start()
            c = Client(remote=f"127.0.0.1:{fake_port}", auth=self.secret)
            with self.assertRaises(RemoteError) as ctx:
                c.call(lambda: 1)
            self.assertIn("Serializer mismatch", str(ctx.exception))
            t.join(timeout=3.0)

    def test_run_cmd_pipes_stdin_and_hold_until_exit(self) -> None:
        out_buf = io.StringIO()
        in_buf = io.BytesIO(b"hello-stdin-data")
        start = time.monotonic()
        rc = self.client.run_cmd(
            [
                sys.executable,
                "-c",
                "import sys, time; data = sys.stdin.read(); print('got:' + data); time.sleep(0.2); exit(7)",
            ],
            stdin=in_buf,
            stdout=out_buf,
        )
        elapsed = time.monotonic() - start
        self.assertEqual(rc, 7)
        self.assertGreaterEqual(elapsed, 0.15)
        self.assertIn("got:hello-stdin-data", out_buf.getvalue())

        bin_out = io.BytesIO()
        bin_err = io.BytesIO()
        rc_bin = self.client.run_cmd(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'\\xff\\xfe\\x00\\x80'); sys.stderr.buffer.write(b'\\x01\\x02')",
            ],
            pty=False,
            stdin=io.BytesIO(),
            stdout=bin_out,
            stderr=bin_err,
        )
        self.assertEqual(rc_bin, 0)
        self.assertEqual(bin_out.getvalue(), b"\xff\xfe\x00\x80")
        self.assertEqual(bin_err.getvalue(), b"\x01\x02")

    def test_server_strips_secret_from_child_env(self) -> None:
        old = os.environ.get("SIMPYREMOTE_SECRET")
        os.environ["SIMPYREMOTE_SECRET"] = "must_not_leak_secret_123456"
        try:
            def read_env() -> str | None:
                import os

                return os.environ.get("SIMPYREMOTE_SECRET")

            self.assertIsNone(self.client.call(read_env))
        finally:
            if old is None:
                os.environ.pop("SIMPYREMOTE_SECRET", None)
            else:
                os.environ["SIMPYREMOTE_SECRET"] = old

    def test_call_python_function_and_module_globals(self) -> None:
        def x() -> str:
            print(__name__)
            return __name__

        buf = io.StringIO()
        with redirect_stdout(buf):
            res = self.client.call(x)
        self.assertEqual(res, "__main__")
        self.assertEqual(buf.getvalue().strip(), "__main__")

    def test_run_shell_auto_preset_and_custom(self) -> None:
        out = io.StringIO()
        rc = self.client.run_shell("echo shell-auto-ok", stdout=out, stdin=DEVNULL)
        self.assertEqual(rc, 0)
        self.assertIn("shell-auto-ok", out.getvalue())

        if os.name == "posix":
            sh_out = io.StringIO()
            rc_sh = self.client.run_shell(
                "VAL=42; echo v=$VAL >&1; echo err >&2; exit 3",
                shell=SHELL_SH,
                stdout=sh_out,
                stderr=DEVNULL,
                stdin=DEVNULL,
            )
            self.assertEqual(rc_sh, 3)
            self.assertEqual(sh_out.getvalue().strip(), "v=42")

            rc_ml, ml_out, _ = self.client.capture_shell(
                "A='hello'\nprintf '%s\\n' \"$A 'world'\"",
                shell=SHELL_SH,
            )
            self.assertEqual(rc_ml, 0)
            self.assertEqual(ml_out.strip(), "hello 'world'")

            if shutil.which("bash"):
                bash_out = io.StringIO()
                self.assertEqual(
                    self.client.run_shell(
                        "[[ ok == ok ]] && echo $((20 + 22))",
                        shell=SHELL_BASH,
                        stdout=bash_out,
                        stdin=DEVNULL,
                    ),
                    0,
                )
                self.assertEqual(bash_out.getvalue().strip(), "42")

            # SHELL_AUTO honors POSIX $SHELL and falls back to sh for non-POSIX $SHELL
            old_shell = os.environ.get("SHELL")
            try:
                bash_path = shutil.which("bash")
                if bash_path:
                    os.environ["SHELL"] = bash_path
                    rc_b, out_b, _ = self.client.capture_shell(
                        "[[ -n ok ]] && echo auto-bash"
                    )
                    self.assertEqual(rc_b, 0)
                    self.assertEqual(out_b.strip(), "auto-bash")

                os.environ["SHELL"] = "/nonexistent/pwsh"
                rc_fb, out_fb, _ = self.client.capture_shell("echo auto-fallback")
                self.assertEqual(rc_fb, 0)
                self.assertEqual(out_fb.strip(), "auto-fallback")
            finally:
                if old_shell is None:
                    os.environ.pop("SHELL", None)
                else:
                    os.environ["SHELL"] = old_shell

            if not shutil.which("cmd.exe"):
                with self.assertRaises(RemoteError) as cmd_missing:
                    self.client.run_shell("echo hi", shell=SHELL_CMD, stdin=DEVNULL)
                self.assertEqual(cmd_missing.exception.exc_type, "FileNotFoundError")

        if sys.platform == "win32":
            rc_cmd, out_cmd, _ = self.client.capture_shell(
                'echo "a & b" & exit /b 5',
                shell=SHELL_CMD,
            )
            self.assertEqual(rc_cmd, 5)
            self.assertIn('"a & b"', out_cmd)

            rc_auto_q, out_auto_q, _ = self.client.capture_shell('echo "auto & ok"')
            self.assertEqual(rc_auto_q, 0)
            self.assertIn("auto & ok", out_auto_q)

            if not _is_wine() and shutil.which("powershell.exe"):
                rc_ps, out_ps, _ = self.client.capture_shell(
                    '$x = 21 * 2; Write-Output "ps=$x"',
                    shell=SHELL_POWERSHELL,
                )
                self.assertEqual(rc_ps, 0)
                self.assertIn("ps=42", out_ps)

            if not shutil.which("sh"):
                with self.assertRaises(RemoteError) as sh_missing:
                    self.client.run_shell("echo hi", shell=SHELL_SH, stdin=DEVNULL)
                self.assertEqual(sh_missing.exception.exc_type, "FileNotFoundError")

        # Verify SHELL_PWSH end-to-end UTF-16LE -EncodedCommand via a temporary shim in PATH
        with tempfile.TemporaryDirectory() as shim_dir:
            shim_py = Path(shim_dir) / "pwsh_shim.py"
            shim_py.write_text(
                (
                    "import base64, json, sys\n"
                    "args = sys.argv[1:]\n"
                    "idx = args.index('-EncodedCommand')\n"
                    "decoded = base64.b64decode(args[idx + 1]).decode('utf-16le')\n"
                    "print(json.dumps({'flags': args[:idx + 1], 'cmd': decoded}, ensure_ascii=False))\n"
                ),
                encoding="utf-8",
            )
            if sys.platform == "win32":
                shim_bin = Path(shim_dir) / "pwsh.cmd"
                shim_bin.write_text(
                    f'@echo off\r\n"{sys.executable}" "{shim_py}" %*\r\n',
                    encoding="utf-8",
                )
            else:
                shim_bin = Path(shim_dir) / "pwsh"
                shim_bin.write_text(
                    f"#!{sys.executable}\n{shim_py.read_text(encoding='utf-8')}",
                    encoding="utf-8",
                )
                os.chmod(shim_bin, 0o755)

            old_path = os.environ.get("PATH", "")
            os.environ["PATH"] = f"{shim_dir}{os.pathsep}{old_path}"
            try:
                rc_pw, out_pw, _ = self.client.capture_shell(
                    'Write-Output "hello \'quotes\'"\nexit 0',
                    shell=SHELL_PWSH,
                )
                self.assertEqual(rc_pw, 0)
                parsed_pw = json.loads(out_pw.strip())
                self.assertEqual(parsed_pw["flags"], ["-NoLogo", "-NoProfile", "-EncodedCommand"])
                self.assertEqual(parsed_pw["cmd"], 'Write-Output "hello \'quotes\'"\nexit 0')

                rc_pw_empty, out_pw_empty, _ = self.client.capture_shell("", shell=SHELL_PWSH)
                self.assertEqual(rc_pw_empty, 0)
                self.assertEqual(json.loads(out_pw_empty.strip())["cmd"], " ")
            finally:
                os.environ["PATH"] = old_path

        def custom_py_shell(cmd: str) -> int:
            import subprocess
            import sys

            return subprocess.run([sys.executable, "-c", cmd]).returncode

        custom_out = io.StringIO()
        rc_custom = self.client.run_shell(
            "import sys; print('via:' + sys.stdin.read())",
            shell=custom_py_shell,
            stdin=io.BytesIO(b"pipe-ok"),
            stdout=custom_out,
        )
        self.assertEqual(rc_custom, 0)
        self.assertEqual(custom_out.getvalue().strip(), "via:pipe-ok")

        def oneshot_stdin_shell(cmd: str) -> int:
            import subprocess
            import sys

            return subprocess.run(
                [sys.executable, "-"],
                input=cmd.encode("utf-8"),
            ).returncode

        oneshot_out = io.StringIO()
        rc_oneshot = self.client.run_shell(
            "print('oneshot-stdin-ok')",
            shell=oneshot_stdin_shell,
            stdout=oneshot_out,
            stdin=DEVNULL,
        )
        self.assertEqual(rc_oneshot, 0)
        self.assertEqual(oneshot_out.getvalue().strip(), "oneshot-stdin-ok")

    def test_run_exec_stdio_devnull_and_errors(self) -> None:
        bin_out = io.BytesIO()
        bin_err = io.BytesIO()
        rc = self.client.run_exec(
            [
                sys.executable,
                "-c",
                "import sys; data = sys.stdin.read(); sys.stdout.buffer.write(b'out:' + data.encode()); sys.stderr.buffer.write(b'err')",
            ],
            stdin=io.BytesIO(b"hello"),
            stdout=bin_out,
            stderr=bin_err,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(bin_out.getvalue(), b"out:hello")
        self.assertEqual(bin_err.getvalue(), b"err")

        # stdin=DEVNULL and forward_stdin=False must close remote stdin immediately
        eof_out = io.StringIO()
        rc_eof = self.client.run_exec(
            [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
            stdin=DEVNULL,
            stdout=eof_out,
        )
        self.assertEqual(rc_eof, 0)
        self.assertEqual(eof_out.getvalue().strip(), "''")

        # stdout=False / stderr=DEVNULL discard output cleanly
        self.assertEqual(
            self.client.run_exec(
                [sys.executable, "-c", "import sys; print('drop'); print('err', file=sys.stderr)"],
                stdin=False,
                stdout=False,
                stderr=DEVNULL,
            ),
            0,
        )

        with self.assertRaises(RemoteError) as ctx:
            self.client.run_exec(["definitely_missing_binary_simpyremote_test"], stdin=DEVNULL)
        self.assertEqual(ctx.exception.exc_type, "FileNotFoundError")

        with self.assertRaises(TypeError):
            self.client.run_shell(["echo", "bad"])  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.client.run_shell("echo ok", shell="sh")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.client.run_exec("echo bad")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.client.run_exec(b"ls")  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.client.run_exec(bytearray(b"ls"))  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            self.client.run_exec([])

        with self.assertRaises(TypeError):
            self.client.run_shell("echo hi", stdin=123)
        with self.assertRaises(TypeError):
            self.client.run_shell("echo hi", stdout=123)
        with self.assertRaises(TypeError):
            self.client.run_shell("echo hi", stdout=b"")
        with self.assertRaises(TypeError):
            self.client.run_shell("echo hi", stderr=123)

        # bytes / str stdin and forward_stdin=False
        bytes_out = io.StringIO()
        self.assertEqual(
            self.client.run_exec(
                [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
                stdin=b"raw-bytes",
                stdout=bytes_out,
            ),
            0,
        )
        self.assertEqual(bytes_out.getvalue().strip(), "RAW-BYTES")

        str_out = io.StringIO()
        self.assertEqual(
            self.client.run_exec(
                [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
                stdin="raw-str",
                stdout=str_out,
            ),
            0,
        )
        self.assertEqual(str_out.getvalue().strip(), "raw-str")

        fwd_false_out = io.StringIO()
        self.assertEqual(
            self.client.run_exec(
                [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
                stdin=io.BytesIO(b"ignored"),
                forward_stdin=False,
                stdout=fwd_false_out,
            ),
            0,
        )
        self.assertEqual(fwd_false_out.getvalue().strip(), "''")

        # cwd= on run_shell, run_exec, call_with
        with tempfile.TemporaryDirectory() as work_dir:
            sh_cwd_out = io.StringIO()
            self.assertEqual(
                self.client.run_shell(
                    f"{sys.executable} -c \"import os; print(os.getcwd())\"",
                    cwd=work_dir,
                    stdin=DEVNULL,
                    stdout=sh_cwd_out,
                ),
                0,
            )
            self.assertEqual(Path(sh_cwd_out.getvalue().strip()).resolve(), Path(work_dir).resolve())

            ex_cwd_out = io.StringIO()
            self.assertEqual(
                self.client.run_exec(
                    [sys.executable, "-c", "import os; print(os.getcwd())"],
                    cwd=work_dir,
                    stdin=DEVNULL,
                    stdout=ex_cwd_out,
                ),
                0,
            )
            self.assertEqual(Path(ex_cwd_out.getvalue().strip()).resolve(), Path(work_dir).resolve())

            call_cwd = self.client.call_with(os.getcwd, cwd=work_dir)
            self.assertEqual(Path(call_cwd).resolve(), Path(work_dir).resolve())

        # Custom shell returning None defaults to exit code 0; empty cmd works cleanly
        def void_shell(cmd: str) -> None:
            return None

        self.assertEqual(self.client.run_shell("", shell=void_shell, stdin=DEVNULL), 0)
        self.assertEqual(self.client.run_shell("", stdin=DEVNULL), 0)

        for preset in (
            SHELL_AUTO,
            SHELL_SH,
            SHELL_BASH,
            SHELL_PWSH,
            SHELL_POWERSHELL,
            SHELL_CMD,
        ):
            job = serialize_callable(preset, ("echo hi",), {}, mode="call", serializer="json")
            self.assertEqual(job["kind"], "source")
            self.assertEqual(job["imports"], [])
            self.assertEqual(job["bindings"], {})

        if sys.platform == "win32":
            self.assertEqual(self.client.run_shell("", shell=SHELL_CMD, stdin=DEVNULL), 0)
            with self.assertRaises(RemoteError) as cmd_err:
                self.client.run_shell("echo a\necho b", shell=SHELL_CMD, stdin=DEVNULL)
            self.assertEqual(cmd_err.exception.exc_type, "ValueError")

        def read_stdin() -> str:
            import sys

            return sys.stdin.read()

        self.assertEqual(self.client.call_with(read_stdin), "")
        self.assertEqual(
            self.client.call_with(read_stdin, stdin=io.BytesIO(b"rpc-stdin")),
            "rpc-stdin",
        )
        self.assertEqual(
            self.client.call_with(read_stdin, stdin=io.BytesIO(b"ignored"), forward_stdin=False),
            "",
        )

        # Closed file object as stdin must not hang
        with tempfile.TemporaryFile() as closed_f:
            closed_f.close()
            closed_out = io.StringIO()
            self.assertEqual(
                self.client.run_exec(
                    [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
                    stdin=closed_f,
                    stdout=closed_out,
                ),
                0,
            )
            self.assertEqual(closed_out.getvalue().strip(), "''")

        # capture_shell / capture_exec helpers
        rc_cap, cap_out, cap_err = self.client.capture_shell("echo cap-ok")
        self.assertEqual(rc_cap, 0)
        self.assertEqual(cap_out.strip(), "cap-ok")
        self.assertEqual(cap_err, "")

        rc_ex, ex_out, ex_err = self.client.capture_exec(
            [
                sys.executable,
                "-c",
                "import sys; print('in:' + sys.stdin.read()); print('e1', file=sys.stderr); sys.exit(4)",
            ],
            stdin="abc",
        )
        self.assertEqual(rc_ex, 4)
        self.assertEqual(ex_out.strip(), "in:abc")
        self.assertEqual(ex_err.strip(), "e1")

        # Write-only stdin, Path cwd, non-sequence run_cmd, and minimal write-only sink
        class _WriteOnlySink:
            def __init__(self) -> None:
                self.parts: list[str] = []

            def write(self, data: str) -> int:
                self.parts.append(data)
                return len(data)

        sink = _WriteOnlySink()
        self.assertEqual(
            self.client.run_exec(
                [sys.executable, "-c", "print('sink-ok')"],
                stdin=DEVNULL,
                stdout=sink,
            ),
            0,
        )
        self.assertEqual("".join(sink.parts).strip(), "sink-ok")

        with tempfile.TemporaryFile("wb") as wo_file:
            with self.assertRaises(TypeError):
                self.client.run_exec([sys.executable, "-c", "pass"], stdin=wo_file)

        with self.assertRaises(TypeError):
            self.client.run_shell("echo hi", cwd=Path("/tmp"))  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            self.client.run_cmd("echo hi")  # type: ignore[arg-type]

        # bytearray, memoryview, and StringIO as stdin
        mv_out = io.StringIO()
        self.assertEqual(
            self.client.run_exec(
                [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
                stdin=memoryview(b"mv-ok"),
                stdout=mv_out,
            ),
            0,
        )
        self.assertEqual(mv_out.getvalue().strip(), "mv-ok")

        sio_rc, sio_out, _ = self.client.capture_exec(
            [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
            stdin=io.StringIO("sio-ok"),
        )
        self.assertEqual(sio_rc, 0)
        self.assertEqual(sio_out.strip(), "sio-ok")

        # run_cmd with stdin=DEVNULL closes stdin without hanging
        cmd_eof_out = io.StringIO()
        self.assertEqual(
            self.client.run_cmd(
                [sys.executable, "-c", "import sys; print(repr(sys.stdin.read()))"],
                stdin=DEVNULL,
                stdout=cmd_eof_out,
            ),
            0,
        )
        self.assertEqual(cmd_eof_out.getvalue().strip(), "''")

        if sys.platform == "win32":
            rc_q, out_q, _ = self.client.capture_shell('echo "a & b"')
            self.assertEqual(rc_q, 0)
            self.assertIn("a & b", out_q)

        # Frozen LD_LIBRARY_PATH cleanup in _clean_child_env
        old_frozen = getattr(sys, "frozen", False)
        sys.frozen = True  # type: ignore[attr-defined]
        try:
            cleaned_orig = _clean_child_env(
                {"LD_LIBRARY_PATH": "/meipass", "LD_LIBRARY_PATH_ORIG": "/orig", "SIMPYREMOTE_SECRET": "x"},
                is_worker=False,
            )
            if sys.platform != "win32":
                self.assertEqual(cleaned_orig["LD_LIBRARY_PATH"], "/orig")
                self.assertNotIn("LD_LIBRARY_PATH_ORIG", cleaned_orig)
            self.assertNotIn("SIMPYREMOTE_SECRET", cleaned_orig)
        finally:
            if old_frozen:
                sys.frozen = old_frozen  # type: ignore[attr-defined]
            else:
                delattr(sys, "frozen")

    def test_call_rpc_stateless_and_stdout_isolation(self) -> None:
        def get_cwd_after_chdir(target: str) -> str:
            import os

            print("noisy debug line")
            os.chdir(target)
            return os.getcwd()

        with tempfile.TemporaryDirectory() as d1:
            buf = io.StringIO()
            with redirect_stdout(buf):
                res1 = self.client.call(get_cwd_after_chdir, d1)
            self.assertEqual(Path(res1).resolve(), Path(d1).resolve())
            self.assertIn("noisy debug line", buf.getvalue())

            res2 = self.client.call(os.getcwd)
            self.assertNotEqual(Path(res2).resolve(), Path(d1).resolve())

        lam_res = self.client.call(lambda a, b: a + b, 19, 23)
        self.assertEqual(lam_res, 42)

        pickled = self.client.call_with(lambda: (b"raw", {1, 2}), serializer="pickle")
        self.assertEqual(pickled, (b"raw", {1, 2}))

    def test_call_non_json_return_reports_clear_error(self) -> None:
        def bad_return() -> bytes:
            return b"not-json"

        with self.assertRaises(RemoteError) as ctx:
            self.client.call(bad_return)
        self.assertIn("Failed to serialize", str(ctx.exception))

    def test_call_propagates_remote_exception(self) -> None:
        def boom() -> None:
            raise KeyError("missing-item")

        with self.assertRaises(RemoteError) as ctx:
            self.client.call(boom)
        self.assertIn("KeyError", str(ctx.exception))
        self.assertIn("missing-item", str(ctx.exception))

    def test_bytecode_fallback_with_closure_and_builtin_normalization(self) -> None:
        factor = 7
        ns: dict[str, object] = {}
        exec("def mul(v):\n    return v * factor\n", {"factor": factor}, ns)
        dyn_fn = ns["mul"]
        job = serialize_callable(dyn_fn, (6,), {}, mode="call", serializer="json")
        self.assertEqual(job["kind"], "code")
        rebuilt = _build_callable_from_job(job)
        self.assertEqual(rebuilt(6), 42)

        def make_adder(base: int):
            def inner(x: int) -> int:
                return base + x

            return inner

        closure_fn = make_adder(10)
        cjob = serialize_callable(closure_fn, (5,), {}, mode="call", serializer="json")
        cjob["kind"] = "code"
        import marshal

        cjob["code_b64"] = base64.b64encode(marshal.dumps(closure_fn.__code__)).decode("ascii")
        rebuilt_closure = _build_callable_from_job(cjob)
        self.assertEqual(rebuilt_closure(5), 15)

        builtin_job = serialize_callable(os.getcwd, (), {}, mode="call", serializer="json")
        self.assertEqual(builtin_job["module"], "os")
        with self.assertRaises(TypeError):
            serialize_callable("hello".upper, (), {}, mode="call", serializer="json")

    def test_push_and_pull_file_directory_and_security(self) -> None:
        for bad_name in ("", ".", "..", "/etc/passwd", "../evil", "a/b", "a\\b", "C:evil", "a\x00b"):
            with self.assertRaises(ValueError):
                _sanitize_leaf_name(bad_name)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(ValueError):
                _resolve_dest_file(str(root), "../escape.txt")

            src_file = root / "hello.bin"
            payload = os.urandom(150_000)
            src_file.write_bytes(payload)
            if os.name == "posix":
                os.chmod(src_file, 0o666)

            remote_file = root / "remote_copy.bin"
            pulled_file = root / "pulled_copy.bin"
            _, pushed_sz = self.client.push(src_file, str(remote_file))
            self.assertEqual(pushed_sz, len(payload))
            self.assertEqual(remote_file.read_bytes(), payload)
            if os.name == "posix":
                mode = remote_file.stat().st_mode
                self.assertEqual(mode & (stat.S_IWGRP | stat.S_IWOTH), 0)

            _, pulled_sz = self.client.pull(str(remote_file), pulled_file)
            self.assertEqual(pulled_sz, len(payload))
            self.assertEqual(pulled_file.read_bytes(), payload)

            src_dir = root / "pkg_dir"
            (src_dir / "sub").mkdir(parents=True)
            (src_dir / "a.txt").write_text("alpha", encoding="utf-8")
            (src_dir / "sub" / "b.txt").write_text("beta", encoding="utf-8")

            remote_dst = root / "remote_out"
            self.client.push(src_dir, str(remote_dst), recursive=True)
            self.assertEqual(
                (remote_dst / "pkg_dir" / "a.txt").read_text(encoding="utf-8"), "alpha"
            )
            self.assertEqual(
                (remote_dst / "pkg_dir" / "sub" / "b.txt").read_text(encoding="utf-8"), "beta"
            )

            local_back = root / "local_back"
            self.client.pull(str(remote_dst / "pkg_dir"), local_back, recursive=True)
            self.assertEqual(
                (local_back / "pkg_dir" / "sub" / "b.txt").read_text(encoding="utf-8"), "beta"
            )

            with self.assertRaises(FileNotFoundError):
                self.client.pull(str(root / "missing_remote_file.bin"), root / "nope.bin")
            with self.assertRaises(IsADirectoryError):
                self.client.pull(str(remote_dst / "pkg_dir"), root / "nope_dir", recursive=False)
            with self.assertRaises(TypeError):
                self.client.push(src_file, remote_file)  # type: ignore[arg-type]
            with self.assertRaises(TypeError):
                self.client.pull(remote_file, pulled_file)  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                _raise_transfer_error(json.dumps({"error": "bad", "exc_type": "ValueError"}).encode())
            with self.assertRaises(RuntimeError):
                _raise_transfer_error(b"plain non-json error")

    def test_signal_interrupt_terminates_remote_process(self) -> None:
        ctx = build_client_ssl_context(derive_psk(self.secret))
        with connect_tls("127.0.0.1", self.port, ctx) as sock:
            send_json(
                sock,
                FRAME_EXEC_CMD,
                {"argv": [sys.executable, "-c", "import time; time.sleep(30)"], "cwd": None},
            )
            started = recv_frame(sock)
            self.assertIsNotNone(started)
            assert started is not None
            self.assertEqual(started[0], FRAME_STARTED)

            send_frame(sock, FRAME_SIGNAL, b"INT")
            exit_frame = None
            while True:
                fr = recv_frame(sock)
                if fr is None:
                    break
                if fr[0] == FRAME_EXIT:
                    exit_frame = fr
                    break
            self.assertIsNotNone(exit_frame)

    def test_cli_edge_cases(self) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(
                [
                    "--remote",
                    f"127.0.0.1:{self.port}",
                    "--auth",
                    self.secret,
                    "--",
                    sys.executable,
                    "-c",
                    "import sys; print(sys.argv[1])",
                    "--_worker",
                ]
            )
        self.assertEqual(rc, 0)
        self.assertEqual(buf.getvalue().strip(), "--_worker")

        with tempfile.TemporaryDirectory() as tmp:
            rc_err = cli_main(
                [
                    "--remote",
                    f"127.0.0.1:{self.port}",
                    "--auth",
                    self.secret,
                    "--pull",
                    str(Path(tmp) / "does_not_exist.bin"),
                    str(Path(tmp) / "out.bin"),
                ]
            )
            self.assertEqual(rc_err, 1)

        with self.assertRaises(SystemExit) as cm:
            cli_main(["--push", "a", "b", "--pull", "c", "d"])
        self.assertEqual(cm.exception.code, 2)
        for bad_cli in (
            ["--server", "127.0.0.1", "-r"],
            ["-r", "--", "echo", "hi"],
            ["-t", "-T", "--", "echo", "hi"],
            ["-t", "--push", "a", "b"],
        ):
            with self.assertRaises(SystemExit) as cm_bad:
                cli_main(bad_cli)
            self.assertEqual(cm_bad.exception.code, 2)

    def test_frame_started_always_first_on_fast_command(self) -> None:
        ctx = build_client_ssl_context(derive_psk(self.secret))
        for _ in range(5):
            with connect_tls("127.0.0.1", self.port, ctx) as sock:
                send_json(
                    sock,
                    FRAME_EXEC_CMD,
                    {"argv": [sys.executable, "-c", "print('fast')"], "cwd": None, "pty": False},
                )
                first = recv_frame(sock)
                self.assertIsNotNone(first)
                assert first is not None
                self.assertEqual(first[0], FRAME_STARTED)
                while True:
                    fr = recv_frame(sock)
                    if fr is None or fr[0] == FRAME_EXIT:
                        break

    def test_pty_escape_filter_and_tar_validation(self) -> None:
        filt = _PtyEscapeFilter()
        self.assertEqual(filt.feed(b"echo ~/ok\r"), (b"echo ~/ok\r", False))
        self.assertEqual(filt.feed(b"~~hello\n"), (b"~hello\n", False))
        self.assertEqual(filt.feed(b"~/dir\r"), (b"~/dir\r", False))
        self.assertEqual(filt.feed(b"~."), (b"", True))

        def _make_tar_with(members: list[tuple[str, int, str]]) -> io.BytesIO:
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w") as tf:
                for name, mtype, linkname in members:
                    info = tarfile.TarInfo(name=name)
                    info.type = mtype
                    if linkname:
                        info.linkname = linkname
                    elif mtype == tarfile.REGTYPE:
                        info.size = 1
                        tf.addfile(info, io.BytesIO(b"x"))
                        continue
                    tf.addfile(info)
            raw.seek(0)
            return raw

        for evil in (
            [(".bashrc", tarfile.REGTYPE, "")],
            [("safe/hl", tarfile.LNKTYPE, "other/file")],
            [("safe/abs_link", tarfile.SYMTYPE, "/etc/passwd")],
        ):
            with tarfile.open(fileobj=_make_tar_with(evil), mode="r:") as tf:
                with self.assertRaises(ValueError):
                    _prepare_tar_members(tf, "safe")

        with tempfile.TemporaryDirectory() as tmp:
            dst_dir = Path(tmp)
            target_dir = dst_dir / "safe"
            target_dir.mkdir()
            two_step_escape = _make_tar_with(
                [
                    ("safe/a/b", tarfile.DIRTYPE, ""),
                    ("safe/a/b/link1", tarfile.SYMTYPE, "../.."),
                    ("safe/a/b/link1/link2", tarfile.SYMTYPE, ".."),
                    ("safe/a/b/link1/link2/.bashrc", tarfile.REGTYPE, ""),
                ]
            )
            with tarfile.open(fileobj=two_step_escape, mode="r:") as tf:
                with self.assertRaises((ValueError, tarfile.TarError)):
                    members = _prepare_tar_members(tf, "safe")
                    tf.extractall(path=target_dir, members=members, filter="data")
            self.assertFalse((dst_dir / ".bashrc").exists())

            good_tar = _make_tar_with(
                [
                    ("safe", tarfile.DIRTYPE, ""),
                    ("safe/a.txt", tarfile.REGTYPE, ""),
                    ("safe/sub", tarfile.DIRTYPE, ""),
                    ("safe/sub/link", tarfile.SYMTYPE, "../a.txt"),
                ]
            )
            with tarfile.open(fileobj=good_tar, mode="r:") as tf:
                members = _prepare_tar_members(tf, "safe")
                tf.extractall(path=target_dir, members=members, filter="data")
            self.assertTrue((target_dir / "a.txt").is_file())

    def test_async_gen_rejected_and_recursive_pickle_safe(self) -> None:
        async def agen():
            yield 1

        with self.assertRaises(TypeError):
            serialize_callable(agen, (), {}, mode="call", serializer="json")

        class _Holder:
            def method(self) -> int:
                return 1

        with self.assertRaises(TypeError):
            serialize_callable(_Holder().method, (), {}, mode="call", serializer="json")

        cyclic: list[object] = []
        cyclic.append(cyclic)
        self.assertFalse(_is_json_primitive(cyclic))

        self.assertEqual(self.client.call(_wrapped_math_fn, 49), 21)

        def _make_nonlocal_mod_fn():
            import math as m_local

            def _inner(x: int) -> int:
                return m_local.isqrt(x)

            return _inner

        self.assertEqual(self.client.call(_make_nonlocal_mod_fn(), 64), 8)

        job = serialize_callable(_recursive_fact, (5,), {}, mode="call", serializer="pickle")
        self.assertNotIn("_recursive_fact", job.get("bindings", {}))
        self.assertEqual(self.client.call_with(_recursive_fact, args=(5,), serializer="pickle"), 120)

    def test_detached_child_drains_large_stdout_without_deadlock(self) -> None:
        ctx = build_client_ssl_context(derive_psk(self.secret))
        with tempfile.TemporaryDirectory() as tmp:
            done_marker = Path(tmp) / "done.txt"
            code = (
                "import pathlib, sys, time; "
                "time.sleep(0.15); "
                "sys.stdout.buffer.write(b'x' * 220000); "
                "sys.stdout.buffer.flush(); "
                f"pathlib.Path({str(done_marker)!r}).write_text('ok', encoding='utf-8')"
            )
            with connect_tls("127.0.0.1", self.port, ctx) as sock:
                send_json(
                    sock,
                    FRAME_EXEC_CMD,
                    {"argv": [sys.executable, "-c", code], "cwd": None, "pty": False},
                )
                started = recv_frame(sock)
                self.assertIsNotNone(started)
                assert started is not None
                self.assertEqual(started[0], FRAME_STARTED)
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not done_marker.exists():
                time.sleep(0.05)
            self.assertTrue(done_marker.is_file())

    def test_incremental_utf8_stream_decoding(self) -> None:
        buf = io.StringIO()
        dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        sample = "hello-\u00e9-\u2603-\U0001f600"
        raw = sample.encode("utf-8")
        for i in range(0, len(raw), 2):
            _write_stream(buf, raw[i : i + 2], dec)
        _flush_text_decoder(buf, dec)
        self.assertEqual(buf.getvalue(), sample)

    @unittest.skipUnless(sys.platform == "win32" and not _is_wine(), "Windows ConPTY test")
    def test_windows_conpty_interactive_and_resize(self) -> None:
        ctx = build_client_ssl_context(derive_psk(self.secret))
        with connect_tls("127.0.0.1", self.port, ctx) as sock:
            sock.settimeout(5.0)
            send_json(
                sock,
                FRAME_EXEC_CMD,
                {
                    "argv": [
                        sys.executable,
                        "-c",
                        "import os, sys, time; time.sleep(0.2); print('CONPTY_SZ', tuple(os.get_terminal_size()), flush=True)",
                    ],
                    "cwd": None,
                    "pty": True,
                    "cols": 90,
                    "rows": 30,
                },
            )
            started = recv_frame(sock)
            self.assertIsNotNone(started)
            assert started is not None
            self.assertEqual(started[0], FRAME_STARTED)
            self.assertTrue(json.loads(started[1].decode("utf-8")).get("pty"))
            send_json(sock, FRAME_RESIZE, {"cols": 105, "rows": 33})
            out = bytearray()
            rc = None
            while True:
                fr = recv_frame(sock)
                if fr is None:
                    break
                if fr[0] == FRAME_STDOUT:
                    out.extend(fr[1])
                elif fr[0] == FRAME_EXIT:
                    rc = int(json.loads(fr[1].decode("utf-8"))["returncode"])
                    break
            self.assertEqual(rc, 0)
            self.assertIn(b"CONPTY_SZ", bytes(out))

    @unittest.skipUnless(os.name == "posix", "POSIX PTY realtime test")
    def test_pty_interactive_python_repl_and_resize(self) -> None:
        ctx = build_client_ssl_context(derive_psk(self.secret))
        with connect_tls("127.0.0.1", self.port, ctx) as sock:
            sock.settimeout(5.0)
            send_json(
                sock,
                FRAME_EXEC_CMD,
                {
                    "argv": [sys.executable, "-q"],
                    "cwd": None,
                    "pty": True,
                    "cols": 90,
                    "rows": 30,
                    "term": "xterm-256color",
                },
            )
            started = recv_frame(sock)
            self.assertIsNotNone(started)
            assert started is not None
            self.assertEqual(started[0], FRAME_STARTED)
            start_info = json.loads(started[1].decode("utf-8"))
            self.assertTrue(start_info.get("pty"))

            def _read_until(needle: bytes, timeout: float = 5.0) -> bytes:
                buf = bytearray()
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    sock.settimeout(max(0.1, deadline - time.monotonic()))
                    fr = recv_frame(sock)
                    if fr is None:
                        break
                    if fr[0] == FRAME_STDOUT:
                        buf.extend(fr[1])
                        if needle in buf:
                            return bytes(buf)
                return bytes(buf)

            banner = _read_until(b">>>")
            self.assertIn(b">>>", banner)

            send_frame(sock, FRAME_STDIN, b"print(123 + 456)\r")
            calc = _read_until(b"579")
            self.assertIn(b"579", calc)

            send_json(sock, FRAME_RESIZE, {"cols": 111, "rows": 37})
            send_frame(sock, FRAME_STDIN, b"import os; print(tuple(os.get_terminal_size()))\r")
            resized = _read_until(b"(111, 37)")
            self.assertIn(b"(111, 37)", resized)

            send_frame(sock, FRAME_STDIN, b"import time; time.sleep(5)\r")
            time.sleep(0.2)
            send_frame(sock, FRAME_STDIN, b"\x03")
            interrupted = _read_until(b"KeyboardInterrupt")
            self.assertIn(b"KeyboardInterrupt", interrupted)
            if b">>>" not in interrupted.split(b"KeyboardInterrupt", 1)[1]:
                _read_until(b">>>")

            send_frame(sock, FRAME_STDIN, b"\x04")
            exit_rc = None
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                sock.settimeout(max(0.1, deadline - time.monotonic()))
                fr = recv_frame(sock)
                if fr is None:
                    break
                if fr[0] == FRAME_EXIT:
                    exit_rc = int(json.loads(fr[1].decode("utf-8"))["returncode"])
                    break
            self.assertEqual(exit_rc, 0)

    def test_recv_frame_truncated_header_raises(self) -> None:
        s1, s2 = socket.socketpair()
        try:
            s1.sendall(b"\x01\x00")
            s1.close()
            with self.assertRaises(EOFError):
                recv_frame(s2)
        finally:
            s2.close()

    def test_top_level_helpers_with_rc_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc_path = Path(tmp) / ".simpyremote"
            rc_path.write_text(
                f"addr=127.0.0.1\nport={self.port}\nsecret={self.secret}\n",
                encoding="utf-8",
            )
            if os.name == "posix":
                os.chmod(rc_path, 0o600)
            old_cwd = os.getcwd()
            old_env = os.environ.pop("SIMPYREMOTE_SECRET", None)
            old_cfg = os.environ.pop("SIMPYREMOTE_CONFIG", None)
            try:
                os.chdir(tmp)
                self.assertEqual(call(lambda n: n * 2, 21), 42)
                self.assertEqual(call_with(lambda n: n * 2, args=(21,), serializer="pickle"), 42)
                buf = io.StringIO()
                self.assertEqual(
                    run_shell("echo top-shell", stdout=buf, stdin=DEVNULL),
                    0,
                )
                self.assertEqual(buf.getvalue().strip(), "top-shell")
                exec_buf = io.StringIO()
                self.assertEqual(
                    run_exec(
                        [sys.executable, "-c", "print('top-exec')"],
                        stdout=exec_buf,
                        stdin=DEVNULL,
                    ),
                    0,
                )
                self.assertEqual(exec_buf.getvalue().strip(), "top-exec")
                rc_cs, cs_out, _ = capture_shell("echo top-cap-shell")
                self.assertEqual(rc_cs, 0)
                self.assertEqual(cs_out.strip(), "top-cap-shell")
                rc_ce, ce_out, _ = capture_exec([sys.executable, "-c", "print('top-cap-exec')"])
                self.assertEqual(rc_ce, 0)
                self.assertEqual(ce_out.strip(), "top-cap-exec")
                src = Path(tmp) / "top.txt"
                dst = Path(tmp) / "top_up.txt"
                back = Path(tmp) / "top_down.txt"
                src.write_text("top", encoding="utf-8")
                push(src, str(dst))
                pull(str(dst), back)
                self.assertEqual(back.read_text(encoding="utf-8"), "top")
            finally:
                os.chdir(old_cwd)
                if old_env is not None:
                    os.environ["SIMPYREMOTE_SECRET"] = old_env
                if old_cfg is not None:
                    os.environ["SIMPYREMOTE_CONFIG"] = old_cfg


class SingleFileDistributionTests(unittest.TestCase):
    def test_amalgamated_single_file_server_and_import(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        build_script = repo_root / "scripts" / "build_single.py"
        with tempfile.TemporaryDirectory() as tmp:
            dist_py = Path(tmp) / "simpyremote.py"
            subprocess.run([sys.executable, str(build_script), str(dist_py)], check=True)
            self.assertTrue(dist_py.is_file())

            secret = "singlefile_test_secret_1234567890"
            proc = subprocess.Popen(
                [
                    sys.executable,
                    str(dist_py),
                    "--server",
                    "127.0.0.1",
                    "--port",
                    "0",
                    "--pre-auth",
                    secret,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                assert proc.stderr is not None
                line = proc.stderr.readline()
                self.assertIn("listening on 127.0.0.1:", line)
                self.assertNotIn(secret, line)
                bound_port = int(line.split("127.0.0.1:", 1)[1].split(" ", 1)[0])

                out = subprocess.check_output(
                    [
                        sys.executable,
                        "-c",
                        (
                            f"import io, sys; sys.path.insert(0, {str(dist_py.parent)!r}); "
                            f"import simpyremote; "
                            f"from simpyremote import Client, DEVNULL, SHELL_AUTO; "
                            f"c = Client(remote='127.0.0.1:{bound_port}', auth={secret!r}); "
                            f"out = io.StringIO(); "
                            f"rc = c.run_shell('echo amalg', shell=SHELL_AUTO, stdout=out, stdin=DEVNULL); "
                            f"print(c.call(lambda: __name__), rc, out.getvalue().strip(), len(simpyremote.__all__))"
                        ),
                    ],
                    text=True,
                )
                import simpyremote as pkg_simpyremote

                self.assertEqual(
                    out.strip(),
                    f"__main__ 0 amalg {len(pkg_simpyremote.__all__)}",
                )
            finally:
                proc.terminate()
                proc.wait(timeout=5)
                if proc.stdout is not None:
                    proc.stdout.close()
                if proc.stderr is not None:
                    proc.stderr.close()


if __name__ == "__main__":
    unittest.main()
