import argparse
import sys

from .client import Client
from .config import DEFAULT_PORT, split_argv_at_double_dash, validate_port
from .serialize import RemoteError, run_worker_from_ctl
from .server import serve


def build_parser() -> argparse.ArgumentParser:
    """Create the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="simpyremote",
        description="Simple cross-platform remote shell, Python runner, RPC, and file transfer over TLS 1.3 PSK.",
    )
    parser.add_argument(
        "--server",
        nargs="?",
        const="127.0.0.1",
        default=None,
        metavar="HOST",
        help="Run in server mode bound to HOST (default 127.0.0.1 if flag passed without value)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"Port to listen on or connect to (default {DEFAULT_PORT})",
    )
    parser.add_argument(
        "--pre-auth",
        default=None,
        metavar="SECRET",
        help="Server pre-shared secret (overrides SIMPYREMOTE_SECRET; random 32 chars if omitted)",
    )
    parser.add_argument(
        "--remote",
        default=None,
        metavar="HOST[:PORT]",
        help="Remote server address (overrides .simpyremote)",
    )
    parser.add_argument(
        "--auth",
        default=None,
        metavar="SECRET",
        help="Client authentication secret (overrides SIMPYREMOTE_SECRET and .simpyremote)",
    )
    parser.add_argument(
        "--push",
        nargs=2,
        metavar=("LOCAL", "REMOTE"),
        help="Upload LOCAL file/directory to REMOTE path",
    )
    parser.add_argument(
        "--pull",
        nargs=2,
        metavar=("REMOTE", "LOCAL"),
        help="Download REMOTE file/directory to LOCAL path",
    )
    parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Enable recursive directory transfer with --push or --pull",
    )
    parser.add_argument(
        "--ignore-warnings",
        action="store_true",
        help="Suppress non-fatal security warnings (short secret, .simpyremote permissions)",
    )
    pty_group = parser.add_mutually_exclusive_group()
    pty_group.add_argument(
        "-t",
        "--pty",
        action="store_true",
        help="Force interactive pseudo-terminal (PTY) allocation",
    )
    pty_group.add_argument(
        "-T",
        "--no-pty",
        action="store_true",
        help="Disable pseudo-terminal (PTY) allocation and use raw pipes",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entrypoint for simpyremote."""
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv == ["--_worker"]:
        return run_worker_from_ctl()

    cli_args, cmd_argv = split_argv_at_double_dash(raw_argv)
    parser = build_parser()
    args = parser.parse_args(cli_args)

    if args.server is not None:
        if (
            args.remote
            or args.auth
            or args.push
            or args.pull
            or args.recursive
            or args.pty
            or args.no_pty
            or cmd_argv is not None
        ):
            parser.error("--server cannot be combined with client flags or '-- <command>'")
        port = DEFAULT_PORT if args.port is None else args.port
        if not (0 <= port <= 65535):
            parser.error(f"invalid --port: {port}")
        try:
            serve(
                host=args.server,
                port=port,
                pre_auth=args.pre_auth,
                ignore_warnings=args.ignore_warnings,
            )
        except (OSError, ValueError, RuntimeError) as exc:
            print(f"[simpyremote] error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.pre_auth is not None:
        parser.error("--pre-auth is only valid with --server")
    if args.push and args.pull:
        parser.error("cannot use --push and --pull together")
    if (args.push or args.pull) and cmd_argv is not None:
        parser.error("cannot combine --push/--pull with '-- <command>'")
    if (args.push or args.pull) and (args.pty or args.no_pty):
        parser.error("cannot combine --push/--pull with -t/--pty or -T/--no-pty")
    if args.recursive and not (args.push or args.pull):
        parser.error("-r/--recursive is only valid with --push or --pull")
    if args.port is not None:
        try:
            validate_port(args.port)
        except ValueError as exc:
            parser.error(str(exc))

    try:
        client = Client(
            remote=args.remote,
            port=args.port,
            auth=args.auth,
            ignore_warnings=True if args.ignore_warnings else None,
        )
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"[simpyremote] {exc}", file=sys.stderr)
        if cmd_argv is None and not args.push and not args.pull:
            parser.print_help(sys.stderr)
        return 2

    pty_opt: bool | None = True if args.pty else (False if args.no_pty else None)

    try:
        if args.push:
            saved_path, size = client.push(
                args.push[0], args.push[1], recursive=args.recursive
            )
            print(f"pushed {size} bytes -> {saved_path}", file=sys.stderr)
            return 0

        if args.pull:
            saved_path, size = client.pull(
                args.pull[0], args.pull[1], recursive=args.recursive
            )
            print(f"pulled {size} bytes -> {saved_path}", file=sys.stderr)
            return 0

        return client.run_cmd(cmd_argv, pty=pty_opt)
    except KeyboardInterrupt:
        return 130
    except (RemoteError, OSError, ValueError, EOFError, RuntimeError) as exc:
        print(f"[simpyremote] error: {exc}", file=sys.stderr)
        return 1
