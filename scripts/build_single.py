import ast
import sys
from pathlib import Path

MODULE_ORDER = [
    "config.py",
    "proto.py",
    "tls.py",
    "serialize.py",
    "io_pump.py",
    "transfer.py",
    "server.py",
    "client.py",
    "cli.py",
]


def _defined_names(node: ast.stmt) -> list[str]:
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.TypeAlias):
        return [node.name.id]
    if isinstance(node, ast.Assign):
        names: list[str] = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
        return names
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return [node.target.id]
    return []


def amalgamate(src_pkg_dir: Path, out_file: Path) -> None:
    """Combine src/simpyremote/*.py in DAG order into a single runnable .py file."""
    plain_imports: set[str] = set()
    from_imports: dict[str, set[str]] = {}
    seen_symbols: dict[str, str] = {}
    sections: list[str] = []

    for mod_name in MODULE_ORDER:
        mod_path = src_pkg_dir / mod_name
        source = mod_path.read_text(encoding="utf-8")
        lines = source.splitlines()
        tree = ast.parse(source, filename=str(mod_path))

        kept_chunks: list[str] = []
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    entry = f"{alias.name} as {alias.asname}" if alias.asname else alias.name
                    plain_imports.add(entry)
                continue
            if isinstance(node, ast.ImportFrom):
                if node.level > 0 or (node.module and node.module.startswith("simpyremote")):
                    continue
                assert node.module is not None
                bucket = from_imports.setdefault(node.module, set())
                for alias in node.names:
                    entry = f"{alias.name} as {alias.asname}" if alias.asname else alias.name
                    bucket.add(entry)
                continue

            for sym in _defined_names(node):
                if sym in seen_symbols:
                    raise RuntimeError(
                        f"Symbol collision '{sym}' in {mod_name} (already defined in {seen_symbols[sym]})"
                    )
                seen_symbols[sym] = mod_name

            start_line = min(
                [node.lineno, *(dec.lineno for dec in getattr(node, "decorator_list", []))]
            )
            assert node.end_lineno is not None
            kept_chunks.append("\n".join(lines[start_line - 1 : node.end_lineno]))

        sections.append("\n\n".join(kept_chunks))

    import_lines: list[str] = []
    if "__future__" in from_imports:
        future_names = ", ".join(sorted(from_imports.pop("__future__")))
        import_lines.append(f"from __future__ import {future_names}")
    import_lines.extend(f"import {mod}" for mod in sorted(plain_imports))
    for mod in sorted(from_imports):
        names = ", ".join(sorted(from_imports[mod]))
        import_lines.append(f"from {mod} import {names}")

    header = "\n".join(
        [
            "#!/usr/bin/env python3",
            '"""Single-file amalgamated distribution of simpyremote."""',
            "",
            "\n".join(import_lines),
            "",
            "_AMALGAMATED = True",
            '__all__ = ["DEVNULL", "SHELL_AUTO", "SHELL_BASH", "SHELL_CMD", "SHELL_POWERSHELL", "SHELL_PWSH", "SHELL_SH", "Client", "RemoteError", "call", "call_with", "capture_exec", "capture_shell", "main", "pull", "push", "run_exec", "run_shell", "serve"]',
            "",
        ]
    )
    footer = '\nif __name__ == "__main__":\n    raise SystemExit(main())\n'
    combined = header + "\n\n".join(sections) + footer

    ast.parse(combined, filename=str(out_file))
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(combined, encoding="utf-8")
    out_file.chmod(0o755)


if __name__ == "__main__":
    root = Path(__file__).resolve().parent.parent
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else root / "dist" / "simpyremote.py"
    amalgamate(root / "src" / "simpyremote", out)
    print(f"Wrote {out}")
