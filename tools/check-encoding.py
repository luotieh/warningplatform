#!/usr/bin/env python3
"""Check repository text files for invalid UTF-8 and common mojibake."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

EXCLUDE_DIRS = {
    ".cache",
    ".git",
    ".turbo",
    "dist",
    "node_modules",
}

TEXT_EXTENSIONS = {
    ".css",
    ".env",
    ".go",
    ".html",
    ".js",
    ".json",
    ".md",
    ".mjs",
    ".mod",
    ".mts",
    ".ps1",
    ".scss",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".yaml",
    ".yml",
}

TEXT_FILENAMES = {
    ".env",
    ".env.development",
    ".env.production",
    ".gitattributes",
    ".gitignore",
    "AGENTS.md",
    "CLAUDE.md",
    "DEVELOPMENT.md",
}

MOJIBAKE_MARKERS = [
    "\u9352\u6fc6",  # common fragment from UTF-8 decoded as GBK
    "\u6434\u65c2\u6564",
    "\u95b0\u5d76",
    "\u699b\u6a3f",
    "\u6904\u572d\u6d30",
    "\u7eef\u8364\u7cba",
    "\u951b",
    "\u9286",
    "\u9225",
    "\ufffd",
]


def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTENSIONS or path.name in TEXT_FILENAMES


def iter_files() -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [name for name in dirnames if name not in EXCLUDE_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if is_text_candidate(path):
                files.append(path)
    return files


def check_file(path: Path) -> list[str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        return [f"cannot read file: {exc}"]

    if b"\x00" in data[:4096]:
        return []

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return [f"invalid UTF-8: {exc}"]

    issues: list[str] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for marker in MOJIBAKE_MARKERS:
            if marker in line:
                escaped = marker.encode("unicode_escape").decode("ascii")
                snippet = line[:160].encode("unicode_escape").decode("ascii")
                issues.append(f"line {lineno}: marker {escaped}: {snippet}")
                break
    return issues


def main() -> int:
    failures: list[tuple[Path, list[str]]] = []
    for path in iter_files():
        issues = check_file(path)
        if issues:
            failures.append((path, issues))

    if not failures:
        print("OK: all checked text files are UTF-8 and no mojibake markers were found.")
        return 0

    for path, issues in failures:
        rel = path.relative_to(ROOT)
        print(f"{rel}:")
        for issue in issues[:10]:
            print(f"  - {issue}")
        if len(issues) > 10:
            print(f"  - ... {len(issues) - 10} more")
    return 1


if __name__ == "__main__":
    sys.exit(main())
