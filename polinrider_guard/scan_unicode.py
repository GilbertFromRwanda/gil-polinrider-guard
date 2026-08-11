"""Byte/codepoint-level scanner for the Glassworm invisible-Unicode technique.

PolinRider's Glassworm module hides an execution path inside source files by
inserting Unicode code points that render as nothing (zero width) or as
nothing meaningful (private-use-area, bidi controls, variation selectors).
`grep` and code review both miss it because the characters are invisible on
screen; this module inspects the actual code points instead.
"""
from __future__ import annotations

import os
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

# Extensions we treat as "source-like" and worth decoding as text. PolinRider
# has targeted JS/TS, but the whole point of Part 4 of the writeup is that
# extension is not a trust boundary -- so this list is used only to skip
# obviously-binary assets (images, archives, fonts by declared type), not to
# gate detection the way a naive scanner would.
SKIP_DIR_NAMES = {
    ".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
    "__pycache__", ".tox", ".mypy_cache",
}

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bmp", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".mov", ".avi",
    ".pdf",
}

# (start, end, label, severity) -- inclusive code point ranges.
SUSPICIOUS_RANGES: list[tuple[int, int, str, str]] = [
    (0x200B, 0x200B, "zero-width space", "high"),
    (0x200C, 0x200D, "zero-width joiner/non-joiner", "high"),
    (0x2060, 0x2060, "word joiner", "high"),
    (0xFEFF, 0xFEFF, "zero-width no-break space (BOM)", "medium"),
    (0x202A, 0x202E, "bidirectional override control", "high"),
    (0x2066, 0x2069, "bidirectional isolate control", "high"),
    (0x061C, 0x061C, "arabic letter mark", "low"),
    (0x200E, 0x200F, "directional mark (LRM/RLM)", "low"),
    (0xFE00, 0xFE0F, "variation selector (VS1-16)", "high"),
    (0xE0100, 0xE01EF, "variation selector supplement (VS17-256)", "high"),
    (0xE000, 0xF8FF, "private use area (BMP)", "high"),
    (0xF0000, 0xFFFFD, "supplementary private use area-A", "high"),
    (0x100000, 0x10FFFD, "supplementary private use area-B", "high"),
]


def classify(codepoint: int) -> tuple[str, str] | None:
    for start, end, label, severity in SUSPICIOUS_RANGES:
        if start <= codepoint <= end:
            return label, severity
    return None


@dataclass
class UnicodeFinding:
    file: str
    line: int
    column: int
    codepoint: str
    category: str
    label: str
    severity: str
    context: str

    def to_dict(self) -> dict:
        return {
            "type": "invisible_unicode",
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "codepoint": self.codepoint,
            "unicode_category": self.category,
            "description": self.label,
            "severity": self.severity,
            "context": self.context,
        }


def _iter_candidate_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() in SKIP_EXTENSIONS:
                continue
            yield path


def _context_snippet(line_text: str, column: int, width: int = 20) -> str:
    start = max(0, column - width)
    end = min(len(line_text), column + width)
    return line_text[start:end]


def scan_file(path: Path, root: Path) -> list[UnicodeFinding]:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return []

    # Skip files that are clearly binary (NUL byte in the first 8KB) --
    # legitimate binary assets aren't decodable as text anyway, and this
    # keeps us from wasting time trying to decode fonts/images that slipped
    # past the extension skip-list.
    if b"\x00" in raw[:8192]:
        return []

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[UnicodeFinding] = []
    rel = str(path.relative_to(root))
    for line_no, line in enumerate(text.splitlines(), start=1):
        for col_no, ch in enumerate(line, start=1):
            cp = ord(ch)
            hit = classify(cp)
            if hit is None:
                continue
            label, severity = hit
            try:
                category = unicodedata.category(ch)
            except ValueError:
                category = "?"
            findings.append(
                UnicodeFinding(
                    file=rel,
                    line=line_no,
                    column=col_no,
                    codepoint=f"U+{cp:04X}",
                    category=category,
                    label=label,
                    severity=severity,
                    context=_context_snippet(line, col_no - 1),
                )
            )
    return findings


def scan_path(target: str | os.PathLike) -> list[UnicodeFinding]:
    root = Path(target).resolve()
    if root.is_file():
        return scan_file(root, root.parent)

    findings: list[UnicodeFinding] = []
    for path in _iter_candidate_files(root):
        findings.extend(scan_file(path, root))
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-unicode",
        description="Scan for invisible/steganographic Unicode code points (Glassworm technique).",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No invisible Unicode findings in {args.path}")
        for f in findings:
            print(
                f"[{f.severity.upper()}] {f.file}:{f.line}:{f.column} "
                f"{f.codepoint} ({f.category}) - {f.label}"
            )
            print(f"    context: {f.context!r}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
