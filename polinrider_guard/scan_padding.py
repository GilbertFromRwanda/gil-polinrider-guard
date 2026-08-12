"""Scanner for the whitespace-padding hiding technique confirmed in a real
PolinRider/BeaverTail sample: a legitimate-looking file (e.g. an eslint
config) with a normal-looking ending, followed by hundreds of spaces to push
a malicious statement off the right edge of an editor's viewport, all on one
physical line.

This is structural, not byte-signature-based -- it doesn't need to know what
the hidden payload says, only that something is hidden this way. That makes
it complementary to scan_ioc.py, which needs to recognize specific bytes.
"""
from __future__ import annotations

import os
import re
import statistics
from dataclasses import dataclass
from pathlib import Path

from . import allowlist
from .skip_lists import SKIP_DIR_NAMES, SKIP_EXTENSIONS, SKIP_FILENAME_SUFFIXES

# 80+ consecutive spaces/tabs followed by more content on the same line has
# no ordinary formatting purpose -- even deeply nested or column-aligned
# code doesn't do this. This is the primary, high-confidence signal: it
# doesn't depend on comparing against other lines in the file. Public (no
# leading underscore) so polinrider_guard/recovery.py can reuse the exact
# same signal to strip the offending line during history surgery, instead
# of re-deriving it.
WHITESPACE_RUN_RE = re.compile(r"[ \t]{80,}\S")
# Same signal as bytes, for recovery.py's git-filter-repo blob callback,
# which operates on raw blob bytes rather than decoded text.
WHITESPACE_RUN_RE_BYTES = re.compile(rb"[ \t]{80,}\S")

# Secondary, softer signal: a line that's a massive outlier next to the
# file's own other lines, even without deliberate space-padding (e.g. a
# payload appended directly after existing code with no attempt to hide the
# seam). Comparing against the file's OWN median -- rather than a fixed
# threshold -- means a uniformly minified/bundled file (long lines
# throughout) doesn't trip this; only a line that stands out *within that
# file* does.
_MIN_LINES_FOR_OUTLIER = 5
_OUTLIER_ABSOLUTE_FLOOR = 2000
_OUTLIER_RATIO = 15


@dataclass
class PaddingFinding:
    file: str
    line: int
    kind: str
    line_length: int
    severity: str
    context: str

    def to_dict(self) -> dict:
        return {
            "type": "hidden_payload_padding",
            "file": self.file,
            "line": self.line,
            "kind": self.kind,
            "line_length": self.line_length,
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
            if name.lower().endswith(SKIP_FILENAME_SUFFIXES):
                continue
            yield path


def _whitespace_run_context(line: str, match: re.Match, before: int = 30, after: int = 60) -> str:
    gap = (match.end() - 1) - match.start()  # exclude the trailing \S char from the count
    prefix = line[max(0, match.start() - before) : match.start()]
    suffix = line[match.end() - 1 : match.end() - 1 + after]
    return f"...{prefix!r} <{gap} whitespace chars> {suffix!r}..."


def scan_file(path: Path, root: Path) -> list[PaddingFinding]:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return []

    if b"\x00" in raw[:8192]:
        return []

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return []

    lines = text.splitlines()
    if not lines:
        return []

    rel = str(path.relative_to(root))
    findings: list[PaddingFinding] = []
    lengths = [len(line) for line in lines]
    median_len = statistics.median(lengths)

    for line_no, line in enumerate(lines, start=1):
        match = WHITESPACE_RUN_RE.search(line)
        if match:
            findings.append(
                PaddingFinding(
                    file=rel,
                    line=line_no,
                    kind="excessive_whitespace_padding",
                    line_length=len(line),
                    severity="high",
                    context=_whitespace_run_context(line, match),
                )
            )
            continue  # already flagged this line; don't also report it as an outlier

        if (
            len(lines) >= _MIN_LINES_FOR_OUTLIER
            and len(line) >= _OUTLIER_ABSOLUTE_FLOOR
            and median_len > 0
            and len(line) > median_len * _OUTLIER_RATIO
        ):
            findings.append(
                PaddingFinding(
                    file=rel,
                    line=line_no,
                    kind="line_length_outlier",
                    line_length=len(line),
                    severity="medium",
                    context=line[:80] + "...",
                )
            )

    return findings


def scan_path(target: str | os.PathLike) -> list[PaddingFinding]:
    root = Path(target).resolve()
    entries = allowlist.load_allowlist(root)

    if root.is_file():
        findings = scan_file(root, root.parent)
    else:
        findings = []
        for path in _iter_candidate_files(root):
            findings.extend(scan_file(path, root))

    return [
        f for f in findings
        if not allowlist.is_file_line_allowlisted(entries, "hidden_payload_padding", f.file, f.line)
    ]


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-padding",
        description="Detect a payload hidden via whitespace padding or an anomalously long line.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No hidden-payload padding found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file}:{f.line} ({f.kind}, {f.line_length} chars)")
            print(f"    {f.context}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
