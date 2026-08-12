"""Scanner for decoy-commit camouflage: a single commit that mass-touches a
huge number of files (mostly as a no-op -- identical addition/deletion
counts, e.g. a line-ending sweep or reformat) while also introducing a
script/executable file, so the one change that matters gets lost in a diff
nobody reviews file-by-file.

Confirmed against a real PolinRider-family commit that touched ~180 files
with matching add/delete counts on almost all of them, while adding a
malicious .bat file and appending a hidden payload to an existing config.
Complements scan_clock_tamper.py (the dropped script itself) -- this one
looks at the *shape* of the commit rather than any single file's content.
"""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist

MIN_FILES_CHANGED = 40
MIN_NOOP_RATIO = 0.6  # fraction of (non-binary) changed files with additions == deletions

# Extensions worth flagging when newly introduced inside an otherwise
# reformat-shaped commit. Deliberately script/executable types, not general
# source files -- a mass rewrite that also adds a .ts file is unremarkable;
# one that also adds a .bat/.ps1/.sh is not.
SUSPICIOUS_NEW_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".psm1", ".sh", ".bash",
    ".exe", ".dll", ".scr", ".com", ".msi", ".vbs", ".jar",
}


@dataclass
class CamouflageFinding:
    commit: str
    subject: str
    files_changed: int
    noop_like_files: int
    suspicious_new_files: list[str] = field(default_factory=list)
    severity: str = "critical"

    def to_dict(self) -> dict:
        return {
            "type": "commit_camouflage",
            "commit": self.commit,
            "subject": self.subject,
            "files_changed": self.files_changed,
            "noop_like_files": self.noop_like_files,
            "suspicious_new_files": self.suspicious_new_files,
            "severity": self.severity,
        }


class NotAGitRepoError(RuntimeError):
    pass


def scan_path(target: str | os.PathLike) -> list[CamouflageFinding]:
    root = Path(target).resolve()

    result = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--is-inside-work-tree"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or result.stdout.strip() != "true":
        raise NotAGitRepoError(f"{root} is not a git repository")

    fmt = "%x1e%H%x1f%s"
    log = subprocess.run(
        ["git", "-C", str(root), "log", "--all", "--numstat", f"--pretty=format:{fmt}"],
        capture_output=True,
        text=True,
    )
    if log.returncode != 0:
        raise NotAGitRepoError(f"git log failed in {root}: {log.stderr.strip()}")

    entries = allowlist.load_allowlist(root)
    findings: list[CamouflageFinding] = []
    for block in log.stdout.split("\x1e"):
        block = block.strip("\n")
        if not block:
            continue
        lines = block.split("\n")
        header = lines[0].split("\x1f")
        if len(header) != 2:
            continue
        commit_hash, subject = header

        files_changed = 0
        noop_like = 0
        suspicious_new: list[str] = []
        for numstat_line in lines[1:]:
            if not numstat_line.strip():
                continue
            parts = numstat_line.split("\t")
            if len(parts) != 3:
                continue
            added_s, deleted_s, path = parts
            files_changed += 1
            if added_s.isdigit() and deleted_s.isdigit():
                added, deleted = int(added_s), int(deleted_s)
                if added == deleted and added > 0:
                    noop_like += 1
                # deleted == 0 with added > 0 is consistent with a newly
                # added file (or an append-only edit to an existing one) --
                # numstat alone can't distinguish those, but either way a
                # script file that only ever grows inside a reformat-shaped
                # commit is the pattern worth surfacing.
                if deleted == 0 and added > 0 and Path(path).suffix.lower() in SUSPICIOUS_NEW_EXTENSIONS:
                    suspicious_new.append(path)

        if (
            files_changed >= MIN_FILES_CHANGED
            and suspicious_new
            and (noop_like / files_changed) >= MIN_NOOP_RATIO
            and not allowlist.is_commit_allowlisted(entries, "commit_camouflage", commit_hash)
        ):
            findings.append(
                CamouflageFinding(
                    commit=commit_hash,
                    subject=subject,
                    files_changed=files_changed,
                    noop_like_files=noop_like,
                    suspicious_new_files=suspicious_new,
                )
            )

    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-commit-camouflage",
        description="Detect a mass-reformat-shaped commit that hides a new script/executable in the noise.",
    )
    parser.add_argument("path", help="Path to a git repository")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        findings = scan_path(args.path)
    except NotAGitRepoError as exc:
        print(str(exc))
        return 2

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No camouflaged commits found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.commit[:12]} - {f.subject}")
            print(f"    {f.files_changed} files changed, {f.noop_like_files} look like no-ops")
            print(f"    suspicious new/appended files: {', '.join(f.suspicious_new_files)}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
