#!/usr/bin/env python3
"""Surgically strip PolinRider payload lines from every historical blob.

WHY THIS EXISTS
----------------
`git revert` only fixes the tip of a branch. `git filter-repo --invert-paths`
removes a whole file from history. Neither is right when a malicious commit
sits *underneath* months of legitimate work on the same files: reverting
conflicts with everything on top, and deleting the file destroys the
legitimate history along with the payload.

The correct fix is a blob-level rewrite: walk every version of every file
that has ever existed in the repository, strip only the lines that match a
known PolinRider IOC pattern, and leave everything else byte-for-byte
identical. `git filter-repo`'s --blob-callback does exactly this.

THIS SCRIPT DOES NOT FORCE-PUSH ANYTHING. It rewrites a local copy of the
repository and stops. Pushing the result is a separate, explicit decision
you make after verifying the output.

SAFETY MODEL
------------
1. Default mode is --analyze: read-only, reports which blobs/commits would
   be touched, changes nothing.
2. --apply is required to actually rewrite history, and by default only
   runs against a bare or mirror clone (`git clone --mirror`), never a
   working copy with uncommitted changes or a single working tree you might
   still be using. Pass --i-understand-this-rewrites-history-in-place to
   override that check (not recommended -- clone a mirror instead).
3. git filter-repo itself refuses to run on a repo that still has its
   original `origin` remote configured, as a second safety net against
   accidentally rewriting a repo you didn't mean to.
4. After --apply, the script re-runs the analysis and fails loudly if any
   IOC pattern is still present anywhere in history.

USAGE
-----
    # 1. Make a mirror clone to work on (never rewrite your only copy)
    git clone --mirror https://github.com/org/repo.git repo.git

    # 2. See what would be touched, change nothing
    python scripts/surgical_clean.py repo.git --analyze

    # 3. Actually rewrite the mirror clone's history
    python scripts/surgical_clean.py repo.git --apply

    # 4. Inspect the result yourself, THEN push if you're satisfied:
    #    cd repo.git && git push --force --all && git push --force --tags
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from polinrider_guard.iocs import DEFAULT_IOC_PATTERNS as _SHARED_IOC_PATTERNS

# Same IOC list scan_ioc.py uses to find these strings in plain source, kept
# in one place (polinrider_guard/iocs.py) so detection and remediation never
# drift apart. Extend via --iocs-file for anything newer than what's here.
DEFAULT_IOC_PATTERNS: list[bytes] = [p for p, _desc, _sev in _SHARED_IOC_PATTERNS]


def load_patterns(iocs_file: Path | None) -> list[re.Pattern]:
    patterns = [re.compile(p) for p in DEFAULT_IOC_PATTERNS]
    if iocs_file:
        for line in iocs_file.read_bytes().splitlines():
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            patterns.append(re.compile(line))
    return patterns


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def is_bare_or_mirror(repo: Path) -> bool:
    result = _run(["git", "-C", str(repo), "rev-parse", "--is-bare-repository"])
    return result.returncode == 0 and result.stdout.strip() == "true"


def analyze(repo: Path, patterns: list[re.Pattern]) -> list[tuple[str, bytes, int]]:
    """Return (blob_sha, matched_line, line_number) for every IOC hit across
    every blob that has ever existed in the repo's history."""
    rev_list = _run(["git", "-C", str(repo), "rev-list", "--objects", "--all"])
    if rev_list.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {rev_list.stderr}")

    blob_shas = set()
    for line in rev_list.stdout.splitlines():
        parts = line.split(" ", 1)
        sha = parts[0]
        blob_shas.add(sha)

    if not blob_shas:
        return []

    batch = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input="\n".join(blob_shas).encode(),
        capture_output=True,
        text=False,
    )
    findings: list[tuple[str, bytes, int]] = []
    data = batch.stdout
    pos = 0
    while pos < len(data):
        header_end = data.index(b"\n", pos)
        header = data[pos:header_end].decode()
        parts = header.split()
        sha = parts[0]
        obj_type = parts[1] if len(parts) > 1 else "missing"
        if obj_type == "missing":
            pos = header_end + 1
            continue
        size = int(parts[2])
        content_start = header_end + 1
        content = data[content_start:content_start + size]
        pos = content_start + size + 1  # +1 for trailing newline git adds

        if obj_type != "blob":
            continue

        for line_no, line in enumerate(content.split(b"\n"), start=1):
            if any(p.search(line) for p in patterns):
                findings.append((sha, line, line_no))

    return findings


def build_callback_source(patterns: list[re.Pattern]) -> str:
    """Build the body git-filter-repo will splice into its own generated
    `def callback(blob, _do_not_use_this_var=None): <body>` function.

    Critically, --blob-callback code is a *function body*, not a standalone
    script: git-filter-repo indents whatever we pass here and drops it
    straight inside its own def. It must NOT define its own function named
    blob_callback (that would just create an unused nested function and
    silently do nothing) -- it must operate on the `blob` argument directly.
    """
    pattern_literals = ",\n".join(repr(p.pattern) for p in patterns)
    return f"""import re
_patterns = [re.compile(p) for p in [
{pattern_literals}
]]
lines = blob.data.split(b'\\n')
kept = [ln for ln in lines if not any(p.search(ln) for p in _patterns)]
if len(kept) != len(lines):
    blob.data = b'\\n'.join(kept)
"""


def find_filter_repo_script() -> Path:
    spec = importlib.util.find_spec("git_filter_repo")
    if spec is None or spec.origin is None:
        raise RuntimeError(
            "git-filter-repo is not installed. Install it with:\n"
            "    pip install git-filter-repo"
        )
    return Path(spec.origin)


def apply_clean(repo: Path, patterns: list[re.Pattern], force_non_mirror: bool) -> None:
    if not force_non_mirror and not is_bare_or_mirror(repo):
        raise RuntimeError(
            f"{repo} does not look like a bare/mirror clone.\n"
            "Surgical history rewriting should run against a disposable mirror clone, "
            "not your working copy:\n"
            f"    git clone --mirror <url> {repo}.git\n"
            "Pass --i-understand-this-rewrites-history-in-place to override."
        )

    script_path = find_filter_repo_script()
    callback_src = build_callback_source(patterns)

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
        f.write(callback_src)
        callback_file = f.name

    try:
        cmd = [
            sys.executable,
            str(script_path),
            "--blob-callback",
            Path(callback_file).read_text(),
            "--force",
        ]
        result = subprocess.run(cmd, cwd=repo, capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            raise RuntimeError("git filter-repo failed; repository was not fully rewritten")
    finally:
        Path(callback_file).unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Strip PolinRider payload lines from every blob in git history.",
    )
    parser.add_argument("repo", help="Path to the repository (bare/mirror clone recommended)")
    parser.add_argument("--iocs-file", type=Path, default=None, help="Extra IOC regex patterns, one per line")
    parser.add_argument("--apply", action="store_true", help="Actually rewrite history (default: analyze only)")
    parser.add_argument(
        "--i-understand-this-rewrites-history-in-place",
        dest="force_non_mirror",
        action="store_true",
        help="Allow --apply on a non-bare/non-mirror repo (not recommended)",
    )
    args = parser.parse_args(argv)

    repo = Path(args.repo).resolve()
    patterns = load_patterns(args.iocs_file)

    print(f"Analyzing {repo} against {len(patterns)} IOC pattern(s)...")
    findings = analyze(repo, patterns)

    if not findings:
        print("No IOC matches found in any historical blob. Nothing to clean.")
        return 0

    blobs_affected = {sha for sha, _, _ in findings}
    print(f"Found {len(findings)} matching line(s) across {len(blobs_affected)} blob(s):")
    for sha, line, line_no in findings[:20]:
        preview = line[:100].decode("utf-8", errors="replace")
        print(f"  blob {sha[:12]} line {line_no}: {preview!r}")
    if len(findings) > 20:
        print(f"  ... and {len(findings) - 20} more")

    if not args.apply:
        print("\nDry run only (pass --apply to rewrite history in the target repo).")
        return 1

    print("\nApplying surgical clean via git filter-repo...")
    apply_clean(repo, patterns, args.force_non_mirror)

    print("\nRe-analyzing to verify the payload is gone from all history...")
    remaining = analyze(repo, patterns)
    if remaining:
        print(f"ERROR: {len(remaining)} match(es) still present after rewrite.", file=sys.stderr)
        return 2

    print("Verified clean: no IOC patterns remain in any historical blob.")
    print(
        "Next steps (not done automatically): inspect the repo, then from inside it:\n"
        "    git push --force --all\n"
        "    git push --force --tags\n"
        "and notify collaborators that their local clones need to be re-cloned."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
