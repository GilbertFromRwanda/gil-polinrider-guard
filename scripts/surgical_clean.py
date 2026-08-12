#!/usr/bin/env python3
"""CLI wrapper around polinrider_guard.recovery -- see that module for the
actual analyze/apply logic and full safety model.

THIS SCRIPT DOES NOT FORCE-PUSH ANYTHING. It rewrites a local copy of the
repository and stops. Pushing the result is a separate, explicit decision
you make after verifying the output.

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
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from polinrider_guard.recovery import (  # noqa: E402
    analyze,
    apply_clean,
    find_masquerade_blobs,
    find_risky_vscode_task_blobs,
    load_patterns,
)


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
    masquerade_blobs = find_masquerade_blobs(repo)
    vscode_task_blobs = find_risky_vscode_task_blobs(repo)

    if not findings and not masquerade_blobs and not vscode_task_blobs:
        print(
            "No IOC matches, confirmed masquerade blobs, or risky historical tasks.json blobs "
            "found in any historical blob. Nothing to clean."
        )
        return 0

    blobs_affected = {sha for sha, _, _ in findings}
    print(f"Found {len(findings)} matching line(s) across {len(blobs_affected)} blob(s):")
    for sha, line, line_no in findings[:20]:
        preview = line[:100].decode("utf-8", errors="replace")
        print(f"  blob {sha[:12]} line {line_no}: {preview!r}")
    if len(findings) > 20:
        print(f"  ... and {len(findings) - 20} more")

    print(f"Found {len(masquerade_blobs)} confirmed extension-masquerade blob(s) (would be blanked entirely):")
    for sha, path in masquerade_blobs[:20]:
        print(f"  blob {sha[:12]}: {path}")
    if len(masquerade_blobs) > 20:
        print(f"  ... and {len(masquerade_blobs) - 20} more")

    print(f"Found {len(vscode_task_blobs)} historical risky tasks.json blob(s) (would be blanked entirely):")
    for sha, path in vscode_task_blobs[:20]:
        print(f"  blob {sha[:12]}: {path}")
    if len(vscode_task_blobs) > 20:
        print(f"  ... and {len(vscode_task_blobs) - 20} more")

    if not args.apply:
        print("\nDry run only (pass --apply to rewrite history in the target repo).")
        return 1

    print("\nApplying surgical clean via git filter-repo...")
    masquerade_shas = [sha for sha, _ in masquerade_blobs]
    vscode_task_shas = [sha for sha, _ in vscode_task_blobs]
    try:
        apply_clean(
            repo,
            patterns,
            masquerade_shas=masquerade_shas,
            vscode_task_shas=vscode_task_shas,
            force_non_mirror=args.force_non_mirror,
        )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print("\nRe-analyzing to verify the payload is gone from all history...")
    remaining = analyze(repo, patterns)
    remaining_masquerade = find_masquerade_blobs(repo)
    remaining_vscode_task_blobs = find_risky_vscode_task_blobs(repo)
    if remaining or remaining_masquerade or remaining_vscode_task_blobs:
        print(
            f"ERROR: {len(remaining)} line match(es), {len(remaining_masquerade)} masquerade blob(s), "
            f"and {len(remaining_vscode_task_blobs)} risky tasks.json blob(s) still present after rewrite.",
            file=sys.stderr,
        )
        return 2

    print(
        "Verified clean: no IOC patterns, confirmed masquerade blobs, or risky historical "
        "tasks.json blobs remain in any historical blob."
    )
    print(
        "Next steps (not done automatically): inspect the repo, then from inside it:\n"
        "    git push --force --all\n"
        "    git push --force --tags\n"
        "and notify collaborators that their local clones need to be re-cloned."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
