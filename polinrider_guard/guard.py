"""polinrider-guard: run every scanner against a path and produce one report.

This is the command meant to be run before opening an unfamiliar repository
in an IDE (the "pre-open checklist"), and the one whose --json output feeds
the batch cleaner in scripts/batch-clean.sh.
"""
from __future__ import annotations

import json as jsonlib
import os
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import (
    scan_clock_tamper,
    scan_commit_camouflage,
    scan_ioc,
    scan_masquerade,
    scan_padding,
    scan_vscode,
)


# (step key, human label) for every scanner, in the order they run -- shared
# with polinrider_guard.webapp so the web UI's progress feed matches reality
# instead of a hardcoded guess at what the CLI is doing. The git-dependent
# scanner (commit_camouflage) is last, since it's the one --no-git / a
# missing .git directory skips.
SCANNER_STEPS: list[tuple[str, str]] = [
    ("extension_masquerade", "Extension masquerade (font-file vector)"),
    ("vscode_tasks", "Risky VS Code tasks (TasksJacker)"),
    ("hidden_payload_padding", "Hidden payload padding (whitespace/line-length anomaly)"),
    ("clock_tamper_tooling", "Clock-tamper git automation (ForceMemo tooling)"),
    ("ioc_literal_match", "Known IOC strings (C2 domains, loader markers)"),
    ("commit_camouflage", "Commit camouflage (mass-touch decoy commit)"),
]


def build_report(
    root: str | os.PathLike,
    scanners: dict[str, list[dict]],
    git_skipped_reason: str | None = None,
) -> dict:
    """Assemble the summary/severity-count envelope around raw scanner output.

    Split out of run_guard() so callers that need to report progress between
    scanners (the web UI) can run each scanner themselves and still produce
    an identical report shape at the end.
    """
    report: dict = {
        "target": str(Path(root).resolve()),
        "scanners": dict(scanners),
        "summary": {"total_findings": 0, "by_severity": {}},
    }
    if git_skipped_reason:
        report["git_skipped_reason"] = git_skipped_reason

    all_findings = [
        finding
        for findings in report["scanners"].values()
        for finding in findings
    ]
    report["summary"]["total_findings"] = len(all_findings)
    by_sev: dict[str, int] = {}
    for finding in all_findings:
        sev = finding.get("severity", "unknown")
        by_sev[sev] = by_sev.get(sev, 0) + 1
    report["summary"]["by_severity"] = by_sev

    return report


def run_guard(target: str | os.PathLike, include_git: bool = True) -> dict:
    root = Path(target).resolve()

    # Each scanner does its own independent os.walk (some also shell out to
    # git) over the same read-only tree -- nothing shared/mutable between
    # them, so running them concurrently is safe and, for a large repo,
    # meaningfully faster than the equivalent sequential sum.
    tasks: dict[str, object] = {
        "extension_masquerade": lambda: scan_masquerade.scan_path(root),
        "vscode_tasks": lambda: scan_vscode.scan_path(root),
        "hidden_payload_padding": lambda: scan_padding.scan_path(root),
        "clock_tamper_tooling": lambda: scan_clock_tamper.scan_path(root),
        "ioc_literal_match": lambda: scan_ioc.scan_path(root),
    }
    if include_git:
        tasks["commit_camouflage"] = lambda: scan_commit_camouflage.scan_path(root)

    scanners: dict[str, list[dict]] = {}
    git_skipped_reason = None

    with ThreadPoolExecutor(max_workers=len(tasks)) as executor:
        futures = {key: executor.submit(fn) for key, fn in tasks.items()}
        for key, future in futures.items():
            if key == "commit_camouflage":
                try:
                    scanners[key] = [f.to_dict() for f in future.result()]
                except scan_commit_camouflage.NotAGitRepoError:
                    scanners[key] = []
                    git_skipped_reason = "not a git repository"
            else:
                scanners[key] = [f.to_dict() for f in future.result()]

    if not include_git:
        scanners["commit_camouflage"] = []
        git_skipped_reason = "--no-git"

    return build_report(root, scanners, git_skipped_reason)


def _print_text_report(report: dict) -> None:
    target = report["target"]
    total = report["summary"]["total_findings"]

    if total == 0:
        print(f"No findings in {target}")
        return

    print(f"polinrider-guard report for {target}")
    print(f"Total findings: {total}  ({_format_severity_counts(report['summary']['by_severity'])})")
    print()

    labels = dict(SCANNER_STEPS)

    for key, findings in report["scanners"].items():
        if not findings:
            continue
        print(f"== {labels.get(key, key)} ({len(findings)}) ==")
        for f in findings:
            _print_finding_line(key, f)
        print()

    if report.get("git_skipped_reason"):
        print(f"(git checks skipped: {report['git_skipped_reason']})")


def _print_finding_line(scanner: str, f: dict) -> None:
    sev = f.get("severity", "?").upper()
    if scanner == "extension_masquerade":
        print(f"  [{sev}] {f['file']} claims {f['claimed_type']} but is {f['actual_type']}")
    elif scanner == "vscode_tasks":
        print(f"  [{sev}] {f['file']} task '{f['task_label']}': {'; '.join(f['reasons'])}")
    elif scanner == "ioc_literal_match":
        print(f"  [{sev}] {f['file']}:{f['line']} - {f['description']} ({f['matched_text']!r})")
    elif scanner == "hidden_payload_padding":
        print(f"  [{sev}] {f['file']}:{f['line']} ({f['kind']}, {f['line_length']} chars)")
        print(f"      {f['context']}")
    elif scanner == "clock_tamper_tooling":
        print(f"  [{sev}] {f['file']}: {'; '.join(f['indicators'])}")
    elif scanner == "commit_camouflage":
        print(
            f"  [{sev}] {f['commit'][:12]} - {f['subject']} "
            f"({f['files_changed']} files, {f['noop_like_files']} no-op-like, "
            f"new: {', '.join(f['suspicious_new_files'])})"
        )
    else:
        print(f"  [{sev}] {f}")


def _format_severity_counts(by_sev: dict) -> str:
    order = ["critical", "high", "medium", "low", "unknown"]
    parts = [f"{sev}={by_sev[sev]}" for sev in order if sev in by_sev]
    return ", ".join(parts)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="polinrider-guard",
        description="Run all PolinRider detection scanners against a path and produce a combined report.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--no-git", action="store_true", help="Skip git history checks")
    args = parser.parse_args(argv)

    report = run_guard(args.path, include_git=not args.no_git)

    if args.json:
        print(jsonlib.dumps(report, indent=2))
    else:
        _print_text_report(report)

    return 1 if report["summary"]["total_findings"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
