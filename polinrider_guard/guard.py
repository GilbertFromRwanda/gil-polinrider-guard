"""polinrider-guard: run every scanner against a path and produce one report.

This is the command meant to be run before opening an unfamiliar repository
in an IDE (the "pre-open checklist"), and the one whose --json output feeds
the batch cleaner in scripts/batch-clean.sh.
"""
from __future__ import annotations

import json as jsonlib
import os
import sys
from pathlib import Path

from . import scan_git_dates, scan_ioc, scan_masquerade, scan_unicode, scan_vscode


def run_guard(target: str | os.PathLike, include_git: bool = True) -> dict:
    root = Path(target).resolve()

    report: dict = {
        "target": str(root),
        "scanners": {},
        "summary": {"total_findings": 0, "by_severity": {}},
    }

    unicode_findings = [f.to_dict() for f in scan_unicode.scan_path(root)]
    masquerade_findings = [f.to_dict() for f in scan_masquerade.scan_path(root)]
    vscode_findings = [f.to_dict() for f in scan_vscode.scan_path(root)]
    ioc_findings = [f.to_dict() for f in scan_ioc.scan_path(root)]

    report["scanners"]["invisible_unicode"] = unicode_findings
    report["scanners"]["extension_masquerade"] = masquerade_findings
    report["scanners"]["vscode_tasks"] = vscode_findings
    report["scanners"]["ioc_literal_match"] = ioc_findings

    if include_git:
        try:
            git_findings = [f.to_dict() for f in scan_git_dates.scan_path(root)]
            report["scanners"]["git_date_backdating"] = git_findings
        except scan_git_dates.NotAGitRepoError:
            report["scanners"]["git_date_backdating"] = []
            report["git_skipped_reason"] = "not a git repository"
    else:
        report["scanners"]["git_date_backdating"] = []
        report["git_skipped_reason"] = "--no-git"

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


def _print_text_report(report: dict) -> None:
    target = report["target"]
    total = report["summary"]["total_findings"]

    if total == 0:
        print(f"No findings in {target}")
        return

    print(f"polinrider-guard report for {target}")
    print(f"Total findings: {total}  ({_format_severity_counts(report['summary']['by_severity'])})")
    print()

    labels = {
        "invisible_unicode": "Invisible Unicode (Glassworm)",
        "extension_masquerade": "Extension masquerade (font-file vector)",
        "vscode_tasks": "Risky VS Code tasks (TasksJacker)",
        "git_date_backdating": "Git author/committer date gaps (ForceMemo)",
        "ioc_literal_match": "Known IOC strings (C2 domains, loader markers)",
    }

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
    if scanner == "invisible_unicode":
        print(f"  [{sev}] {f['file']}:{f['line']}:{f['column']} {f['codepoint']} - {f['description']}")
    elif scanner == "extension_masquerade":
        print(f"  [{sev}] {f['file']} claims {f['claimed_type']} but is {f['actual_type']}")
    elif scanner == "vscode_tasks":
        print(f"  [{sev}] {f['file']} task '{f['task_label']}': {'; '.join(f['reasons'])}")
    elif scanner == "git_date_backdating":
        print(f"  [{sev}] {f['commit'][:12]} gap={f['gap_human']} - {f['subject']}")
    elif scanner == "ioc_literal_match":
        print(f"  [{sev}] {f['file']}:{f['line']} - {f['description']} ({f['matched_text']!r})")
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
