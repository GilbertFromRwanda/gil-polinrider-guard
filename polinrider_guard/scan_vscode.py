"""Scanner for risky .vscode/tasks.json auto-execution configuration.

TasksJacker abuses VS Code's `runOn: folderOpen` task trigger to execute a
command the instant a project is opened -- before the developer has run a
single command themselves. This module looks for that trigger combined with
the stealth-presentation settings PolinRider uses to hide the task from the
UI, and flags any command that shells out to `node`/`python`/etc. against a
path with a binary-looking extension (the font-file vector).
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

SUSPICIOUS_RUN_TARGET = re.compile(
    r"\b(node|python3?|ruby|perl|php|bash|sh|powershell|pwsh)\b[^\n]*"
    r"\.(woff2?|ttf|otf|eot|png|jpe?g|gif|ico|webp|bmp|wasm|pdf|zip)\b",
    re.IGNORECASE,
)

INTERPRETER_PATTERN = re.compile(
    r"\b(node|python3?|ruby|perl|php|bash|-c|Invoke-Expression|iex)\b", re.IGNORECASE
)


def _strip_jsonc_comments(text: str) -> str:
    """Strip // and /* */ comments so tasks.json (JSONC) parses as JSON.

    Not a full tokenizer, but good enough for tasks.json: it respects string
    literals so it won't eat a `//` that appears inside a command string.
    """
    out = []
    i = 0
    n = len(text)
    in_string = False
    string_char = ""
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == string_char:
                in_string = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    # tasks.json also tolerates trailing commas; strip ",}" / ",]"
    joined = "".join(out)
    joined = re.sub(r",(\s*[}\]])", r"\1", joined)
    return joined


@dataclass
class VscodeFinding:
    file: str
    task_label: str
    reasons: list[str]
    command: str
    severity: str

    def to_dict(self) -> dict:
        return {
            "type": "vscode_task_risk",
            "file": self.file,
            "task_label": self.task_label,
            "reasons": self.reasons,
            "command": self.command,
            "severity": self.severity,
        }


def _evaluate_task(task: dict) -> VscodeFinding | None:
    reasons: list[str] = []

    run_on = str(task.get("runOptions", {}).get("runOn", "")).lower()
    is_folder_open = run_on == "folderopen"
    if is_folder_open:
        reasons.append("runOptions.runOn is 'folderOpen' (executes with zero user interaction)")

    hidden = task.get("hide") is True
    if hidden:
        reasons.append("hide=true (task is removed from the VS Code task picker UI)")

    presentation = task.get("presentation", {}) or {}
    stealthy_presentation = (
        presentation.get("reveal") == "never"
        and presentation.get("echo") is False
    )
    if stealthy_presentation:
        reasons.append("presentation suppresses terminal output (reveal=never, echo=false)")

    command = str(task.get("command", ""))
    args = task.get("args", []) or []
    full_command = " ".join([command, *[str(a) for a in args]])

    if SUSPICIOUS_RUN_TARGET.search(full_command):
        reasons.append("command runs an interpreter against a binary-extension file (font/image/wasm masquerade)")
    elif is_folder_open and INTERPRETER_PATTERN.search(full_command):
        reasons.append("folderOpen task invokes a script interpreter")

    if not reasons:
        return None

    # Severity: folderOpen + hidden/stealthy + suspicious target is the full
    # confirmed PolinRider chain; anything less is still worth a human look.
    if is_folder_open and (hidden or stealthy_presentation) and SUSPICIOUS_RUN_TARGET.search(full_command):
        severity = "critical"
    elif is_folder_open and (hidden or stealthy_presentation):
        severity = "high"
    elif is_folder_open:
        severity = "medium"
    else:
        severity = "low"

    return VscodeFinding(
        file="",  # filled by caller
        task_label=str(task.get("label", "<unlabeled>")),
        reasons=reasons,
        command=full_command.strip(),
        severity=severity,
    )


def scan_tasks_file(path: Path, root: Path) -> list[VscodeFinding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []

    try:
        data = json.loads(_strip_jsonc_comments(raw))
    except json.JSONDecodeError:
        return []

    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    rel = str(path.relative_to(root))
    findings: list[VscodeFinding] = []
    for task in tasks:
        if not isinstance(task, dict):
            continue
        finding = _evaluate_task(task)
        if finding:
            finding.file = rel
            findings.append(finding)
    return findings


def scan_path(target: str | os.PathLike) -> list[VscodeFinding]:
    root = Path(target).resolve()
    if root.is_file():
        return scan_tasks_file(root, root.parent)

    findings: list[VscodeFinding] = []
    for tasks_file in root.rglob(".vscode/tasks.json"):
        if "node_modules" in tasks_file.parts:
            continue
        findings.extend(scan_tasks_file(tasks_file, root))
    return findings


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-vscode",
        description="Detect risky auto-executing .vscode/tasks.json configuration (TasksJacker technique).",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        import json as jsonlib
        print(jsonlib.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No risky VS Code task configuration found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file} - task '{f.task_label}'")
            for r in f.reasons:
                print(f"    - {r}")
            print(f"    command: {f.command}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
