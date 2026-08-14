"""Scanner for the JavaScript-ecosystem execution-stage attack surface.

Most of this project's other scanners look for a specific payload shape (a
font-file masquerade, a folderOpen task, a literal IOC string). This one
instead walks the *order* in which a JS/Node project actually executes code
-- because a supply-chain payload doesn't need to hide in application code at
all if it can run earlier, at a stage nobody reviews:

    Stage 1 -- npm lifecycle scripts (pre/postinstall, prepare), which run
               the instant `npm install` finishes -- before a developer has
               run a single command of their own, and recursively for every
               dependency's own package.json too.
    Stage 2 -- .vscode/settings.json's task.allowAutomaticTasks, which (when
               set to "on") removes VS Code's confirmation prompt before a
               folderOpen task (see scan_vscode.py) runs automatically.
    Stage 3 -- NODE_OPTIONS / NODE_PATH / --require / --import preload hooks,
               which run before any application code -- most dangerously via
               a committed .env file, since an env var applies silently to
               every node invocation without appearing in any visible
               command.
    Stage 4 -- framework config files (next.config.*, vite.config.*, etc.),
               which execute as soon as the dev server or build tool starts
               parsing them -- before a single line of application code.
    Stage 5 -- the application's own entry points (scripts.start/dev/build).

Font/image-extension masquerade (payload disguised as a .woff2/.png/etc, most
often dropped in a fonts/ or assets/ directory) is a distinct vector already
covered end-to-end by scan_masquerade.py, which checks content-vs-extension
for every binary-like file in the tree -- it isn't duplicated here.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist
from .progress import OnProgress, make_reporter
from .scan_vscode import strip_jsonc_comments
from .skip_lists import SKIP_DIR_NAMES

# node_modules is deliberately NOT skipped here (unlike every other text
# scanner in this project) -- stage 1 needs to walk into it on purpose, to
# recursively inspect every dependency's own package.json lifecycle scripts.
_WALK_SKIP_DIR_NAMES = SKIP_DIR_NAMES - {"node_modules"}

LIFECYCLE_SCRIPT_KEYS = ("preinstall", "install", "postinstall", "prepare")
ENTRY_SCRIPT_KEYS = ("start", "dev", "build")

_FRAMEWORK_CONFIG_RE = re.compile(
    r"^(?:next|vite|webpack|astro|nuxt|babel|jest|eslint|tailwind|postcss)"
    r"\.config\.(?:js|cjs|mjs|ts|cts|mts)$",
    re.IGNORECASE,
)
_ENV_FILENAME_RE = re.compile(r"^\.env(?:\..+)?$")
# Conventionally-committed sample/template env files, not real secrets/config
# -- not worth flagging even if they happen to demonstrate a NODE_OPTIONS line.
_ENV_SAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")

# --- content heuristics, shared across stages ------------------------------

DOWNLOAD_EXEC_RE = re.compile(
    rb"\b(curl|wget|Invoke-WebRequest|iwr)\b[^\n|]{0,200}\|\s*"
    rb"(sh|bash|node|python3?|powershell|pwsh)\b",
    re.IGNORECASE,
)
BASE64_DECODE_RE = re.compile(
    rb"(base64\s+-d|atob\(|Buffer\.from\([^)]*,\s*['\"]base64['\"]\))", re.IGNORECASE
)
EVAL_RE = re.compile(rb"\beval\(|\bnew\s+Function\(", re.IGNORECASE)
NODE_INLINE_EXEC_RE = re.compile(rb"\bnode\s+(?:-e|--eval)\b", re.IGNORECASE)
CHILD_PROCESS_RE = re.compile(
    rb"require\(\s*['\"]child_process['\"]\s*\)|\bexecSync\(|\bspawn\(|\bexec\(", re.IGNORECASE
)
# Deliberately narrower than "https?://" -- a framework config referencing a
# CDN/image domain as a plain string (images.domains, devServer.proxy, etc.)
# is completely ordinary; an actual network *call* made while the config
# module itself loads is not.
NETWORK_CALL_RE = re.compile(
    rb"\bfetch\(|\bhttps?\.request\(|\baxios\.(?:get|post|request)\(|XMLHttpRequest\(",
    re.IGNORECASE,
)

# Any one of these in a lifecycle/entry npm script is a strong, specific
# signal -- unlike a bare `--require` flag (see NODE_PRELOAD_TARGET_RE
# below), none of these have an ordinary legitimate use in a script body.
SUSPICIOUS_SCRIPT_CONTENT_PATTERNS: list[tuple[re.Pattern, str]] = [
    (DOWNLOAD_EXEC_RE, "downloads a remote script and pipes it directly into an interpreter"),
    (BASE64_DECODE_RE, "decodes a base64 payload"),
    (EVAL_RE, "calls eval()/new Function() on dynamic content"),
    (NODE_INLINE_EXEC_RE, "runs inline code via `node -e`/`node --eval`"),
]

NODE_OPTIONS_ASSIGN_RE = re.compile(rb"\bNODE_OPTIONS\s*=", re.IGNORECASE)
NODE_PATH_ASSIGN_RE = re.compile(rb"\bNODE_PATH\s*=", re.IGNORECASE)
# A bare `--require`/`--import` in a script is extremely common and
# legitimate (mocha --require ts-node/register, node --require dotenv/config,
# etc.), so a plain module-name target isn't flagged. A path-shaped target
# (starts with a dot-segment, is absolute, or is a Windows drive path) is a
# different, worth-a-look shape -- it's pointing at a specific file in (or
# outside) the repo rather than a named, installed package.
NODE_PRELOAD_TARGET_RE = re.compile(
    rb"--(?:require|import)\s+['\"]?(\.{1,2}/[\w./-]*|/[\w./-]+|[A-Za-z]:\\[\w\\.-]+)",
    re.IGNORECASE,
)


@dataclass
class JsEcosystemFinding:
    file: str
    stage: str
    category: str
    detail: str
    indicators: list[str] = field(default_factory=list)
    severity: str = "low"

    def to_dict(self) -> dict:
        return {
            "type": "js_ecosystem_attack",
            "file": self.file,
            "stage": self.stage,
            "category": self.category,
            "detail": self.detail,
            "indicators": self.indicators,
            "severity": self.severity,
        }


def _script_indicators(command: str) -> list[str]:
    raw = command.encode("utf-8", errors="replace")
    return [desc for pattern, desc in SUSPICIOUS_SCRIPT_CONTENT_PATTERNS if pattern.search(raw)]


def _preload_indicators(command: str) -> list[tuple[str, str]]:
    """Return (indicator, severity) pairs for NODE_OPTIONS/NODE_PATH/
    path-shaped --require/--import targets found in an npm script string.
    """
    raw = command.encode("utf-8", errors="replace")
    hits: list[tuple[str, str]] = []
    if NODE_OPTIONS_ASSIGN_RE.search(raw):
        hits.append(("sets NODE_OPTIONS inline, injecting a preload hook into the node invocation", "high"))
    if NODE_PATH_ASSIGN_RE.search(raw):
        hits.append(("sets NODE_PATH inline, altering module resolution for the node invocation", "medium"))
    if NODE_PRELOAD_TARGET_RE.search(raw):
        hits.append(("passes --require/--import a file path (rather than a package name) to preload", "medium"))
    return hits


def _load_json_object(path: Path) -> dict | None:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def check_package_json(path: Path, root: Path, *, is_dependency: bool) -> list[JsEcosystemFinding]:
    data = _load_json_object(path)
    if data is None:
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []

    rel = str(path.relative_to(root))
    findings: list[JsEcosystemFinding] = []

    for key in LIFECYCLE_SCRIPT_KEYS:
        command = scripts.get(key)
        if not isinstance(command, str) or not command.strip():
            continue
        suspicious = _script_indicators(command)
        if is_dependency:
            # A dependency declaring pre/postinstall is routine (husky,
            # native-addon builds, puppeteer's Chromium download, ...) --
            # only surface it here when its content is actually suspicious,
            # or every scan of a real node_modules tree would be all noise.
            if not suspicious:
                continue
            severity = "critical"
            indicators = suspicious
        else:
            if suspicious:
                severity = "critical"
                indicators = suspicious
            else:
                severity = "low"
                indicators = ["runs automatically during `npm install`, with zero developer interaction"]
        findings.append(
            JsEcosystemFinding(
                file=rel,
                stage="stage1_install_lifecycle",
                category="npm_lifecycle_script",
                detail=f"scripts.{key}: {command.strip()}",
                indicators=indicators,
                severity=severity,
            )
        )

    # Preload-hook and suspicious-content checks apply to every script, not
    # just the lifecycle ones -- an attacker doesn't need `postinstall` if
    # `scripts.dev`/`scripts.start` themselves inject the same hook the
    # moment a developer runs the command they'd run anyway.
    for key, command in scripts.items():
        if not isinstance(command, str) or not command.strip():
            continue
        for indicator, severity in _preload_indicators(command):
            findings.append(
                JsEcosystemFinding(
                    file=rel,
                    stage="stage3_process_preload",
                    category="npm_script_preload",
                    detail=f"scripts.{key}: {command.strip()}",
                    indicators=[indicator],
                    severity=severity,
                )
            )

    if not is_dependency:
        for key in ENTRY_SCRIPT_KEYS:
            command = scripts.get(key)
            if not isinstance(command, str) or not command.strip():
                continue
            suspicious = _script_indicators(command)
            if not suspicious:
                continue
            findings.append(
                JsEcosystemFinding(
                    file=rel,
                    stage="stage5_entry_point",
                    category="npm_entry_script",
                    detail=f"scripts.{key}: {command.strip()}",
                    indicators=suspicious,
                    severity="high",
                )
            )

    return findings


def _has_folder_open_task(text: str) -> bool:
    try:
        data = json.loads(strip_jsonc_comments(text))
    except json.JSONDecodeError:
        return False
    tasks = data.get("tasks", []) if isinstance(data, dict) else []
    for task in tasks:
        if not isinstance(task, dict):
            continue
        run_on = str(task.get("runOptions", {}).get("runOn", "")).lower()
        if run_on == "folderopen":
            return True
    return False


def check_vscode_settings(path: Path, root: Path) -> list[JsEcosystemFinding]:
    data = None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []
    try:
        data = json.loads(strip_jsonc_comments(raw))
    except json.JSONDecodeError:
        return []
    if not isinstance(data, dict):
        return []

    value = data.get("task.allowAutomaticTasks")
    if str(value).strip().lower() != "on":
        return []

    rel = str(path.relative_to(root))
    indicators = [
        "task.allowAutomaticTasks is 'on' -- suppresses VS Code's confirmation "
        "prompt before a folderOpen task runs automatically",
    ]
    severity = "high"

    tasks_path = path.parent / "tasks.json"
    if tasks_path.is_file():
        try:
            tasks_text = tasks_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            tasks_text = ""
        if tasks_text and _has_folder_open_task(tasks_text):
            severity = "critical"
            indicators.append(
                "a folderOpen task exists in the sibling tasks.json -- this setting removes "
                "the last user-visible confirmation before it runs"
            )

    return [
        JsEcosystemFinding(
            file=rel,
            stage="stage2_ide_autorun",
            category="vscode_allow_automatic_tasks",
            detail=f'task.allowAutomaticTasks: {value!r}',
            indicators=indicators,
            severity=severity,
        )
    ]


def check_env_file(path: Path, root: Path) -> list[JsEcosystemFinding]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return []

    rel = str(path.relative_to(root))
    findings: list[JsEcosystemFinding] = []
    for line_no, line in enumerate(raw.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        raw_line = stripped.encode("utf-8", errors="replace")
        if NODE_OPTIONS_ASSIGN_RE.search(raw_line):
            findings.append(
                JsEcosystemFinding(
                    file=rel,
                    stage="stage3_process_preload",
                    category="env_node_options",
                    detail=f"line {line_no}: {stripped}",
                    indicators=[
                        "NODE_OPTIONS set in a committed .env file -- applies silently to every "
                        "node invocation in this environment, with no visible flag in any command"
                    ],
                    severity="high",
                )
            )
        elif NODE_PATH_ASSIGN_RE.search(raw_line):
            findings.append(
                JsEcosystemFinding(
                    file=rel,
                    stage="stage3_process_preload",
                    category="env_node_path",
                    detail=f"line {line_no}: {stripped}",
                    indicators=["NODE_PATH set in a committed .env file, altering module resolution"],
                    severity="medium",
                )
            )
    return findings


def _config_severity(hits: set[str]) -> str:
    if "download_exec" in hits:
        return "critical"
    if "eval" in hits or "base64" in hits:
        return "critical" if ("child_process" in hits or "network" in hits) else "high"
    if "child_process" in hits and "network" in hits:
        return "critical"
    return "low"


def check_framework_config(path: Path, root: Path) -> list[JsEcosystemFinding]:
    try:
        raw = path.read_bytes()
    except (OSError, PermissionError):
        return []
    if b"\x00" in raw[:8192]:
        return []

    hits: dict[str, str] = {}
    if DOWNLOAD_EXEC_RE.search(raw):
        hits["download_exec"] = "downloads a remote script and pipes it into an interpreter"
    if EVAL_RE.search(raw):
        hits["eval"] = "calls eval()/new Function() at config-load time"
    if BASE64_DECODE_RE.search(raw):
        hits["base64"] = "decodes a base64 payload at config-load time"
    if CHILD_PROCESS_RE.search(raw):
        hits["child_process"] = "spawns a child process at config-load time"
    if NETWORK_CALL_RE.search(raw):
        hits["network"] = "makes a network call at config-load time"

    if not hits:
        return []

    rel = str(path.relative_to(root))
    return [
        JsEcosystemFinding(
            file=rel,
            stage="stage4_framework_config",
            category="framework_config_exec",
            detail=(
                "this file executes the moment the dev server/build tool parses it, "
                "before any application code runs"
            ),
            indicators=list(hits.values()),
            severity=_config_severity(set(hits)),
        )
    ]


def _classify(path: Path, root: Path) -> str | None:
    name = path.name
    if name == "package.json":
        return "dependency_package_json" if "node_modules" in path.relative_to(root).parts[:-1] else "own_package_json"
    if name == "settings.json" and path.parent.name == ".vscode":
        return "vscode_settings"
    if _ENV_FILENAME_RE.match(name) and not name.lower().endswith(_ENV_SAMPLE_SUFFIXES):
        return "env_file"
    if _FRAMEWORK_CONFIG_RE.match(name):
        return "framework_config"
    return None


def _iter_candidate_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _WALK_SKIP_DIR_NAMES]
        dpath = Path(dirpath)
        in_node_modules = "node_modules" in dpath.parts
        for name in filenames:
            path = dpath / name
            if name == "package.json":
                yield path, ("dependency_package_json" if in_node_modules else "own_package_json")
                continue
            if in_node_modules:
                continue  # env/vscode/framework-config checks only apply to the project's own files
            if name == "settings.json" and dpath.name == ".vscode":
                yield path, "vscode_settings"
            elif _ENV_FILENAME_RE.match(name) and not name.lower().endswith(_ENV_SAMPLE_SUFFIXES):
                yield path, "env_file"
            elif _FRAMEWORK_CONFIG_RE.match(name):
                yield path, "framework_config"


def _dispatch(path: Path, root: Path, kind: str) -> list[JsEcosystemFinding]:
    if kind == "own_package_json":
        return check_package_json(path, root, is_dependency=False)
    if kind == "dependency_package_json":
        return check_package_json(path, root, is_dependency=True)
    if kind == "vscode_settings":
        return check_vscode_settings(path, root)
    if kind == "env_file":
        return check_env_file(path, root)
    if kind == "framework_config":
        return check_framework_config(path, root)
    return []


def scan_path(
    target: str | os.PathLike,
    on_progress: OnProgress | None = None,
) -> list[JsEcosystemFinding]:
    """`on_progress`, if given, is called as on_progress(done, total) as
    candidate files are scanned -- see polinrider_guard.progress -- so a
    caller (the web UI) can show a "N/total files" progress bar.
    """
    root = Path(target).resolve()
    entries = allowlist.load_allowlist(root)

    if root.is_file():
        kind = _classify(root, root.parent)
        findings = _dispatch(root, root.parent, kind) if kind else []
    else:
        candidates = list(_iter_candidate_files(root))
        report = make_reporter(len(candidates), on_progress)
        report(0)
        findings = []
        for i, (path, kind) in enumerate(candidates, start=1):
            findings.extend(_dispatch(path, root, kind))
            report(i)

    return [f for f in findings if not allowlist.is_file_allowlisted(entries, "js_ecosystem_attack", f.file)]


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="polinrider-scan-js-ecosystem",
        description=(
            "Detect JS-ecosystem execution-stage attacks: risky npm install-lifecycle "
            "scripts, VS Code auto-run settings, Node preload hooks, and framework "
            "config files that execute code before the application does."
        ),
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    args = parser.parse_args(argv)

    findings = scan_path(args.path)

    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        if not findings:
            print(f"No JS-ecosystem execution-stage attacks found in {args.path}")
        for f in findings:
            print(f"[{f.severity.upper()}] {f.file} ({f.stage}/{f.category})")
            print(f"    {f.detail}")
            for indicator in f.indicators:
                print(f"    - {indicator}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
