"""Git history surgery: strip PolinRider payload lines/files from every
historical blob via git-filter-repo, without destroying legitimate work on
top.

`git revert` only fixes the tip of a branch. `git filter-repo --invert-paths`
removes a whole file from history. Neither is right when a malicious commit
sits *underneath* months of legitimate work on the same files: reverting
conflicts with everything on top, and deleting the file destroys the
legitimate history along with the payload. The correct fix is a blob-level
rewrite: walk every version of every file that has ever existed, strip only
the lines that match a known IOC pattern, and leave everything else
byte-for-byte identical.

This covers five distinct techniques, matching five of the scanners, plus
reports a sixth for human review:
1. Literal IOC lines (scan_ioc.py's patterns) and whitespace-padding-hidden
   lines (scan_padding.py's primary signal) -- both are per-LINE matches,
   stripped out of the blob while keeping everything else.
2. Whole clock-tamper scripts (scan_clock_tamper.py's signal) -- the entire
   blob IS the payload (e.g. a committed .bat file), so it gets blanked
   entirely rather than line-stripped.
3. Confirmed extension-masquerade blobs (scan_masquerade.py's
   highest-confidence tier only -- magic bytes mismatch *and* JavaScript
   syntax in the content) -- also blanked entirely, the same way a
   clock-tamper script is. The softer entropy-based tier is deliberately
   excluded from auto-rewrite: it isn't backed by an unambiguous content
   signal, so blanking on it risks destroying a legitimate file on a false
   positive.
4. Historical risky .vscode/tasks.json blobs (find_risky_vscode_task_blobs())
   -- same TasksJacker signal as scan_vscode.py, applied to every version of
   every tasks.json that has ever been committed, not just the current tree.
   Also blanked entirely: a historical version could have a completely
   different structure than the current file, so surgically removing just
   the risky task (the way remove_risky_vscode_tasks() does for the current
   tree, #6 below) isn't attempted here. This exists because fixing the
   current tree alone leaves the original version fully recoverable from an
   older commit, a stale clone, or a fork -- a large part of the point of
   history surgery in the first place.
5. Camouflage commits (scan_commit_camouflage.py's signal) -- reported for
   human review, not auto-rewritten: which *specific* files in a mass-touch
   commit are suspicious is a judgment call this module doesn't make on its
   own (their content is usually also caught by #1, #2, #3, or #4 above if
   it's actually malicious).
6. Risky VS Code tasks in the *current* tree (scan_vscode.py's signal) --
   reported by find_risky_vscode_tasks(), and optionally removed by
   remove_risky_vscode_tasks(), which is a fundamentally different kind of
   operation from the other five: there's no git *history* to rewrite here,
   just a live config file in the working tree, so that function edits
   `repo` directly rather than a disposable mirror clone. See its own
   docstring for what that trade-off means in practice, and #4 above for
   the historical counterpart of this same technique.

Library home for this logic so scripts/surgical_clean.py (CLI) and
polinrider_guard/webapp.py (browser-triggered recovery) share one
implementation instead of two that can drift apart. Neither this module nor
either caller ever force-pushes on its own -- that stays an explicit,
separate, deliberately-gated action every time.

SAFETY MODEL
------------
1. analyze() and its sibling find_*() functions are read-only: they report
   what would be touched and change nothing.
2. apply_clean() requires a bare/mirror clone by default (never a working
   copy with uncommitted changes or a tree you might still be using) --
   force_non_mirror overrides that, and callers should not expose it to
   untrusted input.
3. git filter-repo itself refuses to run on a repo that still has its
   original `origin` remote configured, as a second safety net (this module
   passes --force to filter-repo, which is what makes --blob-callback mode
   possible at all -- see git-filter-repo's own docs for what --force
   overrides).
4. The one deliberate exception to "never touch the original directly" is
   remove_risky_vscode_tasks(): it isn't git-history surgery, just a normal
   working-tree file edit (the kind you could make yourself), so it writes
   to `repo` in place. It's trivially reversible with a plain
   `git checkout -- <file>` if the file is tracked, unlike a history
   rewrite, which is why it doesn't go through the mirror-clone/apply_clean
   path at all.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator

from . import scan_commit_camouflage, scan_masquerade, scan_vscode
from .iocs import DEFAULT_IOC_PATTERNS as _SHARED_IOC_PATTERNS
from .scan_clock_tamper import AMEND_RE, CLOCK_SET_PATTERNS
from .scan_padding import WHITESPACE_RUN_RE_BYTES

DEFAULT_IOC_PATTERNS: list[bytes] = [p for p, _desc, _sev in _SHARED_IOC_PATTERNS]


def load_patterns(iocs_file: Path | None = None) -> list[re.Pattern]:
    patterns = [re.compile(p) for p in DEFAULT_IOC_PATTERNS]
    if iocs_file:
        for line in iocs_file.read_bytes().splitlines():
            line = line.strip()
            if not line or line.startswith(b"#"):
                continue
            patterns.append(re.compile(line))
    return patterns


def _line_patterns(patterns: list[re.Pattern]) -> list[re.Pattern]:
    """The IOC patterns plus the whitespace-padding signal -- both are
    per-line matches that get stripped the same way. scan_padding.py's
    secondary (median-outlier) signal is deliberately NOT included here:
    it's a softer, statistical heuristic better left for analyze() to
    surface for human review than to auto-strip.
    """
    return [*patterns, WHITESPACE_RUN_RE_BYTES]


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True)


def is_bare_or_mirror(repo: Path) -> bool:
    result = _run(["git", "-C", str(repo), "rev-parse", "--is-bare-repository"])
    return result.returncode == 0 and result.stdout.strip() == "true"


def _cat_file_batch(repo: Path, shas: set[str]) -> dict[str, bytes]:
    """Resolve a set of object shas to their blob content in one
    `git cat-file --batch` call. Shared by _iter_blobs() (every blob in
    history) and find_masquerade_blobs() (only the small subset of blobs
    whose path had a binary-like extension), since batching one big request
    is much faster than shelling out per-object.
    """
    if not shas:
        return {}

    batch = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "--batch"],
        input="\n".join(shas).encode(),
        capture_output=True,
        text=False,
    )
    data = batch.stdout
    pos = 0
    result: dict[str, bytes] = {}
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

        if obj_type == "blob":
            result[sha] = content
    return result


def _iter_blobs(repo: Path) -> Iterator[tuple[str, bytes]]:
    """Yield (blob_sha, content) for every blob that has ever existed in
    the repo's history. Shared by analyze() and find_clock_tamper_blobs()
    so there's one blob-walking implementation, not two.
    """
    rev_list = _run(["git", "-C", str(repo), "rev-list", "--objects", "--all"])
    if rev_list.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {rev_list.stderr}")

    blob_shas = {line.split(" ", 1)[0] for line in rev_list.stdout.splitlines()}
    yield from _cat_file_batch(repo, blob_shas).items()


def analyze_blobs(
    repo: Path, patterns: list[re.Pattern]
) -> tuple[list[tuple[str, bytes, int]], list[tuple[str, list[str]]]]:
    """Single blob walk producing both analyze()'s line-level findings and
    find_clock_tamper_blobs()'s whole-blob findings. Prefer this over
    calling both separately (as analyze() and find_clock_tamper_blobs() do
    internally, for backwards-compatible standalone use) when you want
    both -- each of those otherwise walks the full history independently,
    doubling the git rev-list/cat-file cost for no reason.

    A blob that matches the clock-tamper signal is reported there only, not
    also scanned for line matches: apply_clean() blanks that blob entirely
    rather than line-stripping it, so counting its lines as separate
    line-level findings would overstate what a rewrite actually touches.
    """
    all_patterns = _line_patterns(patterns)
    line_findings: list[tuple[str, bytes, int]] = []
    clock_findings: list[tuple[str, list[str]]] = []
    for sha, content in _iter_blobs(repo):
        clock_hits = [desc for pattern, desc in CLOCK_SET_PATTERNS if pattern.search(content)]
        if clock_hits and AMEND_RE.search(content):
            clock_findings.append((sha, clock_hits))
            continue
        for line_no, line in enumerate(content.split(b"\n"), start=1):
            if any(p.search(line) for p in all_patterns):
                line_findings.append((sha, line, line_no))
    return line_findings, clock_findings


def analyze(repo: Path, patterns: list[re.Pattern]) -> list[tuple[str, bytes, int]]:
    """Return (blob_sha, matched_line, line_number) for every IOC/padding
    line match across every blob that has ever existed in the repo's
    history. Does not cover whole-blob clock-tamper matches -- see
    find_clock_tamper_blobs() for that, which is blob-level, not line-level.
    Standalone convenience wrapper around analyze_blobs(); if you also want
    the clock-tamper result, call analyze_blobs() directly instead of also
    calling find_clock_tamper_blobs() to avoid walking history twice.
    """
    line_findings, _ = analyze_blobs(repo, patterns)
    return line_findings


def find_clock_tamper_blobs(repo: Path) -> list[tuple[str, list[str]]]:
    """Return (blob_sha, indicators) for every blob whose *entire* content
    matches the ForceMemo clock-spoofing automation pattern (a system-clock
    set command plus `git commit --amend` anywhere in the same file) --
    same combined signal as scan_clock_tamper.py's check_file(), just
    applied to historical blobs instead of working-tree files. These get
    blanked entirely by apply_clean(), not line-stripped, since the whole
    file is the payload. Standalone convenience wrapper around
    analyze_blobs(); see analyze()'s docstring for the same caveat.
    """
    _, clock_findings = analyze_blobs(repo, [])
    return clock_findings


def _iter_object_paths(repo: Path) -> Iterator[tuple[str, str]]:
    """Yield (blob_sha, path) for every blob at every path it has ever been
    committed at, across all of history. A blob has no path of its own --
    only the tree entry pointing to it does -- so, unlike _iter_blobs(),
    this needs `git rev-list --objects`'s per-object path column, not just
    the bare object list. A single blob sha can yield more than once here
    (same content committed at several paths, or moved over time).
    """
    rev_list = _run(["git", "-C", str(repo), "rev-list", "--objects", "--all"])
    if rev_list.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {rev_list.stderr}")

    for line in rev_list.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2 or not parts[1]:
            # Commits get no path column at all; each commit's own root
            # tree gets an empty one ("<sha> ", trailing space, no name) --
            # neither is a blob-at-a-path, so both are skipped here.
            continue
        yield parts[0], parts[1]


def _iter_masquerade_candidate_paths(repo: Path) -> Iterator[tuple[str, str]]:
    """Yield (blob_sha, path) for every blob ever committed at a path whose
    extension claims a binary format scan_masquerade.py checks.
    """
    for sha, path in _iter_object_paths(repo):
        if Path(path).suffix.lower() in scan_masquerade.BINARY_LIKE_EXTENSIONS:
            yield sha, path


def blob_paths(repo: Path) -> dict[str, set[str]]:
    """Map every blob sha that has ever existed in history to the set of
    paths it has ever been committed at. Lets a caller scope a rewrite down
    to specific files (recovery's "checked files only" mode in the web UI)
    without re-deriving IOC/padding matches from blob content alone, which
    has no path information (see _iter_blobs()).
    """
    mapping: dict[str, set[str]] = {}
    for sha, path in _iter_object_paths(repo):
        mapping.setdefault(sha, set()).add(path)
    return mapping


def find_masquerade_blobs(repo: Path) -> list[tuple[str, str]]:
    """Return (blob_sha, path) for every historical blob matching
    scan_masquerade.py's *highest-confidence* tier only: magic bytes that
    don't match the claimed extension, AND JavaScript syntax in the content
    -- the same combination scan_masquerade.py itself calls "critical". The
    softer entropy-based tier is intentionally excluded here; see this
    module's docstring for why. These get blanked entirely by
    apply_clean(), the same treatment as a clock-tamper script, since the
    whole file (not just a line within it) is the payload.
    """
    candidates = list(_iter_masquerade_candidate_paths(repo))
    if not candidates:
        return []

    content_by_sha = _cat_file_batch(repo, {sha for sha, _ in candidates})

    findings: list[tuple[str, str]] = []
    seen_shas: set[str] = set()
    for sha, path in candidates:
        if sha in seen_shas:
            continue
        content = content_by_sha.get(sha)
        if content is None:
            continue
        ext = Path(path).suffix.lower()
        head = content[:512]
        if scan_masquerade.magic_bytes_match(ext, head):
            continue
        if scan_masquerade.JS_KEYWORDS.search(head):
            findings.append((sha, path))
            seen_shas.add(sha)
    return findings


def _iter_vscode_tasks_candidate_paths(repo: Path) -> Iterator[tuple[str, str]]:
    """Yield (blob_sha, path) for every blob ever committed at a
    .vscode/tasks.json path, at any depth, excluding node_modules -- the
    same filter scan_vscode.py's working-tree walk (scan_path()) uses.
    """
    rev_list = _run(["git", "-C", str(repo), "rev-list", "--objects", "--all"])
    if rev_list.returncode != 0:
        raise RuntimeError(f"git rev-list failed: {rev_list.stderr}")

    for line in rev_list.stdout.splitlines():
        parts = line.split(" ", 1)
        if len(parts) != 2:
            continue  # commits/trees/root objects rev-list lists with no path
        sha, path = parts
        path_parts = path.split("/")  # git always uses "/", regardless of OS
        if (
            len(path_parts) >= 2
            and path_parts[-1] == "tasks.json"
            and path_parts[-2] == ".vscode"
            and "node_modules" not in path_parts
        ):
            yield sha, path


def find_risky_vscode_task_blobs(repo: Path) -> list[tuple[str, str]]:
    """Return (blob_sha, path) for every historical .vscode/tasks.json blob
    that contains at least one risky task -- same signal as
    find_risky_vscode_tasks(), applied to every version that has ever been
    committed, not just the current tree.

    This exists because remove_risky_vscode_tasks() only fixes the current
    working tree: if a risky tasks.json was already committed (and possibly
    pushed) before you noticed, the old version is still recoverable from
    history -- checking out an older commit, or a stale clone/fork, brings
    the auto-run risk right back even after the current tree is fixed. These
    blobs get blanked entirely by apply_clean(), the same treatment as a
    clock-tamper script or a confirmed masquerade blob: a historical version
    of the file could have a completely different structure than the
    current one, so surgically removing just the risky task the way
    remove_risky_vscode_tasks() does isn't attempted here.
    """
    candidates = list(_iter_vscode_tasks_candidate_paths(repo))
    if not candidates:
        return []

    content_by_sha = _cat_file_batch(repo, {sha for sha, _ in candidates})

    findings: list[tuple[str, str]] = []
    seen_shas: set[str] = set()
    for sha, path in candidates:
        if sha in seen_shas:
            continue
        content = content_by_sha.get(sha)
        if content is None:
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if scan_vscode.evaluate_tasks_json(text):
            findings.append((sha, path))
            seen_shas.add(sha)
    return findings


def find_risky_vscode_tasks(repo: Path) -> list[scan_vscode.VscodeFinding]:
    """Report risky .vscode/tasks.json configuration in the current working
    tree -- same signal as scan_vscode.py, just re-exported here so callers
    only need to import recovery.py to know everything this tool can act
    on. Not rewritten by apply_clean() (see remove_risky_vscode_tasks() for
    the separate, working-tree-editing removal path): the risk here is
    about what auto-runs on folder-open *now*, which only the current tree
    (not every historical revision) controls.
    """
    return scan_vscode.scan_path(repo)


def remove_risky_vscode_tasks(repo: Path) -> list[str]:
    """Edit every .vscode/tasks.json with a risky task in place, removing
    just the risky task object(s) from its "tasks" array and leaving any
    other, legitimate tasks in the same file untouched. Returns the list of
    files actually edited (relative to `repo`).

    Unlike every other function in this module, this operates directly on
    `repo` -- see the module docstring's SAFETY MODEL point 4 for why that's
    fine here specifically: there's no git history involved, just a live
    config file, and the edit is a normal, git-trackable working-tree
    change like any other (reversible with `git checkout -- <file>` if the
    file is tracked).

    Re-serializes the file's JSON structure via json.dumps() rather than
    surgically removing just the matching object's text range, so any
    comments in the original tasks.json (JSONC allows them) are lost and
    formatting is normalized. Review the diff before committing if that
    matters to you. A task is matched for removal by (label, command) --
    the same identity find_risky_vscode_tasks() reports it by -- so an
    edit here always corresponds to a specific reported finding.
    """
    findings = find_risky_vscode_tasks(repo)
    risky_by_file: dict[str, set[tuple[str, str]]] = {}
    for f in findings:
        risky_by_file.setdefault(f.file, set()).add((f.task_label, f.command))

    edited_files: list[str] = []
    for rel_file, risky_keys in risky_by_file.items():
        path = repo / rel_file
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            data = json.loads(scan_vscode.strip_jsonc_comments(raw))
        except json.JSONDecodeError:
            continue
        if not isinstance(data, dict):
            continue

        tasks = data.get("tasks", [])
        kept_tasks = []
        removed_any = False
        for task in tasks:
            if isinstance(task, dict):
                command = str(task.get("command", ""))
                args = task.get("args", []) or []
                full_command = " ".join([command, *[str(a) for a in args]]).strip()
                key = (str(task.get("label", "<unlabeled>")), full_command)
                if key in risky_keys:
                    removed_any = True
                    continue
            kept_tasks.append(task)

        if not removed_any:
            continue
        data["tasks"] = kept_tasks
        path.write_text(json.dumps(data, indent=4) + "\n", encoding="utf-8")
        edited_files.append(rel_file)

    return edited_files


def find_camouflage_commits(repo: Path) -> list[scan_commit_camouflage.CamouflageFinding]:
    """Report (don't rewrite) mass-touch, mostly-no-op commits that also
    introduce a suspicious new file -- which *specific* files deserve
    removal from a commit like this is a judgment call left to a human;
    their content usually also trips analyze() or find_clock_tamper_blobs()
    if it's actually malicious, which *do* get auto-stripped.
    """
    return scan_commit_camouflage.scan_path(repo)


def build_callback_source(
    patterns: list[re.Pattern],
    masquerade_shas: list[str] | None = None,
    vscode_task_shas: list[str] | None = None,
    excluded_blob_shas: set[str] | None = None,
) -> str:
    """Build the body git-filter-repo will splice into its own generated
    `def callback(blob, _do_not_use_this_var=None): <body>` function.

    Critically, --blob-callback code is a *function body*, not a standalone
    script: git-filter-repo indents whatever we pass here and drops it
    straight inside its own def. It must NOT define its own function named
    blob_callback (that would just create an unused nested function and
    silently do nothing) -- it must operate on the `blob` argument directly.

    Three-tier logic, matching find_masquerade_blobs()/find_risky_vscode_task_blobs()/
    find_clock_tamper_blobs() vs analyze(): a blob whose *original*
    (pre-rewrite) sha is a confirmed masquerade or risky-tasks.json match,
    or one that's a whole clock-tamper script, gets blanked entirely; any
    other blob has its matching IOC lines dropped entirely (those patterns
    match self-contained malicious statements, e.g. `global['_V']='8-...'`,
    so the whole line is the payload) and its whitespace-padding lines
    *truncated* rather than dropped: unlike an IOC line, the whole point of
    the padding technique is real code followed by 80+ hidden spaces then a
    payload (e.g. `export default createJestConfig(config);<...>evil()`),
    so dropping the line would delete legitimate code along with the
    payload. Truncating at the start of the padding run keeps the
    legitimate prefix and discards only the hidden suffix. Masquerade and
    vscode-task blobs are matched by sha rather than by re-deriving the
    check from `blob.data` alone because both checks need the blob's *path*
    too (its claimed extension, or "is this actually a .vscode/tasks.json"),
    and a --blob-callback only ever sees blob content, never the path -- so
    those sha sets are precomputed by
    find_masquerade_blobs()/find_risky_vscode_task_blobs() up front and
    passed in here. They're combined into one blank-on-sha-match set since
    both get identical treatment (the whole blob is the payload either way).

    excluded_blob_shas, if given, is the set of blobs to leave completely
    untouched ("checked files only" in the web UI, applied to whichever
    files the user *unchecked*), even if they'd otherwise match an
    IOC/padding/masquerade/vscode-task signal. None or empty (the default)
    means no exclusions -- every matching blob in history is touched, the
    original behavior. Deliberately the *excluded* set, not an included
    one: a user typically unchecks a handful of false positives out of a
    repo that can have thousands of blobs, and this whole set gets embedded
    as literal source in the generated callback (see below) and passed as
    a single git-filter-repo CLI argument -- sized to "what got unchecked"
    instead of "every blob in the repo minus what got unchecked" is the
    difference between that argument staying small and it blowing past the
    OS's command-line length limit on any real-sized repo. Blob content
    alone carries no path, so the caller derives this set from
    blob_paths() plus whichever paths the user left unchecked.
    """
    ioc_pattern_literals = ",\n".join(repr(p.pattern) for p in patterns)
    whitespace_pattern_literal = repr(WHITESPACE_RUN_RE_BYTES.pattern)
    clock_pattern_literals = ",\n".join(repr(p.pattern) for p, _desc in CLOCK_SET_PATTERNS)
    amend_pattern_literal = repr(AMEND_RE.pattern)
    blank_shas = {*(masquerade_shas or []), *(vscode_task_shas or [])}
    blank_sha_literals = ",\n".join(repr(sha.encode()) for sha in blank_shas)
    excluded_sha_literals = ",\n".join(repr(sha.encode()) for sha in (excluded_blob_shas or []))
    return f"""import re
_ioc_patterns = [re.compile(p) for p in [
{ioc_pattern_literals}
]]
_whitespace_pattern = re.compile({whitespace_pattern_literal})
_clock_patterns = [re.compile(p) for p in [
{clock_pattern_literals}
]]
_amend_pattern = re.compile({amend_pattern_literal})
_blank_shas = frozenset([
{blank_sha_literals}
])
_excluded_shas = frozenset([
{excluded_sha_literals}
])

data = blob.data
if blob.original_id in _excluded_shas:
    pass
elif blob.original_id in _blank_shas:
    blob.data = b''
elif data and any(p.search(data) for p in _clock_patterns) and _amend_pattern.search(data):
    blob.data = b''
else:
    lines = data.split(b'\\n')
    kept = []
    changed = False
    for ln in lines:
        m = _whitespace_pattern.search(ln)
        if m:
            # Truncate first: the hidden suffix after the padding is where
            # a real payload lives, and it commonly *also* matches an IOC
            # pattern (e.g. eval(Buffer.from(...))) -- checking IOC
            # patterns against the untruncated line would then drop the
            # whole line, legitimate prefix included. Truncating first
            # removes the hidden suffix outright, so the IOC check below
            # only ever sees the already-clean prefix.
            ln = ln[:m.start() + 1]
            changed = True
        if any(p.search(ln) for p in _ioc_patterns):
            changed = True
            continue
        kept.append(ln)
    if changed:
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


def apply_clean(
    repo: Path,
    patterns: list[re.Pattern],
    masquerade_shas: list[str] | None = None,
    vscode_task_shas: list[str] | None = None,
    excluded_blob_shas: set[str] | None = None,
    force_non_mirror: bool = False,
) -> None:
    if not force_non_mirror and not is_bare_or_mirror(repo):
        raise RuntimeError(
            f"{repo} does not look like a bare/mirror clone.\n"
            "Surgical history rewriting should run against a disposable mirror clone, "
            "not your working copy:\n"
            f"    git clone --mirror <url> {repo}.git\n"
            "Pass force_non_mirror=True to override."
        )

    script_path = find_filter_repo_script()
    callback_src = build_callback_source(patterns, masquerade_shas, vscode_task_shas, excluded_blob_shas)

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
        if result.returncode != 0:
            raise RuntimeError(f"git filter-repo failed; repository was not fully rewritten:\n{result.stderr}")
    finally:
        Path(callback_file).unlink(missing_ok=True)
