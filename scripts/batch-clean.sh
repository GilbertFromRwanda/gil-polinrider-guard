#!/usr/bin/env bash
#
# batch-clean.sh — recover many repositories in one pass.
#
# Takes a plain text file of repository URLs/paths (one per line), and for
# each one: clones it, runs polinrider-guard to confirm/record findings,
# makes a --mirror clone, and runs the surgical cleaner against the mirror.
# It produces a recovery audit log (JSON lines) so you have a record of
# exactly what was found and what was changed, per repository.
#
# THIS SCRIPT NEVER FORCE-PUSHES ON ITS OWN. Cleaning is local-only by
# default. Pushing the cleaned history back requires BOTH --push and
# --i-know-what-im-doing, and even then it prints the exact commands run so
# there is a record. Treat that combination as "yes, actually rewrite the
# shared remote history for this repo" -- coordinate with collaborators
# first; anyone with an existing clone will need to re-clone afterward.
#
# Usage:
#   scripts/batch-clean.sh --repo-list repos.txt --workdir ./recovery
#   scripts/batch-clean.sh --repo-list repos.txt --workdir ./recovery --push --i-know-what-im-doing
#
# repos.txt format: one clone URL or local path per line, blank lines and
# lines starting with # are ignored.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

run_guard() {
  # Prefer the installed console script; fall back to running the module
  # in-place (pip install -e . not required) via PYTHONPATH.
  if command -v polinrider-guard >/dev/null 2>&1; then
    polinrider-guard "$@"
  else
    PYTHONPATH="$PROJECT_ROOT" python -m polinrider_guard.guard "$@"
  fi
}

REPO_LIST=""
WORKDIR=""
DO_PUSH=0
CONFIRM_PUSH=0
IOCS_FILE=""

usage() {
  echo "Usage: $0 --repo-list FILE --workdir DIR [--push --i-know-what-im-doing] [--iocs-file FILE]" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-list) REPO_LIST="$2"; shift 2 ;;
    --workdir) WORKDIR="$2"; shift 2 ;;
    --push) DO_PUSH=1; shift ;;
    --i-know-what-im-doing) CONFIRM_PUSH=1; shift ;;
    --iocs-file) IOCS_FILE="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "Unknown argument: $1" >&2; usage ;;
  esac
done

[[ -n "$REPO_LIST" && -n "$WORKDIR" ]] || usage
[[ -f "$REPO_LIST" ]] || { echo "Repo list not found: $REPO_LIST" >&2; exit 1; }

if [[ "$DO_PUSH" -eq 1 && "$CONFIRM_PUSH" -ne 1 ]]; then
  echo "Error: --push requires --i-know-what-im-doing as well (force-pushing rewritten history affects every collaborator's clone)." >&2
  exit 1
fi

mkdir -p "$WORKDIR/checkouts" "$WORKDIR/mirrors" "$WORKDIR/reports"
AUDIT_LOG="$WORKDIR/recovery-audit.jsonl"
: > "$AUDIT_LOG"

IOC_ARGS=()
if [[ -n "$IOCS_FILE" ]]; then
  IOC_ARGS=(--iocs-file "$IOCS_FILE")
fi

log_audit() {
  # $1 = repo, $2 = stage, $3 = status, $4 = detail (raw JSON value or string)
  printf '{"repo":"%s","stage":"%s","status":"%s","detail":%s}\n' \
    "$1" "$2" "$3" "$4" >> "$AUDIT_LOG"
}

total=0
cleaned=0
failed=0

while IFS= read -r repo || [[ -n "$repo" ]]; do
  [[ -z "$repo" || "$repo" =~ ^# ]] && continue
  total=$((total + 1))

  name="$(basename "$repo" .git)"
  checkout_dir="$WORKDIR/checkouts/$name"
  mirror_dir="$WORKDIR/mirrors/$name.git"
  report_file="$WORKDIR/reports/$name.json"

  echo "=== [$total] $repo ==="

  echo "  cloning working copy for content scan..."
  rm -rf "$checkout_dir"
  if ! git clone -q "$repo" "$checkout_dir" 2>"$WORKDIR/reports/$name.clone.err"; then
    echo "  FAILED to clone $repo (see $WORKDIR/reports/$name.clone.err)"
    log_audit "$repo" "clone" "failed" "\"see $name.clone.err\""
    failed=$((failed + 1))
    continue
  fi

  echo "  running polinrider-guard..."
  run_guard "$checkout_dir" --json > "$report_file" 2>&1 || true
  findings=$(python -c "import json,sys; print(json.load(open(sys.argv[1]))['summary']['total_findings'])" "$report_file" 2>/dev/null || echo "unknown")
  echo "  guard report: $findings finding(s) -> $report_file"
  log_audit "$repo" "guard_scan" "done" "$findings"

  echo "  creating mirror clone for surgical clean..."
  rm -rf "$mirror_dir"
  if ! git clone -q --mirror "$repo" "$mirror_dir" 2>"$WORKDIR/reports/$name.mirror.err"; then
    echo "  FAILED to mirror-clone $repo (see $WORKDIR/reports/$name.mirror.err)"
    log_audit "$repo" "mirror_clone" "failed" "\"see $name.mirror.err\""
    failed=$((failed + 1))
    continue
  fi

  echo "  running surgical clean (--apply)..."
  if python "$SCRIPT_DIR/surgical_clean.py" "$mirror_dir" --apply "${IOC_ARGS[@]}" > "$WORKDIR/reports/$name.clean.log" 2>&1; then
    echo "  cleaned OK -> $WORKDIR/reports/$name.clean.log"
    log_audit "$repo" "surgical_clean" "cleaned" "\"see $name.clean.log\""
    cleaned=$((cleaned + 1))

    if [[ "$DO_PUSH" -eq 1 ]]; then
      echo "  pushing rewritten history back to $repo ..."
      (
        cd "$mirror_dir"
        git remote add origin "$repo" 2>/dev/null || git remote set-url origin "$repo"
        git push --force origin --all
        git push --force origin --tags
      )
      log_audit "$repo" "push" "done" "\"force-pushed --all and --tags\""
    else
      echo "  (not pushed -- pass --push --i-know-what-im-doing to push $mirror_dir back to $repo)"
    fi
  else
    echo "  surgical clean reported no changes or failed -- see $WORKDIR/reports/$name.clean.log"
    log_audit "$repo" "surgical_clean" "no_changes_or_failed" "\"see $name.clean.log\""
  fi

  echo
done < "$REPO_LIST"

echo "=== batch-clean summary ==="
echo "Repositories processed: $total"
echo "Cleaned:                $cleaned"
echo "Failed:                 $failed"
echo "Audit log:              $AUDIT_LOG"
