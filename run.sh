#!/usr/bin/env bash
#
# run.sh -- one-command runner for gil-polinrider-guard.
#
# Creates a local virtualenv (./.venv), installs the project into it, and
# runs whatever you asked for. Re-running is cheap: the install is skipped
# unless pyproject.toml changed or you pass --reinstall.
#
# Usage:
#   ./run.sh                          # web UI on http://127.0.0.1:8765
#   ./run.sh web --port 9000          # web UI, extra flags passed through
#   ./run.sh scan /path/to/repo       # CLI scan (flags passed through)
#   ./run.sh scan /path/to/repo --json
#   ./run.sh demo                     # scan the bundled example fixtures
#   ./run.sh test                     # run the test suite
#   ./run.sh docker                   # docker compose up web (no local Python)
#   ./run.sh help
#
# Options (before the command):
#   --no-venv      use the active/system Python instead of ./.venv
#   --reinstall    force a dependency reinstall
#   --open         open the web UI in your browser once it is up
#
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

VENV_DIR="$PROJECT_ROOT/.venv"
USE_VENV=1
FORCE_INSTALL=0
OPEN_BROWSER=0

say()  { printf 'run.sh: %s\n' "$*"; }
die()  { printf 'run.sh: error: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'USAGE'
run.sh -- one-command runner for gil-polinrider-guard.

Creates a local virtualenv (./.venv), installs the project into it, and runs
whatever you asked for. Re-running is cheap: the install is skipped unless
pyproject.toml changed or you pass --reinstall.

Usage:
  ./run.sh                          # web UI on http://127.0.0.1:8765
  ./run.sh web --port 9000          # web UI, extra flags passed through
  ./run.sh scan /path/to/repo       # CLI scan (flags passed through)
  ./run.sh scan /path/to/repo --json
  ./run.sh demo                     # scan the bundled example fixtures
  ./run.sh test                     # run the test suite
  ./run.sh docker                   # docker compose up web (no local Python)
  ./run.sh help

Options (before the command):
  --no-venv      use the active/system Python instead of ./.venv
  --reinstall    force a dependency reinstall
  --open         open the web UI in your browser once it is up

Exit codes for 'scan' are the guard's own: 0 = no findings, 1 = findings.
USAGE
}

# ---------------------------------------------------------------- options --
while [ $# -gt 0 ]; do
    case "$1" in
        --no-venv)   USE_VENV=0; shift ;;
        --reinstall) FORCE_INSTALL=1; shift ;;
        --open)      OPEN_BROWSER=1; shift ;;
        -h|--help|help) usage; exit 0 ;;
        *) break ;;
    esac
done

COMMAND="${1:-web}"
[ $# -gt 0 ] && shift || true

# ------------------------------------------------------------------ setup --
# Newest first: the web UI's pydantic models use `str | None`, which only
# evaluates natively on 3.10+ (on 3.9 we add eval_type_backport below).
find_python() {
    local candidate
    for candidate in python3.13 python3.12 python3.11 python3.10 python3 python python3.9; do
        if command -v "$candidate" >/dev/null 2>&1; then
            if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 9) else 1)' 2>/dev/null; then
                printf '%s\n' "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

# 0 if the interpreter is 3.10 or newer.
py_is_310_plus() {
    "$PY" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 10) else 1)' 2>/dev/null
}

# Everything after setup runs through "$PY" / the venv's console scripts.
PY=""
BIN_DIR=""

setup_python() {
    local base_python
    base_python="$(find_python)" \
        || die "no Python 3.9+ found on PATH. Install Python 3.9 or newer, or use './run.sh docker'."

    if [ "$USE_VENV" -eq 0 ]; then
        PY="$base_python"
        BIN_DIR="$(dirname "$("$base_python" -c 'import sys; print(sys.executable)')")"
        say "using $("$PY" -V 2>&1) at $("$PY" -c 'import sys; print(sys.executable)') (--no-venv)"
        return
    fi

    if [ ! -x "$VENV_DIR/bin/python" ]; then
        say "creating virtualenv at .venv"
        "$base_python" -m venv "$VENV_DIR" \
            || die "could not create a virtualenv. On Debian/Ubuntu: apt install python3-venv"
    fi
    PY="$VENV_DIR/bin/python"
    BIN_DIR="$VENV_DIR/bin"
}

# Extras needed per command: the web UI needs fastapi/uvicorn, tests need
# pytest, a plain CLI scan needs nothing but the package itself.
extras_for() {
    case "$1" in
        web)        printf '[web]\n' ;;
        test)       printf '[dev,web]\n' ;;
        scan|demo)  printf '\n' ;;
        *)          printf '\n' ;;
    esac
}

install_if_needed() {
    local extras="$1"
    local stamp
    local want pyver tag
    pyver="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
    want="$(cksum pyproject.toml | awk '{print $1 "-" $2}')${extras}-py${pyver}"

    # One stamp per extras set, so alternating `web` and `test` doesn't
    # reinstall on every switch.
    tag="$(printf '%s' "${extras:-base}" | tr -cd 'a-z')"
    stamp="$VENV_DIR/.polinrider-run-stamp-${tag:-base}"
    if [ "$USE_VENV" -eq 0 ]; then
        stamp="$PROJECT_ROOT/.polinrider-run-stamp-system-${tag:-base}"
    fi

    if [ "$FORCE_INSTALL" -eq 0 ] && [ -f "$stamp" ] && [ "$(cat "$stamp")" = "$want" ]; then
        return 0
    fi

    say "installing gil-polinrider-guard${extras} (editable, Python $pyver)"
    "$PY" -m pip install --quiet --upgrade pip >/dev/null 2>&1 || true
    "$PY" -m pip install --quiet -e ".${extras}" \
        || die "pip install failed. Try './run.sh --reinstall' or see the output above."

    # pyproject allows Python 3.9, but webapp.py annotates its pydantic
    # models with PEP 604 unions (`str | None`). Pydantic evaluates those at
    # import time, so on 3.9 the web UI dies on startup unless this shim is
    # installed -- it is what pydantic's own error message asks for.
    # The suite's webapp tests drive the app through Starlette's TestClient
    # (needs httpx) and the recovery tests need git-filter-repo. Without
    # these they silently skip, or -- once fastapi is installed -- error out
    # at collection. Install them so `./run.sh test` really runs the suite.
    if [ "$extras" = "[dev,web]" ]; then
        say "adding test-only deps (httpx, git-filter-repo)"
        "$PY" -m pip install --quiet httpx git-filter-repo \
            || say "WARNING -- could not install httpx/git-filter-repo; some tests will skip"
    fi

    if [ "${extras#*web}" != "$extras" ] && ! py_is_310_plus; then
        say "Python $pyver: adding eval_type_backport (needed for fastapi models below 3.10)"
        "$PY" -m pip install --quiet eval_type_backport \
            || die "could not install eval_type_backport, which the web UI needs on Python $pyver. Install Python 3.10+ or use './run.sh docker'."
    fi

    printf '%s' "$want" > "$stamp"
}

# Resolve a console script, falling back to "python -m" so this works even
# if the venv's bin dir isn't on PATH.
run_entry() {
    local script="$1" module="$2"
    shift 2
    if [ -x "$BIN_DIR/$script" ]; then
        exec "$BIN_DIR/$script" "$@"
    fi
    exec "$PY" -m "$module" "$@"
}

open_url() {
    local url="$1"
    if command -v open >/dev/null 2>&1; then
        open "$url" >/dev/null 2>&1 || true
    elif command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$url" >/dev/null 2>&1 || true
    fi
}

# --------------------------------------------------------------- commands --
case "$COMMAND" in
    web)
        setup_python
        install_if_needed "$(extras_for web)"

        # Mirror webapp.py's own defaults so --open points at the right place.
        host="127.0.0.1"; port="8765"
        prev=""
        for arg in "$@"; do
            case "$prev" in
                --host) host="$arg" ;;
                --port) port="$arg" ;;
            esac
            case "$arg" in
                --host=*) host="${arg#--host=}" ;;
                --port=*) port="${arg#--port=}" ;;
            esac
            prev="$arg"
        done
        case "$host" in
            0.0.0.0|::) browse_host="localhost" ;;
            *) browse_host="$host" ;;
        esac

        if [ "$OPEN_BROWSER" -eq 1 ]; then
            ( sleep 2; open_url "http://$browse_host:$port" ) &
        fi
        say "starting web UI -- http://$browse_host:$port (Ctrl-C to stop)"
        run_entry polinrider-guard-web polinrider_guard.webapp "$@"
        ;;

    scan)
        [ $# -gt 0 ] || die "scan needs a path: ./run.sh scan /path/to/repo"
        setup_python
        install_if_needed "$(extras_for scan)"
        # guard exits 1 when it finds something -- that's a result, not a
        # failure, so hand the exit code straight back to the caller.
        run_entry polinrider-guard polinrider_guard.guard "$@"
        ;;

    demo)
        setup_python
        install_if_needed "$(extras_for demo)"
        guard() {
            if [ -x "$BIN_DIR/polinrider-guard" ]; then
                "$BIN_DIR/polinrider-guard" "$@"
            else
                "$PY" -m polinrider_guard.guard "$@"
            fi
        }
        say "scanning examples/clean-project (expect: no findings, exit 0)"
        guard examples/clean-project --no-git "$@" && clean_rc=0 || clean_rc=$?
        printf '\n'
        say "scanning examples/vulnerable-samples (expect: findings, exit 1)"
        guard examples/vulnerable-samples --no-git "$@" && dirty_rc=0 || dirty_rc=$?
        printf '\n'
        say "clean-project exit=$clean_rc  vulnerable-samples exit=$dirty_rc"
        if [ "$clean_rc" -eq 0 ] && [ "$dirty_rc" -eq 1 ]; then
            say "demo OK"
            exit 0
        fi
        die "unexpected exit codes (wanted 0 and 1)"
        ;;

    test)
        setup_python
        install_if_needed "$(extras_for test)"
        say "running test suite"
        exec "$PY" -m pytest "$@"
        ;;

    docker)
        command -v docker >/dev/null 2>&1 || die "docker is not installed or not on PATH."
        say "docker compose up web -- http://localhost:8765 (Ctrl-C to stop)"
        if docker compose version >/dev/null 2>&1; then
            exec docker compose up "${@:-web}"
        elif command -v docker-compose >/dev/null 2>&1; then
            exec docker-compose up "${@:-web}"
        else
            die "neither 'docker compose' nor 'docker-compose' is available."
        fi
        ;;

    *)
        printf 'run.sh: unknown command: %s\n\n' "$COMMAND" >&2
        usage >&2
        exit 2
        ;;
esac
