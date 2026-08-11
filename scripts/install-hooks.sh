#!/usr/bin/env bash
#
# Installs polinrider-guard's pre-commit/post-merge hooks as GLOBAL git
# hooks (via core.hooksPath), so they run for every commit and merge across
# every repository on this machine -- not just this one.
#
# This changes your global git config (core.hooksPath). If you already use
# core.hooksPath for something else, pass that directory as an argument
# instead of accepting the default, and this script will add these hooks
# alongside whatever's already there (it will not overwrite a differently
# named hook, only pre-commit/post-merge).
#
# Usage:
#   scripts/install-hooks.sh                  # installs to ~/.config/git/hooks
#   scripts/install-hooks.sh /custom/hooks/dir

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOKS_SRC="$SCRIPT_DIR/../hooks"
HOOKS_DEST="${1:-$HOME/.config/git/hooks}"

mkdir -p "$HOOKS_DEST"

for hook in pre-commit post-merge; do
  if [ -f "$HOOKS_DEST/$hook" ] && ! grep -q "polinrider-guard" "$HOOKS_DEST/$hook" 2>/dev/null; then
    echo "Warning: $HOOKS_DEST/$hook already exists and isn't a polinrider-guard hook." >&2
    echo "  Not overwriting it. Merge it manually with $HOOKS_SRC/$hook." >&2
    continue
  fi
  cp "$HOOKS_SRC/$hook" "$HOOKS_DEST/$hook"
  chmod +x "$HOOKS_DEST/$hook"
  echo "Installed $hook -> $HOOKS_DEST/$hook"
done

CURRENT_HOOKS_PATH="$(git config --global core.hooksPath || true)"
if [ -n "$CURRENT_HOOKS_PATH" ] && [ "$CURRENT_HOOKS_PATH" != "$HOOKS_DEST" ]; then
  echo "Note: core.hooksPath is currently set to '$CURRENT_HOOKS_PATH'." >&2
  echo "  Not changing it automatically since it differs from '$HOOKS_DEST'." >&2
  echo "  Run 'git config --global core.hooksPath \"$HOOKS_DEST\"' yourself if you want these hooks active." >&2
else
  git config --global core.hooksPath "$HOOKS_DEST"
  echo "Set git config --global core.hooksPath to $HOOKS_DEST"
fi

echo "Done. These hooks now run for every 'git commit' and 'git merge'/'git pull' on this machine."
echo "Bypass per-command with POLINRIDER_GUARD_SKIP=1, or per-commit with 'git commit --no-verify'."
