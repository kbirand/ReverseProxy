#!/usr/bin/env bash
#
# rproxy self-update — pulls the latest published code and restarts the UI.
# Runs as root, invoked by rproxy-update.service (its own systemd cgroup, so
# it survives the rproxy-ui restart it triggers).
#
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$(realpath "$0")")/.." && pwd)"
BRANCH="${UPDATE_BRANCH:-main}"
OWNER="$(stat -c %U "$REPO_DIR")"
GROUP="$(id -gn "$OWNER" 2>/dev/null || echo "$OWNER")"

echo "[update] repo=$REPO_DIR branch=$BRANCH owner=$OWNER"

cd "$REPO_DIR"

# git may refuse a root operation on a dir owned by someone else.
git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true

# Safety: never blow away uncommitted local edits to tracked files.
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "[update] ABORT — the checkout has uncommitted local changes."
  echo "[update] Commit or discard them before updating (git status)."
  exit 1
fi

echo "[update] fetching origin/$BRANCH ..."
git fetch --quiet origin "$BRANCH"
BEFORE="$(git rev-parse HEAD)"
git reset --hard "origin/$BRANCH"
AFTER="$(git rev-parse HEAD)"
echo "[update] $BEFORE -> $AFTER"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "[update] already up to date — nothing to restart."
  exit 0
fi

echo "[update] installing dependencies ..."
sudo -u "$OWNER" npm install --omit=dev --no-audit --no-fund --prefix "$REPO_DIR" \
  || npm install --omit=dev --no-audit --no-fund --prefix "$REPO_DIR"

# Pulled/installed files may now be root-owned — hand the tree back.
chown -R "$OWNER:$GROUP" "$REPO_DIR" 2>/dev/null || true
chmod -R o+rX "$REPO_DIR/src" "$REPO_DIR/node_modules" 2>/dev/null || true

echo "[update] restarting rproxy-ui ..."
systemctl restart rproxy-ui

echo "[update] done."
