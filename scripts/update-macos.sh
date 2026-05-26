#!/usr/bin/env bash
#
# rproxy self-update for macOS — pulls the latest published code and restarts
# the UI. Invoked by com.rproxy.update (a launchd WatchPaths daemon) when the
# UI writes $UPDATE_TRIGGER. Runs as root, in its own launchd job, so the
# rproxy-ui restart it triggers does not kill the update itself.
#
set -euo pipefail

REPO_DIR="${REPO_DIR:-$(cd "$(dirname "$0")/.." && pwd -P)}"
RUN_USER="${RUN_USER:-$(stat -f %Su "$REPO_DIR")}"
RUN_GROUP="$(id -gn "$RUN_USER" 2>/dev/null || echo "$RUN_USER")"
BREW_PREFIX="${BREW_PREFIX:-$(brew --prefix 2>/dev/null || echo /opt/homebrew)}"
UPDATE_TRIGGER="${UPDATE_TRIGGER:-$BREW_PREFIX/var/rproxy/.update-requested}"
BRANCH="${UPDATE_BRANCH:-main}"

# Always clear the trigger so launchd doesn't immediately re-fire us.
rm -f "$UPDATE_TRIGGER"

echo "[update] repo=$REPO_DIR branch=$BRANCH owner=$RUN_USER"

cd "$REPO_DIR"
git config --global --add safe.directory "$REPO_DIR" 2>/dev/null || true

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "[update] ABORT — the checkout has uncommitted local changes."
  echo "[update] Commit or discard them before updating (git status)."
  exit 1
fi

echo "[update] fetching origin/$BRANCH ..."
sudo -u "$RUN_USER" git -C "$REPO_DIR" fetch --quiet origin "$BRANCH"
BEFORE="$(git rev-parse HEAD)"
sudo -u "$RUN_USER" git -C "$REPO_DIR" reset --hard "origin/$BRANCH"
AFTER="$(git rev-parse HEAD)"
echo "[update] $BEFORE -> $AFTER"
if [ "$BEFORE" = "$AFTER" ]; then
  echo "[update] already up to date — nothing to restart."
  exit 0
fi

echo "[update] installing dependencies ..."
sudo -u "$RUN_USER" -H "$BREW_PREFIX/bin/npm" install \
  --prefix "$REPO_DIR" --omit=dev --no-audit --no-fund

chown -R "$RUN_USER:$RUN_GROUP" "$REPO_DIR" 2>/dev/null || true

echo "[update] restarting rproxy-ui ..."
launchctl kickstart -k system/com.rproxy.ui

echo "[update] done."
