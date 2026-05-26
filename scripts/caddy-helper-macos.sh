#!/usr/bin/env bash
#
# macOS counterpart of caddy-helper.sh. Invoked by launchd's
# com.rproxy.caddy-helper plist when the UI drops $CADDY_ACTION_FILE. Two
# actions:
#
#   {"action":"snapshot"}  -> tar $CADDY_STORE into
#                             $CADDY_STAGING_DIR/caddy-snapshot.tar.gz,
#                             rewriting paths so the archive looks just like
#                             the Linux snapshot (.local/share/caddy/...).
#
#   {"action":"restore"}   -> unpack $CADDY_STAGING_DIR/caddy-restore.tar.gz
#                             into $CADDY_STORE, then bounce caddy.
#
# Linux-archive compatibility: the Linux helper stores its tree at
# /var/lib/caddy/.local/share/caddy and archives it with a `.local/share/caddy`
# top-level prefix. We restore both shapes (with or without the prefix) so a
# tarball produced on Linux can be restored on a Mac and vice versa.
#
set -euo pipefail

# Defaults are overridden by EnvironmentVariables in the plist.
CADDY_STORE="${CADDY_STORE:-/opt/homebrew/var/rproxy/caddy}"
STAGING_DIR="${CADDY_STAGING_DIR:-/opt/homebrew/var/rproxy/staging}"
ACTION_FILE="${CADDY_ACTION_FILE:-/opt/homebrew/var/rproxy/.caddy-action}"
RESULT_FILE="${CADDY_RESULT_FILE:-/opt/homebrew/var/rproxy/.caddy-action-result}"
UI_USER="${UI_USER:-$(stat -f %Su "$STAGING_DIR" 2>/dev/null || echo root)}"
UI_GROUP="${UI_GROUP:-$(stat -f %Sg "$STAGING_DIR" 2>/dev/null || echo wheel)}"
CADDY_LABEL="${CADDY_LABEL:-com.rproxy.caddy}"

SNAPSHOT_TGZ="$STAGING_DIR/caddy-snapshot.tar.gz"
RESTORE_TGZ="$STAGING_DIR/caddy-restore.tar.gz"
# Linux-shaped prefix inside snapshot tarballs (kept for cross-host parity).
ARCHIVE_PREFIX=".local/share/caddy"

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
}

write_result() {
  # $1 = ok|error, $2 = message, $3 (optional) = path
  local status="$1" message="$2" path="${3:-}"
  printf '{"status":"%s","message":"%s","path":"%s","ts":%s}\n' \
    "$status" \
    "$(json_escape "$message")" \
    "$(json_escape "$path")" \
    "$(date +%s)" \
    > "$RESULT_FILE"
  chown "$UI_USER:$UI_GROUP" "$RESULT_FILE" 2>/dev/null || true
  chmod 0640 "$RESULT_FILE" 2>/dev/null || true
}

cleanup_action_file() {
  rm -f "$ACTION_FILE"
}

trap cleanup_action_file EXIT

if [[ ! -f "$ACTION_FILE" ]]; then
  echo "[caddy-helper] no action file; nothing to do"
  exit 0
fi

ACTION="$(grep -o '"action"[[:space:]]*:[[:space:]]*"[a-z]*"' "$ACTION_FILE" | head -1 | sed 's/.*"\([a-z]*\)"$/\1/')"
echo "[caddy-helper] action=$ACTION"

install -d -m 0750 -o "$UI_USER" -g "$UI_GROUP" "$STAGING_DIR"

case "$ACTION" in
  snapshot)
    if [[ ! -d "$CADDY_STORE" ]]; then
      write_result error "Caddy storage not found at $CADDY_STORE"
      exit 1
    fi
    rm -f "$SNAPSHOT_TGZ"
    # Re-shape the archive to look like the Linux snapshot: top-level
    # directory is .local/share/caddy/, with all of $CADDY_STORE's contents
    # underneath. BSD tar supports -s '/old/new/' substitutions.
    PARENT="$(dirname "$CADDY_STORE")"
    BASE="$(basename "$CADDY_STORE")"
    tar -czf "$SNAPSHOT_TGZ" \
      -C "$PARENT" \
      -s "|^$BASE|$ARCHIVE_PREFIX|" \
      "$BASE"
    chown "$UI_USER:$UI_GROUP" "$SNAPSHOT_TGZ"
    chmod 0640 "$SNAPSHOT_TGZ"
    SIZE="$(stat -f %z "$SNAPSHOT_TGZ")"
    echo "[caddy-helper] snapshot ok ($SIZE bytes)"
    write_result ok "snapshot ready ($SIZE bytes)" "$SNAPSHOT_TGZ"
    ;;

  restore)
    if [[ ! -f "$RESTORE_TGZ" ]]; then
      write_result error "no upload at $RESTORE_TGZ"
      exit 1
    fi
    # Sanity-check the tarball. Accept either Linux-shape entries (rooted at
    # .local/share/caddy/) or Mac-shape entries (rooted at the storage dir's
    # basename). Reject absolute paths and parent traversal in either case.
    BASE="$(basename "$CADDY_STORE")"
    BAD="$(tar -tzf "$RESTORE_TGZ" | awk -v base="$BASE" -v prefix="$ARCHIVE_PREFIX" '
      /^\// { print "absolute path: " $0; exit }
      /(^|\/)\.\.(\/|$)/ { print "parent traversal: " $0; exit }
      {
        ok = 0
        if (index($0, prefix) == 1) ok = 1
        if (index($0, "./" prefix) == 1) ok = 1
        if (index($0, base "/") == 1) ok = 1
        if ($0 == base) ok = 1
        if (!ok) { print "outside store: " $0; exit }
      }
    ')"
    if [[ -n "$BAD" ]]; then
      write_result error "rejecting tarball entry — $BAD"
      rm -f "$RESTORE_TGZ"
      exit 1
    fi
    # Stop caddy while we swap the storage to avoid races with renewals.
    launchctl bootout "system/$CADDY_LABEL" >/dev/null 2>&1 || true
    install -d -m 0700 -o root -g wheel "$CADDY_STORE"
    # Detect archive shape by the first entry, then unpack accordingly so
    # the result lands directly inside $CADDY_STORE.
    FIRST="$(tar -tzf "$RESTORE_TGZ" | head -1)"
    if [[ "$FIRST" == "./$ARCHIVE_PREFIX"* || "$FIRST" == "$ARCHIVE_PREFIX"* ]]; then
      # Linux shape — strip ".local/share/caddy/" (3 components, optional ./)
      STRIP=3
      [[ "$FIRST" == "./"* ]] && STRIP=4
      tar -xzf "$RESTORE_TGZ" -C "$CADDY_STORE" --strip-components=$STRIP
    else
      # Mac shape — strip the leading "<basename>/" (1 component)
      tar -xzf "$RESTORE_TGZ" -C "$CADDY_STORE" --strip-components=1
    fi
    chown -R root:wheel "$CADDY_STORE"
    chmod -R go-rwx "$CADDY_STORE"
    launchctl bootstrap system "/Library/LaunchDaemons/$CADDY_LABEL.plist"
    rm -f "$RESTORE_TGZ"
    echo "[caddy-helper] restore ok"
    write_result ok "Caddy storage restored, caddy restarted" ""
    ;;

  *)
    write_result error "unknown or missing action in $ACTION_FILE"
    exit 1
    ;;
esac
