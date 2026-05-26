#!/usr/bin/env bash
#
# Privileged Caddy snapshot/restore helper, invoked by
# rproxy-caddy-helper.service when the UI drops /var/lib/rproxy/.caddy-action.
# Two actions, dispatched by the JSON content of the action file:
#
#   {"action":"snapshot"}  -> tar /var/lib/caddy/.local/share/caddy into
#                             /var/lib/rproxy/staging/caddy-snapshot.tar.gz
#                             (owned by rproxy:rproxy so the UI can read it)
#
#   {"action":"restore"}   -> unpack /var/lib/rproxy/staging/caddy-restore.tar.gz
#                             into /var/lib/caddy/.local/share/caddy,
#                             then restart caddy so it picks up the new certs.
#
# The result is written to /var/lib/rproxy/.caddy-action-result (JSON), and
# the action file is removed so the .path unit can re-trigger on the next
# request.
#
set -euo pipefail

ACTION_FILE=/var/lib/rproxy/.caddy-action
RESULT_FILE=/var/lib/rproxy/.caddy-action-result
STAGING_DIR=/var/lib/rproxy/staging
SNAPSHOT_TGZ=$STAGING_DIR/caddy-snapshot.tar.gz
RESTORE_TGZ=$STAGING_DIR/caddy-restore.tar.gz

# Caddy's data root. The "caddy" home is /var/lib/caddy on this install
# (set by the distro package); the actual storage lives under
# $CADDY_HOME/.local/share/caddy.
CADDY_HOME=/var/lib/caddy
CADDY_STORE=$CADDY_HOME/.local/share/caddy

UI_USER=rproxy
UI_GROUP=rproxy

json_escape() {
  # Minimal JSON-string escaping: backslash + double-quote, plus newlines.
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
    # Tar the storage tree with relative paths so restore can unpack cleanly.
    # Includes certificates/, acme/, locks/, and the local CA root.
    tar -czf "$SNAPSHOT_TGZ" \
      --owner=caddy --group=caddy \
      -C "$CADDY_HOME" \
      .local/share/caddy
    chown "$UI_USER:$UI_GROUP" "$SNAPSHOT_TGZ"
    chmod 0640 "$SNAPSHOT_TGZ"
    SIZE="$(stat -c %s "$SNAPSHOT_TGZ")"
    echo "[caddy-helper] snapshot ok ($SIZE bytes)"
    write_result ok "snapshot ready ($SIZE bytes)" "$SNAPSHOT_TGZ"
    ;;

  restore)
    if [[ ! -f "$RESTORE_TGZ" ]]; then
      write_result error "no upload at $RESTORE_TGZ"
      exit 1
    fi
    # Sanity-check the tarball: reject absolute paths, parent traversal, or
    # any entry outside .local/share/caddy. tar -tzf lists the contents.
    BAD="$(tar -tzf "$RESTORE_TGZ" | awk '
      /^\// { print "absolute path: " $0; exit }
      /(^|\/)\.\.(\/|$)/ { print "parent traversal: " $0; exit }
      $0 !~ /^\.?\/?\.local\/share\/caddy(\/|$)/ { print "outside store: " $0; exit }
    ')"
    if [[ -n "$BAD" ]]; then
      write_result error "rejecting tarball entry — $BAD"
      rm -f "$RESTORE_TGZ"
      exit 1
    fi
    # Stop caddy while we swap the storage to avoid races with renewals.
    systemctl stop caddy || true
    install -d -m 0700 -o caddy -g caddy "$CADDY_HOME/.local" "$CADDY_HOME/.local/share"
    # Unpack on top of existing storage; tar's defaults preserve perms from
    # the archive (which the snapshot recorded as caddy:caddy 0700/0600).
    tar -xzf "$RESTORE_TGZ" -C "$CADDY_HOME" --no-absolute-names
    chown -R caddy:caddy "$CADDY_HOME/.local"
    systemctl start caddy
    rm -f "$RESTORE_TGZ"
    echo "[caddy-helper] restore ok"
    write_result ok "Caddy storage restored, caddy restarted" ""
    ;;

  *)
    write_result error "unknown or missing action in $ACTION_FILE"
    exit 1
    ;;
esac
