#!/usr/bin/env bash
#
# Privileged ufw helper, invoked by rproxy-ufw-helper.service when the UI drops
# /var/lib/rproxy/.ufw-action. ufw needs root for every operation (even reading
# status), and the UI runs unprivileged as rproxy — so, exactly like the Caddy
# helper, the UI asks for work by writing a JSON action file and reads the
# result back from files this script owns to rproxy:rproxy.
#
# Action file JSON (one operation per request):
#   {"action":"status"}                         -> just refresh the status file
#   {"action":"enable"} / {"action":"disable"}  -> toggle the firewall
#   {"action":"delete","num":5}                 -> delete numbered rule 5
#   {"action":"allow"|"deny", ...}              -> add a rule, fields:
#        "port":  "1".."65535"   (optional)
#        "proto": "tcp"|"udp"     (optional)
#        "from":  IP / CIDR / "any" (optional)
#        "comment": short label   (optional)
#
# EVERY value pulled from the action file is re-validated here against a strict
# regex before it is placed — as a single, quoted array element — into the ufw
# argument vector. Nothing from the file is ever evaluated by the shell, so a
# malformed or hostile action file can only be rejected, never executed. This
# is defence-in-depth: the Node route validates the same fields first.
#
# Outputs:
#   /var/lib/rproxy/.ufw-status         raw `ufw status numbered` (rproxy:rproxy 0640)
#   /var/lib/rproxy/.ufw-action-result  JSON {status,message,ts} (rproxy:rproxy 0640)
# The action file is removed on exit so the .path unit can re-trigger.
#
set -euo pipefail

ACTION_FILE=/var/lib/rproxy/.ufw-action
RESULT_FILE=/var/lib/rproxy/.ufw-action-result
STATUS_FILE=/var/lib/rproxy/.ufw-status

UI_USER=rproxy
UI_GROUP=rproxy

UFW=/usr/sbin/ufw

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '
}

write_result() {
  # $1 = ok|error, $2 = message
  printf '{"status":"%s","message":"%s","ts":%s}\n' \
    "$1" "$(json_escape "$2")" "$(date +%s)" > "$RESULT_FILE"
  chown "$UI_USER:$UI_GROUP" "$RESULT_FILE" 2>/dev/null || true
  chmod 0640 "$RESULT_FILE" 2>/dev/null || true
}

# Always publish the current numbered status for the UI to parse. ufw exits
# non-zero when inactive, so don't let set -e abort here.
refresh_status() {
  "$UFW" status numbered > "$STATUS_FILE" 2>/dev/null || \
    printf 'Status: unknown\n' > "$STATUS_FILE"
  chown "$UI_USER:$UI_GROUP" "$STATUS_FILE" 2>/dev/null || true
  chmod 0640 "$STATUS_FILE" 2>/dev/null || true
}

fail() { refresh_status; write_result error "$1"; exit 1; }

cleanup() { rm -f "$ACTION_FILE"; }
trap cleanup EXIT

[[ -f "$ACTION_FILE" ]] || { echo "[ufw-helper] no action file"; exit 0; }
command -v jq >/dev/null 2>&1 || fail "jq not installed on host"

ACTION="$(jq -r '.action // ""' "$ACTION_FILE" 2>/dev/null || echo "")"
echo "[ufw-helper] action=$ACTION"

case "$ACTION" in
  status)
    refresh_status
    write_result ok "status refreshed"
    ;;

  enable)
    "$UFW" --force enable >/dev/null 2>&1 || fail "ufw enable failed"
    refresh_status
    write_result ok "firewall enabled"
    ;;

  disable)
    "$UFW" --force disable >/dev/null 2>&1 || fail "ufw disable failed"
    refresh_status
    write_result ok "firewall disabled"
    ;;

  delete)
    NUM="$(jq -r '.num // ""' "$ACTION_FILE")"
    [[ "$NUM" =~ ^[0-9]{1,4}$ ]] || fail "invalid rule number"
    # `ufw --force delete N` skips the y/n prompt. Deleting renumbers the
    # remaining rules, which is why the UI always re-reads status after.
    OUT="$("$UFW" --force delete "$NUM" 2>&1)" || fail "delete failed: $(json_escape "$OUT")"
    refresh_status
    write_result ok "deleted rule $NUM"
    ;;

  allow|deny)
    PORT="$(jq -r '.port    // ""' "$ACTION_FILE")"
    PROTO="$(jq -r '.proto  // ""' "$ACTION_FILE")"
    FROM="$(jq -r '.from    // ""' "$ACTION_FILE")"
    COMMENT="$(jq -r '.comment // ""' "$ACTION_FILE")"

    # Validate every field; reject anything that isn't exactly what we expect.
    if [[ -n "$PORT"  ]]; then
      [[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || fail "invalid port"
    fi
    if [[ -n "$PROTO" ]]; then
      [[ "$PROTO" =~ ^(tcp|udp)$ ]] || fail "invalid proto"
    fi
    if [[ -n "$FROM"  ]]; then
      [[ "$FROM" == "any" || "$FROM" =~ ^[0-9a-fA-F:.]+(/[0-9]{1,3})?$ ]] || fail "invalid source address"
    fi
    if [[ -n "$COMMENT" ]]; then
      [[ "$COMMENT" =~ ^[A-Za-z0-9\ _.:/+-]{1,64}$ ]] || fail "invalid comment"
    fi
    [[ -n "$PORT" || -n "$FROM" ]] || fail "a rule needs at least a port or a source address"

    # Assemble the argument vector from validated tokens only. Each value is a
    # single array element, so the shell never word-splits or expands it.
    ARGV=("$ACTION")
    if [[ -n "$FROM" && -n "$PORT" ]]; then
      ARGV+=(from "$FROM" to any port "$PORT")
      [[ -n "$PROTO" ]] && ARGV+=(proto "$PROTO")
    elif [[ -n "$FROM" ]]; then
      ARGV+=(from "$FROM")
    else
      if [[ -n "$PROTO" ]]; then ARGV+=("$PORT/$PROTO"); else ARGV+=("$PORT"); fi
    fi
    [[ -n "$COMMENT" ]] && ARGV+=(comment "$COMMENT")

    OUT="$("$UFW" "${ARGV[@]}" 2>&1)" || fail "ufw rejected rule: $(json_escape "$OUT")"
    refresh_status
    write_result ok "rule added"
    ;;

  *)
    fail "unknown or missing action"
    ;;
esac
