#!/usr/bin/env bash
#
# Privileged tailnet-DNS helper, invoked by rproxy-tsdns-helper.service when the
# UI drops /var/lib/rproxy/.tsdns-action. Writing under /etc/dnsmasq.d and
# restarting dnsmasq both need root; the UI runs unprivileged as rproxy. Same
# arrangement as the ufw and Caddy helpers: the UI asks by writing a file, and
# reads the outcome from a result file this script owns back to rproxy:rproxy.
#
# The action file holds the COMPLETE desired dnsmasq config, already rendered by
# src/tailnetDns.js. This script does not build config from parts — it validates
# what it was handed and installs it whole, so there is exactly one place where
# the file's content is decided.
#
# Validation is deliberately strict and defence-in-depth: the Node side already
# rejects malformed hostnames, and every line is checked again here. Only
# comments, blank lines, and `address=/<hostname>/<ipv4>` are permitted. A file
# containing anything else is refused outright rather than partially applied —
# a dnsmasq config accepts directives like `server=` that could redirect every
# lookup this machine makes.
#
# Outputs:
#   /etc/dnsmasq.d/rproxy-tailnet.conf     the installed config (root, 0644)
#   /var/lib/rproxy/.tsdns-action-result   JSON {status,message,ts} (rproxy:rproxy 0640)
# The action file is removed on exit so the .path unit can re-trigger.
#
set -euo pipefail

ACTION_FILE=/var/lib/rproxy/.tsdns-action
RESULT_FILE=/var/lib/rproxy/.tsdns-action-result
CONF_FILE=/etc/dnsmasq.d/rproxy-tailnet.conf

UI_USER=rproxy
UI_GROUP=rproxy

finish() {
  local status="$1" message="$2"
  printf '{"status":"%s","message":%s,"ts":%s}\n' \
    "$status" "$(printf '%s' "$message" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')" \
    "$(date +%s000)" > "$RESULT_FILE"
  chown "$UI_USER:$UI_GROUP" "$RESULT_FILE" 2>/dev/null || true
  chmod 0640 "$RESULT_FILE" 2>/dev/null || true
  rm -f "$ACTION_FILE"
  [ "$status" = ok ] || exit 1
  exit 0
}

[ -r "$ACTION_FILE" ] || finish error "no action file"

# Only comments, blanks and address= lines. Anything else and the whole file is
# rejected: a stray `server=` would silently repoint every DNS lookup.
BAD=$(grep -vE '^\s*(#.*)?$|^address=/[A-Za-z0-9.-]+/[0-9]{1,3}(\.[0-9]{1,3}){3}$' "$ACTION_FILE" || true)
if [ -n "$BAD" ]; then
  finish error "refused: config contains a line that is not a comment or an address= directive"
fi

# Every override must point at THIS machine's tailnet address. A rendered file
# aiming elsewhere would mean the UI and the host disagree about where traffic
# should go, and silently installing it would send tailnet clients to a stranger.
TS_IP=$(tailscale ip -4 2>/dev/null | head -1 || true)
if [ -n "$TS_IP" ]; then
  WRONG=$(grep -oE '^address=/[^/]+/[0-9.]+$' "$ACTION_FILE" | grep -v "/${TS_IP}\$" || true)
  [ -z "$WRONG" ] || finish error "refused: an address= line points somewhere other than ${TS_IP}"
fi

install -m 0644 -o root -g root "$ACTION_FILE" "$CONF_FILE"

if ! dnsmasq --test >/dev/null 2>&1; then
  rm -f "$CONF_FILE"
  systemctl reload-or-restart dnsmasq >/dev/null 2>&1 || true
  finish error "dnsmasq rejected the config; the previous state was restored"
fi

# restart, not reload: dnsmasq re-reads /etc/dnsmasq.d only on restart
if systemctl restart dnsmasq >/dev/null 2>&1; then
  finish ok "applied $(grep -c '^address=' "$CONF_FILE" || echo 0) hostname override(s)"
else
  finish error "config installed but dnsmasq failed to restart"
fi
