#!/usr/bin/env bash
#
# rproxy installer — sets up Caddy + the Node.js admin UI on a fresh Ubuntu/
# Debian box. Idempotent: safe to re-run to apply config changes or upgrade.
#
#   sudo ./install.sh
#
# Reads ./install.conf (copy it from install.conf.example first).
#
set -euo pipefail

# ---- preflight -------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "This installer must run as root:  sudo ./install.sh" >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"
cd "$REPO_DIR"

CONF="$REPO_DIR/install.conf"
if [[ ! -f "$CONF" ]]; then
  echo "No install.conf found — copying defaults from install.conf.example."
  echo "Review it, then re-run:  sudo ./install.sh"
  cp "$REPO_DIR/install.conf.example" "$CONF"
  exit 1
fi

# ---- config ----------------------------------------------------------------
UI_PORT=8080
UI_BIND=0.0.0.0
FALLBACK_UPSTREAM=""
ACME_DNS_PROVIDER=""
ACME_EMAIL=""
AUTH_ENABLED=true
# shellcheck disable=SC1090
source "$CONF"

RUN_USER=rproxy
DB_PATH=/var/lib/rproxy/rules.db
CERT_DIR=/etc/rproxy/certs
CF_ENV=/etc/rproxy/cloudflare.env

# Detect this machine's primary LAN IP so bare-IP requests can hit the
# optional fallback upstream.
PRIMARY_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
FALLBACK_HOSTS="127.0.0.1,localhost,::1${PRIMARY_IP:+,$PRIMARY_IP}"

echo "=== rproxy installer ==="
echo "  repo dir:          $REPO_DIR"
echo "  UI:                ${UI_BIND}:${UI_PORT}"
echo "  fallback upstream: ${FALLBACK_UPSTREAM:-<none, unmatched hosts -> 404>}"
echo "  fallback hosts:    $FALLBACK_HOSTS"
echo "  ACME challenge:    ${ACME_DNS_PROVIDER:-http-01 (default)}"
echo

# ---- 1. install Caddy (official repo) + Node.js ----------------------------
echo "[1/9] Installing Caddy + Node.js ..."
if ! command -v caddy >/dev/null 2>&1 || ! caddy version 2>/dev/null | grep -qE 'v2\.(1[0-9]|[89])'; then
  apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
    | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
  curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
    > /etc/apt/sources.list.d/caddy-stable.list
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq caddy
fi
if ! command -v node >/dev/null 2>&1; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs npm
fi
echo "       caddy $(caddy version | head -1) · node $(node --version)"

# ---- 2. Cloudflare DNS plugin (only if requested) --------------------------
if [[ "$ACME_DNS_PROVIDER" == "cloudflare" ]]; then
  echo "[2/9] Ensuring caddy-dns/cloudflare plugin ..."
  if ! caddy list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
    caddy add-package github.com/caddy-dns/cloudflare
  fi
  echo "       plugin present"
else
  echo "[2/9] Skipping Cloudflare plugin (ACME_DNS_PROVIDER not 'cloudflare')."
fi

# ---- 3. system user + directories ------------------------------------------
echo "[3/9] Creating system user '$RUN_USER' + directories ..."
id "$RUN_USER" >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin "$RUN_USER"
install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" /var/lib/rproxy
install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" "$CERT_DIR"
# Caddy (running as user 'caddy') must read manual certs under $CERT_DIR.
usermod -a -G "$RUN_USER" caddy
# Caddy writes the JSON access log here; the UI reads it for the activity
# view, so the run user needs to be in caddy's group.
install -d -m 0750 -o caddy -g caddy /var/log/rproxy
usermod -a -G caddy "$RUN_USER"
# Let the run user traverse + read the repo (it may live under /home).
chmod o+x "$REPO_DIR" 2>/dev/null || true
chmod -R o+rX "$REPO_DIR/src" "$REPO_DIR/package.json" "$REPO_DIR/package-lock.json" 2>/dev/null || true

# ---- 4. Node dependencies --------------------------------------------------
echo "[4/9] Installing Node dependencies ..."
( cd "$REPO_DIR" && npm install --omit=dev --no-audit --no-fund >/dev/null 2>&1 )
chmod -R o+rX "$REPO_DIR/node_modules" 2>/dev/null || true

# ---- 5. Caddy bootstrap config ---------------------------------------------
echo "[5/9] Installing Caddy bootstrap config ..."
install -m 0644 -o root -g caddy "$REPO_DIR/etc/Caddyfile.bootstrap" /etc/caddy/Caddyfile

# ---- 6. Cloudflare token env + caddy drop-in -------------------------------
if [[ "$ACME_DNS_PROVIDER" == "cloudflare" ]]; then
  echo "[6/9] Setting up Cloudflare token file + caddy drop-in ..."
  if [[ ! -f "$CF_ENV" ]]; then
    install -m 0640 -o root -g caddy "$REPO_DIR/etc/cloudflare.env.example" "$CF_ENV"
    echo "       created $CF_ENV — you must paste your CF_API_TOKEN into it."
  fi
  install -d -m 0755 /etc/systemd/system/caddy.service.d
  cat > /etc/systemd/system/caddy.service.d/cf-token.conf <<EOF
[Service]
EnvironmentFile=$CF_ENV
EOF
else
  echo "[6/9] Skipping Cloudflare token setup."
fi

# ---- 7. rproxy-ui systemd unit ---------------------------------------------
echo "[7/9] Writing rproxy-ui systemd unit ..."
cat > /etc/systemd/system/rproxy-ui.service <<EOF
[Unit]
Description=rproxy management UI (Node.js + SQLite + Caddy admin-API client)
Wants=network-online.target caddy.service
After=network-online.target caddy.service

[Service]
Type=simple
User=$RUN_USER
Group=$RUN_USER
WorkingDirectory=$REPO_DIR
Environment=NODE_ENV=production
Environment=PORT=$UI_PORT
Environment=BIND=$UI_BIND
Environment=DB_PATH=$DB_PATH
Environment=CADDY_ADMIN=http://127.0.0.1:2019
Environment=CERT_DIR=$CERT_DIR
Environment=ACCESS_LOG=/var/log/rproxy/access.log
Environment=FALLBACK_UPSTREAM=$FALLBACK_UPSTREAM
Environment=FALLBACK_HOSTS=$FALLBACK_HOSTS
Environment=ACME_DNS_PROVIDER=$ACME_DNS_PROVIDER
Environment=ACME_EMAIL=$ACME_EMAIL
Environment=AUTH_ENABLED=$AUTH_ENABLED
Environment=COOKIE_SECURE=false
ExecStart=/usr/bin/node src/server.js
Restart=always
RestartSec=2
StandardOutput=journal
StandardError=journal

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/var/lib/rproxy /etc/rproxy
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

[Install]
WantedBy=multi-user.target
EOF

# self-update units: a path unit watches for the UI's request file and starts
# the privileged updater. No sudo needed — keeps the UI sandbox intact.
chmod +x "$REPO_DIR/scripts/update.sh"
sed "s|__REPO_DIR__|$REPO_DIR|g" "$REPO_DIR/etc/rproxy-update.service" \
  > /etc/systemd/system/rproxy-update.service
install -m 0644 "$REPO_DIR/etc/rproxy-update.path" /etc/systemd/system/rproxy-update.path

# Caddy snapshot/restore helper: same pattern as self-update. Lets the UI
# tar /var/lib/caddy and unpack a saved tarball back into it without ever
# granting the UI process direct access to caddy's data dir.
chmod +x "$REPO_DIR/scripts/caddy-helper.sh"
sed "s|__REPO_DIR__|$REPO_DIR|g" "$REPO_DIR/etc/rproxy-caddy-helper.service" \
  > /etc/systemd/system/rproxy-caddy-helper.service
install -m 0644 "$REPO_DIR/etc/rproxy-caddy-helper.path" /etc/systemd/system/rproxy-caddy-helper.path
install -d -m 0750 -o "$RUN_USER" -g "$RUN_USER" /var/lib/rproxy/staging

# ---- 8. enable + (re)start services ----------------------------------------
echo "[8/9] Enabling and starting services ..."
systemctl daemon-reload
systemctl enable caddy rproxy-ui rproxy-update.path rproxy-caddy-helper.path >/dev/null 2>&1
systemctl restart caddy
sleep 2
systemctl restart rproxy-ui
systemctl restart rproxy-update.path
systemctl restart rproxy-caddy-helper.path
sleep 2

# ---- 9. health check -------------------------------------------------------
echo "[9/9] Health check ..."
CADDY_OK=$(systemctl is-active caddy || true)
UI_OK=$(systemctl is-active rproxy-ui || true)
# /api/auth/me always answers (200 authed / 401 not) — any response = UI is up.
UI_HTTP=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${UI_PORT}/api/auth/me" 2>/dev/null || echo 000)
echo "       caddy: $CADDY_OK · rproxy-ui: $UI_OK · UI responding: $([ "$UI_HTTP" != 000 ] && echo yes || echo no)"

echo
echo "=== Done ==="
echo "  Admin UI:  http://${PRIMARY_IP:-127.0.0.1}:${UI_PORT}/"
if [[ "$AUTH_ENABLED" != "false" ]]; then
  echo "  Login:     admin / admin  —  CHANGE THIS immediately in the UI."
fi
if [[ "$ACME_DNS_PROVIDER" == "cloudflare" ]] && ! grep -q '^CF_API_TOKEN=.\+' "$CF_ENV" 2>/dev/null; then
  echo
  echo "  NEXT STEP — paste your Cloudflare API token:"
  echo "    sudo nano $CF_ENV"
  echo "    sudo systemctl restart caddy"
fi
echo
echo "  Point your router / firewall so inbound :80 and :443 reach this host,"
echo "  then add rules in the UI. The rules database is created automatically"
echo "  at $DB_PATH on first run."
