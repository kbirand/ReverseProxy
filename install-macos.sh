#!/usr/bin/env bash
#
# rproxy installer for macOS — sets up Caddy + the Node.js admin UI on a
# Mac (Apple Silicon or Intel) using Homebrew + launchd. Idempotent.
#
#   sudo ./install-macos.sh
#
# Reads ./install.conf (copy it from install.conf.example first).
#
set -euo pipefail

# ---- preflight -------------------------------------------------------------
if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer is for macOS. Use ./install.sh on Linux." >&2
  exit 1
fi
if [[ $EUID -ne 0 ]]; then
  echo "This installer must run as root:  sudo ./install-macos.sh" >&2
  exit 1
fi
if [[ -z "${SUDO_USER:-}" || "$SUDO_USER" == "root" ]]; then
  echo "Run via 'sudo' from your normal user account (not as root directly)." >&2
  exit 1
fi

REPO_DIR="$(cd "$(dirname "$0")" && pwd -P)"
cd "$REPO_DIR"

CONF="$REPO_DIR/install.conf"
if [[ ! -f "$CONF" ]]; then
  echo "No install.conf found — copying defaults from install.conf.example."
  echo "Review it, then re-run:  sudo ./install-macos.sh"
  cp "$REPO_DIR/install.conf.example" "$CONF"
  chown "$SUDO_USER" "$CONF"
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

RUN_USER="$SUDO_USER"
RUN_GROUP="$(id -gn "$RUN_USER")"

# Homebrew lives at /opt/homebrew on Apple Silicon and /usr/local on Intel.
BREW_BIN="$(sudo -u "$RUN_USER" command -v brew || true)"
if [[ -z "$BREW_BIN" ]]; then
  if [[ -x /opt/homebrew/bin/brew ]]; then BREW_BIN=/opt/homebrew/bin/brew
  elif [[ -x /usr/local/bin/brew ]];   then BREW_BIN=/usr/local/bin/brew
  else
    echo "Homebrew not found. Install it first:  https://brew.sh" >&2
    exit 1
  fi
fi
BREW_PREFIX="$("$BREW_BIN" --prefix)"

# All persistent state lives under the brew prefix so an Intel and an
# Apple Silicon Mac both get a clean, self-contained install.
STATE_DIR="$BREW_PREFIX/var/rproxy"
CONFIG_DIR="$BREW_PREFIX/etc/rproxy"
LOG_DIR="$BREW_PREFIX/var/log/rproxy"
DB_PATH="$STATE_DIR/rules.db"
CERT_DIR="$CONFIG_DIR/certs"
CF_ENV="$CONFIG_DIR/cloudflare.env"
ACCESS_LOG="$LOG_DIR/access.log"
UPDATE_TRIGGER="$STATE_DIR/.update-requested"
CADDYFILE="$CONFIG_DIR/Caddyfile"

# Custom-built caddy (with cloudflare DNS plugin) goes here; otherwise we use
# brew's stock caddy from $BREW_PREFIX/bin/caddy.
CADDY_BIN_CUSTOM="$BREW_PREFIX/bin/rproxy-caddy"

PRIMARY_IFACE="$(route -n get 1.1.1.1 2>/dev/null | awk '/interface:/ {print $2}')"
PRIMARY_IP="$(ipconfig getifaddr "${PRIMARY_IFACE:-en0}" 2>/dev/null || true)"
FALLBACK_HOSTS="127.0.0.1,localhost,::1${PRIMARY_IP:+,$PRIMARY_IP}"

echo "=== rproxy installer (macOS) ==="
echo "  repo dir:          $REPO_DIR"
echo "  brew prefix:       $BREW_PREFIX"
echo "  run as user:       $RUN_USER ($RUN_GROUP)"
echo "  UI:                ${UI_BIND}:${UI_PORT}"
echo "  fallback upstream: ${FALLBACK_UPSTREAM:-<none, unmatched hosts -> 404>}"
echo "  fallback hosts:    $FALLBACK_HOSTS"
echo "  ACME challenge:    ${ACME_DNS_PROVIDER:-http-01 (default)}"
echo

brew_install() {
  # Run brew as the unprivileged user — Homebrew refuses to run as root.
  local pkg="$1"
  if ! sudo -u "$RUN_USER" "$BREW_BIN" list --formula "$pkg" >/dev/null 2>&1; then
    echo "       installing $pkg via brew ..."
    sudo -u "$RUN_USER" "$BREW_BIN" install "$pkg" >/dev/null
  fi
}

# ---- 1. install Caddy + Node.js --------------------------------------------
echo "[1/8] Installing Caddy + Node.js ..."
brew_install caddy
brew_install node
echo "       node $(sudo -u "$RUN_USER" "$BREW_PREFIX/bin/node" --version) · caddy $(sudo -u "$RUN_USER" "$BREW_PREFIX/bin/caddy" version | head -1)"

# ---- 2. custom caddy with Cloudflare DNS plugin (only if requested) --------
# We fetch a custom-built binary from caddyserver.com's download API rather
# than rebuilding caddy locally — no Go toolchain required, ~10 MB download.
CADDY_BIN="$BREW_PREFIX/bin/caddy"
if [[ "$ACME_DNS_PROVIDER" == "cloudflare" ]]; then
  echo "[2/8] Fetching caddy with caddy-dns/cloudflare plugin ..."
  if [[ ! -x "$CADDY_BIN_CUSTOM" ]] \
     || ! "$CADDY_BIN_CUSTOM" list-modules 2>/dev/null | grep -q 'dns.providers.cloudflare'; then
    case "$(uname -m)" in
      arm64)  CADDY_ARCH=arm64 ;;
      x86_64) CADDY_ARCH=amd64 ;;
      *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
    esac
    TMP="$(mktemp)"
    curl -fsSL --retry 3 \
      "https://caddyserver.com/api/download?os=darwin&arch=${CADDY_ARCH}&p=github.com/caddy-dns/cloudflare" \
      -o "$TMP"
    chmod 0755 "$TMP"
    # Strip Gatekeeper quarantine so launchd can exec it without a prompt.
    xattr -d com.apple.quarantine "$TMP" 2>/dev/null || true
    "$TMP" version >/dev/null  # sanity check
    mv "$TMP" "$CADDY_BIN_CUSTOM"
  fi
  CADDY_BIN="$CADDY_BIN_CUSTOM"
  echo "       using $CADDY_BIN"
else
  echo "[2/8] Skipping custom caddy build (ACME_DNS_PROVIDER not 'cloudflare')."
fi

# ---- 3. directories --------------------------------------------------------
echo "[3/8] Creating directories ..."
install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" "$STATE_DIR"
install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" "$CONFIG_DIR"
install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" "$CERT_DIR"
# Both Caddy (root) and the UI ($RUN_USER) write into this dir. Owning it to
# $RUN_USER works because root can write anywhere regardless of mode.
install -d -m 0755 -o "$RUN_USER" -g "$RUN_GROUP" "$LOG_DIR"

# ---- 4. Node dependencies --------------------------------------------------
echo "[4/8] Installing Node dependencies ..."
sudo -u "$RUN_USER" -H "$BREW_PREFIX/bin/npm" install \
  --prefix "$REPO_DIR" --omit=dev --no-audit --no-fund

# ---- 5. Caddy bootstrap config ---------------------------------------------
echo "[5/8] Installing Caddy bootstrap config ..."
install -m 0644 -o "$RUN_USER" -g "$RUN_GROUP" "$REPO_DIR/etc/Caddyfile.bootstrap" "$CADDYFILE"

# ---- 6. Cloudflare token file (only if cloudflare DNS is selected) ---------
if [[ "$ACME_DNS_PROVIDER" == "cloudflare" ]]; then
  echo "[6/8] Setting up Cloudflare token file ..."
  if [[ ! -f "$CF_ENV" ]]; then
    install -m 0640 -o root -g wheel "$REPO_DIR/etc/cloudflare.env.example" "$CF_ENV"
    echo "       created $CF_ENV — you must paste your CF_API_TOKEN into it."
  fi
else
  echo "[6/8] Skipping Cloudflare token setup."
fi

# ---- 7. launchd plists -----------------------------------------------------
echo "[7/8] Writing launchd plists ..."

CADDY_PLIST=/Library/LaunchDaemons/com.rproxy.caddy.plist
UI_PLIST=/Library/LaunchDaemons/com.rproxy.ui.plist
UPDATE_PLIST=/Library/LaunchDaemons/com.rproxy.update.plist

# Caddy needs the Cloudflare token in its environment (DNS-01 challenge). The
# brew-bundled launchd plist doesn't know about our env file, so we ship our
# own that sources it via a tiny wrapper.
CADDY_LAUNCHER="$CONFIG_DIR/caddy-launch.sh"
cat > "$CADDY_LAUNCHER" <<EOF
#!/bin/bash
# Wrapper for launchd — sources the Cloudflare env file (if present) then execs
# caddy. Caddy expands env vars (e.g. {env.CF_API_TOKEN}) at config-load time.
set -e
if [[ -f "$CF_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$CF_ENV"
  set +a
fi
exec "$CADDY_BIN" run --config "$CADDYFILE" --adapter caddyfile
EOF
chmod 0755 "$CADDY_LAUNCHER"

cat > "$CADDY_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTD/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.rproxy.caddy</string>
  <key>ProgramArguments</key>
  <array>
    <string>$CADDY_LAUNCHER</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG_DIR/caddy.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/caddy.err</string>
  <key>WorkingDirectory</key><string>$STATE_DIR</string>
</dict>
</plist>
EOF
chmod 0644 "$CADDY_PLIST"

cat > "$UI_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTD/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.rproxy.ui</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BREW_PREFIX/bin/node</string>
    <string>$REPO_DIR/src/server.js</string>
  </array>
  <key>WorkingDirectory</key><string>$REPO_DIR</string>
  <key>UserName</key><string>$RUN_USER</string>
  <key>GroupName</key><string>$RUN_GROUP</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>NODE_ENV</key><string>production</string>
    <key>PORT</key><string>$UI_PORT</string>
    <key>BIND</key><string>$UI_BIND</string>
    <key>DB_PATH</key><string>$DB_PATH</string>
    <key>CADDY_ADMIN</key><string>http://127.0.0.1:2019</string>
    <key>CERT_DIR</key><string>$CERT_DIR</string>
    <key>ACCESS_LOG</key><string>$ACCESS_LOG</string>
    <key>FALLBACK_UPSTREAM</key><string>$FALLBACK_UPSTREAM</string>
    <key>FALLBACK_HOSTS</key><string>$FALLBACK_HOSTS</string>
    <key>ACME_DNS_PROVIDER</key><string>$ACME_DNS_PROVIDER</string>
    <key>ACME_EMAIL</key><string>$ACME_EMAIL</string>
    <key>AUTH_ENABLED</key><string>$AUTH_ENABLED</string>
    <key>COOKIE_SECURE</key><string>false</string>
    <key>UPDATE_TRIGGER</key><string>$UPDATE_TRIGGER</string>
    <key>PATH</key><string>$BREW_PREFIX/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG_DIR/rproxy-ui.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/rproxy-ui.err</string>
</dict>
</plist>
EOF
chmod 0644 "$UI_PLIST"

# Self-update: launchd watches the trigger file and runs update-macos.sh.
chmod +x "$REPO_DIR/scripts/update-macos.sh"
cat > "$UPDATE_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTD/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.rproxy.update</string>
  <key>ProgramArguments</key>
  <array>
    <string>$REPO_DIR/scripts/update-macos.sh</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>REPO_DIR</key><string>$REPO_DIR</string>
    <key>RUN_USER</key><string>$RUN_USER</string>
    <key>UPDATE_TRIGGER</key><string>$UPDATE_TRIGGER</string>
    <key>BREW_PREFIX</key><string>$BREW_PREFIX</string>
    <key>PATH</key><string>$BREW_PREFIX/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>WatchPaths</key>
  <array>
    <string>$UPDATE_TRIGGER</string>
  </array>
  <key>StandardOutPath</key><string>$LOG_DIR/update.log</string>
  <key>StandardErrorPath</key><string>$LOG_DIR/update.err</string>
</dict>
</plist>
EOF
chmod 0644 "$UPDATE_PLIST"

# ---- 8. (re)load launchd services ------------------------------------------
echo "[8/8] (Re)loading launchd services ..."
# brew may have started caddy via 'brew services' — stop that so it doesn't
# fight our daemon for :80.
sudo -u "$RUN_USER" "$BREW_BIN" services stop caddy >/dev/null 2>&1 || true

reload() {
  local plist="$1" label="$2"
  launchctl bootout system "$plist" >/dev/null 2>&1 || true
  launchctl bootstrap system "$plist"
  launchctl enable "system/$label" >/dev/null 2>&1 || true
}
reload "$CADDY_PLIST"  com.rproxy.caddy
reload "$UI_PLIST"     com.rproxy.ui
reload "$UPDATE_PLIST" com.rproxy.update

sleep 2

echo
echo "=== Health check ==="
caddy_ok=$(launchctl print system/com.rproxy.caddy 2>/dev/null | awk '/state =/{print $3; exit}')
ui_ok=$(launchctl print system/com.rproxy.ui 2>/dev/null | awk '/state =/{print $3; exit}')
ui_http=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${UI_PORT}/api/auth/me" 2>/dev/null || echo 000)
echo "  caddy: ${caddy_ok:-unknown} · rproxy-ui: ${ui_ok:-unknown} · UI responding: $([ "$ui_http" != 000 ] && echo "yes ($ui_http)" || echo no)"

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
  echo "    sudo launchctl kickstart -k system/com.rproxy.caddy"
fi
echo
echo "  Logs:"
echo "    UI    : $LOG_DIR/rproxy-ui.log  (stderr: rproxy-ui.err)"
echo "    Caddy : $LOG_DIR/caddy.log      (stderr: caddy.err)"
echo "  Manage:"
echo "    sudo launchctl kickstart -k system/com.rproxy.ui     # restart UI"
echo "    sudo launchctl kickstart -k system/com.rproxy.caddy  # restart Caddy"
echo "    sudo launchctl bootout system/com.rproxy.ui          # stop UI"
echo
