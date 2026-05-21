# rproxy

A small self-hosted reverse-proxy manager: **[Caddy](https://caddyserver.com/)**
does the proxying, a lightweight **Node.js + SQLite** web UI manages the rules.
No Docker, no framework bloat — installs natively via `systemd`.

Built to replace a Synology DSM reverse proxy, but it works in front of any
set of HTTP backends.

## Features

- Web UI to add / edit / delete / enable / disable proxy rules — sortable,
  filterable table.
- **`www.` alias toggle** — one rule serves both `example.com` and
  `www.example.com`.
- **Per-rule TLS mode**: `http` (no origin TLS — e.g. behind a CDN),
  `self` (Caddy internal CA), `letsencrypt` (auto cert), `manual` (your files).
- **Automatic HTTPS** via Let's Encrypt — HTTP-01, or DNS-01 through Cloudflare
  (works even when port 80 isn't publicly reachable). Caddy auto-renews.
- **Per-rule IP blocklist** with optional redirect — Cloudflare-aware, so it
  matches the real visitor IP, not the CDN edge.
- WebSocket pass-through, HSTS, custom upstream timeouts, HTTPS backends.
- Live **cert-expiry** column (probes what Caddy actually serves).
- Hot config reload via Caddy's admin API — no dropped connections.
- Source of truth is one SQLite file; "Copy details" exports the whole config
  as Markdown + JSON.

## Architecture

```
            inbound :80 / :443
                   │
                   ▼
         ┌──────────────────┐  admin API   ┌──────────────────┐
         │  Caddy (systemd) │◀─────────────│  rproxy-ui (Node)│
         │  :80 :443        │  hot reload  │  :8080  + SQLite │
         └────────┬─────────┘              └──────────────────┘
                  │ matched hostname → that rule's backend
                  │ bare IP          → optional fallback upstream
                  └ unknown host     → clean 404
```

The UI never serves traffic itself — it renders the rule set into a Caddy JSON
config and `POST`s it to Caddy's local admin API. Caddy is the data plane;
the UI is the control plane.

## Requirements

- Ubuntu / Debian (uses `apt` and `systemd`)
- Root access for the installer
- Ports 80 and 443 free (move any existing web server off them first — or
  point `FALLBACK_UPSTREAM` at it, see below)
- For Cloudflare DNS-01: a Cloudflare account with your domains, and an API
  token (the installer tells you how)

## Install

```bash
git clone https://github.com/kbirand/ReverseProxy.git
cd ReverseProxy
cp install.conf.example install.conf
nano install.conf          # set UI port, ACME method, etc.
sudo ./install.sh
```

The installer is idempotent — re-run it any time to apply `install.conf`
changes or pull updates. It:

1. installs Caddy (official build) + Node.js
2. installs the `caddy-dns/cloudflare` plugin if you chose DNS-01
3. creates the `rproxy` system user and `/var/lib/rproxy`, `/etc/rproxy/certs`
4. installs Node dependencies
5. writes `/etc/caddy/Caddyfile`, the `rproxy-ui` systemd unit, and (for
   Cloudflare) the token env file + caddy drop-in
6. enables and starts both services

If you picked `ACME_DNS_PROVIDER=cloudflare`, paste your token afterwards:

```bash
sudo nano /etc/rproxy/cloudflare.env      # set CF_API_TOKEN=...
sudo systemctl restart caddy
```

Then open `http://<this-host>:8080/` and start adding rules.

## Configuration (`install.conf`)

| Key | Meaning |
|---|---|
| `UI_PORT` | Port the admin UI listens on (default 8080) |
| `UI_BIND` | `0.0.0.0` for LAN access, `127.0.0.1` to restrict to this host |
| `FALLBACK_UPSTREAM` | `host:port` to proxy bare-IP/loopback requests to (e.g. a pre-existing Apache). Empty → unmatched requests get a clean 404 |
| `ACME_DNS_PROVIDER` | `cloudflare` for DNS-01, empty for HTTP-01 |
| `ACME_EMAIL` | Let's Encrypt account email (expiry notices) |

Runtime settings live as `Environment=` lines in
`/etc/systemd/system/rproxy-ui.service` — re-run `install.sh` to regenerate it.

## The database

- A single SQLite file at `/var/lib/rproxy/rules.db`.
- **Created automatically, empty, on first run** — a fresh install starts with
  zero rules; you add them in the UI.
- Not shipped in the repo (it is per-deployment data) and gitignored.
- Back it up by copying the file, or use the safe online-backup helper:

  ```bash
  sudo ./scripts/backup-db.sh            # -> /var/lib/rproxy/backups/
  ```

- To move to a new machine: install fresh, then copy `rules.db` into place
  (`sudo systemctl stop rproxy-ui`, copy, `chown rproxy:rproxy`, start) and
  hit "Reload" in the UI.

## Migrating from Synology DSM

`scripts/import-synology.js` reads a DSM reverse-proxy export and seeds the
database. See the comments at the top of that file. (Optional — only useful
if you are coming from a Synology.)

## Service management

```bash
sudo systemctl status  rproxy-ui caddy
sudo systemctl restart rproxy-ui          # after editing src/
sudo journalctl -u rproxy-ui -f -o cat    # live logs
sudo journalctl -u caddy     -f -o cat
```

Both services are `systemd`-managed with `Restart=always` — they survive
crashes and reboots. No PM2 / forever needed.

## Development

```bash
npm install
node --test src/caddy.test.js     # renderer unit tests
PORT=8080 DB_PATH=./data/dev.db node src/server.js
```

The config renderer ([src/caddy.js](src/caddy.js)) is a pure function
(`renderConfig(rules) -> Caddy JSON`) with no I/O, so it is fully unit-tested.

## License

MIT — see [LICENSE](LICENSE).
