const path = require('node:path');
const express = require('express');
const db = require('./db');
const auth = require('./auth');
const { caddyHealthy, DEFAULT_BLOCK_ACTION_PATH } = require('./caddy');
const { reloadCaddy, scheduleMaintenanceAutoEnd, seedBlockAction } = require('./sync');
const { startIngester } = require('./access-log');
const breach = require('./breach');
const notify = require('./notify');
const rulesRoute = require('./routes/rules');
const systemRoute = require('./routes/system');
const activityRoute = require('./routes/activity');
const tsdnsRoute = require('./routes/tsdns');
const blockActionRoute = require('./routes/blockAction');
const blockToken = require('./blockToken');
const authRoute = require('./routes/auth');
const firewallRoute = require('./routes/firewall');

const PORT = Number(process.env.PORT || 8080);
const BIND = process.env.BIND || '0.0.0.0';

// What a tapped Block button reports back. The notification action gives the
// phone no visible answer, so the outcome returns as its own push — see the
// note in routes/blockAction.js. Reads the environment per call so it picks up
// the same NTFY_* the breach watcher uses.
function pushBlockOutcome({ title, body, priority, tags }) {
  const topic = (process.env.NTFY_TOPIC || '').trim();
  if (!topic) return Promise.resolve({ sent: false, reason: 'ntfy topic is not configured' });
  return notify.send({ title, body, priority, tags }, {
    topic,
    server: process.env.NTFY_SERVER || notify.DEFAULT_SERVER,
    token: process.env.NTFY_TOKEN || '',
  });
}

const database = db.open();
auth.ensureAuthSeed(database);
// Copy BLOCK_ACTION_* into the database so every later reload republishes the
// block route, including reloads from processes that never had those variables
// in their environment. The unit file is still where they are set.
seedBlockAction(database);
const app = express();

// The notification block button. Deliberately mounted BEFORE requireAuth: it is
// tapped from a phone with no panel session, and its authorisation is a signed
// single-IP token instead (see routes/blockAction.js). Caddy publishes exactly
// this one prefix on one hostname, from the same BLOCK_ACTION_PATH value, so
// nothing else the panel serves is reachable from the internet alongside it.
//
// Also mounted BEFORE the body parsers. Everything this route needs is in the
// URL, and it is the one route reachable from the internet — parsing up to a
// megabyte of attacker-chosen JSON before deciding the token is forged is work
// nobody should be able to make us do.
app.use(DEFAULT_BLOCK_ACTION_PATH, blockActionRoute.buildRouter(database, {
  secret: () => blockToken.secretFor(database),
  confirm: pushBlockOutcome,
}));
// Restore uploads bundle every rule + embedded manual certs, so give that
// one endpoint a larger ceiling. Mounted first so the per-route parser sets
// req._body and the general parser below skips re-parsing. Guarded by
// requireAuth so an unauthenticated request is rejected BEFORE its (up to
// 20mb) body is parsed — the general /api gate still re-checks downstream.
app.use('/api/system/restore', auth.requireAuth(database), express.json({ limit: '20mb' }));
app.use(express.json({ limit: '1mb' }));
// Auth router is public (its routes self-guard); everything else under /api
// requires a valid session. Static files stay public — they hold no secrets.
app.use('/api/auth', authRoute.buildRouter(database));
app.use('/api', auth.requireAuth(database));
// Until the default admin/admin password is changed, block privileged and
// secret-exposing endpoints (rule/firewall edits, self-update, restore, backup,
// snapshots). Login + password change live on the public /api/auth router above.
app.use('/api', auth.requireNonDefaultPassword(database));
app.use('/api/rules', rulesRoute.buildRouter(database));
// Mounted before /api/system so this more specific path wins cleanly.
app.use('/api/system/firewall', firewallRoute.buildRouter());
app.use('/api/system', systemRoute.buildRouter(database));
app.use('/api/activity', activityRoute.buildRouter(database));
// Which hosts resolve to the tailnet address, and how each one is reachable.
app.use('/api/tsdns', tsdnsRoute.buildRouter(database));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error('[server] uncaught', err);
  res.status(500).json({ error: 'server_error', message: String(err.message || err) });
});

// On startup, push the database's rules into Caddy. Caddy boots from a minimal
// bootstrap Caddyfile that knows nothing about user rules — without this, a
// reboot would leave every rule down until someone opened the UI. Waits for
// Caddy's admin API to come up first (systemd orders us After=caddy.service,
// but the admin socket may still be initializing).
async function syncOnStartup() {
  for (let i = 0; i < 30; i++) {
    if (await caddyHealthy()) break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  try {
    const { rules, blocks } = await reloadCaddy(database);
    console.log(`[rproxy-ui] startup sync: ${rules} rules, ${blocks} global blocks pushed to Caddy`);
  } catch (e) {
    console.error(`[rproxy-ui] startup sync failed (UI still up, use Reload): ${e.message}`);
  }
  // Re-arm the maintenance auto-end timer after a restart so an in-progress
  // window still ends on schedule (or ends immediately if it already passed).
  scheduleMaintenanceAutoEnd(database);
}

// Loudly flag the most dangerous misconfiguration: the known default credential
// still active on a network-reachable bind. Privileged endpoints are already
// blocked in this state (requireNonDefaultPassword), but make it impossible to
// miss in the logs.
function warnIfInsecure() {
  if (!auth.AUTH_ENABLED) {
    console.warn('[rproxy-ui] WARNING: AUTH_ENABLED=false — the UI is completely unauthenticated. Use only on a trusted, isolated network.');
    return;
  }
  const loopback = BIND === '127.0.0.1' || BIND === '::1' || BIND === 'localhost';
  if (auth.passwordIsDefault(database)) {
    console.warn('[rproxy-ui] WARNING: the admin password is still the default (admin/admin). '
      + 'Privileged actions are DISABLED until you change it (topbar → Password).'
      + (loopback ? '' : ` The UI is bound to ${BIND} (network-reachable) — change the password now.`));
  }
}

// Watch for a genuinely serious source and push it to the operator's phone.
// Scope is a 1h window: long enough that a slow exfiltration still shows a full
// picture, short enough that an old incident does not re-alert forever. Only
// ALERT verdicts qualify, and notify.js keeps a 6h cooldown per source.
function startBreachWatcher(database) {
  const topic = (process.env.NTFY_TOPIC || '').trim();
  if (!topic) {
    console.log('[rproxy-ui] breach alerts disabled (NTFY_TOPIC not set)');
    return null;
  }
  const server = process.env.NTFY_SERVER || notify.DEFAULT_SERVER;
  const every = Math.max(30, Number(process.env.BREACH_WATCH_SECONDS) || 60) * 1000;
  // Which verdicts page you. Defaults to both; set NTFY_LEVELS=alert to go back
  // to breaches only. notify.js ignores anything outside its own allowlist.
  const levels = (process.env.NTFY_LEVELS || notify.NOTIFIABLE.join(','))
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
  console.log(`[rproxy-ui] breach alerts on: ${server}/${topic.slice(0, 4)}… every ${every / 1000}s, levels: ${levels.join('+')}`);

  const tick = async () => {
    try {
      const acl = db.listRules(database)
        .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
      const rows = breach.ipSummary(database, {
        hours: 1,
        hostsWithAcl: new Set(acl.map((x) => x.hostname)),
        allowlistedIps: new Set(acl.flatMap((x) => x.deny_ips.split(/[\n,]+/)
          .map((v) => v.replace(/#.*$/, '').trim()).filter(Boolean))),
        limit: 200,
      });
      const sent = await notify.runOnce(database, rows, {
        server,
        topic,
        levels,
        token: process.env.NTFY_TOKEN || '',
        // BLOCK_ACTION_HOST is what publishes the endpoint through Caddy. With
        // no host there is nothing reachable to point a button at, so the button
        // is absent rather than broken.
        // Fetch well past what the message shows: notify.js caps the list at 12,
        // and the "…and N more" line is only honest if the rows behind the cap
        // were actually counted. Refused paths are fetched too — they sort after
        // served ones and are filtered out of the message, but they are what
        // makes the count mean anything.
        pathsFor: (ip) => breach.pathsForIp(database, ip, { hours: 1, limit: 60 }),
        blockUrlFor: (ip) => {
          const host = (process.env.BLOCK_ACTION_HOST || '').trim();
          if (!host) return '';
          const token = blockToken.mint(ip, { secret: blockToken.secretFor(database) });
          return `https://${host}${DEFAULT_BLOCK_ACTION_PATH}/${token}`;
        },
        // Same host and token as the block button; the read-only detail page lives
        // under <path>/details/<token> and shows the full report the message
        // truncated.
        detailUrlFor: (ip) => {
          const host = (process.env.BLOCK_ACTION_HOST || '').trim();
          if (!host) return '';
          const token = blockToken.mint(ip, { secret: blockToken.secretFor(database) });
          return `https://${host}${DEFAULT_BLOCK_ACTION_PATH}/details/${token}`;
        },
        onError: (ip, reason) => console.error(`[rproxy-ui] breach alert for ${ip} failed: ${reason}`),
      });
      for (const ip of sent) console.warn(`[rproxy-ui] BREACH ALERT sent for ${ip}`);
    } catch (e) {
      // Never let the watcher take the UI down.
      console.error(`[rproxy-ui] breach watcher error: ${e.message}`);
    }
  };
  tick();
  return setInterval(tick, every);
}

app.listen(PORT, BIND, () => {
  console.log(`[rproxy-ui] listening on ${BIND}:${PORT}`);
  warnIfInsecure();
  syncOnStartup();
  // Tail Caddy's access log into SQLite for the activity view.
  startIngester(database);
  startBreachWatcher(database);
});
