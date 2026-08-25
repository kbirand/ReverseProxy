// The one-tap "block this source" endpoint behind a notification button.
//
// PUBLIC BY DESIGN — this is the only unauthenticated route in the panel, and it
// is published on its own hostname so the rest of /api stays unreachable from
// the internet. What stands in for a session is a signed token that names one IP
// and expires (see blockToken.js): the notification it rides in travels through
// ntfy and sits on a lock screen, so it must not carry a reusable credential.
//
// Three things keep the blast radius at "one scanner gets blocked":
//   1. The IP is inside the signed payload, so a token cannot be repointed.
//   2. blockGuard runs anyway, so a token naming an allowlisted or internal
//      address is refused even with a perfect signature — a mis-tap at 3am
//      cannot cut you off from your own dashboard.
//   3. POST only. A GET would let any link preview, crawler or chat client that
//      unfurls the URL block an address by accident.

const express = require('express');
const db = require('../db');
const breach = require('../breach');
const blockToken = require('../blockToken');
const { reloadCaddy: defaultReload } = require('../sync');

// Crude, deliberate: this endpoint is reachable from the internet, so an
// attacker who cannot forge a signature should not be able to spend the box's
// CPU making us try. Per-source, in memory, resets on restart.
const RATE_WINDOW_MS = 60 * 1000;
const RATE_MAX = 20;

// Every request arrives through Caddy, which dials loopback, so req.ip is
// 127.0.0.1 for all of them — keying on it would put the whole internet in ONE
// bucket, and 21 requests a minute from anywhere would 429 the operator's own
// button for the rest of the window. Caddy sets X-Block-Client-Ip on this route
// from its resolved client_ip, which honours trusted_proxies (so behind
// Cloudflare it is the real visitor, not a CF edge node).
//
// The header is only trusted when the request really did come from loopback.
// Anyone already on the box could forge it, but they can reach :8080 directly
// and do not need this route; from the internet the header cannot be set,
// because Caddy overwrites it on the way through.
const LOOPBACK = new Set(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
function sourceKey(req) {
  const peer = req.socket?.remoteAddress || '';
  if (LOOPBACK.has(peer)) {
    const fromCaddy = (req.get('x-block-client-ip') || '').trim();
    if (fromCaddy) return fromCaddy;
  }
  return req.ip || peer || 'unknown';
}

// A self-contained, mobile-first page. No external assets — it is served to a
// phone from a bare endpoint. `pre` holds the monospace handoff report; `msg` is
// a short human line for the empty/refused cases.
function esc(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}
function page(title, msg, pre) {
  return `<!doctype html><html><head><meta charset="utf-8">`
    + `<meta name="viewport" content="width=device-width, initial-scale=1">`
    + `<title>${esc(title)}</title><style>`
    + `body{font:14px/1.5 -apple-system,system-ui,sans-serif;margin:0;padding:16px;`
    + `background:#0f1419;color:#e6e6e6}h1{font-size:16px;margin:0 0 12px}`
    + `pre{white-space:pre-wrap;word-break:break-word;font:12px/1.45 ui-monospace,Menlo,monospace;`
    + `background:#161b22;border:1px solid #30363d;border-radius:8px;padding:12px;overflow-x:auto}`
    + `p{color:#9aa5b1}</style></head><body><h1>${esc(title)}</h1>`
    + (msg ? `<p>${esc(msg)}</p>` : '')
    + (pre ? `<pre>${esc(pre)}</pre>` : '')
    + `</body></html>`;
}

function buildRouter(database, opts = {}) {
  const r = express.Router();
  const reloadCaddy = opts.reloadCaddy === undefined ? defaultReload : opts.reloadCaddy;
  const secretFor = opts.secret;
  const confirm = opts.confirm || null;
  const hits = new Map();

  // Feedback for a tap. The button lives inside a notification, and the phone
  // shows nothing for the HTTP response — you tap it and cannot tell whether
  // anything happened. That is not a cosmetic gap on a security control: the
  // first live test was tapped twice for exactly this reason, and both taps
  // were silently landing on a 404 at the time. So every outcome comes back as
  // its own notification.
  //
  // Only signature-verified taps notify. This endpoint is public, and if a bad
  // token also pushed, anyone who found the path could ring the phone at will —
  // the rate limiter would cap that flood at 20 a minute rather than stop it.
  //
  // Never awaited and never allowed to throw: the tap's own response must not
  // wait on ntfy, and a push outage must not turn a successful block into an
  // error on the phone.
  const tell = (title, body, priority, tags) => {
    if (!confirm) return;
    try {
      const out = confirm({ title, body, priority, tags });
      if (out && typeof out.catch === 'function') out.catch(() => {});
    } catch { /* feedback is never worth failing the action for */ }
  };

  const rateLimited = (key, now) => {
    const seen = (hits.get(key) || []).filter((t) => now - t < RATE_WINDOW_MS);
    seen.push(now);
    hits.set(key, seen);
    if (hits.size > 5000) hits.clear();       // unbounded growth is a memory bug
    return seen.length > RATE_MAX;
  };

  // Read-only per-IP detail — the full report the notification had to truncate.
  // GET, because it changes nothing; the same single-IP token gates it. A crawler
  // that unfurls the link renders a path list (queries already redacted) and
  // nothing more — no side effect, unlike the block POST above.
  r.get('/details/:token', (req, res) => {
    const now = Date.now();
    const secret = typeof secretFor === 'function' ? secretFor() : secretFor;
    const check = blockToken.verify(req.params.token, { secret, now });
    if (!check.ok) {
      return res.status(403).type('text/html').send(page('Not available',
        'This link is not valid or has expired.'));
    }
    const ip = check.ip;
    const rows = db.listRules(database)
      .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
    const hostsWithAcl = new Set(rows.map((x) => x.hostname));
    const allowlistedIps = new Set(rows.flatMap((x) => x.deny_ips.split(/[\n,]+/)
      .map((v) => v.replace(/#.*$/, '').trim()).filter(Boolean)));
    const summary = breach.ipSummary(database, { hours: 24, hostsWithAcl, allowlistedIps, limit: 400 });
    const row = summary.find((r) => r.client_ip === ip);
    if (!row) {
      return res.status(200).type('text/html').send(page(ip,
        'No activity recorded for this source in the last 24 hours.'));
    }
    const paths = breach.pathsForIp(database, ip, { hours: 24, limit: 400 });
    const report = breach.formatForHandoff({ row, paths, hours: 24 });
    res.status(200).type('text/html').send(page(`${ip} — detail`, null, report));
  });

  r.post('/:token', async (req, res) => {
    const now = Date.now();
    const peer = sourceKey(req);
    if (rateLimited(peer, now)) {
      return res.status(429).type('text/plain').send('Too many attempts. Try again shortly.');
    }

    const secret = typeof secretFor === 'function' ? secretFor() : secretFor;
    const check = blockToken.verify(req.params.token, { secret, now });
    if (!check.ok) {
      // A token whose SIGNATURE was good but whose day ran out came from a real
      // notification, so it earns an answer — otherwise tapping an old alert
      // looks identical to tapping a working one. A forged or malformed token
      // says nothing back, on the wire or to the phone.
      if (check.reason === 'expired' && check.ip) {
        tell('Block link expired', `${check.ip} was NOT blocked — that alert is over a day old. `
          + 'Block it from the panel if it still matters.', 4, 'hourglass');
      }
      // One message for every failure mode: a caller probing this endpoint
      // learns nothing about whether a token was wrong, stale, or unsigned.
      return res.status(403).type('text/plain').send('This block link is not valid or has expired.');
    }
    const ip = check.ip;

    const acl = db.listRules(database)
      .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
    const allow = new Set(acl.flatMap((x) => x.deny_ips.split(/[\n,]+/)
      .map((v) => v.replace(/#.*$/, '').trim()).filter(Boolean)));
    const guard = breach.blockGuard({
      client_ip: ip,
      verdict: { level: breach.inAllowlist(ip, allow) ? 'yours' : 'other' },
    });
    if (!guard.allowed) {
      tell('Not blocked', `${ip}: ${guard.reason}`, 4, 'warning');
      return res.status(409).type('text/plain').send(`Not blocked: ${guard.reason}`);
    }

    // Already blocked is a success, not an error: tapping the button twice from
    // two notifications must not read as a failure.
    const already = db.listGlobalBlocks(database).some((b) => b.ip === ip);
    if (already) {
      tell('Already blocked', `${ip} was already on the blocklist — an earlier tap worked. `
        + 'Nothing changed.', 3, 'white_check_mark');
      return res.status(200).type('text/plain').send(`${ip} was already blocked.`);
    }

    db.addGlobalBlock(database, ip, 'blocked from a notification');
    try {
      if (reloadCaddy) await reloadCaddy(database);
    } catch (e) {
      db.removeGlobalBlock(database, ip);
      tell('Block FAILED', `${ip} is NOT blocked: ${e.message}`, 5, 'x');
      return res.status(502).type('text/plain').send(`Could not apply the block: ${e.message}`);
    }
    tell('Blocked', `${ip} is now blocked at the proxy, for every host.`, 3, 'white_check_mark');
    res.status(200).type('text/plain').send(`Blocked ${ip}.`);
  });

  return r;
}

module.exports = { buildRouter, RATE_MAX, RATE_WINDOW_MS };
