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

function buildRouter(database, opts = {}) {
  const r = express.Router();
  const reloadCaddy = opts.reloadCaddy === undefined ? defaultReload : opts.reloadCaddy;
  const secretFor = opts.secret;
  const hits = new Map();

  const rateLimited = (key, now) => {
    const seen = (hits.get(key) || []).filter((t) => now - t < RATE_WINDOW_MS);
    seen.push(now);
    hits.set(key, seen);
    if (hits.size > 5000) hits.clear();       // unbounded growth is a memory bug
    return seen.length > RATE_MAX;
  };

  r.post('/:token', async (req, res) => {
    const now = Date.now();
    const peer = req.ip || req.socket?.remoteAddress || 'unknown';
    if (rateLimited(peer, now)) {
      return res.status(429).type('text/plain').send('Too many attempts. Try again shortly.');
    }

    const secret = typeof secretFor === 'function' ? secretFor() : secretFor;
    const check = blockToken.verify(req.params.token, { secret, now });
    if (!check.ok) {
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
      return res.status(409).type('text/plain').send(`Not blocked: ${guard.reason}`);
    }

    // Already blocked is a success, not an error: tapping the button twice from
    // two notifications must not read as a failure.
    const already = db.listGlobalBlocks(database).some((b) => b.ip === ip);
    if (already) return res.status(200).type('text/plain').send(`${ip} was already blocked.`);

    db.addGlobalBlock(database, ip, 'blocked from a notification');
    try {
      if (reloadCaddy) await reloadCaddy(database);
    } catch (e) {
      db.removeGlobalBlock(database, ip);
      return res.status(502).type('text/plain').send(`Could not apply the block: ${e.message}`);
    }
    res.status(200).type('text/plain').send(`Blocked ${ip}.`);
  });

  return r;
}

module.exports = { buildRouter, RATE_MAX, RATE_WINDOW_MS };
