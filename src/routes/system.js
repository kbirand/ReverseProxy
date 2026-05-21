const express = require('express');
const fs = require('node:fs');
const db = require('../db');
const { caddyHealthy, DEFAULT_FALLBACK_UPSTREAM, DEFAULT_CERT_DIR, DEFAULT_ADMIN } = require('../caddy');
const certs = require('../certs');
const { checkUpdate } = require('../version');
const { reloadCaddy } = require('../sync');

// Writing this file is picked up by rproxy-update.path, which starts the
// privileged rproxy-update.service. Keeps the UI sandbox intact (no sudo).
const UPDATE_TRIGGER = process.env.UPDATE_TRIGGER || '/var/lib/rproxy/.update-requested';

// Small in-process cache so a UI polling every few seconds doesn't hammer
// the TLS handshake path. Probes take ~50-200ms each; 30s of cache is plenty.
let certCache = { ts: 0, data: [] };
const CERT_CACHE_TTL_MS = 30_000;

function buildRouter(database) {
  const r = express.Router();

  r.get('/health', async (req, res) => {
    const caddy = await caddyHealthy();
    const lastReload = db.getMeta(database, 'last_reload_at');
    res.json({
      ok: true,
      caddy,
      caddy_admin: DEFAULT_ADMIN,
      fallback_upstream: DEFAULT_FALLBACK_UPSTREAM || null,
      cert_dir: DEFAULT_CERT_DIR,
      last_reload_at: lastReload ? Number(lastReload) : null,
      schema_version: db.getMeta(database, 'schema_version'),
    });
  });

  r.get('/certs', async (req, res) => {
    const fresh = req.query.refresh === '1';
    const now = Date.now();
    if (!fresh && now - certCache.ts < CERT_CACHE_TTL_MS) {
      return res.json({ certs: certCache.data, cached: true, age_ms: now - certCache.ts });
    }
    const rules = db.listRules(database);
    const data = await certs.probeAll(rules);
    certCache = { ts: Date.now(), data };
    res.json({ certs: data, cached: false, age_ms: 0 });
  });

  // Update check: compares the local git checkout against GitHub. Cached 1h.
  r.get('/version', async (req, res) => {
    try {
      res.json(await checkUpdate(req.query.refresh === '1'));
    } catch (e) {
      res.status(500).json({ error: 'version_check_failed', message: e.message });
    }
  });

  // Download a full backup (rules + global blocklist + auth) as a JSON file.
  r.get('/backup', (req, res) => {
    const data = db.exportBackup(database);
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="rproxy-backup-${stamp}.json"`);
    res.send(JSON.stringify(data, null, 2));
  });

  // Restore from an uploaded backup — replaces rules, blocklist, and auth,
  // then reloads Caddy. Destructive; the UI confirms first.
  r.post('/restore', async (req, res) => {
    let result;
    try {
      result = db.importBackup(database, req.body);
    } catch (e) {
      return res.status(400).json({ error: 'bad_backup', message: e.message });
    }
    try {
      await reloadCaddy(database);
    } catch (e) {
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.json({ ok: true, ...result });
  });

  // Trigger a self-update by dropping the request file. systemd's
  // rproxy-update.path notices it and starts the privileged updater.
  r.post('/update', (req, res) => {
    try {
      fs.writeFileSync(UPDATE_TRIGGER, `requested ${new Date().toISOString()}\n`);
      res.json({ ok: true, message: 'Update requested. The UI will restart in a few seconds.' });
    } catch (e) {
      res.status(500).json({
        error: 'update_failed',
        message: `Could not write update trigger (${e.code || e.message}). `
          + 'Re-run install.sh so the updater service is set up, or update manually with git pull + ./install.sh.',
      });
    }
  });

  return r;
}

module.exports = { buildRouter };
