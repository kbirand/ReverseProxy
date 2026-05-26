const express = require('express');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const db = require('../db');
const { caddyHealthy, DEFAULT_FALLBACK_UPSTREAM, DEFAULT_CERT_DIR, DEFAULT_ADMIN } = require('../caddy');
const certs = require('../certs');
const { checkUpdate } = require('../version');
const { reloadCaddy, scheduleMaintenanceAutoEnd } = require('../sync');

// Writing this file is picked up by rproxy-update.path, which starts the
// privileged rproxy-update.service. Keeps the UI sandbox intact (no sudo).
const UPDATE_TRIGGER = process.env.UPDATE_TRIGGER || '/var/lib/rproxy/.update-requested';

// Privileged Caddy snapshot/restore helper. The UI writes CADDY_ACTION_FILE
// to request work; the helper writes CADDY_RESULT_FILE when done and stages
// tarballs in CADDY_STAGING_DIR. See scripts/caddy-helper.sh.
const CADDY_ACTION_FILE = process.env.CADDY_ACTION_FILE || '/var/lib/rproxy/.caddy-action';
const CADDY_RESULT_FILE = process.env.CADDY_RESULT_FILE || '/var/lib/rproxy/.caddy-action-result';
const CADDY_STAGING_DIR = process.env.CADDY_STAGING_DIR || '/var/lib/rproxy/staging';
const CADDY_SNAPSHOT_TGZ = path.join(CADDY_STAGING_DIR, 'caddy-snapshot.tar.gz');
const CADDY_RESTORE_TGZ = path.join(CADDY_STAGING_DIR, 'caddy-restore.tar.gz');

// Drop any stale result file, then write the action file so the .path unit
// fires. Poll until the helper publishes a new result, capped at timeoutMs.
async function triggerCaddyHelper(action, timeoutMs = 60_000) {
  try { await fsp.unlink(CADDY_RESULT_FILE); } catch (_) {}
  await fsp.writeFile(CADDY_ACTION_FILE, JSON.stringify({ action }) + '\n');
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const raw = await fsp.readFile(CADDY_RESULT_FILE, 'utf8');
      return JSON.parse(raw);
    } catch (_) {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error('caddy helper timed out');
}

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

  // Download a full backup (rules + global blocklist + auth + manual-TLS
  // certs) as a single JSON file.
  r.get('/backup', (req, res) => {
    const data = db.exportBackup(database, { certDir: DEFAULT_CERT_DIR });
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="rproxy-backup-${stamp}.json"`);
    res.send(JSON.stringify(data, null, 2));
  });

  // Restore from an uploaded backup — replaces rules, blocklist, and auth,
  // re-materializes any embedded manual certs to disk, then reloads Caddy.
  // Destructive; the UI confirms first.
  r.post('/restore', async (req, res) => {
    let result;
    try {
      result = db.importBackup(database, req.body, { certDir: DEFAULT_CERT_DIR });
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

  // Caddy storage snapshot — asks the privileged helper to tar
  // /var/lib/caddy/.local/share/caddy and streams the resulting .tar.gz
  // back. Includes every ACME-issued cert, the ACME account key, and the
  // local CA root, so a restore on a new machine skips Let's Encrypt
  // re-issuance and preserves trust for self-signed rules.
  r.get('/caddy-snapshot', async (req, res) => {
    let result;
    try {
      result = await triggerCaddyHelper('snapshot');
    } catch (e) {
      return res.status(503).json({
        error: 'helper_unavailable',
        message: `${e.message}. Re-run install.sh to set up rproxy-caddy-helper.`,
      });
    }
    if (result.status !== 'ok' || !result.path) {
      return res.status(500).json({ error: 'snapshot_failed', message: result.message });
    }
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    res.setHeader('Content-Type', 'application/gzip');
    res.setHeader('Content-Disposition', `attachment; filename="caddy-storage-${stamp}.tar.gz"`);
    fs.createReadStream(result.path)
      .on('error', (e) => res.status(500).end(e.message))
      .on('close', () => { fs.unlink(result.path, () => {}); })
      .pipe(res);
  });

  // Caddy storage restore — accepts a .tar.gz upload (raw body), stages it
  // under /var/lib/rproxy/staging, then asks the privileged helper to
  // unpack it back into /var/lib/caddy and restart Caddy. Mirrors the
  // snapshot endpoint above; intended for migrations to a fresh host.
  r.post('/caddy-restore', express.raw({ type: '*/*', limit: '100mb' }), async (req, res) => {
    if (!req.body || !req.body.length) {
      return res.status(400).json({ error: 'empty_upload', message: 'no tarball uploaded' });
    }
    try {
      await fsp.writeFile(CADDY_RESTORE_TGZ, req.body);
    } catch (e) {
      return res.status(500).json({ error: 'stage_failed', message: e.message });
    }
    let result;
    try {
      result = await triggerCaddyHelper('restore', 120_000);
    } catch (e) {
      return res.status(503).json({
        error: 'helper_unavailable',
        message: `${e.message}. Re-run install.sh to set up rproxy-caddy-helper.`,
      });
    }
    if (result.status !== 'ok') {
      return res.status(400).json({ error: 'restore_failed', message: result.message });
    }
    res.json({ ok: true, message: result.message });
  });

  // Read current maintenance state.
  r.get('/maintenance', (req, res) => {
    res.json({ maintenance: db.getMaintenance(database) });
  });

  // Enable / disable / update maintenance mode. Body shape:
  //   { active: bool, until?: number|null (ms), hosts?: string[] }
  // Empty hosts array means "every enabled rule".
  r.post('/maintenance', async (req, res) => {
    const body = req.body || {};
    const state = {
      active: !!body.active,
      until: body.until ? Number(body.until) : null,
      hosts: Array.isArray(body.hosts)
        ? body.hosts.map((s) => String(s).trim()).filter(Boolean)
        : [],
    };
    if (state.active && state.until && state.until <= Date.now()) {
      return res.status(400).json({ error: 'bad_until', message: 'end time must be in the future' });
    }
    const prev = db.getMaintenance(database);
    db.setMaintenance(database, state);
    try {
      await reloadCaddy(database);
    } catch (e) {
      db.setMaintenance(database, prev);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    scheduleMaintenanceAutoEnd(database);
    res.json({ ok: true, maintenance: state });
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
