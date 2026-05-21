const express = require('express');
const db = require('../db');
const { caddyHealthy, DEFAULT_FALLBACK_UPSTREAM, DEFAULT_CERT_DIR, DEFAULT_ADMIN } = require('../caddy');
const certs = require('../certs');

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

  return r;
}

module.exports = { buildRouter };
