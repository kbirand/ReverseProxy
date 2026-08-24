const express = require('express');
const db = require('../db');
const { reloadCaddy } = require('../sync');
const tsdns = require('../tailnetDns');
const tsdnsRoute = require('./tsdns');

function buildRouter(database) {
  const r = express.Router();

  async function reloadFromDb() {
    const { rules } = await reloadCaddy(database);
    // Regenerate the tailnet DNS overrides from the same rules, so the two can
    // never disagree about which hosts are reachable over Tailscale. Best
    // effort: a DNS helper problem must not block a Caddy reload, and it is
    // reported on the tailnet screen rather than swallowed.
    try {
      // db.listRules, NOT reloadCaddy's return: that resolves to
      // { rules: <count> }, so passing it here handed a number to something
      // expecting an array and the regeneration silently did nothing.
      const conf = tsdns.renderDnsmasqConf(
        db.listRules(database), { tailscaleIp: tsdnsRoute.tailscaleIp() });
      require('fs').writeFileSync(
        process.env.TSDNS_ACTION_FILE || '/var/lib/rproxy/.tsdns-action', conf, { mode: 0o640 });
    } catch (e) {
      console.warn(`[rproxy-ui] tailnet DNS regeneration skipped: ${e.message}`);
    }
    return rules;
  }

  r.get('/', (req, res) => {
    res.json({ rules: db.listRules(database) });
  });

  r.get('/:id', (req, res) => {
    const rule = db.getRule(database, Number(req.params.id));
    if (!rule) return res.status(404).json({ error: 'not_found' });
    res.json({ rule });
  });

  r.post('/', async (req, res) => {
    let created;
    try {
      created = db.createRule(database, req.body);
    } catch (e) {
      return res.status(400).json({ error: 'bad_input', message: e.message });
    }
    try {
      await reloadFromDb();
    } catch (e) {
      db.deleteRule(database, created.id);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.status(201).json({ rule: created });
  });

  r.put('/:id', async (req, res) => {
    const id = Number(req.params.id);
    const before = db.getRule(database, id);
    if (!before) return res.status(404).json({ error: 'not_found' });
    let updated;
    try {
      updated = db.updateRule(database, id, req.body);
    } catch (e) {
      return res.status(400).json({ error: 'bad_input', message: e.message });
    }
    try {
      await reloadFromDb();
    } catch (e) {
      db.updateRule(database, id, before);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.json({ rule: updated });
  });

  r.delete('/:id', async (req, res) => {
    const id = Number(req.params.id);
    const before = db.getRule(database, id);
    if (!before) return res.status(404).json({ error: 'not_found' });
    const ok = db.deleteRule(database, id);
    if (!ok) return res.status(404).json({ error: 'not_found' });
    try {
      await reloadFromDb();
    } catch (e) {
      db.createRule(database, before);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.json({ ok: true });
  });

  r.post('/reload', async (req, res) => {
    try {
      const n = await reloadFromDb();
      res.json({ ok: true, rules: n });
    } catch (e) {
      res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
  });

  return r;
}

module.exports = { buildRouter };
