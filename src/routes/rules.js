const express = require('express');
const db = require('../db');
const { renderConfig, pushConfig } = require('../caddy');

function buildRouter(database) {
  const r = express.Router();

  async function reloadFromDb() {
    const rules = db.listRules(database);
    const config = renderConfig(rules);
    await pushConfig(config);
    db.setMeta(database, 'last_reload_at', Date.now());
    return rules.length;
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
