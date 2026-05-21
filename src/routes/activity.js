const express = require('express');
const db = require('../db');
const { scoreActivity } = require('../activity');
const { reloadCaddy } = require('../sync');
const ipinfo = require('../ipinfo');

function buildRouter(database) {
  const r = express.Router();

  // Per-IP rollup over a time window (?hours=, default 24). Suspicious IPs
  // first, then by most-recently-seen.
  r.get('/', (req, res) => {
    const hours = Math.min(Math.max(Number(req.query.hours) || 24, 1), 24 * 30);
    const windowMs = hours * 3600 * 1000;
    const rows = db.activityRollup(database, windowMs);
    const blocked = new Set(db.listGlobalBlocks(database).map((b) => b.ip));
    const infoMap = db.getIpInfoMany(database, rows.map((r) => r.client_ip));
    const hostsMap = db.hostsByIp(database, windowMs);

    // host -> rule lookup (covers www. aliases) for the per-rule block menu.
    const ruleByHost = {};
    for (const rule of db.listRules(database)) {
      if (!rule.enabled) continue;
      ruleByHost[rule.hostname] = rule;
      if (rule.add_www) ruleByHost[`www.${rule.hostname}`] = rule;
    }

    const ips = rows.map((row) => {
      const { flags, suspicious } = scoreActivity(row);
      const info = infoMap[row.client_ip];
      const hostList = hostsMap[row.client_ip] || [];
      const rulesTouched = [];
      const seenRule = new Set();
      for (const h of hostList) {
        const rule = ruleByHost[h.host];
        if (rule && !seenRule.has(rule.id)) {
          seenRule.add(rule.id);
          rulesTouched.push({ id: rule.id, hostname: rule.hostname });
        }
      }
      return {
        client_ip: row.client_ip,
        top_host: hostList.length ? hostList[0].host : null,
        rules: rulesTouched,
        total: row.total,
        first_seen: row.first_seen,
        last_seen: row.last_seen,
        c4xx: row.c4xx,
        c5xx: row.c5xx,
        c404: row.c404,
        probes: row.probes,
        hosts: row.hosts,
        last_ua: row.last_ua,
        flags,
        suspicious,
        blocked: blocked.has(row.client_ip),
        country: info ? info.country : null,
        country_code: info ? info.country_code : null,
        rdns: info ? info.rdns : null,
      };
    });
    ips.sort((a, b) => {
      if (a.suspicious !== b.suspicious) return a.suspicious ? -1 : 1;
      return b.last_seen - a.last_seen;
    });
    res.json({ window_hours: hours, count: ips.length, ips, stats: db.eventStats(database) });
    // Background-fill geo/rDNS for IPs we haven't enriched yet (rate-limited).
    ipinfo.enrichMissing(database, ips.map((i) => i.client_ip), 6);
  });

  // Full detail for one IP: geo/network info + everything it accessed.
  r.get('/ip/:ip', async (req, res) => {
    const ip = req.params.ip;
    const hours = Math.min(Math.max(Number(req.query.hours) || 24, 1), 24 * 30);
    const detail = db.ipDetail(database, ip, hours * 3600 * 1000);
    let info = null;
    try {
      info = await ipinfo.enrich(database, ip, { force: req.query.refresh === '1' });
    } catch (e) {
      info = db.getIpInfo(database, ip); // fall back to whatever is cached
    }
    const blocked = !!db.listGlobalBlocks(database).find((b) => b.ip === ip);
    const { flags, suspicious } = scoreActivity({
      total: detail.summary.total, c4xx: detail.summary.c4xx, c404: detail.summary.c404,
      probes: detail.summary.probes, hosts: detail.summary.hosts,
    });
    res.json({ ip, window_hours: hours, info, blocked, flags, suspicious, ...detail });
  });

  // Recent raw requests (?limit=, default 200).
  r.get('/recent', (req, res) => {
    res.json({ events: db.recentEvents(database, Number(req.query.limit) || 200) });
  });

  // Global blocklist.
  r.get('/blocklist', (req, res) => {
    res.json({ blocks: db.listGlobalBlocks(database) });
  });

  r.post('/blocklist', async (req, res) => {
    const ip = String((req.body && req.body.ip) || '').trim();
    if (!ip) return res.status(400).json({ error: 'bad_input', message: 'ip is required' });
    const note = req.body && req.body.note ? String(req.body.note) : null;
    db.addGlobalBlock(database, ip, note);
    try {
      await reloadCaddy(database);
    } catch (e) {
      db.removeGlobalBlock(database, ip);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.status(201).json({ ok: true, ip });
  });

  r.delete('/blocklist/:ip', async (req, res) => {
    const ip = req.params.ip;
    const existed = db.listGlobalBlocks(database).find((b) => b.ip === ip);
    if (!existed) return res.status(404).json({ error: 'not_found' });
    db.removeGlobalBlock(database, ip);
    try {
      await reloadCaddy(database);
    } catch (e) {
      db.addGlobalBlock(database, existed.ip, existed.note);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.json({ ok: true });
  });

  // Block an IP on ONE rule (append to that rule's deny_ips), rather than
  // globally. Body: { ip, rule_id }.
  r.post('/block-rule', async (req, res) => {
    const ip = String((req.body && req.body.ip) || '').trim();
    const ruleId = Number(req.body && req.body.rule_id);
    if (!ip || !ruleId) {
      return res.status(400).json({ error: 'bad_input', message: 'ip and rule_id are required' });
    }
    const rule = db.getRule(database, ruleId);
    if (!rule) return res.status(404).json({ error: 'not_found' });
    if (rule.access_mode === 'whitelist') {
      return res.status(409).json({
        error: 'whitelist_rule',
        message: `Rule ${rule.hostname} uses a whitelist — block this IP globally instead.`,
      });
    }
    const existing = (rule.deny_ips || '')
      .split(/[\n,]+/).map((s) => s.replace(/#.*$/, '').trim()).filter(Boolean);
    if (existing.includes(ip)) {
      return res.json({ ok: true, already: true, hostname: rule.hostname });
    }
    const before = rule.deny_ips;
    const next = (rule.deny_ips && rule.deny_ips.trim() ? `${rule.deny_ips.trimEnd()}\n` : '') + ip;
    db.updateRule(database, ruleId, { deny_ips: next });
    try {
      await reloadCaddy(database);
    } catch (e) {
      db.updateRule(database, ruleId, { deny_ips: before });
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.status(201).json({ ok: true, ip, hostname: rule.hostname });
  });

  return r;
}

module.exports = { buildRouter };
