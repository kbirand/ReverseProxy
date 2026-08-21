const express = require('express');
const db = require('../db');
const breach = require('../breach');
const explain = require('../explain');
const { scoreActivity } = require('../activity');
const { reloadCaddy } = require('../sync');
const { accessEvents } = require('../access-log');
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

  // Access log for one virtual host: who hit it, top paths, recent requests.
  // Folds in the www. alias when a matching rule serves it.
  r.get('/host/:host', (req, res) => {
    const host = req.params.host;
    const hours = Math.min(Math.max(Number(req.query.hours) || 24, 1), 24 * 30);
    const hosts = new Set([host]);
    for (const rule of db.listRules(database)) {
      if (rule.hostname === host || `www.${rule.hostname}` === host) {
        hosts.add(rule.hostname);
        if (rule.add_www) hosts.add(`www.${rule.hostname}`);
      }
    }
    const detail = db.hostDetail(database, [...hosts], hours * 3600 * 1000);
    const ips = detail.clients.map((c) => c.client_ip);
    const infoMap = db.getIpInfoMany(database, ips);
    const blocked = new Set(db.listGlobalBlocks(database).map((b) => b.ip));
    detail.clients = detail.clients.map((c) => ({
      ...c, info: infoMap[c.client_ip] || null, blocked: blocked.has(c.client_ip),
    }));
    detail.recent = detail.recent.map((e) => ({ ...e, blocked: blocked.has(e.client_ip) }));
    res.json({ host, hosts: [...hosts], window_hours: hours, ...detail });
    // Background-fill geo for client IPs we haven't enriched yet.
    ipinfo.enrichMissing(database, ips, 6);
  });

  // Live access-event stream (Server-Sent Events). With ?host= it is filtered
  // to that host and its www. alias; without, it streams every host. The
  // host-detail dialog uses it to append requests the moment they arrive.
  r.get('/stream', (req, res) => {
    const host = req.query.host ? String(req.query.host) : null;
    const wanted = new Set();
    if (host) {
      wanted.add(host);
      for (const rule of db.listRules(database)) {
        if (rule.hostname === host || `www.${rule.hostname}` === host) {
          wanted.add(rule.hostname);
          if (rule.add_www) wanted.add(`www.${rule.hostname}`);
        }
      }
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write('retry: 3000\n\n');

    const onEvents = (events) => {
      const matched = host ? events.filter((e) => wanted.has(e.host)) : events;
      if (!matched.length) return;
      const blocked = new Set(db.listGlobalBlocks(database).map((b) => b.ip));
      for (const e of matched) {
        const payload = { ...e, blocked: blocked.has(e.client_ip) };
        res.write(`event: access\ndata: ${JSON.stringify(payload)}\n\n`);
      }
    };
    accessEvents.on('events', onEvents);

    // Comment-only pings keep the connection alive through idle proxy timeouts.
    const ping = setInterval(() => res.write(': ping\n\n'), 25000);
    if (ping.unref) ping.unref();

    req.on('close', () => {
      clearInterval(ping);
      accessEvents.removeListener('events', onEvents);
    });
  });

  // Recent raw requests (?limit=, default 200).
  // Breach analysis: four cross-cutting questions the per-IP and per-host views
  // cannot answer. Nothing is filtered out — rows carry a `confidence` marker so
  // a heuristic can never hide a real break-in.
  r.get('/breach', (req, res) => {
    const hours = Math.min(720, Math.max(1, Number(req.query.hours) || 24));
    const acl = db.listRules(database)
      .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
    const hostsWithAcl = new Set(acl.map((x) => x.hostname));
    // Entries are CIDRs and literals with `#` comments; breach.inAllowlist
    // understands both. Without this your own LAN reads as an intruder.
    const allowlistedIps = new Set(
      acl.flatMap((x) => x.deny_ips.split(/[\n,]+/)
        .map((v) => v.replace(/#.*$/, '').trim())
        .filter(Boolean)),
    );
    const report = breach.report(database, { hours, hostsWithAcl, allowlistedIps, limit: 25 });
    // Explanations were paid for; surface the stored ones so a refresh does not
    // lose them (and does not tempt a second, billable click).
    const stored = db.getExplanationsMany(database, report.ip_summary.map((r) => r.client_ip), hours);
    const blocked = new Set(db.listGlobalBlocks(database).map((b) => b.ip));
    for (const row of report.ip_summary) {
      const ex = stored[row.client_ip];
      if (ex) row.explanation = { text: ex.text, model: ex.model, created_at: ex.created_at };
      // NB: `row.blocked` is the parked-page response COUNT from ipSummary.
      // Blocklist membership goes under a different name or it destroys it.
      row.is_blocked = blocked.has(row.client_ip);
      row.block_guard = breach.blockGuard(row);
    }
    res.json(report);
  });

  // "Explain this" — one row, on demand, sent to Claude via Kie. Deliberately
  // not a pipeline: the operator chooses each time, and buildPayload strips
  // query strings so the JWTs this estate puts in URLs never leave the machine.
  //
  // Results are cached briefly so a double-click does not bill twice.
  // Re-asking within this window returns the stored answer unless the operator
  // explicitly asks again — that is what the `force` flag is for. Without it,
  // "Explain again" silently returned the cached text and looked broken.
  const EXPLAIN_TTL_MS = 10 * 60 * 1000;

  // Which endpoints one source touched. Fetched on demand — only ALERT and
  // WATCH rows offer it, and only when expanded, so the report stays small.
  r.get('/breach/paths', (req, res) => {
    const ip = String(req.query.ip || '').trim();
    if (!ip) return res.status(400).json({ error: 'bad_request', message: 'ip is required' });
    const hours = Math.min(720, Math.max(1, Number(req.query.hours) || 24));
    const hostsWithAcl = new Set(
      db.listRules(database)
        .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim())
        .map((x) => x.hostname),
    );
    res.json({ ip, hours, paths: breach.pathsForIp(database, ip, { hours, hostsWithAcl, limit: 60 }) });
  });

  // Paste-ready handoff for one source: identity, verdict, counts, the stored
  // AI assessment and the endpoints reached — with credential query values
  // stripped, since this text is meant to be pasted elsewhere.
  r.get('/breach/handoff', (req, res) => {
    const ip = String(req.query.ip || '').trim();
    if (!ip) return res.status(400).json({ error: 'bad_request', message: 'ip is required' });
    const hours = Math.min(720, Math.max(1, Number(req.query.hours) || 24));
    const acl = db.listRules(database)
      .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
    const hostsWithAcl = new Set(acl.map((x) => x.hostname));
    const rows = breach.ipSummary(database, {
      hours,
      hostsWithAcl,
      allowlistedIps: new Set(acl.flatMap((x) => x.deny_ips.split(/[\n,]+/)
        .map((v) => v.replace(/#.*$/, '').trim()).filter(Boolean))),
      limit: 5000,
    });
    const row = rows.find((x) => x.client_ip === ip);
    if (!row) return res.status(404).json({ error: 'not_found', message: 'No activity for that IP in this window' });
    const text = breach.formatForHandoff({
      row,
      hours,
      paths: breach.pathsForIp(database, ip, { hours, hostsWithAcl, limit: 60 }),
      explanation: db.getExplanation(database, ip, hours),
    });
    res.json({ ip, hours, text });
  });

  r.post('/breach/explain', async (req, res) => {
    const ip = String((req.body || {}).ip || '').trim();
    if (!ip) return res.status(400).json({ error: 'bad_request', message: 'ip is required' });
    const hours = Math.min(720, Math.max(1, Number((req.body || {}).hours) || 24));

    const force = !!(req.body || {}).force;
    const prior = db.getExplanation(database, ip, hours);
    if (!force && prior && Date.now() - prior.created_at < EXPLAIN_TTL_MS) {
      return res.json({ ip, text: prior.text, model: prior.model, usage: prior.usage, cached: true });
    }

    const acl = db.listRules(database)
      .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
    const rows = breach.ipSummary(database, {
      hours,
      hostsWithAcl: new Set(acl.map((x) => x.hostname)),
      allowlistedIps: new Set(acl.flatMap((x) => x.deny_ips.split(/[\n,]+/)
        .map((v) => v.replace(/#.*$/, '').trim()).filter(Boolean))),
      limit: 5000,
    });
    const row = rows.find((x) => x.client_ip === ip);
    if (!row) return res.status(404).json({ error: 'not_found', message: 'No activity for that IP in this window' });

    const since = Date.now() - hours * 3600 * 1000;
    const events = database.prepare(
      'SELECT uri, status, size, user_agent FROM access_events WHERE client_ip = ? AND ts >= ? ORDER BY size DESC LIMIT 300',
    ).all(ip, since);
    if (events.length && events[0].user_agent) row.user_agent = events[0].user_agent;

    try {
      const payload = explain.buildPayload(row, events);
      const out = await explain.askClaude(payload, { apiKey: process.env.KIE_API_KEY });
      db.saveExplanation(database, { ip, hours, text: out.text, model: out.model, usage: out.usage });
      res.json({ ip, text: out.text, model: out.model, usage: out.usage, cached: false });
    } catch (e) {
      res.status(502).json({ error: 'explain_failed', message: e.message });
    }
  });

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
    // Refuse the self-inflicted cases outright: blocking the LAN gateway or an
    // allowlisted line would cut the operator off from this dashboard.
    const acl = db.listRules(database)
      .filter((x) => x.access_mode === 'whitelist' && (x.deny_ips || '').trim());
    const allow = new Set(acl.flatMap((x) => x.deny_ips.split(/[\n,]+/)
      .map((v) => v.replace(/#.*$/, '').trim()).filter(Boolean)));
    const guard = breach.blockGuard({
      client_ip: ip,
      verdict: { level: breach.inAllowlist(ip, allow) ? 'yours' : 'other' },
    });
    if (!guard.allowed) {
      return res.status(409).json({ error: 'refused', message: guard.reason });
    }
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

  // Block several IPs at once — one Caddy reload for the whole batch.
  r.post('/blocklist/bulk', async (req, res) => {
    const raw = Array.isArray(req.body && req.body.ips) ? req.body.ips : [];
    const ips = [...new Set(raw.map((s) => String(s || '').trim()).filter(Boolean))];
    if (!ips.length) {
      return res.status(400).json({ error: 'bad_input', message: 'ips is required' });
    }
    const note = req.body && req.body.note ? String(req.body.note) : 'bulk block';
    const already = new Set(db.listGlobalBlocks(database).map((b) => b.ip));
    const added = ips.filter((ip) => !already.has(ip));
    for (const ip of ips) db.addGlobalBlock(database, ip, note);
    try {
      await reloadCaddy(database);
    } catch (e) {
      // Roll back only the entries this request added — leave prior blocks be.
      for (const ip of added) db.removeGlobalBlock(database, ip);
      return res.status(502).json({ error: 'caddy_rejected', message: e.message, body: e.body });
    }
    res.status(201).json({ ok: true, count: ips.length, added: added.length });
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
