const path = require('node:path');
const fs = require('node:fs');
const Database = require('better-sqlite3');

const DEFAULT_DB = path.join(__dirname, '..', 'data', 'rules.db');

function open(dbPath = process.env.DB_PATH || DEFAULT_DB) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');
  migrate(db);
  return db;
}

function migrate(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS rules (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      hostname      TEXT NOT NULL UNIQUE,
      backend_host  TEXT NOT NULL,
      backend_port  INTEGER NOT NULL,
      backend_tls   INTEGER NOT NULL DEFAULT 0,
      add_www       INTEGER NOT NULL DEFAULT 0,
      tls_mode      TEXT NOT NULL DEFAULT 'http',
      cert_path     TEXT,
      websocket     INTEGER NOT NULL DEFAULT 0,
      hsts          INTEGER NOT NULL DEFAULT 0,
      read_timeout  INTEGER NOT NULL DEFAULT 60,
      enabled       INTEGER NOT NULL DEFAULT 1,
      notes         TEXT,
      deny_ips      TEXT,
      deny_redirect TEXT,
      access_mode   TEXT NOT NULL DEFAULT 'blacklist',
      created_at    INTEGER NOT NULL,
      updated_at    INTEGER NOT NULL,
      CHECK (tls_mode IN ('http','self','letsencrypt','manual'))
    );
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', '1');

    CREATE TABLE IF NOT EXISTS access_events (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      ts              INTEGER NOT NULL,
      client_ip       TEXT NOT NULL,
      host            TEXT,
      method          TEXT,
      uri             TEXT,
      status          INTEGER,
      user_agent      TEXT,
      suspicious_path INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_access_ts ON access_events(ts);
    CREATE INDEX IF NOT EXISTS idx_access_ip ON access_events(client_ip);

    CREATE TABLE IF NOT EXISTS global_blocks (
      ip       TEXT PRIMARY KEY,
      added_at INTEGER NOT NULL,
      note     TEXT
    );

    CREATE TABLE IF NOT EXISTS ip_info (
      ip           TEXT PRIMARY KEY,
      rdns         TEXT,
      country      TEXT,
      country_code TEXT,
      region       TEXT,
      city         TEXT,
      isp          TEXT,
      org          TEXT,
      asn          TEXT,
      is_proxy     INTEGER,
      is_hosting   INTEGER,
      is_mobile    INTEGER,
      fetched_at   INTEGER NOT NULL
    );
  `);

  // Post-v1 column additions (idempotent — skip if already present).
  const cols = db.prepare('PRAGMA table_info(rules)').all().map((c) => c.name);
  if (!cols.includes('deny_ips')) {
    db.exec('ALTER TABLE rules ADD COLUMN deny_ips TEXT');
  }
  if (!cols.includes('deny_redirect')) {
    db.exec('ALTER TABLE rules ADD COLUMN deny_redirect TEXT');
  }
  if (!cols.includes('access_mode')) {
    db.exec("ALTER TABLE rules ADD COLUMN access_mode TEXT NOT NULL DEFAULT 'blacklist'");
  }
}

const COLUMNS = [
  'hostname','backend_host','backend_port','backend_tls','add_www',
  'tls_mode','cert_path','websocket','hsts','read_timeout','enabled','notes',
  'deny_ips','deny_redirect','access_mode'
];

function normalize(input) {
  const r = {};
  for (const col of COLUMNS) {
    if (input[col] === undefined) continue;
    if (['backend_tls','add_www','websocket','hsts','enabled'].includes(col)) {
      r[col] = input[col] ? 1 : 0;
    } else if (['backend_port','read_timeout'].includes(col)) {
      r[col] = Number(input[col]);
    } else {
      r[col] = input[col] === null ? null : String(input[col]);
    }
  }
  return r;
}

function listRules(db) {
  return db.prepare('SELECT * FROM rules ORDER BY hostname COLLATE NOCASE').all();
}

function getRule(db, id) {
  return db.prepare('SELECT * FROM rules WHERE id = ?').get(id);
}

function createRule(db, input) {
  const r = normalize(input);
  if (!r.hostname || !r.backend_host || !r.backend_port) {
    throw new Error('hostname, backend_host, backend_port are required');
  }
  if (!r.tls_mode) r.tls_mode = 'http';
  if (r.read_timeout === undefined) r.read_timeout = 60;
  if (r.enabled === undefined) r.enabled = 1;
  const now = Date.now();
  const stmt = db.prepare(`
    INSERT INTO rules
      (hostname, backend_host, backend_port, backend_tls, add_www,
       tls_mode, cert_path, websocket, hsts, read_timeout, enabled, notes,
       deny_ips, deny_redirect, access_mode, created_at, updated_at)
    VALUES
      (@hostname, @backend_host, @backend_port, @backend_tls, @add_www,
       @tls_mode, @cert_path, @websocket, @hsts, @read_timeout, @enabled, @notes,
       @deny_ips, @deny_redirect, @access_mode, @created_at, @updated_at)
  `);
  const res = stmt.run({
    hostname: r.hostname,
    backend_host: r.backend_host,
    backend_port: r.backend_port,
    backend_tls: r.backend_tls ?? 0,
    add_www: r.add_www ?? 0,
    tls_mode: r.tls_mode,
    cert_path: r.cert_path ?? null,
    websocket: r.websocket ?? 0,
    hsts: r.hsts ?? 0,
    read_timeout: r.read_timeout,
    enabled: r.enabled,
    notes: r.notes ?? null,
    deny_ips: r.deny_ips ?? null,
    deny_redirect: r.deny_redirect ?? null,
    access_mode: r.access_mode || 'blacklist',
    created_at: now,
    updated_at: now,
  });
  return getRule(db, res.lastInsertRowid);
}

function updateRule(db, id, patch) {
  const existing = getRule(db, id);
  if (!existing) return null;
  const r = normalize(patch);
  const merged = { ...existing, ...r, updated_at: Date.now() };
  db.prepare(`
    UPDATE rules SET
      hostname=@hostname, backend_host=@backend_host, backend_port=@backend_port,
      backend_tls=@backend_tls, add_www=@add_www, tls_mode=@tls_mode,
      cert_path=@cert_path, websocket=@websocket, hsts=@hsts,
      read_timeout=@read_timeout, enabled=@enabled, notes=@notes,
      deny_ips=@deny_ips, deny_redirect=@deny_redirect, access_mode=@access_mode,
      updated_at=@updated_at
    WHERE id=@id
  `).run({ ...merged, id });
  return getRule(db, id);
}

function deleteRule(db, id) {
  const info = db.prepare('DELETE FROM rules WHERE id = ?').run(id);
  return info.changes > 0;
}

function upsertByHostname(db, input) {
  const r = normalize(input);
  const existing = db.prepare('SELECT id FROM rules WHERE hostname = ?').get(r.hostname);
  if (existing) return updateRule(db, existing.id, input);
  return createRule(db, input);
}

function setMeta(db, k, v) {
  db.prepare('INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v')
    .run(k, String(v));
}

function getMeta(db, k) {
  const row = db.prepare('SELECT v FROM meta WHERE k = ?').get(k);
  return row ? row.v : null;
}

// ---- maintenance mode ------------------------------------------------------

// Stored as one JSON blob in meta so the whole state lands or rolls back atomically.
// Shape: { active: bool, until: number|null (ms epoch), hosts: string[] (empty = all) }
function getMaintenance(db) {
  const raw = getMeta(db, 'maintenance');
  if (!raw) return { active: false, until: null, hosts: [] };
  try {
    const v = JSON.parse(raw);
    return {
      active: !!v.active,
      until: v.until ? Number(v.until) : null,
      hosts: Array.isArray(v.hosts) ? v.hosts.map(String) : [],
    };
  } catch {
    return { active: false, until: null, hosts: [] };
  }
}

function setMaintenance(db, state) {
  setMeta(db, 'maintenance', JSON.stringify({
    active: !!state.active,
    until: state.until ? Number(state.until) : null,
    hosts: Array.isArray(state.hosts) ? state.hosts.map(String) : [],
  }));
}

// ---- access events ---------------------------------------------------------

const MAX_ACCESS_ROWS = 200_000;     // hard cap to bound DB size
const ACCESS_RETENTION_MS = 14 * 24 * 60 * 60 * 1000;

function insertAccessEvents(db, events) {
  if (!events.length) return;
  const stmt = db.prepare(`
    INSERT INTO access_events (ts, client_ip, host, method, uri, status, user_agent, suspicious_path)
    VALUES (@ts, @client_ip, @host, @method, @uri, @status, @user_agent, @suspicious_path)
  `);
  const tx = db.transaction((rows) => { for (const r of rows) stmt.run(r); });
  tx(events);
}

function pruneAccessEvents(db) {
  db.prepare('DELETE FROM access_events WHERE ts < ?').run(Date.now() - ACCESS_RETENTION_MS);
  // Backstop row cap: drop the oldest beyond MAX_ACCESS_ROWS.
  const n = db.prepare('SELECT COUNT(*) AS c FROM access_events').get().c;
  if (n > MAX_ACCESS_ROWS) {
    db.prepare(`
      DELETE FROM access_events WHERE id IN (
        SELECT id FROM access_events ORDER BY id ASC LIMIT ?
      )`).run(n - MAX_ACCESS_ROWS);
  }
}

function recentEvents(db, limit = 200) {
  return db.prepare('SELECT * FROM access_events ORDER BY id DESC LIMIT ?')
    .all(Math.min(Number(limit) || 200, 1000));
}

// Per-IP rollup over the last `sinceMs` window.
function activityRollup(db, sinceMs) {
  const since = Date.now() - sinceMs;
  return db.prepare(`
    SELECT client_ip,
           COUNT(*)                                              AS total,
           MIN(ts)                                               AS first_seen,
           MAX(ts)                                               AS last_seen,
           SUM(CASE WHEN status>=400 AND status<500 THEN 1 ELSE 0 END) AS c4xx,
           SUM(CASE WHEN status>=500 THEN 1 ELSE 0 END)           AS c5xx,
           SUM(CASE WHEN status=404 THEN 1 ELSE 0 END)            AS c404,
           SUM(suspicious_path)                                  AS probes,
           COUNT(DISTINCT host)                                  AS hosts,
           MAX(user_agent)                                       AS last_ua
    FROM access_events
    WHERE ts >= ?
    GROUP BY client_ip
  `).all(since);
}

function eventStats(db) {
  const row = db.prepare('SELECT COUNT(*) AS c, MIN(ts) AS oldest FROM access_events').get();
  return { count: row.c, oldest: row.oldest };
}

// Hosts each client IP requested within the window, ordered most-hit first:
//   { "<ip>": [ { host, count }, ... ] }
function hostsByIp(db, sinceMs) {
  const rows = db.prepare(`
    SELECT client_ip, host, COUNT(*) AS c
    FROM access_events WHERE ts >= ? AND host <> ''
    GROUP BY client_ip, host ORDER BY c DESC
  `).all(Date.now() - sinceMs);
  const map = {};
  for (const r of rows) {
    (map[r.client_ip] || (map[r.client_ip] = [])).push({ host: r.host, count: r.c });
  }
  return map;
}

// Everything one client IP did within the window: summary + breakdowns.
function ipDetail(db, ip, sinceMs) {
  const since = Date.now() - sinceMs;
  const summary = db.prepare(`
    SELECT COUNT(*) AS total, MIN(ts) AS first_seen, MAX(ts) AS last_seen,
           SUM(CASE WHEN status>=400 AND status<500 THEN 1 ELSE 0 END) AS c4xx,
           SUM(CASE WHEN status>=500 THEN 1 ELSE 0 END) AS c5xx,
           SUM(CASE WHEN status=404 THEN 1 ELSE 0 END) AS c404,
           SUM(suspicious_path) AS probes,
           COUNT(DISTINCT host) AS hosts
    FROM access_events WHERE client_ip=? AND ts>=?
  `).get(ip, since);
  const q = (sql, lim) => db.prepare(sql).all(ip, since, ...(lim ? [lim] : []));
  return {
    summary,
    hosts: q('SELECT host, COUNT(*) AS c FROM access_events WHERE client_ip=? AND ts>=? GROUP BY host ORDER BY c DESC'),
    paths: q(`SELECT host, uri, COUNT(*) AS c,
                     SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) AS errors,
                     MAX(suspicious_path) AS probe
              FROM access_events WHERE client_ip=? AND ts>=?
              GROUP BY host, uri ORDER BY c DESC LIMIT ?`, 30),
    methods: q('SELECT method, COUNT(*) AS c FROM access_events WHERE client_ip=? AND ts>=? GROUP BY method ORDER BY c DESC'),
    statuses: q('SELECT status, COUNT(*) AS c FROM access_events WHERE client_ip=? AND ts>=? GROUP BY status ORDER BY c DESC'),
    user_agents: q('SELECT user_agent, COUNT(*) AS c FROM access_events WHERE client_ip=? AND ts>=? GROUP BY user_agent ORDER BY c DESC LIMIT 10'),
    recent: q('SELECT ts, host, method, uri, status, suspicious_path FROM access_events WHERE client_ip=? AND ts>=? ORDER BY id DESC LIMIT ?', 60),
  };
}

// Everything one virtual host received within the window: summary + breakdowns.
// `hosts` is the set of hostnames to aggregate together — a rule plus its
// optional www. alias — so the access log covers both names as one site.
function hostDetail(db, hosts, sinceMs) {
  const since = Date.now() - sinceMs;
  const list = Array.isArray(hosts) ? hosts : [hosts];
  const ph = list.map(() => '?').join(',');
  const summary = db.prepare(`
    SELECT COUNT(*) AS total, MIN(ts) AS first_seen, MAX(ts) AS last_seen,
           SUM(CASE WHEN status>=400 AND status<500 THEN 1 ELSE 0 END) AS c4xx,
           SUM(CASE WHEN status>=500 THEN 1 ELSE 0 END) AS c5xx,
           SUM(CASE WHEN status=404 THEN 1 ELSE 0 END) AS c404,
           SUM(suspicious_path) AS probes,
           COUNT(DISTINCT client_ip) AS ips
    FROM access_events WHERE host IN (${ph}) AND ts>=?
  `).get(...list, since);
  const q = (sql, lim) => db.prepare(sql).all(...list, since, ...(lim ? [lim] : []));
  return {
    summary,
    clients: q(`SELECT client_ip, COUNT(*) AS c,
                       SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) AS errors,
                       SUM(suspicious_path) AS probes, MAX(ts) AS last_seen
                FROM access_events WHERE host IN (${ph}) AND ts>=?
                GROUP BY client_ip ORDER BY c DESC LIMIT ?`, 30),
    paths: q(`SELECT host, uri, COUNT(*) AS c,
                     SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END) AS errors,
                     MAX(suspicious_path) AS probe
              FROM access_events WHERE host IN (${ph}) AND ts>=?
              GROUP BY host, uri ORDER BY c DESC LIMIT ?`, 30),
    methods: q(`SELECT method, COUNT(*) AS c FROM access_events
                WHERE host IN (${ph}) AND ts>=? GROUP BY method ORDER BY c DESC`),
    statuses: q(`SELECT status, COUNT(*) AS c FROM access_events
                 WHERE host IN (${ph}) AND ts>=? GROUP BY status ORDER BY c DESC`),
    recent: q(`SELECT ts, client_ip, method, uri, status, suspicious_path
               FROM access_events WHERE host IN (${ph}) AND ts>=?
               ORDER BY id DESC LIMIT ?`, 60),
  };
}

// ---- IP enrichment cache (geo + reverse DNS) -------------------------------

function getIpInfo(db, ip) {
  return db.prepare('SELECT * FROM ip_info WHERE ip = ?').get(ip) || null;
}

function getIpInfoMany(db, ips) {
  if (!ips.length) return {};
  const ph = ips.map(() => '?').join(',');
  const rows = db.prepare(`SELECT * FROM ip_info WHERE ip IN (${ph})`).all(...ips);
  return Object.fromEntries(rows.map((r) => [r.ip, r]));
}

function upsertIpInfo(db, info) {
  db.prepare(`
    INSERT INTO ip_info (ip, rdns, country, country_code, region, city, isp, org, asn,
                         is_proxy, is_hosting, is_mobile, fetched_at)
    VALUES (@ip, @rdns, @country, @country_code, @region, @city, @isp, @org, @asn,
            @is_proxy, @is_hosting, @is_mobile, @fetched_at)
    ON CONFLICT(ip) DO UPDATE SET
      rdns=excluded.rdns, country=excluded.country, country_code=excluded.country_code,
      region=excluded.region, city=excluded.city, isp=excluded.isp, org=excluded.org,
      asn=excluded.asn, is_proxy=excluded.is_proxy, is_hosting=excluded.is_hosting,
      is_mobile=excluded.is_mobile, fetched_at=excluded.fetched_at
  `).run({
    ip: info.ip, rdns: info.rdns ?? null,
    country: info.country ?? null, country_code: info.country_code ?? null,
    region: info.region ?? null, city: info.city ?? null,
    isp: info.isp ?? null, org: info.org ?? null, asn: info.asn ?? null,
    is_proxy: info.is_proxy ? 1 : 0, is_hosting: info.is_hosting ? 1 : 0,
    is_mobile: info.is_mobile ? 1 : 0, fetched_at: info.fetched_at || Date.now(),
  });
}

// ---- global blocklist ------------------------------------------------------

function listGlobalBlocks(db) {
  return db.prepare('SELECT ip, added_at, note FROM global_blocks ORDER BY added_at DESC').all();
}

function addGlobalBlock(db, ip, note) {
  db.prepare(`
    INSERT INTO global_blocks (ip, added_at, note) VALUES (?, ?, ?)
    ON CONFLICT(ip) DO UPDATE SET note=excluded.note
  `).run(ip, Date.now(), note || null);
}

function removeGlobalBlock(db, ip) {
  return db.prepare('DELETE FROM global_blocks WHERE ip = ?').run(ip).changes > 0;
}

// ---- backup / restore ------------------------------------------------------

// A portable snapshot of everything the UI manages: rules, the global
// blocklist, and the auth credentials. Transient monitoring tables
// (access_events, ip_info) are intentionally excluded — they regenerate.
function exportBackup(db) {
  return {
    format: 'rproxy-backup',
    version: 1,
    created_at: new Date().toISOString(),
    rules: db.prepare('SELECT * FROM rules').all(),
    global_blocks: db.prepare('SELECT * FROM global_blocks').all(),
    meta: db.prepare("SELECT k, v FROM meta WHERE k LIKE 'auth_%'").all(),
  };
}

function tableColumns(db, table) {
  return db.prepare(`PRAGMA table_info(${table})`).all().map((c) => c.name);
}

// Replace rules + global blocklist + auth meta from a backup, atomically.
// Inserts only columns that exist in the current schema, so a backup made on a
// slightly older/newer version still restores cleanly.
function importBackup(db, data) {
  if (!data || data.format !== 'rproxy-backup' || !Array.isArray(data.rules)) {
    throw new Error('not a valid rproxy backup file');
  }
  const ruleCols = tableColumns(db, 'rules');
  const blockCols = tableColumns(db, 'global_blocks');
  const insertRow = (table, cols, row) => {
    const present = cols.filter((c) => Object.prototype.hasOwnProperty.call(row, c));
    if (!present.length) return;
    db.prepare(
      `INSERT INTO ${table} (${present.join(',')}) VALUES (${present.map(() => '?').join(',')})`,
    ).run(...present.map((c) => row[c]));
  };
  const tx = db.transaction(() => {
    db.prepare('DELETE FROM rules').run();
    db.prepare('DELETE FROM global_blocks').run();
    for (const r of data.rules) insertRow('rules', ruleCols, r);
    for (const b of (data.global_blocks || [])) insertRow('global_blocks', blockCols, b);
    for (const m of (data.meta || [])) {
      if (m && typeof m.k === 'string' && m.k.startsWith('auth_')) setMeta(db, m.k, m.v);
    }
  });
  tx();
  return { rules: data.rules.length, blocks: (data.global_blocks || []).length };
}

module.exports = {
  open,
  listRules,
  getRule,
  createRule,
  updateRule,
  deleteRule,
  upsertByHostname,
  setMeta,
  getMeta,
  getMaintenance,
  setMaintenance,
  insertAccessEvents,
  pruneAccessEvents,
  recentEvents,
  activityRollup,
  eventStats,
  hostsByIp,
  ipDetail,
  hostDetail,
  getIpInfo,
  getIpInfoMany,
  upsertIpInfo,
  listGlobalBlocks,
  addGlobalBlock,
  removeGlobalBlock,
  exportBackup,
  importBackup,
};
