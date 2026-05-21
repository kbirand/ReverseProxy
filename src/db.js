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
      created_at    INTEGER NOT NULL,
      updated_at    INTEGER NOT NULL,
      CHECK (tls_mode IN ('http','self','letsencrypt','manual'))
    );
    CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', '1');
  `);

  // Post-v1 column additions (idempotent — skip if already present).
  const cols = db.prepare('PRAGMA table_info(rules)').all().map((c) => c.name);
  if (!cols.includes('deny_ips')) {
    db.exec('ALTER TABLE rules ADD COLUMN deny_ips TEXT');
  }
  if (!cols.includes('deny_redirect')) {
    db.exec('ALTER TABLE rules ADD COLUMN deny_redirect TEXT');
  }
}

const COLUMNS = [
  'hostname','backend_host','backend_port','backend_tls','add_www',
  'tls_mode','cert_path','websocket','hsts','read_timeout','enabled','notes',
  'deny_ips','deny_redirect'
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
       deny_ips, deny_redirect, created_at, updated_at)
    VALUES
      (@hostname, @backend_host, @backend_port, @backend_tls, @add_www,
       @tls_mode, @cert_path, @websocket, @hsts, @read_timeout, @enabled, @notes,
       @deny_ips, @deny_redirect, @created_at, @updated_at)
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
      deny_ips=@deny_ips, deny_redirect=@deny_redirect, updated_at=@updated_at
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
};
