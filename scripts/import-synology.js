#!/usr/bin/env node
/*
 * One-shot import of Synology DSM reverse-proxy rules into the local SQLite DB.
 *
 * Usage:
 *   SYNO_HOST=192.168.1.239 SYNO_USER=kbirand SYNO_PASS=... \
 *     node scripts/import-synology.js [--dry-run] [--file path]
 *
 * Without --file, the script SSHes to the NAS (via sshpass if SYNO_PASS is set,
 * otherwise plain ssh w/ key) and reads /usr/syno/etc/www/ReverseProxy.json.
 * With --file, it reads that local JSON path instead.
 *
 * Merging rules:
 *   1. <apex> + www.<apex> with the same backend  ->  one row, add_www=ON
 *   2. :80 + :443 siblings for the same fqdn       ->  one row
 *   3. tls_mode is always 'http' on import; user flips per rule afterwards.
 *
 * Skipped:
 *   - koraybirand.synology.me:5543 (NAS web-station entry)
 */

const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const db = require('../src/db');

const args = process.argv.slice(2);
const DRY = args.includes('--dry-run');
const fileIdx = args.indexOf('--file');
const FILE = fileIdx >= 0 ? args[fileIdx + 1] : null;

const SYNO_HOST = process.env.SYNO_HOST || '192.168.1.239';
const SYNO_USER = process.env.SYNO_USER || 'kbirand';
const SYNO_PASS = process.env.SYNO_PASS || '';
const REMOTE_PATH = '/usr/syno/etc/www/ReverseProxy.json';

function fetchRemoteJson() {
  if (FILE) {
    return fs.readFileSync(FILE, 'utf8');
  }
  const sshArgs = [
    '-o', 'StrictHostKeyChecking=no',
    '-o', 'UserKnownHostsFile=/dev/null',
    '-o', 'LogLevel=ERROR',
    `${SYNO_USER}@${SYNO_HOST}`,
    `cat ${REMOTE_PATH}`,
  ];
  if (SYNO_PASS) {
    const res = spawnSync('sshpass', ['-e', 'ssh', ...sshArgs], {
      env: { ...process.env, SSHPASS: SYNO_PASS },
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    if (res.status !== 0) throw new Error(`sshpass/ssh failed: ${res.stderr}`);
    return res.stdout;
  }
  return execFileSync('ssh', sshArgs, { encoding: 'utf8' });
}

function parseRules(json) {
  const data = JSON.parse(json);
  const entries = [];
  for (const [key, val] of Object.entries(data)) {
    if (key === 'version') continue;
    if (!val || !val.frontend || !val.backend) continue;
    entries.push({
      key,
      fqdn: val.frontend.fqdn,
      front_port: val.frontend.port,
      front_proto: val.frontend.protocol, // 0=http, 1=https
      hsts: !!(val.frontend.https && val.frontend.https.hsts),
      backend_host: val.backend.fqdn,
      backend_port: val.backend.port,
      backend_proto: val.backend.protocol, // 0=http, 1=https
      timeout: val.proxy_read_timeout || 60,
      websocket: Array.isArray(val.customize_headers)
        && val.customize_headers.some((h) => h && h.name === 'Upgrade'),
      description: val.description || '',
    });
  }
  return entries;
}

function shouldSkip(e) {
  if (e.fqdn === 'koraybirand.synology.me' && e.front_port === 5543) return true;
  return false;
}

function mergeRules(entries) {
  // Bucket by fqdn. Within a bucket, fold :80 + :443 siblings if backends match.
  const byFqdn = new Map();
  for (const e of entries) {
    if (shouldSkip(e)) continue;
    if (!byFqdn.has(e.fqdn)) byFqdn.set(e.fqdn, []);
    byFqdn.get(e.fqdn).push(e);
  }

  const merged = []; // each entry: { hostname, backend_host, backend_port, backend_tls, websocket, hsts, read_timeout, notes }
  for (const [fqdn, list] of byFqdn) {
    // Group by backend fingerprint
    const byBackend = new Map();
    for (const e of list) {
      const fp = `${e.backend_host}:${e.backend_port}:${e.backend_proto}`;
      if (!byBackend.has(fp)) byBackend.set(fp, []);
      byBackend.get(fp).push(e);
    }
    for (const [_, siblings] of byBackend) {
      const first = siblings[0];
      const hsts = siblings.some((s) => s.hsts);
      const ws = siblings.some((s) => s.websocket);
      const timeout = Math.max(...siblings.map((s) => s.timeout || 60));
      merged.push({
        hostname: fqdn,
        backend_host: first.backend_host,
        backend_port: first.backend_port,
        backend_tls: first.backend_proto === 1 ? 1 : 0,
        websocket: ws ? 1 : 0,
        hsts: hsts ? 1 : 0,
        read_timeout: timeout,
        notes: siblings.map((s) => s.description).filter(Boolean).join(' / '),
        _ports: siblings.map((s) => s.front_port),
      });
    }
  }

  // Now collapse apex + www.apex with identical backend into one row with add_www=1.
  const out = [];
  const byHost = new Map(merged.map((r) => [r.hostname, r]));
  const consumed = new Set();
  for (const r of merged) {
    if (consumed.has(r.hostname)) continue;
    if (r.hostname.startsWith('www.')) {
      const apex = r.hostname.slice(4);
      const apexRow = byHost.get(apex);
      if (apexRow && sameBackend(apexRow, r)) {
        // merged into apexRow on its turn -> skip
        continue;
      }
      out.push({ ...r, add_www: 0 });
      consumed.add(r.hostname);
    } else {
      const wwwRow = byHost.get(`www.${r.hostname}`);
      if (wwwRow && sameBackend(wwwRow, r)) {
        out.push({
          ...r,
          add_www: 1,
          websocket: r.websocket || wwwRow.websocket,
          hsts: r.hsts || wwwRow.hsts,
          read_timeout: Math.max(r.read_timeout, wwwRow.read_timeout),
        });
        consumed.add(r.hostname);
        consumed.add(wwwRow.hostname);
      } else {
        out.push({ ...r, add_www: 0 });
        consumed.add(r.hostname);
      }
    }
  }
  return out;
}

function sameBackend(a, b) {
  return a.backend_host === b.backend_host
    && a.backend_port === b.backend_port
    && a.backend_tls === b.backend_tls;
}

function table(rows) {
  const headers = ['hostname','backend','www','tls','ws','hsts','timeout','notes'];
  const lines = rows.map((r) => [
    r.hostname,
    `${r.backend_host}:${r.backend_port}${r.backend_tls ? ' (tls)' : ''}`,
    r.add_www ? 'ON' : '',
    'http',
    r.websocket ? 'ws' : '',
    r.hsts ? 'hsts' : '',
    String(r.read_timeout),
    (r.notes || '').slice(0, 30),
  ]);
  const widths = headers.map((h, i) => Math.max(h.length, ...lines.map((l) => l[i].length)));
  const fmt = (cols) => cols.map((c, i) => c.padEnd(widths[i])).join('  ');
  console.log(fmt(headers));
  console.log(fmt(widths.map((w) => '-'.repeat(w))));
  for (const l of lines) console.log(fmt(l));
}

function main() {
  console.log(`[import] reading ${FILE ? FILE : `${SYNO_USER}@${SYNO_HOST}:${REMOTE_PATH}`}`);
  const json = fetchRemoteJson();
  const entries = parseRules(json);
  console.log(`[import] parsed ${entries.length} raw rules`);
  const merged = mergeRules(entries);
  console.log(`[import] merged into ${merged.length} logical hosts:\n`);
  table(merged);

  if (DRY) {
    console.log(`\n[import] --dry-run set, not writing DB`);
    return;
  }

  const database = db.open();
  let inserted = 0, updated = 0;
  for (const r of merged) {
    const existed = database.prepare('SELECT id FROM rules WHERE hostname=?').get(r.hostname);
    db.upsertByHostname(database, {
      ...r,
      tls_mode: 'http',
      enabled: 1,
      notes: `${r.notes} | imported from Synology`.trim(),
    });
    if (existed) updated++; else inserted++;
  }
  console.log(`\n[import] DB updated: ${inserted} inserted, ${updated} updated.`);
  console.log(`[import] All rows land as tls_mode='http'. Flip TLS per rule in the UI as needed.`);
}

main();
