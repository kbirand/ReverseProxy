const fs = require('node:fs');
const db = require('./db');

const DEFAULT_LOG = process.env.ACCESS_LOG || '/var/log/rproxy/access.log';
const POLL_MS = Number(process.env.ACCESS_POLL_MS || 5000);

// URI patterns that strongly indicate scanning / probing rather than real use.
const PROBE_RE = new RegExp([
  '\\.(env|git|aws|ssh|sql|bak)\\b',
  'wp-login', 'wp-admin', 'xmlrpc\\.php', '/wordpress/',
  'phpmyadmin', '/pma/', '/dbadmin',
  '/vendor/', 'eval-stdin', '/cgi-bin/', '/actuator', '/solr/',
  '/\\.well-known/(?!acme|pki-validation)',
  '/owa/', '/autodiscover', '/boaform', '/HNAP1',
  '\\.\\./', '%2e%2e',
].join('|'), 'i');

function isProbe(uri) {
  return PROBE_RE.test(uri || '');
}

function parseLine(line) {
  let e;
  try { e = JSON.parse(line); } catch { return null; }
  const req = e.request;
  if (!req || !req.host) return null; // not an access-log entry
  const ua = req.headers && req.headers['User-Agent'] && req.headers['User-Agent'][0];
  return {
    ts: Math.round((e.ts || 0) * 1000) || Date.now(),
    client_ip: req.client_ip || req.remote_ip || '?',
    host: req.host || '',
    method: req.method || '',
    uri: req.uri || '',
    status: Number(e.status) || 0,
    user_agent: (ua || '').slice(0, 300),
    suspicious_path: isProbe(req.uri) ? 1 : 0,
  };
}

// Tail the Caddy JSON access log into SQLite. Returns the interval handle.
// On first run it skips to end-of-file (no backlog re-ingest); handles log
// rotation by detecting the file shrinking.
function startIngester(database, opts = {}) {
  const logPath = opts.path || DEFAULT_LOG;
  const intervalMs = opts.intervalMs || POLL_MS;
  let offset = 0;
  let remainder = '';
  let primed = false;

  function tick() {
    let st;
    try { st = fs.statSync(logPath); } catch { return; } // not created yet
    if (!primed) { offset = st.size; primed = true; return; }
    if (st.size < offset) { offset = 0; remainder = ''; } // rotated/truncated
    if (st.size === offset) return;

    let chunk;
    try {
      const fd = fs.openSync(logPath, 'r');
      const len = st.size - offset;
      const b = Buffer.alloc(len);
      fs.readSync(fd, b, 0, len, offset);
      fs.closeSync(fd);
      chunk = b.toString('utf8');
    } catch (e) {
      console.error(`[access-log] read failed: ${e.message}`);
      return;
    }
    offset = st.size;

    const lines = (remainder + chunk).split('\n');
    remainder = lines.pop(); // possibly-incomplete last line
    const events = [];
    for (const line of lines) {
      if (!line.trim()) continue;
      const ev = parseLine(line);
      if (ev) events.push(ev);
    }
    if (events.length) {
      try {
        db.insertAccessEvents(database, events);
        db.pruneAccessEvents(database);
      } catch (e) {
        console.error(`[access-log] insert failed: ${e.message}`);
      }
    }
  }

  tick(); // prime the offset
  const handle = setInterval(tick, intervalMs);
  if (handle.unref) handle.unref();
  console.log(`[access-log] ingesting ${logPath} every ${intervalMs}ms`);
  return handle;
}

module.exports = { startIngester, isProbe, parseLine };
