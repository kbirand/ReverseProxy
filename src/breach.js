// Breach analysis over access_events.
//
// The hard part is not finding suspicious requests — it is not crying wolf.
// Two things in this estate answer HTTP 200 without serving anything:
//   * SPA catch-all routes (every unknown path returns index.html)
//   * the parked block page shown to visitors rejected by IP access control
// A naive "2xx on an admin path" query reports both as break-ins. It is how a
// webshell scan against steamactive.com reads as compromise, and how an IP that
// was successfully *blocked* reads as an IP that got in.
//
// So instead of guessing from hardcoded sizes, we learn them: a host that
// returns the exact same byte count across many different URIs is serving a
// fixed body, not a payload. Nothing is ever filtered out — every row is
// returned, carrying a `confidence` marker, so a real breach can never be
// hidden by a heuristic that happened to match.

const SENSITIVE = [
  '%/api/system/list%',
  '%/api/backups/download%',
  '%/api/admin%',
  '%/admin/%',
  '%/api/users%',
  '%/api/auth/users%',
];

// How many distinct URIs must share a byte count before we call it a fixed body.
const FIXED_BODY_MIN_URIS = 5;
// ...and an upper bound on how big such a body can be. Catch-all pages and the
// parked page are a few kB. Without this ceiling, a gallery serving many
// identically-sized images or video files gets written off as "a shell", and
// real content leaving the estate would be reported as nothing having happened.
const FIXED_BODY_MAX_BYTES = 256 * 1024;

function since(opts = {}) {
  if (typeof opts.sinceMs === 'number') return opts.sinceMs;
  const hours = opts.hours || 24;
  return Date.now() - hours * 3600 * 1000;
}

// Set of "host|size" pairs that look like a fixed body on that host.
function shellSizes(db, sinceMs = 0) {
  const rows = db.prepare(`
    SELECT host, size, COUNT(DISTINCT uri) AS uris
    FROM access_events
    WHERE ts >= ? AND size IS NOT NULL AND size <= ?
      AND status >= 200 AND status < 300
    GROUP BY host, size
    HAVING uris >= ?
  `).all(sinceMs, FIXED_BODY_MAX_BYTES, FIXED_BODY_MIN_URIS);
  return new Set(rows.map((r) => `${r.host}|${r.size}`));
}

// Never returns null/undefined: an unmeasurable row is 'unknown', not 'real'
// and not silently dropped.
function classify(row, shells, hostsWithAcl) {
  if (row.size === null || row.size === undefined) return 'unknown';
  if (shells.has(`${row.host}|${row.size}`)) {
    return hostsWithAcl && hostsWithAcl.has(row.host) ? 'likely-blocked' : 'likely-shell';
  }
  return 'real';
}

// 2xx responses on sensitive paths, every one of them, each marked.
function gotIn(db, opts = {}) {
  const from = since(opts);
  const shells = shellSizes(db, from);
  const where = SENSITIVE.map(() => 'uri LIKE ?').join(' OR ');
  const rows = db.prepare(`
    SELECT ts, client_ip, host, method, uri, status, size, user_agent
    FROM access_events
    WHERE ts >= ? AND status >= 200 AND status < 400 AND (${where})
    ORDER BY ts DESC
    LIMIT ?
  `).all(from, ...SENSITIVE, opts.limit || 200);
  return rows.map((r) => ({ ...r, confidence: classify(r, shells, opts.hostsWithAcl) }));
}

// Bytes leaving the estate, grouped by who pulled them and from where.
// Exfiltration is loud in this view and invisible in every other one.
function dataOut(db, opts = {}) {
  const from = since(opts);
  return db.prepare(`
    SELECT client_ip, host,
           SUM(size) AS bytes,
           COUNT(*)  AS requests,
           MAX(size) AS largest,
           MAX(ts)   AS last_ts
    FROM access_events
    WHERE ts >= ? AND size IS NOT NULL
    GROUP BY client_ip, host
    ORDER BY bytes DESC
    LIMIT ?
  `).all(from, opts.limit || 25);
}

// Who is being turned away, and from what.
function triedAndFailed(db, opts = {}) {
  const from = since(opts);
  return db.prepare(`
    SELECT client_ip,
           COUNT(*) AS failures,
           COUNT(DISTINCT host) AS hosts,
           GROUP_CONCAT(DISTINCT host) AS host_list,
           MAX(ts) AS last_ts
    FROM access_events
    WHERE ts >= ? AND status IN (401, 403)
    GROUP BY client_ip
    ORDER BY failures DESC
    LIMIT ?
  `).all(from, opts.limit || 25);
}

// Scanners walking known-vulnerable paths. suspicious_path is computed at
// ingest time by access-log.js.
function probing(db, opts = {}) {
  const from = since(opts);
  return db.prepare(`
    SELECT client_ip,
           COUNT(*) AS probes,
           COUNT(DISTINCT uri) AS distinct_paths,
           MAX(ts) AS last_ts
    FROM access_events
    WHERE ts >= ? AND suspicious_path = 1
    GROUP BY client_ip
    ORDER BY probes DESC
    LIMIT ?
  `).all(from, opts.limit || 25);
}

// ---- enrichment ------------------------------------------------------------
// Three questions get asked of every interesting row: who is this, did they get
// anything, and do I care. All three are computable, so they belong on the page
// rather than in an investigation. `label` answers the first, the real/blocked/
// shell/unknown counts answer the second, and `verdict` answers the third.

// What kind of bytes left. A portfolio handing 127 MB of video to a visitor and
// an intruder taking 127 MB of database dumps are the same number and opposite
// events; only the content tells them apart.
const CONTENT_RE = [
  ['archive', /\.(sql|sql\.gz|gz|zip|tar|tgz|bak|dump|7z|rar)(\?|$)/i],
  ['media',   /\.(mp4|mov|webm|m4v|jpe?g|png|webp|gif|avif|svg|mp3|wav)(\?|$)/i],
  ['code',    /\.(js|css|map|woff2?|ttf)(\?|$)/i],
];

function contentClass(uri) {
  for (const [name, re] of CONTENT_RE) if (re.test(uri)) return name;
  if (/\/api\//.test(uri)) return 'api';
  return 'other';
}

const BIG_TRANSFER = 100 * 1024 * 1024; // 100 MB from one IP is worth a look

// IPv4 CIDR / literal membership. The allowlist is authored as CIDRs
// (192.168.1.0/24, 100.64.0.0/10), so literal string matching silently fails
// and flags your own LAN as an intruder.
function ip4ToInt(ip) {
  const p = String(ip).split('.');
  if (p.length !== 4) return null;
  let n = 0;
  for (const o of p) {
    const v = Number(o);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = (n * 256) + v;
  }
  return n;
}

function inAllowlist(ip, entries) {
  if (!entries || !entries.size) return false;
  if (entries.has(ip)) return true;
  const n = ip4ToInt(ip);
  if (n === null) return false;
  for (const e of entries) {
    const slash = e.indexOf('/');
    if (slash < 0) continue;
    const base = ip4ToInt(e.slice(0, slash));
    const bits = Number(e.slice(slash + 1));
    if (base === null || !Number.isInteger(bits) || bits < 0 || bits > 32) continue;
    const mask = bits === 0 ? 0 : (-1 << (32 - bits)) >>> 0;
    if (((n & mask) >>> 0) === ((base & mask) >>> 0)) return true;
  }
  return false;
}

// Loopback and RFC1918: this machine, or something on the same wire.
function isInternal(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip === 'localhost') return true;
  const n = ip4ToInt(ip);
  if (n === null) return false;
  return inAllowlist(ip, new Set(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16']));
}

function ipLabel(info) {
  if (!info) return '';
  const who = info.org || info.isp || '';
  const bits = [who, info.country_code].filter(Boolean);
  const base = bits.join(' · ');
  if (!base) return info.rdns || '';
  return info.is_hosting ? `${base} · hosting` : base;
}

// Rules are ordered: the first that matches wins. Deliberately small — a rule
// set you can hold in your head beats one that is subtly wrong.
function verdictFor(r, allowlisted) {
  if (isInternal(r.client_ip)) {
    return { level: 'internal', text: 'This machine or your local network — not an outside request.' };
  }
  if (allowlisted) {
    return { level: 'yours', text: 'Your own access — this IP is on an allowlist.' };
  }
  // Genuine content served from a protected endpoint is the only true finding.
  if (r.real_sensitive > 0) {
    return {
      level: 'alert',
      text: `Reached a sensitive endpoint and received real content (${r.real_sensitive} response`
          + `${r.real_sensitive === 1 ? '' : 's'}). Worth reading the rows below.`,
    };
  }
  // Checked BEFORE the refusal rule: an IP that was turned away is the system
  // working. Ranking that above real findings buries them.
  if (r.probes >= 20 || r.distinct_paths >= 20) {
    if (r.real === 0 || r.blocked + r.shell > r.real) {
      return {
        level: 'noise',
        text: `Automated scan — ${r.requests} requests across ${r.distinct_paths} paths, nothing served.`
            + (r.is_hosting ? ' Running on rented cloud infrastructure.' : ''),
      };
    }
  }
  if (r.bytes >= BIG_TRANSFER) {
    const mb = (r.bytes / 1e6).toFixed(0);
    const where = r.top_host ? ` from ${r.top_host}` : '';
    // Overwhelmingly public media off an unprotected host is a visitor, and
    // saying so is more useful than flagging it every single day.
    if (r.content && r.content.media > 0.9 && !r.protected_top_host) {
      return {
        level: 'quiet',
        text: `${mb} MB of public media (video and images)${where} — a visitor browsing the site. `
            + `Large, but nothing protected was touched.`,
      };
    }
    if (r.content && r.content.archive > 0.2) {
      return { level: 'alert', text: `${mb} MB${where}, mostly archives or database dumps. This is what exfiltration looks like.` };
    }
    return { level: 'watch', text: `${mb} MB${where}. Large for an unrecognised source — check what it was.` };
  }
  if (r.failures >= 20) {
    return { level: 'watch', text: `Refused ${r.failures} times, and nothing sensitive was served. Being turned away is the system working.` };
  }
  if (r.real === 0) return { level: 'quiet', text: 'Nothing was served to this IP.' };
  return { level: 'quiet', text: `${r.requests} requests, ordinary traffic.` };
}

// Per-IP rollup: identity, what they actually received, and a verdict.
function ipSummary(db, opts = {}) {
  const from = since(opts);
  const shells = shellSizes(db, from);
  const acl = opts.hostsWithAcl || new Set();
  const allow = opts.allowlistedIps || new Set();
  const sensitiveWhere = SENSITIVE.map(() => 'uri LIKE ?').join(' OR ');

  const buckets = db.prepare(`
    SELECT client_ip, host, size, status, COUNT(*) AS c,
           SUM(CASE WHEN (${sensitiveWhere}) THEN 1 ELSE 0 END) AS sensitive
    FROM access_events
    WHERE ts >= ?
    GROUP BY client_ip, host, size, status
  `).all(...SENSITIVE, from);

  const base = db.prepare(`
    SELECT client_ip,
           COUNT(*) AS requests,
           COUNT(DISTINCT uri)  AS distinct_paths,
           COUNT(DISTINCT host) AS hosts,
           COALESCE(SUM(size), 0) AS bytes,
           SUM(CASE WHEN status IN (401, 403) THEN 1 ELSE 0 END) AS failures,
           SUM(suspicious_path) AS probes,
           MIN(ts) AS first_ts, MAX(ts) AS last_ts
    FROM access_events
    WHERE ts >= ?
    GROUP BY client_ip
  `).all(from);

  const tally = {};
  for (const b of buckets) {
    const t = (tally[b.client_ip] ||= { real: 0, blocked: 0, shell: 0, unknown: 0, real_sensitive: 0 });
    const served = b.status >= 200 && b.status < 400;
    const kind = classify(b, shells, acl);
    if (!served) continue;
    t[kind === 'likely-blocked' ? 'blocked' : kind === 'likely-shell' ? 'shell' : kind === 'unknown' ? 'unknown' : 'real'] += b.c;
    if (kind === 'real' && b.sensitive > 0) t.real_sensitive += b.c;
  }

  // Bytes by content class, and the host that most of them came from.
  const mix = {};
  for (const b of db.prepare(`
    SELECT client_ip, host, uri, COALESCE(SUM(size), 0) AS bytes
    FROM access_events WHERE ts >= ? AND size IS NOT NULL
    GROUP BY client_ip, host, uri
  `).all(from)) {
    const m = (mix[b.client_ip] ||= { total: 0, byClass: {}, byHost: {} });
    m.total += b.bytes;
    const k = contentClass(b.uri);
    m.byClass[k] = (m.byClass[k] || 0) + b.bytes;
    m.byHost[b.host] = (m.byHost[b.host] || 0) + b.bytes;
  }

  const info = require('./db').getIpInfoMany(db, base.map((r) => r.client_ip));
  return base.map((r) => {
    const t = tally[r.client_ip] || { real: 0, blocked: 0, shell: 0, unknown: 0, real_sensitive: 0 };
    const i = info[r.client_ip] || null;
    const m = mix[r.client_ip] || { total: 0, byClass: {}, byHost: {} };
    const content = {};
    for (const k of ['archive', 'media', 'code', 'api', 'other']) {
      content[k] = m.total ? (m.byClass[k] || 0) / m.total : 0;
    }
    const topHost = Object.entries(m.byHost).sort((a, b2) => b2[1] - a[1])[0];
    const row = {
      ...r, ...t, ...(i || {}),
      label: ipLabel(i),
      is_hosting: i ? i.is_hosting : null,
      content,
      top_host: topHost ? topHost[0] : null,
      protected_top_host: topHost ? acl.has(topHost[0]) : false,
    };
    row.verdict = verdictFor(row, inAllowlist(r.client_ip, allow));
    return row;
  }).sort((a, b) => {
    const rank = { alert: 0, watch: 1, noise: 2, quiet: 3, yours: 4, internal: 5 };
    return rank[a.verdict.level] - rank[b.verdict.level] || b.requests - a.requests;
  });
}

// Whether an IP may be blocked from the breach view. The block button sits
// beside your own rows, so refusing the dangerous cases is cheaper than trusting
// a careful click: blocking the allowlisted office line or the LAN gateway would
// lock you out of this dashboard. Deliberate blocks of those remain possible
// from the Blocklist tab.
// Status first, size second. `classify` answers "was that body real content or
// a stock page?", which is only a meaningful question when something was
// actually served. Applied to a 403 it reported refusals as real reads.
function classifyPath(row, shells, acl) {
  const st = Number(row.status) || 0;
  if (st >= 500) return 'error';
  if (st === 401 || st === 403 || st === 429) return 'refused';
  if (st >= 400) return 'not-found';
  return classify(row, shells, acl);
}

// Which endpoints one source actually touched. Backs the expandable detail on
// ALERT/WATCH rows: "reached a sensitive endpoint" is only actionable once you
// can see which one, and whether the response was real or a catch-all page.
function pathsForIp(db, ip, opts = {}) {
  const from = since(opts);
  const shells = shellSizes(db, from);
  const acl = opts.hostsWithAcl || new Set();
  const rows = db.prepare(`
    SELECT host, uri, method, status, size,
           COUNT(*) AS count,
           COALESCE(SUM(size), 0) AS bytes,
           MAX(ts) AS last_ts
    FROM access_events
    WHERE client_ip = ? AND ts >= ?
    GROUP BY host, uri, method, status, size
    ORDER BY bytes DESC, count DESC
    LIMIT ?
  `).all(ip, from, opts.limit || 60);
  return rows.map((r) => ({ ...r, confidence: classifyPath(r, shells, acl) }));
}

// Query parameters whose VALUE is a credential. The parameter name stays so the
// shape of the request is still readable; only the secret goes.
const SECRET_PARAMS = new Set([
  'token', 'access_token', 'refresh_token', 'id_token', 'api_key', 'apikey',
  'key', 'secret', 'password', 'passwd', 'pwd', 'sig', 'signature', 'auth',
  'authorization', 'session', 'sessionid', 'jwt',
]);

// Unlike explain.js — which drops query strings wholesale — the handoff text
// keeps them, because `?file=db.sql.gz` IS the evidence. Only credential values
// are replaced.
function redactQuery(uri) {
  const s = String(uri || '');
  const q = s.indexOf('?');
  if (q < 0) return s;
  const path = s.slice(0, q);
  const parts = s.slice(q + 1).split('&').map((kv) => {
    const eq = kv.indexOf('=');
    if (eq < 0) return kv;
    const k = kv.slice(0, eq);
    return SECRET_PARAMS.has(k.toLowerCase()) ? `${k}=REDACTED` : kv;
  });
  return `${path}?${parts.join('&')}`;
}

function fmtBytes(n) {
  if (n == null) return '—';
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)} GB`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)} MB`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)} kB`;
  return `${n} B`;
}
const fmtTime = (ms) => (ms ? new Date(ms).toISOString().replace('T', ' ').slice(0, 19) : '—');

// A self-contained block the operator can paste somewhere else for a second
// opinion. Everything needed to reason about the source, nothing that would
// hand over a working credential.
function formatForHandoff({ row, paths = [], explanation = null, hours = 24 }) {
  const pct = (n) => Math.round((n || 0) * 100);
  const L = [];
  L.push('=== rproxy breach handoff ===');
  L.push(`IP:        ${row.client_ip}`);
  if (row.label) L.push(`Identity:  ${row.label}${row.is_hosting ? ' (cloud/hosting)' : ''}`);
  L.push(`Window:    last ${hours} h`);
  L.push(`Active:    ${fmtTime(row.first_ts)} → ${fmtTime(row.last_ts)} UTC`);
  L.push(`Verdict:   ${String(row.verdict.level).toUpperCase()} — ${row.verdict.text}`);
  L.push(`Volume:    ${row.requests} requests · ${fmtBytes(row.bytes)} · ${row.distinct_paths} distinct paths · ${row.hosts} hosts`);
  L.push(`Received:  real ${row.real} · blocked ${row.blocked} · shell ${row.shell} · unknown ${row.unknown} · ${row.failures} refused`);
  if (row.content) {
    L.push(`Content:   media ${pct(row.content.media)}% · api ${pct(row.content.api)}% · archive ${pct(row.content.archive)}% · code ${pct(row.content.code)}% · other ${pct(row.content.other)}%`);
  }
  if (row.top_host) L.push(`Top host:  ${row.top_host}`);
  L.push('');
  if (explanation && explanation.text) {
    L.push(`--- AI assessment (${explanation.model || 'unknown model'}, ${fmtTime(explanation.created_at)} UTC) ---`);
    L.push(explanation.text);
  } else {
    L.push('--- no AI assessment recorded for this source ---');
  }
  L.push('');
  if (paths.length) {
    L.push(`--- endpoints reached (top ${paths.length} by bytes) ---`);
    L.push('result    status  bytes       count  endpoint');
    for (const p of paths) {
      const tag = { real: 'real', 'likely-blocked': 'blocked', 'likely-shell': 'shell',
        refused: 'refused', 'not-found': 'not-found', error: 'error', unknown: 'unknown' }[p.confidence] || '?';
      L.push(`${tag.padEnd(9)} ${String(p.status).padEnd(6)} ${fmtBytes(p.bytes).padStart(10)} ${String(p.count).padStart(6)}  ${p.host}${redactQuery(p.uri)}`);
    }
  } else {
    L.push('--- no endpoint detail available ---');
  }
  L.push('');
  L.push('Note: credential-bearing query values are replaced with REDACTED.');
  return L.join('\n');
}

function blockGuard(row) {
  const ip = row && row.client_ip;
  if (!ip) return { allowed: false, reason: 'No IP on this row.' };
  if (isInternal(ip)) {
    return { allowed: false, reason: 'This is your local network or this machine — blocking it would cut off the dashboard.' };
  }
  if (row.verdict && row.verdict.level === 'yours') {
    return { allowed: false, reason: 'This IP is on one of your allowlists. Remove it there first if you really mean to block it.' };
  }
  if (row.verdict && row.verdict.level === 'internal') {
    return { allowed: false, reason: 'Internal traffic cannot be blocked from here.' };
  }
  return { allowed: true, reason: '' };
}

function report(db, opts = {}) {
  return {
    window_hours: opts.hours || 24,
    got_in: gotIn(db, opts),
    data_out: dataOut(db, opts),
    tried_and_failed: triedAndFailed(db, opts),
    probing: probing(db, opts),
    ip_summary: ipSummary(db, opts).slice(0, opts.limit || 25),
  };
}

module.exports = {
  shellSizes, classify, gotIn, dataOut, triedAndFailed, probing,
  ipSummary, ipLabel, verdictFor, inAllowlist, isInternal, contentClass, blockGuard,
  pathsForIp, classifyPath, redactQuery, formatForHandoff, report, SENSITIVE,
};
