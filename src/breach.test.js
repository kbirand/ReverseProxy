const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('./db');
const breach = require('./breach');

// A host that answers 200 with the SAME byte count for many different paths is
// serving a fixed body — an SPA catch-all, or the parked block page. Real
// payloads vary in size. That distinction is the whole point of this module:
// without it, blocked and non-existent requests read as successful breaches.
function seed() {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  const ev = (o) => rows.push({
    ts: now, client_ip: '1.1.1.1', host: 'h', method: 'GET', uri: '/', status: 200,
    user_agent: 'ua', suspicious_path: 0, size: 100, ...o,
  });
  // steamactive: SPA catch-all — 6 different paths, all exactly 881 bytes
  for (const p of ['/a.php', '/b.php', '/c.php', '/d.php', '/e.php', '/f.php']) {
    ev({ host: 'steamactive.com', uri: p, size: 881, client_ip: '9.9.9.9' });
  }
  // esc: parked block page — 5 different paths, all exactly 3171 bytes
  for (const p of ['/', '/x', '/y', '/z', '/w']) {
    ev({ host: 'private.example.com', uri: p, size: 3171, client_ip: '8.8.8.8' });
  }
  // a genuine exfil: one IP pulling a large unique payload
  ev({ host: 'backups.example.com', uri: '/api/backups/download?file=db.sql.gz',
       size: 37701795, client_ip: '203.0.113.10' });
  // genuine sensitive read
  ev({ host: 'catalog.example.com', uri: '/api/system/list?path=/etc',
       size: 11427, client_ip: '203.0.113.10' });
  // failures
  for (let i = 0; i < 4; i++) ev({ host: 'finance.example.com', uri: '/api/clients', status: 401, size: 29, client_ip: '5.5.5.5' });
  // probing
  for (let i = 0; i < 3; i++) ev({ host: 'x.com', uri: '/wp-login.php', status: 404, size: 12, suspicious_path: 1, client_ip: '7.7.7.7' });
  db.insertAccessEvents(d, rows);
  return d;
}

test('fixed-body sizes are detected per host', () => {
  const d = seed();
  const shells = breach.shellSizes(d, 0);
  assert.ok(shells.has('steamactive.com|881'), 'SPA catch-all size detected');
  assert.ok(shells.has('private.example.com|3171'), 'parked page size detected');
  assert.ok(!shells.has('backups.example.com|37701795'), 'a unique payload is not a shell');
});

test('gotIn flags shell and blocked responses instead of hiding them', () => {
  const d = seed();
  const rows = breach.gotIn(d, { sinceMs: 0 });
  const uris = rows.map((r) => r.uri);
  assert.ok(uris.some((u) => u.includes('/api/system/list')), 'real sensitive hit is present');
  for (const r of rows) {
    assert.ok(['real', 'likely-shell', 'likely-blocked', 'unknown'].includes(r.confidence));
  }
  const real = rows.find((r) => r.uri.includes('/api/system/list'));
  assert.equal(real.confidence, 'real');
});

test('nothing is filtered out — everything surfaces with a marker', () => {
  const d = seed();
  const rows = breach.gotIn(d, { sinceMs: 0, hostsWithAcl: new Set(['private.example.com']) });
  assert.ok(rows.length > 0);
  // the parked-page host is reported, but marked as blocked rather than a breach
  const parked = rows.filter((r) => r.host === 'private.example.com');
  if (parked.length) assert.equal(parked[0].confidence, 'likely-blocked');
});

test('dataOut ranks by bytes and finds the exfil', () => {
  const d = seed();
  const rows = breach.dataOut(d, { sinceMs: 0, limit: 5 });
  assert.equal(rows[0].client_ip, '203.0.113.10');
  assert.ok(rows[0].bytes >= 37701795);
});

test('triedAndFailed counts 401/403 per IP', () => {
  const d = seed();
  const rows = breach.triedAndFailed(d, { sinceMs: 0 });
  const r = rows.find((x) => x.client_ip === '5.5.5.5');
  assert.equal(r.failures, 4);
});

test('probing counts suspicious paths per IP', () => {
  const d = seed();
  const rows = breach.probing(d, { sinceMs: 0 });
  const r = rows.find((x) => x.client_ip === '7.7.7.7');
  assert.equal(r.probes, 3);
});

test('rows with no recorded size are marked unknown, never assumed safe', () => {
  const d = seed();
  d.prepare("UPDATE access_events SET size=NULL WHERE uri LIKE '%system/list%'").run();
  const rows = breach.gotIn(d, { sinceMs: 0 });
  const r = rows.find((x) => x.uri.includes('system/list'));
  assert.equal(r.confidence, 'unknown');
});

// ---- enrichment: identity, outcome, verdict --------------------------------
// The point of this layer is that the three questions a human asks on seeing a
// row — who is this, did they get anything, do I care — are answered on the
// page instead of requiring an investigation each time.

function seedEnrich() {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  const ev = (o) => rows.push({
    ts: now, client_ip: '1.1.1.1', host: 'h', method: 'GET', uri: '/', status: 200,
    user_agent: 'ua', suspicious_path: 0, size: 100, ...o,
  });
  // a cloud scanner: many paths, every answer is the parked page (fixed body)
  for (let i = 0; i < 30; i++) {
    ev({ client_ip: '198.51.100.20', host: 'www.example.com', uri: `/probe${i}`, size: 3171, suspicious_path: 1 });
  }
  // the owner, on an allowlist, doing real admin work
  for (let i = 0; i < 5; i++) {
    ev({ client_ip: '203.0.113.1', host: 'benchverz.com', uri: `/api/admin/tables/x/${i}`, size: 900 + i });
  }
  // an intruder: unique large payloads from a sensitive endpoint
  ev({ client_ip: '203.0.113.10', host: 'backups.example.com',
       uri: '/api/backups/download?file=db.sql.gz', size: 37701795 });
  // someone being refused repeatedly
  for (let i = 0; i < 25; i++) {
    ev({ client_ip: '5.5.5.5', host: 'finance.example.com', uri: '/api/clients', status: 401, size: 29 });
  }
  db.insertAccessEvents(d, rows);
  db.upsertIpInfo(d, { ip: '198.51.100.20', rdns: 'x.bc.googleusercontent.com', isp: 'Google LLC',
    org: 'Google Cloud', asn: 'AS15169', country: 'United States', country_code: 'US',
    region: '', city: '', is_proxy: 0, is_hosting: 1, is_mobile: 0 });
  return d;
}

const OPTS = () => ({
  sinceMs: 0,
  hostsWithAcl: new Set(['www.example.com']),
  allowlistedIps: new Set(['203.0.113.1']),
});

test('a scanner that received only fixed bodies is called noise, not a breach', () => {
  const r = breach.ipSummary(seedEnrich(), OPTS()).find((x) => x.client_ip === '198.51.100.20');
  assert.equal(r.real, 0, 'nothing real was served');
  assert.equal(r.blocked, 30, 'all answers were the parked page');
  assert.equal(r.verdict.level, 'noise');
  assert.match(r.verdict.text, /nothing/i);
});

test('identity is attached so the IP does not have to be looked up', () => {
  const r = breach.ipSummary(seedEnrich(), OPTS()).find((x) => x.client_ip === '198.51.100.20');
  assert.equal(r.org, 'Google Cloud');
  assert.equal(r.is_hosting, 1);
  assert.match(r.label, /Google/);
});

test('an allowlisted IP reading admin endpoints is your own access, not an alert', () => {
  const r = breach.ipSummary(seedEnrich(), OPTS()).find((x) => x.client_ip === '203.0.113.1');
  assert.equal(r.verdict.level, 'yours');
});

test('a real payload from a sensitive endpoint by an unlisted IP is an alert', () => {
  const r = breach.ipSummary(seedEnrich(), OPTS()).find((x) => x.client_ip === '203.0.113.10');
  assert.equal(r.verdict.level, 'alert');
  assert.ok(r.real_sensitive >= 1);
  assert.match(r.verdict.text, /sensitive/i);
});

test('repeated refusals are worth watching but are not a breach', () => {
  const r = breach.ipSummary(seedEnrich(), OPTS()).find((x) => x.client_ip === '5.5.5.5');
  assert.equal(r.verdict.level, 'watch');
  assert.equal(r.failures, 25);
});

test('verdict levels are always one of the known set', () => {
  for (const r of breach.ipSummary(seedEnrich(), OPTS())) {
    assert.ok(['alert', 'watch', 'noise', 'yours', 'quiet'].includes(r.verdict.level), r.verdict.level);
    assert.ok(r.verdict.text.length > 0);
  }
});

// ---- rule corrections found by running against real traffic ----------------
// 1. The allowlist is stored as CIDRs (192.168.1.0/24, 100.64.0.0/10). Matching
//    it as literal strings flagged the LAN gateway as an ALERT.
// 2. "Refused N times" fired ahead of "scanner that got nothing", so a Google
//    Cloud scanner with 258 parked-page responses was ranked WATCH, above real
//    findings. Being refused is what is *supposed* to happen.
// 3. Loopback and RFC1918 traffic is this machine talking to itself.

test('an IP inside an allowlisted CIDR counts as your own access', () => {
  // Uses a PUBLIC range on purpose: a LAN address would match the internal
  // rule first and prove nothing about CIDR handling.
  const d = seedEnrich();
  db.insertAccessEvents(d, [{ ts: Date.now(), client_ip: '203.0.113.2', host: 'h', method: 'GET',
    uri: '/api/admin/x', status: 200, user_agent: 'u', suspicious_path: 0, size: 4242 }]);
  const r = breach.ipSummary(d, { ...OPTS(), allowlistedIps: new Set(['203.0.113.0/24']) })
    .find((x) => x.client_ip === '203.0.113.2');
  assert.equal(r.verdict.level, 'yours', 'CIDR membership must be honoured');
  // and the same address outside the range is not
  const r2 = breach.ipSummary(d, { ...OPTS(), allowlistedIps: new Set(['198.51.100.0/24']) })
    .find((x) => x.client_ip === '203.0.113.2');
  assert.notEqual(r2.verdict.level, 'yours');
});

test('private and loopback addresses are internal, never alerts', () => {
  const d = seedEnrich();
  db.insertAccessEvents(d, [{ ts: Date.now(), client_ip: '192.168.1.1', host: 'h', method: 'GET',
    uri: '/api/admin/x', status: 200, user_agent: 'u', suspicious_path: 0, size: 5150 }]);
  const r = breach.ipSummary(d, OPTS()).find((x) => x.client_ip === '192.168.1.1');
  assert.equal(r.verdict.level, 'internal');
});

test('a scanner that got nothing stays noise even when refused many times', () => {
  const d = seedEnrich();
  const rows = [];
  for (let i = 0; i < 40; i++) {
    rows.push({ ts: Date.now(), client_ip: '198.51.100.20', host: 'www.example.com', method: 'GET',
      uri: `/probe-b${i}`, status: 403, user_agent: 'u', suspicious_path: 1, size: 29 });
  }
  db.insertAccessEvents(d, rows);
  const r = breach.ipSummary(d, OPTS()).find((x) => x.client_ip === '198.51.100.20');
  assert.equal(r.real_sensitive, 0);
  assert.equal(r.verdict.level, 'noise', 'being refused is the system working, not a finding');
});

test('verdict levels include the internal bucket', () => {
  for (const r of breach.ipSummary(seedEnrich(), OPTS())) {
    assert.ok(['alert', 'watch', 'noise', 'yours', 'internal', 'quiet'].includes(r.verdict.level), r.verdict.level);
  }
});

// ---- volume alone is not a signal ------------------------------------------
// A portfolio that serves video will hand 100+ MB to any engaged visitor. If
// that reads the same as 100 MB of database dumps, the WATCH bucket fills with
// ordinary visitors and stops being read. What matters is WHAT left, not how
// much — so the verdict names the content and the host it came from.

function seedVolume() {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  // a visitor pulling portfolio video from an unprotected public site
  for (let i = 0; i < 60; i++) {
    rows.push({ ts: now, client_ip: '198.51.100.30', host: 'portfolio.example.com', method: 'GET',
      uri: `/images/reel${i}_vid/video.mp4`, status: 200, user_agent: 'iPhone',
      suspicious_path: 0, size: 2_500_000 });
  }
  // an intruder pulling database dumps
  for (let i = 0; i < 4; i++) {
    rows.push({ ts: now, client_ip: '203.0.113.10', host: 'backups.example.com', method: 'GET',
      uri: `/api/backups/download?file=db${i}.sql.gz`, status: 200, user_agent: 'curl',
      suspicious_path: 0, size: 37_000_000 });
  }
  db.insertAccessEvents(d, rows);
  return d;
}

test('bulk public media is explained, not flagged as a threat', () => {
  const r = breach.ipSummary(seedVolume(), { sinceMs: 0, hostsWithAcl: new Set(), allowlistedIps: new Set() })
    .find((x) => x.client_ip === '198.51.100.30');
  assert.equal(r.verdict.level, 'quiet', 'a visitor watching portfolio video is not a finding');
  assert.match(r.verdict.text, /media/i, 'the verdict must say what the content was');
  assert.match(r.verdict.text, /portfolio\.example\.com/, 'and where it came from');
});

test('the same volume as database dumps is still an alert', () => {
  const r = breach.ipSummary(seedVolume(), {
    sinceMs: 0,
    hostsWithAcl: new Set(['backups.example.com']),
    allowlistedIps: new Set(),
  }).find((x) => x.client_ip === '203.0.113.10');
  assert.equal(r.verdict.level, 'alert');
});

test('content mix is reported so the row explains itself', () => {
  const r = breach.ipSummary(seedVolume(), { sinceMs: 0, hostsWithAcl: new Set(), allowlistedIps: new Set() })
    .find((x) => x.client_ip === '198.51.100.30');
  assert.equal(r.top_host, 'portfolio.example.com');
  assert.ok(r.content.media > 0.9, 'overwhelmingly media');
  assert.equal(r.content.archive, 0);
});

test('large identically-sized responses are content, not a catch-all page', () => {
  // A gallery can serve many files of the same byte size. Treating those as a
  // shell would report real data leaving as "nothing was served" — the exact
  // failure this module exists to prevent.
  const d = db.open(':memory:');
  const rows = [];
  for (let i = 0; i < 40; i++) {
    rows.push({ ts: Date.now(), client_ip: '9.9.9.9', host: 'gallery.example', method: 'GET',
      uri: `/v${i}.mp4`, status: 200, user_agent: 'u', suspicious_path: 0, size: 2_500_000 });
  }
  db.insertAccessEvents(d, rows);
  const shells = breach.shellSizes(d, 0);
  assert.ok(!shells.has('gallery.example|2500000'), '2.5 MB is far too large to be a shell page');
});

// ---- blocking guard ---------------------------------------------------------
// A one-click block sitting next to your own traffic is a foot-gun: blocking
// the allowlisted office line or the LAN gateway would cut you off from the very
// dashboard you are looking at. The guard refuses those outright and explains why.

test('blocking your own allowlisted IP is refused', () => {
  const g = breach.blockGuard({ client_ip: '203.0.113.2', verdict: { level: 'yours' } });
  assert.equal(g.allowed, false);
  assert.match(g.reason, /allowlist/i);
});

test('blocking the LAN or this machine is refused', () => {
  for (const ip of ['127.0.0.1', '192.168.1.1']) {
    const g = breach.blockGuard({ client_ip: ip, verdict: { level: 'internal' } });
    assert.equal(g.allowed, false, `${ip} must not be blockable`);
  }
});

test('an outside source is blockable', () => {
  const g = breach.blockGuard({ client_ip: '198.51.100.20', verdict: { level: 'noise' } });
  assert.equal(g.allowed, true);
});

test('the guard defends itself even when the verdict is missing', () => {
  assert.equal(breach.blockGuard({ client_ip: '127.0.0.1' }).allowed, false);
  assert.equal(breach.blockGuard({ client_ip: '10.0.0.5' }).allowed, false);
  assert.equal(breach.blockGuard({ client_ip: '8.8.8.8' }).allowed, true);
});

test('`blocked` on a summary row is the parked-page COUNT, not a flag', () => {
  // Blocklist membership must not be stored under this name. Overwriting it
  // turned "blocked 258" into "blocked false" in the UI and destroyed the
  // count that distinguishes a refused scanner from one that got through.
  const r = breach.ipSummary(seedEnrich(), OPTS()).find((x) => x.client_ip === '198.51.100.20');
  assert.equal(typeof r.blocked, 'number');
  assert.equal(r.blocked, 30);
});

// ---- per-IP path detail -----------------------------------------------------
// "Reached a sensitive endpoint" is only actionable if you can see WHICH one.
// Same classification as everywhere else, so a row that looks alarming but was
// answered with a catch-all page is not mistaken for a real read.

test('paths are grouped by path+status with counts and bytes', () => {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  for (let i = 0; i < 3; i++) {
    rows.push({ ts: now, client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/api/backups/download?file=a.gz',
      status: 200, user_agent: 'u', suspicious_path: 0, size: 1000 });
  }
  rows.push({ ts: now, client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/api/backups/download?file=a.gz',
    status: 401, user_agent: 'u', suspicious_path: 0, size: 29 });
  db.insertAccessEvents(d, rows);
  const out = breach.pathsForIp(d, '9.9.9.9', { sinceMs: 0 });
  const ok = out.find((r) => r.status === 200);
  assert.equal(ok.count, 3);
  assert.equal(ok.bytes, 3000);
  assert.ok(out.find((r) => r.status === 401), 'a different status is its own row');
});

test('path rows carry the same confidence marker as everything else', () => {
  const d = db.open(':memory:');
  const rows = [];
  // six distinct paths sharing one small size => a catch-all page
  for (let i = 0; i < 6; i++) {
    rows.push({ ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: `/shell${i}.php`,
      status: 200, user_agent: 'u', suspicious_path: 1, size: 1132 });
  }
  rows.push({ ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/api/system/list?path=/etc',
    status: 200, user_agent: 'u', suspicious_path: 0, size: 11427 });
  db.insertAccessEvents(d, rows);
  const out = breach.pathsForIp(d, '9.9.9.9', { sinceMs: 0 });
  assert.equal(out.find((r) => r.uri.includes('shell0')).confidence, 'likely-shell');
  assert.equal(out.find((r) => r.uri.includes('system/list')).confidence, 'real');
});

test('biggest transfers come first and the list is capped', () => {
  const d = db.open(':memory:');
  const rows = [];
  for (let i = 0; i < 200; i++) {
    rows.push({ ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: `/f${i}`,
      status: 200, user_agent: 'u', suspicious_path: 0, size: i * 10 });
  }
  db.insertAccessEvents(d, rows);
  const out = breach.pathsForIp(d, '9.9.9.9', { sinceMs: 0, limit: 25 });
  assert.equal(out.length, 25);
  assert.ok(out[0].bytes >= out[1].bytes, 'ordered by bytes desc');
});

test('an IP with no traffic yields an empty list, not a throw', () => {
  assert.deepEqual(breach.pathsForIp(db.open(':memory:'), '1.1.1.1', { sinceMs: 0 }), []);
});

// ---- handoff text -----------------------------------------------------------
// A block the operator can paste elsewhere for a second opinion. It leaves the
// machine by definition, so credential-bearing query parameters are redacted
// here the same way explain.js redacts them — the difference being that a path
// like ?file=db.sql.gz is evidence and must survive.

test('credential-bearing query parameters are redacted, the rest survives', () => {
  const u = breach.redactQuery('/api/backups/download?host=BravoNew&file=db.sql.gz&token=eyJhbGciOiJI.SECRET.sig');
  assert.match(u, /host=BravoNew/, 'ordinary parameters are evidence, keep them');
  assert.match(u, /file=db\.sql\.gz/, 'the filename is the whole point');
  assert.doesNotMatch(u, /eyJ|SECRET/, 'the token must not survive');
  assert.match(u, /token=REDACTED/);
});

test('every credential-ish parameter name is covered', () => {
  for (const k of ['token', 'access_token', 'api_key', 'apikey', 'key', 'secret', 'password', 'sig', 'signature', 'auth']) {
    const out = breach.redactQuery(`/x?${k}=SUPERSECRETVALUE`);
    assert.doesNotMatch(out, /SUPERSECRETVALUE/, `${k} leaked`);
  }
});

test('a path with no query string is untouched', () => {
  assert.equal(breach.redactQuery('/api/system/list'), '/api/system/list');
});

test('handoff text carries identity, verdict, counts, explanation and endpoints', () => {
  const text = breach.formatForHandoff({
    hours: 24,
    row: {
      client_ip: '203.0.113.10', label: 'Example ISP · XX', requests: 2367, bytes: 974000000,
      real: 1853, blocked: 56, shell: 324, unknown: 0, failures: 73, distinct_paths: 1893, hosts: 17,
      top_host: 'films.example.com', content: { media: 0.67, api: 0.17, archive: 0, code: 0.01, other: 0.15 },
      verdict: { level: 'alert', text: 'Reached a sensitive endpoint.' },
      first_ts: 1787250000000, last_ts: 1787260000000, is_hosting: 0,
    },
    explanation: { text: 'Systematic mirroring.', model: 'claude-opus-5', created_at: 1787300000000 },
    paths: [{ host: 'backups.example.com', uri: '/api/backups/download?file=db.sql.gz&token=eyJx.Y.Z',
              method: 'GET', status: 200, bytes: 113100000, count: 3, confidence: 'real', last_ts: 1787260000000 }],
  });
  assert.match(text, /203\.0\.113\.10/);
  assert.match(text, /ALERT/);
  assert.match(text, /real 1853/);
  assert.match(text, /Example ISP/);
  assert.match(text, /Systematic mirroring/);
  assert.match(text, /claude-opus-5/);
  assert.match(text, /api\/backups\/download/);
  assert.doesNotMatch(text, /eyJx/, 'tokens must not ride along in a paste');
});

test('handoff text is fine with no explanation and no paths', () => {
  const text = breach.formatForHandoff({
    hours: 1,
    row: { client_ip: '8.8.8.8', requests: 1, bytes: 0, real: 0, blocked: 0, shell: 0, unknown: 0,
           failures: 0, distinct_paths: 1, hosts: 1, verdict: { level: 'quiet', text: 'Ordinary.' },
           first_ts: 1, last_ts: 2 },
  });
  assert.match(text, /8\.8\.8\.8/);
  assert.match(text, /no AI assessment/i);
});

// ---- status must outrank size in the path detail ---------------------------
// The size classifier answers "was this body real content or a stock page?" —
// a question that only makes sense for a response that served something. Run
// over a 403 it labelled refusals "real", which is precisely the confusion the
// confidence marker exists to prevent.

test('refusals are marked refused, never real', () => {
  const d = db.open(':memory:');
  db.insertAccessEvents(d, [
    { ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/wp-admin/install.php',
      status: 403, user_agent: 'u', suspicious_path: 1, size: 30 },
    { ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/locked',
      status: 401, user_agent: 'u', suspicious_path: 0, size: 29 },
  ]);
  for (const p of breach.pathsForIp(d, '9.9.9.9', { sinceMs: 0 })) {
    assert.equal(p.confidence, 'refused', `${p.status} must be 'refused', got '${p.confidence}'`);
  }
});

test('404 is reported as not-found, and 5xx as error', () => {
  const d = db.open(':memory:');
  db.insertAccessEvents(d, [
    { ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/missing',
      status: 404, user_agent: 'u', suspicious_path: 0, size: 150 },
    { ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/boom',
      status: 500, user_agent: 'u', suspicious_path: 0, size: 87 },
  ]);
  const out = breach.pathsForIp(d, '9.9.9.9', { sinceMs: 0 });
  assert.equal(out.find((p) => p.status === 404).confidence, 'not-found');
  assert.equal(out.find((p) => p.status === 500).confidence, 'error');
});

test('served responses still get the size-based verdict', () => {
  const d = db.open(':memory:');
  const rows = [];
  for (let i = 0; i < 6; i++) {
    rows.push({ ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: `/s${i}`,
      status: 200, user_agent: 'u', suspicious_path: 0, size: 1132 });
  }
  rows.push({ ts: Date.now(), client_ip: '9.9.9.9', host: 'h', method: 'GET', uri: '/real',
    status: 200, user_agent: 'u', suspicious_path: 0, size: 99999 });
  db.insertAccessEvents(d, rows);
  const out = breach.pathsForIp(d, '9.9.9.9', { sinceMs: 0 });
  assert.equal(out.find((p) => p.uri === '/s0').confidence, 'likely-shell');
  assert.equal(out.find((p) => p.uri === '/real').confidence, 'real');
});

// A scan that FINDS something is the case that matters, and it was the one case
// the verdict dropped. The scan test correctly fired on distinct_paths, then the
// inner `real === 0` gate discarded it whenever anything had been served, so the
// row fell through to the closing "ordinary traffic" default. 20.196.209.81 walked
// 223 paths in 77 seconds, got 6 real responses, and was reported as ordinary.
function scanRow(over = {}) {
  return {
    client_ip: '20.196.209.81', requests: 445, bytes: 771500, distinct_paths: 223,
    real: 0, blocked: 0, shell: 0, unknown: 0, failures: 2, real_sensitive: 0,
    probes: 223, is_hosting: true, top_host: 'www.koraybirand.co.uk',
    protected_top_host: false, content: { media: 0, api: 0, archive: 0, code: 0, other: 1 },
    ...over,
  };
}

test('a scan that served nothing stays noise', () => {
  const v = breach.verdictFor(scanRow({ real: 0 }), false);
  assert.equal(v.level, 'noise');
  assert.match(v.text, /nothing served/);
});

test('a scan that served real content escalates to watch, not ordinary traffic', () => {
  for (const real of [1, 6, 50]) {
    const v = breach.verdictFor(scanRow({ real }), false);
    assert.equal(v.level, 'watch', `real=${real} should be watch`);
    assert.doesNotMatch(v.text, /ordinary traffic/);
    assert.match(v.text, /scan/i);
    assert.match(v.text, new RegExp(String(real)));
  }
});

test('a successful scan is notifiable, so it actually reaches you', () => {
  const notify = require('./notify');
  const v = breach.verdictFor(scanRow({ real: 6 }), false);
  assert.ok(notify.NOTIFIABLE.includes(v.level),
    `verdict "${v.level}" must be in NOTIFIABLE or the alert is never delivered`);
});

test('a sensitive hit still outranks the scan verdict', () => {
  const v = breach.verdictFor(scanRow({ real: 6, real_sensitive: 2 }), false);
  assert.equal(v.level, 'alert');
});

test('allowlisted and internal IPs are never called scans', () => {
  assert.equal(breach.verdictFor(scanRow({ real: 6 }), true).level, 'yours');
  assert.equal(breach.verdictFor(scanRow({ client_ip: '192.168.1.67', real: 6 }), false).level, 'internal');
});

// The first cut of the scan fix regressed exactly here: a visitor browsing a
// gallery touches 60 distinct paths, which tripped the same distinct_paths test
// the scanner does. Many paths is not the signal — being REFUSED on them is.
test('browsing many pages is not a scan when every request is answered', () => {
  const browsing = {
    client_ip: '198.51.100.30', requests: 60, bytes: 5000, distinct_paths: 60,
    real: 60, blocked: 0, shell: 0, unknown: 0, failures: 0, real_sensitive: 0,
    probes: 0, is_hosting: false, top_host: 'portfolio.example.com',
    protected_top_host: false, content: { media: 1, api: 0, archive: 0, code: 0, other: 0 },
  };
  const v = breach.verdictFor(browsing, false);
  assert.notEqual(v.level, 'watch', 'a visitor answered on every request is not a scan');
  assert.doesNotMatch(v.text, /scan/i);
});

test('being answered on known probe paths is a scan even without refusals', () => {
  const v = breach.verdictFor(scanRow({ requests: 40, real: 40, probes: 40, failures: 0 }), false);
  assert.equal(v.level, 'watch', 'hits on probe paths that returned content are worse, not better');
});

// 168.62.48.100 walked 90 paths and was served exactly once. The verdict said
// "1 returned real content. Check what was served" — and the table below it
// showed sixty 404s and not the served row, because it ordered by bytes and cut
// at 60. Every 404 was 3212 bytes; the served response was smaller, so the one
// row worth reading sorted below all 89 refusals. Truncation must drop refusals,
// never evidence.
test('the served row survives truncation even when it is the smallest', () => {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  for (let i = 0; i < 89; i++) {
    rows.push({ ts: now, client_ip: '168.62.48.100', host: 'k', method: 'GET',
      uri: `/wp-includes/blocks/x${i}/index.php`, status: 404, user_agent: 'u',
      suspicious_path: 1, size: 3212 });
  }
  // the single served response, deliberately tiny
  rows.push({ ts: now, client_ip: '168.62.48.100', host: 'k', method: 'GET',
    uri: '/the-one-that-answered', status: 200, user_agent: 'u',
    suspicious_path: 0, size: 412 });
  db.insertAccessEvents(d, rows);

  const out = breach.pathsForIp(d, '168.62.48.100', { sinceMs: 0, limit: 60 });
  assert.equal(out.length, 60);
  const served = out.find((r) => r.uri === '/the-one-that-answered');
  assert.ok(served, 'the served row must appear despite being the smallest of 90');
  assert.equal(out[0].uri, '/the-one-that-answered', 'and it must lead the table');
});

// A redirect is a signpost, not a page. `classify` only ever looked at body size,
// so any status under 400 that carried bytes was called real content served —
// 301, 302 and 304 included. That is what put 168.62.48.100 on WATCH: one answer
// among 90 refusals, counted as content without anyone checking it was content.
test('redirects are labelled as redirects, not as real content', () => {
  for (const st of [301, 302, 303, 307, 308, 304]) {
    assert.equal(breach.classifyPath({ host: 'h', status: st, size: 412 }, new Set(), new Set()),
      'redirect', `status ${st} is not content`);
  }
  assert.equal(breach.classifyPath({ host: 'h', status: 200, size: 412 }, new Set(), new Set()), 'real');
});

test('a scan answered only by redirects served nothing, so it is not a WATCH', () => {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  for (let i = 0; i < 89; i++) {
    rows.push({ ts: now, client_ip: '168.62.48.100', host: 'k', method: 'GET',
      uri: `/wp/x${i}.php`, status: 404, user_agent: 'u', suspicious_path: 1, size: 3212 });
  }
  rows.push({ ts: now, client_ip: '168.62.48.100', host: 'k', method: 'GET',
    uri: '/somewhere', status: 302, user_agent: 'u', suspicious_path: 0, size: 412 });
  db.insertAccessEvents(d, rows);
  const r = breach.ipSummary(d, { sinceMs: 0, hostsWithAcl: new Set(), allowlistedIps: new Set() })
    .find((x) => x.client_ip === '168.62.48.100');
  assert.equal(r.real, 0, 'a redirect is not a served response');
  assert.equal(r.verdict.level, 'noise', 'nothing was served, so this is an ordinary scan');
});

test('the same scan answered by a real page IS a WATCH', () => {
  const d = db.open(':memory:');
  const now = Date.now();
  const rows = [];
  for (let i = 0; i < 89; i++) {
    rows.push({ ts: now, client_ip: '168.62.48.100', host: 'k', method: 'GET',
      uri: `/wp/x${i}.php`, status: 404, user_agent: 'u', suspicious_path: 1, size: 3212 });
  }
  rows.push({ ts: now, client_ip: '168.62.48.100', host: 'k', method: 'GET',
    uri: '/somewhere', status: 200, user_agent: 'u', suspicious_path: 0, size: 412 });
  db.insertAccessEvents(d, rows);
  const r = breach.ipSummary(d, { sinceMs: 0, hostsWithAcl: new Set(), allowlistedIps: new Set() })
    .find((x) => x.client_ip === '168.62.48.100');
  assert.equal(r.real, 1);
  assert.equal(r.verdict.level, 'watch', 'a real page among 90 probes still deserves a look');
});

test('a redirect still appears in the endpoint table — hidden is not the fix', () => {
  const d = db.open(':memory:');
  const now = Date.now();
  db.insertAccessEvents(d, [
    { ts: now, client_ip: '5.5.5.5', host: 'k', method: 'GET', uri: '/gone',
      status: 302, user_agent: 'u', suspicious_path: 0, size: 412 },
    { ts: now, client_ip: '5.5.5.5', host: 'k', method: 'GET', uri: '/missing',
      status: 404, user_agent: 'u', suspicious_path: 0, size: 3212 },
  ]);
  const out = breach.pathsForIp(d, '5.5.5.5', { sinceMs: 0 });
  const red = out.find((r) => r.uri === '/gone');
  assert.ok(red, 'the redirect must still be listed');
  assert.equal(red.confidence, 'redirect');
});

// The same defect lived in gotIn: it selected status 200-399 and labelled every
// row with classify(), which reads body size only. A 302 off /admin/ therefore
// appeared under "got in" as real content. Leaving this while fixing pathsForIp
// would have the panel calling the same response content on one screen and a
// signpost on another.
test('a redirect off a sensitive path is not reported as having got in', () => {
  const d = db.open(':memory:');
  const now = Date.now();
  db.insertAccessEvents(d, [
    { ts: now, client_ip: '7.7.7.7', host: 'k', method: 'GET', uri: '/admin/users',
      status: 302, user_agent: 'u', suspicious_path: 0, size: 412 },
    { ts: now, client_ip: '7.7.7.7', host: 'k', method: 'GET', uri: '/admin/keys',
      status: 200, user_agent: 'u', suspicious_path: 0, size: 9000 },
  ]);
  const rows = breach.gotIn(d, { sinceMs: 0, hostsWithAcl: new Set() });
  const red = rows.find((r) => r.uri === '/admin/users');
  const page = rows.find((r) => r.uri === '/admin/keys');
  assert.ok(red, 'the redirect stays visible — hiding it is not the fix');
  assert.equal(red.confidence, 'redirect', 'but it is not real content');
  assert.equal(page.confidence, 'real', 'a genuine 200 is untouched');
});

// Cloudflare hands us the visitor's real address, and for anyone with IPv6 that
// address is IPv6 — even though this estate has no IPv6 route of its own and
// Caddy is reached over IPv4. inAllowlist parsed addresses with an IPv4-only
// routine and returned false for everything else, so an allowlisted guest read
// as an unrecognised outsider and blockGuard offered to block them. The same
// applies to you the first time you browse on mobile data.
test('inAllowlist matches IPv6 literals and prefixes', () => {
  const allow = new Set(['212.154.65.70', '2a02:ff0:254:9e28::/64']);
  assert.equal(breach.inAllowlist('2a02:ff0:254:9e28:2cca:f431:790f:4e90', allow), true,
    'the /64 must cover a rotating privacy address');
  assert.equal(breach.inAllowlist('2a02:ff0:254:9e29:2cca:f431:790f:4e90', allow), false,
    'a different /64 is a different subscriber');
  assert.equal(breach.inAllowlist('212.154.65.70', allow), true, 'IPv4 still works');
});

test('inAllowlist compares like for like, and normalises IPv6 spelling', () => {
  assert.equal(breach.inAllowlist('::1', new Set(['0:0:0:0:0:0:0:1'])), true,
    'the same address written two ways is the same address');
  assert.equal(breach.inAllowlist('2a02:ff0::1', new Set(['10.0.0.0/8'])), false,
    'an IPv4 range never matches an IPv6 address');
  assert.equal(breach.inAllowlist('10.0.0.5', new Set(['::/0'])), false,
    'and an IPv6 range never matches an IPv4 address');
  assert.equal(breach.inAllowlist('::ffff:212.154.65.70', new Set(['212.154.65.70'])), true,
    'an IPv4-mapped address is that IPv4 address');
});

test('blockGuard protects an allowlisted IPv6 guest', () => {
  const allow = new Set(['2a02:ff0:254:9e28::/64']);
  const ip = '2a02:ff0:254:9e28:2cca:f431:790f:4e90';
  const verdict = breach.verdictFor({ client_ip: ip, requests: 5, bytes: 100, distinct_paths: 3,
    real: 5, blocked: 0, shell: 0, unknown: 0, failures: 0, real_sensitive: 0, probes: 0,
    is_hosting: false, content: { media: 0, api: 0, archive: 0, code: 0, other: 1 } },
    breach.inAllowlist(ip, allow));
  assert.equal(verdict.level, 'yours', 'an allowlisted guest is yours, not an outsider');
  assert.equal(breach.blockGuard({ client_ip: ip, verdict }).allowed, false,
    'and the panel must refuse to block them');
});

test('isInternal knows IPv6 private ranges', () => {
  assert.equal(breach.isInternal('fd12:3456::1'), true, 'unique-local is this network');
  assert.equal(breach.isInternal('fe80::1'), true, 'link-local is this wire');
  assert.equal(breach.isInternal('::1'), true);
  assert.equal(breach.isInternal('2a02:ff0:254:9e28::1'), false, 'a public address is not internal');
  assert.equal(breach.isInternal('192.168.1.67'), true, 'IPv4 unchanged');
  assert.equal(breach.isInternal('8.8.8.8'), false);
});

test('malformed addresses are rejected, never matched', () => {
  const allow = new Set(['2a02:ff0:254:9e28::/64', '10.0.0.0/8']);
  for (const bad of ['', 'not-an-ip', '10.0.0', '10.0.0.256', '1:2:3::4::5', 'gggg::1', '2a02:ff0:254:9e28::/999']) {
    assert.equal(breach.inAllowlist(bad, allow), false, `${bad} must not match`);
  }
  assert.equal(breach.inAllowlist('10.0.0.5', new Set(['2a02:ff0:254:9e28::/999'])), false,
    'a malformed ENTRY must not match either');
});

// `real * 2 < requests` was too crude a stand-in for "mostly refused". A busy
// API client trips it: 95.70.219.213 made 3,307 requests over 256 distinct paths
// — every workflow-image id is its own URI — and 1,638 came back as real content
// with another 1,128 classified as shell because the API answers many endpoints
// with same-sized JSON. Just over half not-real, so it read as a scan, and a
// colleague using the product was reported as an intruder.
//
// What actually separates them is how often the server said "no such thing".
// A scanner is refused on nearly everything; a client is refused on almost
// nothing. That ratio is 99% versus 16% on real traffic.
function row(over = {}) {
  return {
    client_ip: '198.51.100.1', requests: 100, bytes: 1000, distinct_paths: 50,
    real: 0, blocked: 0, shell: 0, unknown: 0, failures: 0, real_sensitive: 0,
    probes: 0, is_hosting: false, top_host: 'h', protected_top_host: false,
    content: { media: 0, api: 0, archive: 0, code: 0, other: 1 }, ...over,
  };
}

test('a busy API client is not a scan, even across hundreds of paths', () => {
  const v = breach.verdictFor(row({
    requests: 3307, distinct_paths: 256, real: 1638, shell: 1128, bytes: 3.2e9,
    content: { media: 0.05, api: 0.95, archive: 0, code: 0, other: 0 },
  }), false);
  // It may still be flagged on VOLUME — 3.2 GB from an address the panel does
  // not recognise is worth a look — but it must not be called a scan, which is
  // the part that was wrong and the part that makes the report unreadable.
  assert.doesNotMatch(v.text, /scan/i, '16% refused is a client, not a scanner');
  assert.match(v.text, /GB|MB/, 'the honest reason is the volume');
});

test('a scanner refused on nearly everything is still caught', () => {
  const v = breach.verdictFor(row({ requests: 445, distinct_paths: 223, real: 6, probes: 223 }), false);
  assert.equal(v.level, 'watch');
  assert.match(v.text, /scan/i);
});

test('and one refused on everything stays noise', () => {
  const v = breach.verdictFor(row({ requests: 445, distinct_paths: 223, real: 0, probes: 223 }), false);
  assert.equal(v.level, 'noise');
});

test('shell responses count as answered — the server did reply', () => {
  // An SPA catch-all and an API returning same-sized JSON both land in `shell`.
  // Neither is the server saying "no such thing", which is what marks a scan.
  const v = breach.verdictFor(row({ requests: 200, distinct_paths: 100, real: 10, shell: 180 }), false);
  assert.notEqual(v.level, 'watch');
});
