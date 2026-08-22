const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('./db');
const notify = require('./notify');

const ALERT = {
  client_ip: '203.0.113.10', label: 'Example ISP · XX', requests: 2367, bytes: 974000000,
  real: 1853, real_sensitive: 99, blocked: 56, shell: 324, unknown: 0, failures: 73,
  top_host: 'films.example.com',
  verdict: { level: 'alert', text: 'Reached a sensitive endpoint and received real content (99 responses).' },
};
const NOISE = { ...ALERT, client_ip: '8.8.8.8', real_sensitive: 0, verdict: { level: 'noise', text: 'Automated scan.' } };

test('only ALERT and WATCH are worth a notification', () => {
  // Originally ALERT alone. WATCH was added after measuring the real rate —
  // 4 sources in 72h — and is sent at a lower priority so it cannot wake
  // anyone. NOISE and QUIET remain permanently excluded: paging on those would
  // drown the channel that matters.
  const d = db.open(':memory:');
  assert.equal(notify.shouldNotify(d, ALERT), true);
  assert.equal(notify.shouldNotify(d, NOISE), false);
  assert.deepEqual(notify.NOTIFIABLE, ['alert', 'watch']);
});

test('the same source does not notify twice inside the cooldown', () => {
  const d = db.open(':memory:');
  assert.equal(notify.shouldNotify(d, ALERT), true);
  notify.recordNotified(d, ALERT.client_ip, 'alert');
  assert.equal(notify.shouldNotify(d, ALERT), false, 'a phone buzzing every 30s is a phone that gets ignored');
});

test('it notifies again once the cooldown has elapsed', () => {
  const d = db.open(':memory:');
  notify.recordNotified(d, ALERT.client_ip, 'alert');
  d.prepare('UPDATE notifications SET sent_at = ? WHERE ip = ?')
    .run(Date.now() - (notify.COOLDOWN_MS + 60000), ALERT.client_ip);
  assert.equal(notify.shouldNotify(d, ALERT), true);
});

test('the message says what happened without leaking anything', () => {
  const m = notify.buildMessage(ALERT);
  assert.match(m.title, /203\.0\.113\.10/);
  assert.match(m.body, /sensitive endpoint/i);
  assert.match(m.body, /films\.example\.com/);
  assert.match(m.body, /974/, 'volume is the detail that conveys urgency');
  // nothing that would be a credential or a working URL
  assert.doesNotMatch(JSON.stringify(m), /token|eyJ|password|Bearer/i);
  assert.ok(m.priority >= 4, 'a breach should break through silent mode');
});

// --- transport ---------------------------------------------------------------

function fakeFetch(capture, ok = true) {
  return async (url, opts) => {
    capture.url = url; capture.opts = opts;
    return { ok, status: ok ? 200 : 500, text: async () => (ok ? 'ok' : 'nope') };
  };
}

test('posts to the configured ntfy topic with priority and title headers', async () => {
  const cap = {};
  await notify.send({ title: 'T', body: 'B', priority: 5, tags: 'rotating_light' },
    { server: 'https://ntfy.sh', topic: 'secret-topic', fetchImpl: fakeFetch(cap) });
  assert.equal(cap.url, 'https://ntfy.sh/secret-topic');
  assert.equal(cap.opts.headers.Title, 'T');
  assert.equal(cap.opts.headers.Priority, '5');
  assert.equal(cap.opts.body, 'B');
});

test('an unconfigured topic is a clear no-op, not a crash', async () => {
  const r = await notify.send({ title: 'T', body: 'B' }, { topic: '', fetchImpl: fakeFetch({}) });
  assert.equal(r.sent, false);
  assert.match(r.reason, /not configured/i);
});

test('a failed send never throws into the watcher loop', async () => {
  const r = await notify.send({ title: 'T', body: 'B' },
    { server: 'https://ntfy.sh', topic: 't', fetchImpl: fakeFetch({}, false) });
  assert.equal(r.sent, false);
  assert.match(r.reason, /500/);
});

test('a source is only recorded as notified when the send actually succeeded', async () => {
  const d = db.open(':memory:');
  await notify.runOnce(d, [ALERT], { server: 'https://ntfy.sh', topic: 't', fetchImpl: fakeFetch({}, false) });
  assert.equal(notify.shouldNotify(d, ALERT), true, 'a failed send must not suppress the next attempt');
  await notify.runOnce(d, [ALERT], { server: 'https://ntfy.sh', topic: 't', fetchImpl: fakeFetch({}) });
  assert.equal(notify.shouldNotify(d, ALERT), false);
});

// ---- WATCH notifications ----------------------------------------------------
// Measured before enabling: 4 WATCH sources in 72h, about one a day — low
// enough not to cause fatigue. But all four were "refused N times", the least
// urgent kind, so WATCH must not break Do Not Disturb the way ALERT does.

const WATCH = {
  ...ALERT, client_ip: '198.51.100.50', real_sensitive: 0,
  verdict: { level: 'watch', text: 'Refused 62 times, and nothing sensitive was served.' },
};

test('WATCH sources notify when enabled', () => {
  const d = db.open(':memory:');
  assert.equal(notify.shouldNotify(d, WATCH, { levels: ['alert', 'watch'] }), true);
});

test('WATCH is ignored when only ALERT is enabled', () => {
  const d = db.open(':memory:');
  assert.equal(notify.shouldNotify(d, WATCH, { levels: ['alert'] }), false);
  assert.equal(notify.shouldNotify(d, ALERT, { levels: ['alert'] }), true);
});

test('ALERT breaks Do Not Disturb, WATCH does not', () => {
  assert.ok(notify.buildMessage(ALERT).priority >= 5, 'a breach must cut through silent mode');
  const w = notify.buildMessage(WATCH);
  assert.ok(w.priority < 5, 'a scanner being refused must not wake anyone at 3am');
  assert.ok(w.priority >= 2);
});

test('the two levels are visibly different on the lock screen', () => {
  const a = notify.buildMessage(ALERT), w = notify.buildMessage(WATCH);
  assert.notEqual(a.title, w.title);
  assert.notEqual(a.tags, w.tags);
  assert.match(w.title, /198\.51\.100\.50/);
});

test('escalation from WATCH to ALERT still notifies despite the cooldown', () => {
  const d = db.open(':memory:');
  const opts = { levels: ['alert', 'watch'] };
  notify.recordNotified(d, WATCH.client_ip, 'watch');
  assert.equal(notify.shouldNotify(d, WATCH, opts), false, 'same level is suppressed');
  const escalated = { ...WATCH, verdict: { level: 'alert', text: 'now serious' }, real_sensitive: 3 };
  assert.equal(notify.shouldNotify(d, escalated, opts), true,
    'a source that gets worse must break through its own cooldown');
});

test('QUIET and NOISE never notify, whatever is enabled', () => {
  const d = db.open(':memory:');
  for (const lvl of ['noise', 'quiet', 'yours', 'internal']) {
    const row = { ...ALERT, verdict: { level: lvl, text: 'x' } };
    assert.equal(notify.shouldNotify(d, row, { levels: ['alert', 'watch', lvl] }), false,
      `${lvl} must never page anyone`);
  }
});

// This module opens by promising the message names the IP, the host and the
// volume and stops there, because notifications cross a third party and land on
// a lock screen. Endpoints were asked for anyway — you cannot judge "check what
// was served" without them — so they go in REDACTED and CAPPED: the shape of the
// request, never the query values that carry credentials or filenames.
const REAL_ROW = {
  client_ip: '203.0.113.10',
  label: 'Example Cloud · US',
  top_host: 'lab.example.com',
  requests: 429, bytes: 186_300_000, real: 340, failures: 8,
  verdict: { level: 'watch', text: '186 MB from lab.example.com.' },
};

test('served endpoints appear, redacted and capped', () => {
  const msg = notify.buildMessage(REAL_ROW, {
    paths: [
      { uri: '/api/backups/download?file=prod-2026-08.sql.gz&token=abcd', confidence: 'real', bytes: 9_900_000 },
      { uri: '/api/uploads/082026/19/assets/wf-gen-1787136210669.jpg', confidence: 'real', bytes: 9_100_000 },
      { uri: '/admin/users', confidence: 'real', bytes: 4_000 },
      { uri: '/wp-login.php', confidence: 'not-found', bytes: 3_212 },
      { uri: '/never-shown', confidence: 'real', bytes: 1 },
    ],
  });
  assert.match(msg.body, /\/api\/backups\/download/, 'the endpoint shape is the point');
  assert.doesNotMatch(msg.body, /prod-2026-08/, 'a filename is not shape, it is content');
  assert.doesNotMatch(msg.body, /abcd/, 'and a token must never ride a lock screen');
  assert.doesNotMatch(msg.body, /wp-login/, 'only what was actually SERVED is listed');
  assert.doesNotMatch(msg.body, /never-shown/, 'capped at three');
});

test('a message with no path data is unchanged', () => {
  const msg = notify.buildMessage(REAL_ROW, {});
  assert.match(msg.body, /Source: 203\.0\.113\.10/);
  assert.ok(!msg.actions, 'no action without a configured block url');
});

test('the block button carries the token and posts', () => {
  const msg = notify.buildMessage(REAL_ROW, { blockUrl: 'https://block.example.com/api/block/TOK123' });
  assert.match(msg.actions, /^http,/, 'an http action fires without opening a browser');
  assert.match(msg.actions, /https:\/\/block\.example\.com\/api\/block\/TOK123/);
  assert.match(msg.actions, /method=POST/, 'GET would let a link preview block an IP');
  assert.match(msg.actions, /203\.0\.113\.10/, 'the button says which IP it blocks');
});

test('the action never contains a comma that would split the header', () => {
  const msg = notify.buildMessage({ ...REAL_ROW, label: 'Big Corp, Inc · US' },
    { blockUrl: 'https://block.example.com/api/block/TOK123' });
  const fields = msg.actions.split(',').map((s) => s.trim());
  assert.equal(fields[0], 'http');
  assert.ok(fields[2].startsWith('https://'), 'the url must land in the third field');
});

test('send passes the action through to ntfy', async () => {
  let seen = null;
  await notify.send(
    { title: 't', body: 'b', priority: 3, tags: 'warning', actions: 'http, Block, https://x/y, method=POST' },
    { topic: 'topic', fetchImpl: async (url, init) => { seen = init; return { ok: true }; } },
  );
  assert.equal(seen.headers.Actions, 'http, Block, https://x/y, method=POST');
});

test('send omits the Actions header entirely when there is none', async () => {
  let seen = null;
  await notify.send({ title: 't', body: 'b' },
    { topic: 'topic', fetchImpl: async (url, init) => { seen = init; return { ok: true }; } });
  assert.ok(!('Actions' in seen.headers), 'an empty header is not the same as no header');
});
