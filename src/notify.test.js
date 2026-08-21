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

test('only ALERT sources are worth waking someone for', () => {
  const d = db.open(':memory:');
  assert.equal(notify.shouldNotify(d, ALERT), true);
  assert.equal(notify.shouldNotify(d, NOISE), false);
  assert.equal(notify.shouldNotify(d, { ...ALERT, verdict: { level: 'watch', text: 'x' } }), false);
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
