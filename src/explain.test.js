const test = require('node:test');
const assert = require('node:assert/strict');
const explain = require('./explain');

const ROW = {
  client_ip: '203.0.113.10',
  label: 'Example ISP · TR',
  requests: 2367, bytes: 974000000, real: 1825, blocked: 56, shell: 352, unknown: 0,
  failures: 73, probes: 12, distinct_paths: 400, hosts: 17,
  top_host: 'films.example.com',
  content: { media: 0.67, api: 0.17, archive: 0.0, code: 0.01, other: 0.15 },
  verdict: { level: 'alert', text: 'Reached a sensitive endpoint and received real content.' },
  first_ts: 1787250000000, last_ts: 1787260000000,
  is_hosting: 0, country: 'Exampleland', org: 'Example ISP',
};

// The access log carries live credentials: DiskKatalog puts JWTs in query
// strings, and sqlbackup download URLs carry a `token=` parameter. Those must
// never leave the machine. Redaction is not a nicety here — it is the reason
// this feature was allowed to be built before that leak is fixed.
test('query strings are stripped from every path before sending', () => {
  const p = explain.buildPayload(ROW, [
    { uri: '/api/backups/download?host=X&file=db.sql.gz&token=eyJhbGciOiJIUzI1NiJ9.SECRET.sig', status: 200, size: 37701795 },
    { uri: '/api/disks/scan/progress/42?token=eyJhbGciOiJIUzI1NiJ9.ANOTHER.sig', status: 200, size: 12 },
  ]);
  const blob = JSON.stringify(p);
  assert.doesNotMatch(blob, /token=/, 'no token parameter may survive');
  assert.doesNotMatch(blob, /eyJ/, 'no JWT may survive');
  assert.doesNotMatch(blob, /SECRET|ANOTHER/, 'no secret material may survive');
  assert.match(blob, /\/api\/backups\/download/, 'the path itself is still useful context');
});

test('no request headers, cookies or user identifiers are included', () => {
  const p = explain.buildPayload({ ...ROW, user_agent: 'curl/8.7.1' }, [
    { uri: '/x', status: 200, size: 1, headers: { Cookie: ['session=abc'] } },
  ]);
  const blob = JSON.stringify(p).toLowerCase();
  assert.doesNotMatch(blob, /cookie|authorization|set-cookie|session=/);
});

test('payload carries the facts a verdict needs', () => {
  const p = explain.buildPayload(ROW, [{ uri: '/a', status: 200, size: 5 }]);
  assert.equal(p.ip, '203.0.113.10');
  assert.equal(p.identity, 'Example ISP · TR');
  assert.equal(p.received.real, 1825);
  assert.equal(p.verdict, 'alert');
  assert.ok(p.sample_paths.length > 0);
});

test('path samples are capped and truncated so the prompt cannot balloon', () => {
  const many = Array.from({ length: 500 }, (_, i) => ({ uri: `/p${i}/${'x'.repeat(400)}`, status: 200, size: 1 }));
  const p = explain.buildPayload(ROW, many);
  assert.ok(p.sample_paths.length <= 40, `capped, got ${p.sample_paths.length}`);
  for (const s of p.sample_paths) assert.ok(s.path.length <= 120, 'each path truncated');
});

// --- transport ---------------------------------------------------------------

function fakeFetch(response, capture) {
  return async (url, opts) => {
    if (capture) { capture.url = url; capture.opts = opts; }
    return { ok: true, status: 200, json: async () => response, text: async () => JSON.stringify(response) };
  };
}

test('calls the Kie Claude messages endpoint with bearer auth', async () => {
  const cap = {};
  const out = await explain.askClaude(
    { ip: '1.2.3.4' },
    { apiKey: 'K', fetchImpl: fakeFetch({ content: [{ type: 'text', text: 'A scanner. Harmless.' }] }, cap) },
  );
  assert.equal(cap.url, 'https://api.kie.ai/claude/v1/messages');
  assert.equal(cap.opts.headers.Authorization, 'Bearer K');
  const body = JSON.parse(cap.opts.body);
  assert.equal(body.model, 'claude-opus-5');
  assert.equal(body.stream, false);
  assert.ok(body.max_tokens > 0);
  assert.equal(out.text, 'A scanner. Harmless.');
});

test('a missing API key fails clearly rather than silently doing nothing', async () => {
  await assert.rejects(
    () => explain.askClaude({ ip: '1.2.3.4' }, { apiKey: '', fetchImpl: fakeFetch({}) }),
    /KIE_API_KEY/,
  );
});

test('an upstream error surfaces as an error, never as a fake explanation', async () => {
  const failing = async () => ({ ok: false, status: 502, text: async () => 'bad gateway', json: async () => ({}) });
  await assert.rejects(
    () => explain.askClaude({ ip: '1.2.3.4' }, { apiKey: 'K', fetchImpl: failing }),
    /502/,
  );
});

// ---- persistence ------------------------------------------------------------
// An explanation costs real money to produce. Keeping it only in a per-process
// Map meant a page refresh threw it away and the next click paid again — and
// "Explain again" silently returned the cached text, so the button looked dead.

const db = require('./db');

test('an explanation survives a restart', () => {
  const d = db.open(':memory:');
  db.saveExplanation(d, { ip: '1.2.3.4', hours: 24, text: 'A scanner.', model: 'claude-opus-5', usage: { output_tokens: 12 } });
  const got = db.getExplanation(d, '1.2.3.4', 24);
  assert.equal(got.text, 'A scanner.');
  assert.equal(got.model, 'claude-opus-5');
  assert.ok(got.created_at > 0);
});

test('re-explaining replaces the stored text rather than duplicating it', () => {
  const d = db.open(':memory:');
  db.saveExplanation(d, { ip: '1.2.3.4', hours: 24, text: 'first', model: 'm' });
  db.saveExplanation(d, { ip: '1.2.3.4', hours: 24, text: 'second', model: 'm' });
  assert.equal(db.getExplanation(d, '1.2.3.4', 24).text, 'second');
  assert.equal(d.prepare('SELECT COUNT(*) c FROM explanations').get().c, 1);
});

test('explanations are stored per window, not shared across them', () => {
  const d = db.open(':memory:');
  db.saveExplanation(d, { ip: '1.2.3.4', hours: 24, text: 'day', model: 'm' });
  db.saveExplanation(d, { ip: '1.2.3.4', hours: 168, text: 'week', model: 'm' });
  assert.equal(db.getExplanation(d, '1.2.3.4', 24).text, 'day');
  assert.equal(db.getExplanation(d, '1.2.3.4', 168).text, 'week');
});

test('many stored explanations can be fetched at once for the summary table', () => {
  const d = db.open(':memory:');
  db.saveExplanation(d, { ip: '1.1.1.1', hours: 24, text: 'a', model: 'm' });
  db.saveExplanation(d, { ip: '2.2.2.2', hours: 24, text: 'b', model: 'm' });
  const map = db.getExplanationsMany(d, ['1.1.1.1', '2.2.2.2', '3.3.3.3'], 24);
  assert.equal(map['1.1.1.1'].text, 'a');
  assert.equal(map['2.2.2.2'].text, 'b');
  assert.equal(map['3.3.3.3'], undefined);
});

test('missing explanation returns null, not a throw', () => {
  assert.equal(db.getExplanation(db.open(':memory:'), '9.9.9.9', 24), null);
});
