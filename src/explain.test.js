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

// ---- resilience -------------------------------------------------------------
// Kie's /claude/v1/messages route returned 500 for every request, on a trivial
// prompt, across both models — an upstream outage, not a rejected request.
// Retry handles the transient case; the fallback model covers a fault specific
// to one model; and when neither works the error must say so plainly, or the
// next person assumes the feature is broken and goes looking in the wrong place.

function seqFetch(responses, calls) {
  let i = 0;
  return async (url, opts) => {
    const r = responses[Math.min(i, responses.length - 1)];
    if (calls) calls.push(JSON.parse(opts.body).model);
    i += 1;
    if (r.throw) throw new Error(r.throw);
    return {
      ok: r.status === 200, status: r.status,
      json: async () => r.body || {},
      text: async () => JSON.stringify(r.body || {}),
    };
  };
}
const OK = { status: 200, body: { content: [{ type: 'text', text: 'fine' }] } };
const BOOM = { status: 500, body: { error: { message: 'Server exception' } } };

test('a transient 500 is retried and succeeds', async () => {
  const calls = [];
  const out = await explain.askClaude({ ip: '1.2.3.4' }, {
    apiKey: 'K', retryDelayMs: 0, fetchImpl: seqFetch([BOOM, OK], calls),
  });
  assert.equal(out.text, 'fine');
  assert.equal(calls.length, 2);
});

test('one dead provider is not survivable by retrying alone', () => {
  // Superseded design, kept as a reminder of why: the original fallback was
  // model-level (opus-5 then opus-4-8) on a single vendor. Kie's outage took
  // out every model on that one route at once — the same trivial prompt failed
  // on both — so switching model achieved nothing. Fallback has to cross
  // vendors, which is what PROVIDERS encodes.
  assert.equal(explain.PROVIDERS.length, 2);
  const hosts = explain.PROVIDERS.map((p) => new URL(p.url).host);
  assert.equal(new Set(hosts).size, 2, 'the two providers must be different vendors');
});

test('a total outage reports an upstream fault, not a user error', async () => {
  await assert.rejects(
    () => explain.askClaude({ ip: '1.2.3.4' }, {
      apiKey: 'K', retryDelayMs: 0, fetchImpl: seqFetch([BOOM], []),
    }),
    (e) => {
      assert.match(e.message, /unavailable|outage/i);
      assert.match(e.message, /500/);
      return true;
    },
  );
});

test('a 401 is NOT retried — a bad key will not fix itself', async () => {
  const calls = [];
  await assert.rejects(
    () => explain.askClaude({ ip: '1.2.3.4' }, {
      apiKey: 'K', retryDelayMs: 0,
      fetchImpl: seqFetch([{ status: 401, body: { error: 'bad key' } }], calls),
    }),
    /401/,
  );
  assert.equal(calls.length, 1, 'exactly one attempt');
});

test('network failures are retried too', async () => {
  const calls = [];
  const out = await explain.askClaude({ ip: '1.2.3.4' }, {
    apiKey: 'K', retryDelayMs: 0,
    fetchImpl: seqFetch([{ throw: 'ECONNRESET' }, OK], calls),
  });
  assert.equal(out.text, 'fine');
});

// ---- provider chain ---------------------------------------------------------
// WaveSpeed first (OpenAI-compatible), Kie second (Anthropic messages shape).
// Two providers rather than two models: Kie's outage took out every model on
// one route at once, which a model-level fallback cannot survive. The response
// shapes differ, so each provider needs its own parser.

function providerFetch(byHost, calls) {
  return async (url, opts) => {
    const host = new URL(url).host;
    if (calls) calls.push(host);
    const r = byHost[host] || { status: 500, body: {} };
    if (r.throw) throw new Error(r.throw);
    return {
      ok: r.status === 200, status: r.status,
      json: async () => r.body || {},
      text: async () => JSON.stringify(r.body || {}),
    };
  };
}
const WS_OK = { status: 200, body: { model: 'anthropic/claude-opus-5',
  choices: [{ message: { role: 'assistant', content: 'wavespeed answered' } }],
  usage: { total_tokens: 20 } } };
const KIE_OK = { status: 200, body: { content: [{ type: 'text', text: 'kie answered' }] } };
const DOWN = { status: 500, body: { error: { message: 'Server exception' } } };
const KEYS = { wavespeedKey: 'WS', apiKey: 'KIE', retryDelayMs: 0 };

test('WaveSpeed is used first and its OpenAI shape is parsed', async () => {
  const calls = [];
  const out = await explain.askClaude({ ip: '1.2.3.4' }, {
    ...KEYS, fetchImpl: providerFetch({ 'llm.wavespeed.ai': WS_OK, 'api.kie.ai': KIE_OK }, calls),
  });
  assert.equal(out.text, 'wavespeed answered');
  assert.equal(calls[0], 'llm.wavespeed.ai', 'primary provider tried first');
  assert.ok(!calls.includes('api.kie.ai'), 'fallback not touched when primary works');
});

test('when WaveSpeed is down it falls through to Kie', async () => {
  const calls = [];
  const out = await explain.askClaude({ ip: '1.2.3.4' }, {
    ...KEYS, fetchImpl: providerFetch({ 'llm.wavespeed.ai': DOWN, 'api.kie.ai': KIE_OK }, calls),
  });
  assert.equal(out.text, 'kie answered', "Kie's Anthropic shape is parsed too");
  assert.ok(calls.includes('llm.wavespeed.ai') && calls.includes('api.kie.ai'));
});

test('a provider with no key is skipped rather than failing the whole call', async () => {
  const calls = [];
  const out = await explain.askClaude({ ip: '1.2.3.4' }, {
    apiKey: 'KIE', wavespeedKey: '', retryDelayMs: 0,
    fetchImpl: providerFetch({ 'api.kie.ai': KIE_OK }, calls),
  });
  assert.equal(out.text, 'kie answered');
  assert.ok(!calls.includes('llm.wavespeed.ai'), 'unconfigured provider never called');
});

test('with no keys at all the error names what to configure', async () => {
  await assert.rejects(
    () => explain.askClaude({ ip: '1.2.3.4' }, { apiKey: '', wavespeedKey: '', fetchImpl: providerFetch({}) }),
    /WAVESPEED_API_KEY|KIE_API_KEY/,
  );
});

test('both providers down reports an upstream outage naming both', async () => {
  await assert.rejects(
    () => explain.askClaude({ ip: '1.2.3.4' }, {
      ...KEYS, fetchImpl: providerFetch({ 'llm.wavespeed.ai': DOWN, 'api.kie.ai': DOWN }),
    }),
    (e) => {
      assert.match(e.message, /wavespeed/i);
      assert.match(e.message, /kie/i);
      assert.match(e.message, /unavailable|outage/i);
      return true;
    },
  );
});

test('the model reported back identifies which provider answered', async () => {
  const out = await explain.askClaude({ ip: '1.2.3.4' }, {
    ...KEYS, fetchImpl: providerFetch({ 'llm.wavespeed.ai': WS_OK, 'api.kie.ai': KIE_OK }),
  });
  assert.match(out.model, /wavespeed/i);
});
