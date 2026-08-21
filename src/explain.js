// "Explain this" — hands ONE row of breach analysis to Claude (via Kie) and
// returns a plain-language read of it.
//
// The rules in breach.js can say "127 MB, unrecognised source". They cannot say
// "iPhone Google app, someone browsing the portfolio, benign". That judgement is
// what this is for, and it is deliberately on-demand and single-row: a pipeline
// that shipped every event off the machine would be both expensive and reckless.
//
// REDACTION IS THE POINT. This estate's access log carries live credentials —
// DiskKatalog puts JWTs in query strings and sqlbackup download URLs carry a
// `token=` parameter. Query strings are therefore stripped from every path
// before anything leaves the machine, and headers are never included at all.
// Tests assert that no `eyJ...` or `token=` can survive; do not relax them.

const KIE_MESSAGES_URL = 'https://api.kie.ai/claude/v1/messages';
const DEFAULT_MODEL = 'claude-opus-5';
// Tried in order. The fallback covers a fault specific to one model; it does
// not help when the whole /claude/v1/messages route is down, which is what an
// outage looks like — every model 500s on a trivial prompt.
const FALLBACK_MODEL = 'claude-opus-4-8';
const ATTEMPTS_PER_MODEL = 2;
const RETRY_DELAY_MS = 1500;
const MAX_SAMPLE_PATHS = 40;
const MAX_PATH_LEN = 120;

// Everything after `?` or `#` is discarded — that is where the secrets are.
function redactPath(uri) {
  const cut = String(uri || '').split(/[?#]/)[0];
  // -1 leaves room for the ellipsis so the cap is a real cap.
  return cut.length > MAX_PATH_LEN ? `${cut.slice(0, MAX_PATH_LEN - 1)}…` : cut;
}

// Builds the entire outbound payload. Nothing reaches the network that does not
// pass through here, so this is the single place to audit.
function buildPayload(row, events = []) {
  const seen = new Set();
  const sample_paths = [];
  for (const e of events) {
    const path = redactPath(e.uri);
    const key = `${path}|${e.status}`;
    if (seen.has(key)) continue;
    seen.add(key);
    sample_paths.push({ path, status: e.status, bytes: e.size ?? null });
    if (sample_paths.length >= MAX_SAMPLE_PATHS) break;
  }
  const pct = (n) => Math.round((n || 0) * 100);
  return {
    ip: row.client_ip,
    identity: row.label || null,
    hosting_provider: row.is_hosting ? true : false,
    user_agent: row.user_agent || null,
    window: { first_seen: row.first_ts, last_seen: row.last_ts },
    volume: { requests: row.requests, bytes: row.bytes, distinct_paths: row.distinct_paths, hosts: row.hosts },
    received: { real: row.real, blocked: row.blocked, shell: row.shell, unknown: row.unknown },
    refused: row.failures,
    probe_requests: row.probes,
    top_host: row.top_host || null,
    content_mix_pct: row.content
      ? { media: pct(row.content.media), api: pct(row.content.api), archive: pct(row.content.archive),
          code: pct(row.content.code), other: pct(row.content.other) }
      : null,
    verdict: row.verdict ? row.verdict.level : null,
    verdict_reason: row.verdict ? row.verdict.text : null,
    sample_paths,
  };
}

const SYSTEM_PROMPT = [
  'You are helping the owner of a small self-hosted web estate triage one source of traffic.',
  'You are given aggregate facts about a single client IP taken from a reverse-proxy access log.',
  '',
  'Key terms:',
  '- "real": responses whose body was unique to the request — actual content was served.',
  '- "blocked": responses byte-identical to a parked block page — the visitor was refused.',
  '- "shell": responses byte-identical to a single-page-app catch-all — nothing was served.',
  '- "unknown": response size was not recorded; do not assume it was safe.',
  '- Query strings are stripped from paths before you see them. Do not ask for them.',
  '',
  'Answer in at most 120 words, in this order:',
  '1. One sentence saying what this source most likely is.',
  '2. One sentence on whether anything of value was actually obtained.',
  '3. One short recommendation, which may be "no action needed".',
  '',
  'Write plain prose. Do not use markdown, asterisks, headings or bullet points —',
  'the answer is rendered as plain text and any markup shows up literally.',
  '',
  'Be concrete and calm. Do not speculate beyond the data. If the evidence is',
  'genuinely ambiguous, say so plainly rather than inventing a story.',
].join('\n');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 5xx and network faults are worth retrying; 4xx is not. A bad key, a bad
// request or a rejected payload will fail identically no matter how many times
// it is sent, and retrying only makes the user wait longer for the same answer.
function isRetryable(status) {
  return status === 0 || status === 429 || (status >= 500 && status < 600);
}

async function callOnce(model, payload, apiKey, fetchImpl) {
  let res;
  try {
    res = await fetchImpl(KIE_MESSAGES_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({
        model,
        max_tokens: 400,
        stream: false,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: `Assess this traffic source:\n\n${JSON.stringify(payload, null, 2)}` }],
      }),
    });
  } catch (e) {
    return { ok: false, status: 0, detail: e.message };
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    return { ok: false, status: res.status, detail: String(body).slice(0, 200) };
  }
  const data = await res.json();
  const text = Array.isArray(data.content)
    ? data.content.filter((b) => b && b.type === 'text').map((b) => b.text).join('\n').trim()
    : '';
  if (!text) return { ok: false, status: res.status, detail: `no text: ${JSON.stringify(data).slice(0, 200)}` };
  return { ok: true, text, usage: data.usage || null };
}

async function askClaude(payload, opts = {}) {
  const apiKey = opts.apiKey;
  if (!apiKey) throw new Error('KIE_API_KEY is not configured — set it before using Explain.');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  const delay = opts.retryDelayMs === undefined ? RETRY_DELAY_MS : opts.retryDelayMs;
  const models = opts.model ? [opts.model] : [DEFAULT_MODEL, FALLBACK_MODEL];

  let last = null;
  for (const model of models) {
    for (let attempt = 1; attempt <= ATTEMPTS_PER_MODEL; attempt += 1) {
      const r = await callOnce(model, payload, apiKey, fetchImpl);
      if (r.ok) return { text: r.text, model, usage: r.usage };
      last = { ...r, model };
      if (!isRetryable(r.status)) {
        throw new Error(`Kie rejected the request (${r.status}): ${r.detail}`);
      }
      if (attempt < ATTEMPTS_PER_MODEL) await sleep(delay);
    }
  }
  throw new Error(
    `Kie's Claude endpoint is unavailable — ${last.status} after `
    + `${ATTEMPTS_PER_MODEL} attempts on each of ${models.join(' and ')}. `
    + `This is an upstream outage at Kie, not a problem with your request or your data. `
    + `Detail: ${last.detail}`,
  );
}

module.exports = {
  buildPayload, redactPath, askClaude, isRetryable,
  SYSTEM_PROMPT, KIE_MESSAGES_URL, DEFAULT_MODEL, FALLBACK_MODEL,
};
