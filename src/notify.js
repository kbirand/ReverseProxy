// Push a notification when something genuinely serious happens.
//
// The bar is deliberately high: only an ALERT verdict — a source that received
// REAL content from a SENSITIVE endpoint. That fired once in the last 24 hours
// (Ismail's backup downloads) while 1,400 cloud scanners did not. A phone that
// buzzes for scanners is a phone whose alerts get swiped away, which is worse
// than no alerts at all.
//
// Nothing secret goes into the message: it names the IP, the host and the
// volume, and stops there. Notifications travel through a third party and end
// up on a lock screen.

const COOLDOWN_MS = 6 * 60 * 60 * 1000; // one buzz per source per 6h
const DEFAULT_SERVER = 'https://ntfy.sh';

function shouldNotify(db, row) {
  if (!row || !row.verdict || row.verdict.level !== 'alert') return false;
  const prior = db.prepare('SELECT sent_at FROM notifications WHERE ip = ? AND kind = ?')
    .get(row.client_ip, 'alert');
  if (!prior) return true;
  return Date.now() - prior.sent_at > COOLDOWN_MS;
}

function recordNotified(db, ip, kind) {
  db.prepare(`
    INSERT INTO notifications (ip, kind, sent_at) VALUES (?, ?, ?)
    ON CONFLICT(ip, kind) DO UPDATE SET sent_at = excluded.sent_at
  `).run(ip, kind, Date.now());
}

function mb(n) {
  if (!n) return '0 MB';
  return n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : `${Math.round(n / 1e6)} MB`;
}

function buildMessage(row) {
  const who = row.label ? ` (${row.label})` : '';
  return {
    title: `Breach alert: ${row.client_ip}`,
    body: [
      row.verdict.text,
      '',
      `Source: ${row.client_ip}${who}`,
      `Host:   ${row.top_host || 'multiple'}`,
      `Volume: ${row.requests} requests · ${mb(row.bytes)}`,
      `Served: real ${row.real} · refused ${row.failures}`,
    ].join('\n'),
    priority: 5,          // max: breaks through Do Not Disturb
    tags: 'rotating_light',
  };
}

// Never throws: this runs inside a timer, and a push outage must not take the
// proxy UI down with it.
async function send(msg, opts = {}) {
  const topic = (opts.topic || '').trim();
  if (!topic) return { sent: false, reason: 'ntfy topic is not configured' };
  const server = (opts.server || DEFAULT_SERVER).replace(/\/+$/, '');
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  try {
    const res = await fetchImpl(`${server}/${topic}`, {
      method: 'POST',
      headers: {
        Title: msg.title,
        Priority: String(msg.priority || 4),
        Tags: msg.tags || 'warning',
        ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}),
      },
      body: msg.body,
    });
    if (!res.ok) return { sent: false, reason: `ntfy responded ${res.status}` };
    return { sent: true };
  } catch (e) {
    return { sent: false, reason: e.message };
  }
}

// One pass over the current summary rows. Only records a source as notified
// when the push actually left the building — otherwise an ntfy outage would
// silently swallow the one alert that mattered.
async function runOnce(db, rows, opts = {}) {
  const sent = [];
  for (const row of rows || []) {
    if (!shouldNotify(db, row)) continue;
    const res = await send(buildMessage(row), opts);
    if (res.sent) {
      recordNotified(db, row.client_ip, 'alert');
      sent.push(row.client_ip);
    } else if (opts.onError) {
      opts.onError(row.client_ip, res.reason);
    }
  }
  return sent;
}

module.exports = { shouldNotify, recordNotified, buildMessage, send, runOnce, COOLDOWN_MS, DEFAULT_SERVER };
