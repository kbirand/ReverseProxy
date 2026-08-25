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

const COOLDOWN_MS = 6 * 60 * 60 * 1000; // one buzz per source per level per 6h
const DEFAULT_SERVER = 'https://ntfy.sh';

// Only these verdicts are ever worth a notification. NOISE and QUIET are, by
// definition, sources that were served nothing worth waking anyone for, and
// YOURS/INTERNAL are you. Overridable via NTFY_LEVELS.
const NOTIFIABLE = ['alert', 'watch'];

// ALERT breaks Do Not Disturb; WATCH deliberately does not. Measured before
// enabling WATCH: 4 sources in 72h, and all four were "refused N times" — a
// scanner bouncing off a locked door is not worth a 3am buzz, but is worth
// seeing in the morning.
const LEVEL_STYLE = {
  alert: { priority: 5, tags: 'rotating_light', title: 'Breach alert' },
  watch: { priority: 3, tags: 'warning', title: 'Worth a look' },
};

function shouldNotify(db, row, opts = {}) {
  const level = row && row.verdict && row.verdict.level;
  if (!level) return false;
  const enabled = opts.levels || NOTIFIABLE;
  // A level outside NOTIFIABLE can never be enabled, even if someone puts it in
  // NTFY_LEVELS — paging on QUIET would drown the channel that matters.
  if (!NOTIFIABLE.includes(level) || !enabled.includes(level)) return false;
  // The cooldown is per level, so a source that escalates from watch to alert
  // still gets through its own watch cooldown.
  const prior = db.prepare('SELECT sent_at FROM notifications WHERE ip = ? AND kind = ?')
    .get(row.client_ip, level);
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

// How many served endpoints ride along, and how much of each. "Check what was
// served" is unanswerable without them, but they cross ntfy and land on a lock
// screen, so: only what was actually served, only the path, never the query.
//
// Three turned out to be too few to act on. The question a notification has to
// answer is "is this legitimate, or do I block it?", and three paths rarely
// separate a customer hitting an API from a scanner walking one — the shape of
// the traffic only shows up over a dozen. The list is ordered served-first then
// by bytes (see breach.pathsForIp), so what survives the cap is the evidence
// that matters. Still well inside ntfy's 4 KB body: 12 lines of at most 61
// characters is under 800 bytes.
const MAX_ENDPOINTS = 12;
// Refused paths are supporting context, not the evidence, so fewer of them:
// three .env variants already convey the shape of a sweep, and the count
// beside them carries the scale.
const MAX_PROBED = 8;
const MAX_PATH = 60;

function endpointLines(paths) {
  if (!Array.isArray(paths) || !paths.length) return [];
  const served = paths.filter((p) => p && p.confidence === 'real');
  if (!served.length) return [];
  const lines = served.slice(0, MAX_ENDPOINTS).map((p) => {
    // Query values carry credentials and filenames. On a lock screen the query
    // earns nothing the path does not, so only the path goes.
    const cut = String(p.uri || '').split(/[?#]/)[0];
    const short = cut.length > MAX_PATH ? `${cut.slice(0, MAX_PATH - 1)}…` : cut;
    return `  ${short}`;
  });
  const more = served.length - lines.length;
  if (more > 0) lines.push(`  …and ${more} more`);
  return ['', 'Reached:', ...lines];
}

// What the server turned away. Without it the message showed 44.223.80.249 as
// two hits on `/` — indistinguishable from a passer-by — while the other 257
// requests swept for .env, .env.production, .git/config and phpinfo. Deciding
// whether to block is a judgement about the SHAPE of what was probed, and that
// judgement gets made on a phone, from this message.
function probedLines(paths) {
  if (!Array.isArray(paths) || !paths.length) return [];
  const refused = paths.filter((p) => p && (p.confidence === 'not-found' || p.confidence === 'refused'));
  if (!refused.length) return [];
  const lines = refused.slice(0, MAX_PROBED).map((p) => {
    const cut = String(p.uri || '').split(/[?#]/)[0];
    const short = cut.length > MAX_PATH ? `${cut.slice(0, MAX_PATH - 1)}…` : cut;
    return `  ${short}`;
  });
  // The count matters as much as the examples: three .env paths look like a
  // typo, three of two hundred and fifty look like a sweep.
  return ['', `Probed: ${refused.length} refused`, ...lines,
    ...(refused.length > lines.length ? [`  …and ${refused.length - lines.length} more`] : [])];
}

// ntfy splits the Actions header on commas, so no field may contain one. An IP
// cannot; the label can, which is why the label is not in the button.
function blockAction(ip, blockUrl) {
  if (!blockUrl) return null;
  return `http, Block ${ip}, ${blockUrl}, method=POST, clear=true`;
}

// ntfy separates multiple actions with ';'. Block first — it is the decision —
// then a view action opening the full per-IP detail page the message truncated.
function actionsFor(ip, blockUrl, detailUrl) {
  const out = [];
  const b = blockAction(ip, blockUrl);
  if (b) out.push(b);
  if (detailUrl) out.push(`view, Details, ${detailUrl}`);
  return out.length ? out.join('; ') : null;
}

function buildMessage(row, opts = {}) {
  const who = row.label ? ` (${row.label})` : '';
  const style = LEVEL_STYLE[row.verdict.level] || LEVEL_STYLE.alert;
  const msg = {
    title: `${style.title}: ${row.client_ip}`,
    body: [
      row.verdict.text,
      '',
      `Source: ${row.client_ip}${who}`,
      `Host:   ${row.top_host || 'multiple'}`,
      `Volume: ${row.requests} requests · ${mb(row.bytes)}`,
      `Served: real ${row.real} · refused ${row.failures}`,
      ...endpointLines(opts.paths),
      ...probedLines(opts.paths),
    ].join('\n'),
    priority: style.priority,
    tags: style.tags,
  };
  const action = actionsFor(row.client_ip, opts.blockUrl, opts.detailUrl);
  if (action) msg.actions = action;
  return msg;
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
        ...(msg.actions ? { Actions: msg.actions } : {}),
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
    if (!shouldNotify(db, row, opts)) continue;
    // Paths and the block token are resolved per row, and only for rows that
    // are actually going out — building them for every source would query the
    // endpoint table hundreds of times a minute for nothing.
    let paths = [];
    let blockUrl = '';
    try { if (opts.pathsFor) paths = opts.pathsFor(row.client_ip) || []; } catch { paths = []; }
    try { if (opts.blockUrlFor) blockUrl = opts.blockUrlFor(row.client_ip) || ''; } catch { blockUrl = ''; }
    let detailUrl = '';
    try { if (opts.detailUrlFor) detailUrl = opts.detailUrlFor(row.client_ip) || ''; } catch { detailUrl = ''; }
    const res = await send(buildMessage(row, { paths, blockUrl, detailUrl }), opts);
    if (res.sent) {
      recordNotified(db, row.client_ip, row.verdict.level);
      sent.push(row.client_ip);
    } else if (opts.onError) {
      opts.onError(row.client_ip, res.reason);
    }
  }
  return sent;
}

module.exports = {
  shouldNotify, recordNotified, buildMessage, send, runOnce,
  COOLDOWN_MS, DEFAULT_SERVER, NOTIFIABLE, LEVEL_STYLE,
};
