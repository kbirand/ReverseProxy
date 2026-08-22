// Single-action tokens for the "block this source" button in a notification.
//
// The notification travels through ntfy and ends up on a lock screen, so it
// cannot carry a panel credential: anyone who saw the message would hold one,
// and the panel can change the firewall. Instead each notification carries a
// token that authorises ONE action on ONE IP and expires. The worst a leaked
// token can do is block the scanner it names — which is what the button existed
// to do. blockGuard still runs at the route, so a token naming an allowlisted or
// internal address is refused even with a valid signature.

const crypto = require('crypto');

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000; // a notification seen next morning still works
const SEP = '.';

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

// `${ip}|${expiresAt}` — the IP is inside the signed payload, so a token cannot
// be pointed at a different address than the one it was issued for.
function mint(ip, opts = {}) {
  const secret = opts.secret;
  if (!secret) throw new Error('block token secret is not configured');
  if (!ip || typeof ip !== 'string') throw new Error('block token needs an ip');
  const now = opts.now == null ? Date.now() : opts.now;
  const ttl = opts.ttlMs == null ? DEFAULT_TTL_MS : opts.ttlMs;
  const payload = `${ip}|${now + ttl}`;
  const body = Buffer.from(payload, 'utf8').toString('base64url');
  return `${body}${SEP}${sign(payload, secret)}`;
}

function verify(token, opts = {}) {
  const secret = opts.secret;
  if (!secret) return { ok: false, reason: 'not-configured' };
  if (typeof token !== 'string' || !token) return { ok: false, reason: 'malformed' };
  const parts = token.split(SEP);
  if (parts.length !== 2 || !parts[0] || !parts[1]) return { ok: false, reason: 'malformed' };
  const [body, sig] = parts;

  let payload;
  try {
    payload = Buffer.from(body, 'base64url').toString('utf8');
  } catch { return { ok: false, reason: 'malformed' }; }
  // base64url decoding is lenient: it drops characters it does not recognise
  // rather than failing, so a mangled body can still decode to something. Round
  // -tripping catches that before the signature is even considered.
  if (Buffer.from(payload, 'utf8').toString('base64url') !== body) {
    return { ok: false, reason: 'malformed' };
  }

  const expected = sign(payload, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  // Length differing is itself a mismatch, and timingSafeEqual throws on it.
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return { ok: false, reason: 'bad-signature' };
  }

  const cut = payload.lastIndexOf('|');   // lastIndexOf: IPv6 has no '|', but be exact
  if (cut < 1) return { ok: false, reason: 'malformed' };
  const ip = payload.slice(0, cut);
  const exp = Number(payload.slice(cut + 1));
  if (!Number.isFinite(exp)) return { ok: false, reason: 'malformed' };

  const now = opts.now == null ? Date.now() : opts.now;
  if (now > exp) return { ok: false, reason: 'expired' };
  return { ok: true, ip };
}

// The secret must survive restarts or every token minted before a restart stops
// working — including the one in the notification you are about to tap. Env wins
// so it can be rotated deliberately; otherwise one is generated and kept.
const META_KEY = 'block_token_secret';

function secretFor(db, env = process.env) {
  const fromEnv = (env.BLOCK_TOKEN_SECRET || '').trim();
  if (fromEnv) return fromEnv;
  if (!db) return '';
  const dbModule = require('./db');
  let stored = dbModule.getMeta(db, META_KEY);
  if (!stored) {
    stored = crypto.randomBytes(32).toString('base64url');
    dbModule.setMeta(db, META_KEY, stored);
  }
  return stored;
}

module.exports = { mint, verify, secretFor, DEFAULT_TTL_MS, META_KEY };
