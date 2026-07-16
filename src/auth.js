const crypto = require('node:crypto');
const db = require('./db');

const COOKIE_NAME = 'rproxy_sess';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const AUTH_ENABLED = process.env.AUTH_ENABLED !== 'false';
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';
const DEFAULT_USER = 'admin';
const DEFAULT_PASS = 'admin';

// ---- credential layer ------------------------------------------------------

// scrypt hash -> "salt:hash" hex.
function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(plain), salt, 32);
  return `${salt.toString('hex')}:${hash.toString('hex')}`;
}

// Constant-time verify. Never throws — malformed input just returns false.
function verifyPassword(plain, stored) {
  try {
    const [saltHex, hashHex] = String(stored).split(':');
    if (!saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(String(plain), Buffer.from(saltHex, 'hex'), expected.length);
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
  } catch {
    return false;
  }
}

// The credential layer: the single seam a future Google verifier sits beside.
function verifyCredentials(database, username, password) {
  const expectedUser = db.getMeta(database, 'auth_username') || DEFAULT_USER;
  const storedHash = db.getMeta(database, 'auth_pwhash');
  if (!storedHash) return false;
  if (String(username || '').toLowerCase() !== expectedUser.toLowerCase()) return false;
  return verifyPassword(password, storedHash);
}

// Seed auth_secret + the default admin/admin credential on first run.
function ensureAuthSeed(database) {
  if (!db.getMeta(database, 'auth_secret')) {
    db.setMeta(database, 'auth_secret', crypto.randomBytes(32).toString('hex'));
  }
  if (!db.getMeta(database, 'auth_pwhash')) {
    db.setMeta(database, 'auth_username', DEFAULT_USER);
    db.setMeta(database, 'auth_pwhash', hashPassword(DEFAULT_PASS));
    db.setMeta(database, 'auth_pw_is_default', '1');
  }
}

// Rotate the session-signing secret. Every outstanding session cookie is signed
// with the old secret, so rotating invalidates them all — call this on password
// change/reset (and after a restore) so a leaked cookie or secret cannot outlive
// the credential it belonged to. The caller re-issues the current admin's cookie
// afterwards to avoid logging themselves out.
function rotateAuthSecret(database) {
  db.setMeta(database, 'auth_secret', crypto.randomBytes(32).toString('hex'));
}

function passwordIsDefault(database) {
  return db.getMeta(database, 'auth_pw_is_default') === '1';
}

// ---- session layer (signed cookie) -----------------------------------------

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function sign(body, secret) {
  return crypto.createHmac('sha256', secret).update(body).digest('base64url');
}

function issueSession(res, database, username) {
  const secret = db.getMeta(database, 'auth_secret');
  const now = Date.now();
  const payload = b64url(JSON.stringify({ u: username, iat: now, exp: now + SESSION_TTL_MS }));
  const token = `${payload}.${sign(payload, secret)}`;
  const attrs = [
    `${COOKIE_NAME}=${token}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  ];
  if (COOKIE_SECURE) attrs.push('Secure');
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function clearSession(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`);
}

// Manual Cookie-header parse — avoids a cookie-parser dependency.
function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

// Returns { username } for a valid session cookie, else null.
function readSession(req, database) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  const dot = token.indexOf('.');
  if (dot < 0) return null;
  const payload = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const secret = db.getMeta(database, 'auth_secret');
  if (!secret) return null;
  const expected = sign(payload, secret);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || typeof data.exp !== 'number' || data.exp < Date.now()) return null;
    return { username: data.u };
  } catch {
    return null;
  }
}

// While the admin password is still the shipped default (admin/admin), refuse
// every state-changing and secret-exposing request. The operator can still log
// in and change the password (that flow lives on the public /api/auth router,
// ahead of this gate), and read-only GETs still work so the UI can render the
// change-password screen — but rule edits, firewall/ufw changes, self-update,
// restore, backup download and Caddy snapshots are all blocked until the
// default credential is replaced. This shrinks the exploit value of the known
// default to nearly nothing: it cannot reach the privileged helpers or exfil
// secrets, and it forces the operator to change the password first.
const SENSITIVE_DEFAULT_GETS = ['/api/system/backup', '/api/system/caddy-snapshot'];

function requireNonDefaultPassword(database) {
  return (req, res, next) => {
    if (!AUTH_ENABLED) return next();
    if (!passwordIsDefault(database)) return next();
    const pathOnly = (req.originalUrl || req.url).split('?')[0];
    const isMutating = req.method !== 'GET' && req.method !== 'HEAD';
    const isSensitiveGet = SENSITIVE_DEFAULT_GETS.includes(pathOnly);
    if (isMutating || isSensitiveGet) {
      return res.status(403).json({
        error: 'default_password',
        message: 'Change the default admin password before using this feature '
          + '(topbar → Password). Privileged actions are disabled until then.',
      });
    }
    return next();
  };
}

// Express middleware factory. Pass-through when auth is disabled.
function requireAuth(database) {
  return (req, res, next) => {
    if (!AUTH_ENABLED) { req.user = { username: null }; return next(); }
    const session = readSession(req, database);
    if (!session) return res.status(401).json({ error: 'unauthorized' });
    req.user = session;
    next();
  };
}

// ---- login throttle (in-memory, per-IP brute-force slowdown) ---------------

const attempts = new Map(); // ip -> { fails, until, seen }
const ATTEMPTS_MAX_ENTRIES = 10_000; // bound memory against IP-rotating floods
const ATTEMPTS_IDLE_MS = 60 * 60 * 1000; // forget an IP after an hour of quiet

// Drop entries that have gone quiet, then — if still over the cap — evict the
// least-recently-seen ones. Keeps the map from growing without bound when an
// attacker rotates source IPs.
function pruneAttempts() {
  const now = Date.now();
  for (const [ip, rec] of attempts) {
    if (rec.until <= now && now - (rec.seen || 0) > ATTEMPTS_IDLE_MS) attempts.delete(ip);
  }
  if (attempts.size > ATTEMPTS_MAX_ENTRIES) {
    const oldest = [...attempts.entries()]
      .sort((a, b) => (a[1].seen || 0) - (b[1].seen || 0))
      .slice(0, attempts.size - ATTEMPTS_MAX_ENTRIES);
    for (const [ip] of oldest) attempts.delete(ip);
  }
}

function loginThrottle() {
  return (req, res, next) => {
    const rec = attempts.get(req.ip);
    if (rec && rec.until > Date.now()) {
      const wait = Math.ceil((rec.until - Date.now()) / 1000);
      return res.status(429).json({ error: 'too_many_attempts', retry_after_s: wait });
    }
    next();
  };
}

function recordLoginFailure(ip) {
  const rec = attempts.get(ip) || { fails: 0, until: 0, seen: 0 };
  rec.fails += 1;
  rec.seen = Date.now();
  if (rec.fails >= 5) {
    rec.until = Date.now() + Math.min(2 ** (rec.fails - 5) * 1000, 60_000);
  }
  attempts.set(ip, rec);
  if (attempts.size > ATTEMPTS_MAX_ENTRIES) pruneAttempts();
}

function recordLoginSuccess(ip) {
  attempts.delete(ip);
}

module.exports = {
  AUTH_ENABLED,
  hashPassword,
  verifyPassword,
  verifyCredentials,
  ensureAuthSeed,
  rotateAuthSecret,
  passwordIsDefault,
  issueSession,
  clearSession,
  readSession,
  requireAuth,
  requireNonDefaultPassword,
  loginThrottle,
  recordLoginFailure,
  recordLoginSuccess,
};
