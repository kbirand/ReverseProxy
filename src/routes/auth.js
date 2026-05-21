const express = require('express');
const db = require('../db');
const auth = require('../auth');

function buildRouter(database) {
  const r = express.Router();

  // This router is mounted BEFORE requireAuth, so each route guards itself.

  r.post('/login', auth.loginThrottle(), (req, res) => {
    const { username, password } = req.body || {};
    if (!auth.verifyCredentials(database, username, password)) {
      auth.recordLoginFailure(req.ip);
      return res.status(401).json({ error: 'invalid_credentials' });
    }
    auth.recordLoginSuccess(req.ip);
    const user = db.getMeta(database, 'auth_username') || 'admin';
    auth.issueSession(res, database, user);
    res.json({ ok: true, username: user, password_is_default: auth.passwordIsDefault(database) });
  });

  r.post('/logout', (req, res) => {
    auth.clearSession(res);
    res.json({ ok: true });
  });

  // Probe used by the SPA to decide whether to show the login screen.
  r.get('/me', (req, res) => {
    if (!auth.AUTH_ENABLED) {
      return res.json({ authenticated: true, username: null, auth_enabled: false });
    }
    const session = auth.readSession(req, database);
    if (!session) {
      return res.status(401).json({ authenticated: false, auth_enabled: true });
    }
    res.json({
      authenticated: true,
      username: session.username,
      password_is_default: auth.passwordIsDefault(database),
      auth_enabled: true,
    });
  });

  r.post('/password', (req, res) => {
    if (auth.AUTH_ENABLED && !auth.readSession(req, database)) {
      return res.status(401).json({ error: 'unauthorized' });
    }
    const { current_password: current, new_password: next } = req.body || {};
    const user = db.getMeta(database, 'auth_username') || 'admin';
    if (!auth.verifyCredentials(database, user, current)) {
      return res.status(400).json({ error: 'wrong_current_password' });
    }
    if (!next || String(next).length < 8) {
      return res.status(400).json({ error: 'weak_password', message: 'New password must be at least 8 characters.' });
    }
    if (String(next) === 'admin') {
      return res.status(400).json({ error: 'weak_password', message: 'Pick something other than "admin".' });
    }
    db.setMeta(database, 'auth_pwhash', auth.hashPassword(next));
    db.setMeta(database, 'auth_pw_is_default', '0');
    auth.issueSession(res, database, user); // refresh the cookie
    res.json({ ok: true });
  });

  return r;
}

module.exports = { buildRouter };
