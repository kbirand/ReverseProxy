#!/usr/bin/env node
/*
 * Lockout recovery — reset the rproxy admin password from the CLI.
 *
 *   node scripts/reset-password.js [newpassword]
 *
 * With no argument, resets username + password to admin / admin.
 * Must run as the user that owns the database (the 'rproxy' system user,
 * or root) so it can write DB_PATH (default /var/lib/rproxy/rules.db).
 */

const db = require('../src/db');
const { hashPassword } = require('../src/auth');

const newPass = process.argv[2] || 'admin';
const database = db.open();

db.setMeta(database, 'auth_username', 'admin');
db.setMeta(database, 'auth_pwhash', hashPassword(newPass));
db.setMeta(database, 'auth_pw_is_default', newPass === 'admin' ? '1' : '0');

console.log(`[reset-password] admin password set to: ${newPass}`);
console.log('[reset-password] active sessions are unaffected; log in fresh to use it.');
