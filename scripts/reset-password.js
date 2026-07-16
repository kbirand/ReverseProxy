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
const { hashPassword, rotateAuthSecret } = require('../src/auth');

const newPass = process.argv[2] || 'admin';
const database = db.open();

db.setMeta(database, 'auth_username', 'admin');
db.setMeta(database, 'auth_pwhash', hashPassword(newPass));
db.setMeta(database, 'auth_pw_is_default', newPass === 'admin' ? '1' : '0');
// Rotate the signing secret so a reset actually evicts any existing session —
// the point of a lockout recovery is to lock the other party out too.
rotateAuthSecret(database);

console.log(`[reset-password] admin password set to: ${newPass}`);
console.log('[reset-password] all existing sessions were invalidated; log in fresh to use it.');
