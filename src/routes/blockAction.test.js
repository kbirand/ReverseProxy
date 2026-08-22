const test = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');
const db = require('../db');
const blockToken = require('../blockToken');
const blockAction = require('./blockAction');

// This is the only unauthenticated route in the panel and it is published on the
// open internet, so the tests below are the contract: a valid token blocks the
// one IP it names, and nothing else gets through.
const SECRET = 'test-secret';

function harness(t) {
  const database = db.open(':memory:');
  db.createRule(database, {
    hostname: 'lab.example.com', backend_host: '127.0.0.1', backend_port: 3001,
    enabled: 1, access_mode: 'whitelist',
    deny_ips: '212.154.65.70\n2a02:ff0:254:9e28::/64',
  });
  const app = express();
  app.use(express.json());
  app.use('/api/block', blockAction.buildRouter(database, {
    secret: SECRET, reloadCaddy: async () => {},
  }));
  const server = app.listen(0);
  t.after(() => server.close());
  const url = (tok) => `http://127.0.0.1:${server.address().port}/api/block/${tok}`;
  return { database, url };
}

test('a valid token blocks the IP it names', async (t) => {
  const { database, url } = harness(t);
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET });
  const res = await fetch(url(tok), { method: 'POST' });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /Blocked 203\.0\.113\.10/);
  assert.ok(db.listGlobalBlocks(database).some((b) => b.ip === '203.0.113.10'));
});

test('a token signed with the wrong secret blocks nothing', async (t) => {
  const { database, url } = harness(t);
  const tok = blockToken.mint('203.0.113.10', { secret: 'not-the-secret' });
  const res = await fetch(url(tok), { method: 'POST' });
  assert.equal(res.status, 403);
  assert.equal(db.listGlobalBlocks(database).length, 0);
});

test('an expired token blocks nothing', async (t) => {
  const { database, url } = harness(t);
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET, ttlMs: -1 });
  assert.equal((await fetch(url(tok), { method: 'POST' })).status, 403);
  assert.equal(db.listGlobalBlocks(database).length, 0);
});

// The guard is the reason a leaked token cannot hurt you: even perfectly signed,
// it will not block a line you allowlisted or your own network.
test('a perfectly signed token cannot block an allowlisted IPv6 guest', async (t) => {
  const { database, url } = harness(t);
  const tok = blockToken.mint('2a02:ff0:254:9e28:2cca:f431:790f:4e90', { secret: SECRET });
  const res = await fetch(url(tok), { method: 'POST' });
  assert.equal(res.status, 409);
  assert.equal(db.listGlobalBlocks(database).length, 0);
});

test('nor your own LAN', async (t) => {
  const { database, url } = harness(t);
  const tok = blockToken.mint('192.168.1.1', { secret: SECRET });
  assert.equal((await fetch(url(tok), { method: 'POST' })).status, 409);
  assert.equal(db.listGlobalBlocks(database).length, 0);
});

test('GET does nothing — a link preview must not block an address', async (t) => {
  const { database, url } = harness(t);
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET });
  const res = await fetch(url(tok));
  assert.equal(res.status, 404);
  assert.equal(db.listGlobalBlocks(database).length, 0);
});

test('tapping twice reads as success, not failure', async (t) => {
  const { url } = harness(t);
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET });
  await fetch(url(tok), { method: 'POST' });
  const res = await fetch(url(tok), { method: 'POST' });
  assert.equal(res.status, 200);
  assert.match(await res.text(), /already blocked/);
});

test('a failed Caddy reload rolls the block back rather than leaving it half applied', async (t) => {
  const database = db.open(':memory:');
  const app = express();
  app.use('/api/block', blockAction.buildRouter(database, {
    secret: SECRET,
    reloadCaddy: async () => { throw new Error('caddy said no'); },
  }));
  const server = app.listen(0);
  t.after(() => server.close());
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET });
  const res = await fetch(`http://127.0.0.1:${server.address().port}/api/block/${tok}`, { method: 'POST' });
  assert.equal(res.status, 502);
  assert.equal(db.listGlobalBlocks(database).length, 0, 'the row must not survive a failed reload');
});
