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

// Every request reaches this router through Caddy, which dials loopback, so
// req.ip is 127.0.0.1 for all of them. Keying the limiter on that would put the
// entire internet in one bucket: 21 attempts a minute from anywhere would 429
// the operator's own button for the rest of the window. Caddy sets
// X-Block-Client-Ip from its resolved client_ip so sources stay distinguishable.
test('one source exhausting the rate limit does not lock out another', async (t) => {
  const { url } = harness(t);
  const bogus = 'not-a-real-token';
  const shout = (ip) => fetch(url(bogus), {
    method: 'POST',
    headers: { 'X-Block-Client-Ip': ip },
  });

  let last;
  for (let i = 0; i <= blockAction.RATE_MAX; i++) last = await shout('198.51.100.7');
  assert.equal(last.status, 429, 'the noisy source must be cut off');

  const other = await shout('203.0.113.55');
  assert.equal(other.status, 403,
    'a different source gets the normal invalid-token answer, not the noisy one\'s 429');
});

test('the client-IP header is ignored when the request did not come from loopback', async (t) => {
  // Not reproducible over a real socket here (the test client IS loopback), so
  // this pins the intent: the header is only read on the loopback hop from
  // Caddy. From the internet it cannot be set, because Caddy overwrites it.
  const { url } = harness(t);
  const res = await fetch(url('nope'), { method: 'POST' });
  assert.equal(res.status, 403, 'no header at all still falls back to the socket address');
});

// A button inside a notification gives the phone nothing to show for the HTTP
// response: you tap it and cannot tell whether anything happened. The outcome
// therefore comes back as its own notification — and only for taps that carried
// a real signature, because this endpoint is public and a push on every bad
// token would let anyone who found the path ring the phone at will.
function confirmHarness(t) {
  const sent = [];
  const database = db.open(':memory:');
  const app = express();
  app.use(express.json());
  app.use('/api/block', blockAction.buildRouter(database, {
    secret: SECRET,
    reloadCaddy: async () => {},
    confirm: (m) => { sent.push(m); return Promise.resolve({ sent: true }); },
  }));
  const server = app.listen(0);
  t.after(() => server.close());
  return { database, sent, url: (tok) => `http://127.0.0.1:${server.address().port}/api/block/${tok}` };
}

test('a successful tap says so on the phone', async (t) => {
  const { sent, url } = confirmHarness(t);
  await fetch(url(blockToken.mint('203.0.113.10', { secret: SECRET })), { method: 'POST' });
  assert.equal(sent.length, 1);
  assert.match(sent[0].title, /Blocked/);
  assert.match(sent[0].body, /203\.0\.113\.10/);
});

test('pressing a second time confirms the first press worked', async (t) => {
  const { sent, url } = confirmHarness(t);
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET });
  await fetch(url(tok), { method: 'POST' });
  await fetch(url(tok), { method: 'POST' });
  assert.equal(sent.length, 2);
  assert.match(sent[1].title, /Already blocked/,
    'the whole point: a second tap must not look like a failure');
});

test('a forged token pushes nothing — the phone is not a spam target', async (t) => {
  const { sent, url } = confirmHarness(t);
  await fetch(url(blockToken.mint('203.0.113.10', { secret: 'wrong-secret' })), { method: 'POST' });
  await fetch(url('total-garbage'), { method: 'POST' });
  assert.equal(sent.length, 0, 'anyone who finds the path could otherwise ring the phone at will');
});

test('an expired link says which IP was not blocked', async (t) => {
  const { sent, url } = confirmHarness(t);
  const stale = blockToken.mint('203.0.113.77', { secret: SECRET, ttlMs: -1000 });
  const res = await fetch(url(stale), { method: 'POST' });
  assert.equal(res.status, 403);
  assert.equal(sent.length, 1, 'a good signature that merely aged out came from a real alert');
  assert.match(sent[0].body, /203\.0\.113\.77/);
  assert.match(sent[0].body, /NOT blocked/);
});

test('a refused block is reported rather than swallowed', async (t) => {
  const { sent, url } = confirmHarness(t);
  const res = await fetch(url(blockToken.mint('127.0.0.1', { secret: SECRET })), { method: 'POST' });
  assert.equal(res.status, 409);
  assert.match(sent[0].title, /Not blocked/);
});

test('a broken push never breaks the block itself', async (t) => {
  const database = db.open(':memory:');
  const app = express();
  app.use('/api/block', blockAction.buildRouter(database, {
    secret: SECRET,
    reloadCaddy: async () => {},
    confirm: () => { throw new Error('ntfy is down'); },
  }));
  const server = app.listen(0);
  t.after(() => server.close());
  const tok = blockToken.mint('203.0.113.10', { secret: SECRET });
  const res = await fetch(`http://127.0.0.1:${server.address().port}/api/block/${tok}`, { method: 'POST' });
  assert.equal(res.status, 200, 'the block succeeded; feedback failing is not the block failing');
  assert.ok(db.listGlobalBlocks(database).some((b) => b.ip === '203.0.113.10'));
});
