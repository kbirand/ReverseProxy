const test = require('node:test');
const assert = require('node:assert/strict');
const bt = require('./blockToken');

// The block button travels through ntfy and lands on a lock screen, so the
// notification cannot carry a panel credential — anyone who sees the message
// would hold one. Instead each notification carries a token that authorises a
// single action on a single IP and then expires. A leaked token blocks the
// scanner it names, which is what the button was for.
const SECRET = 'test-secret-not-the-real-one';

test('a fresh token authorises exactly the IP it was minted for', () => {
  const t = bt.mint('203.0.113.10', { secret: SECRET, now: 1000, ttlMs: 60_000 });
  assert.deepEqual(bt.verify(t, { secret: SECRET, now: 2000 }), { ok: true, ip: '203.0.113.10' });
});

test('a token for one IP cannot be replayed against another', () => {
  const a = bt.mint('203.0.113.10', { secret: SECRET, now: 1000, ttlMs: 60_000 });
  const b = bt.mint('198.51.100.5', { secret: SECRET, now: 1000, ttlMs: 60_000 });
  assert.notEqual(a, b);
  assert.equal(bt.verify(a, { secret: SECRET, now: 2000 }).ip, '203.0.113.10');
  assert.equal(bt.verify(b, { secret: SECRET, now: 2000 }).ip, '198.51.100.5');
});

test('IPv6 survives the round trip', () => {
  const ip = '2a02:ff0:254:9e28:2cca:f431:790f:4e90';
  const t = bt.mint(ip, { secret: SECRET, now: 1000, ttlMs: 60_000 });
  assert.equal(bt.verify(t, { secret: SECRET, now: 2000 }).ip, ip);
});

test('an expired token is refused', () => {
  const t = bt.mint('203.0.113.10', { secret: SECRET, now: 1000, ttlMs: 60_000 });
  const r = bt.verify(t, { secret: SECRET, now: 1000 + 60_001 });
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'expired');
});

test('a token signed with another secret is refused', () => {
  const t = bt.mint('203.0.113.10', { secret: 'someone-elses-secret', now: 1000, ttlMs: 60_000 });
  assert.equal(bt.verify(t, { secret: SECRET, now: 2000 }).ok, false);
});

test('tampering with the payload invalidates the signature', () => {
  const t = bt.mint('203.0.113.10', { secret: SECRET, now: 1000, ttlMs: 60_000 });
  const [body, sig] = t.split('.');
  const forged = Buffer.from('8.8.8.8|9999999999999').toString('base64url');
  assert.equal(bt.verify(`${forged}.${sig}`, { secret: SECRET, now: 2000 }).ok, false,
    'a rewritten IP must not ride an old signature');
  assert.equal(bt.verify(`${body}.${'a'.repeat(sig.length)}`, { secret: SECRET, now: 2000 }).ok, false);
});

test('malformed input is refused rather than throwing', () => {
  for (const bad of ['', '.', 'nodot', 'a.b.c', null, undefined, 42, 'ᚠ.ᚡ']) {
    const r = bt.verify(bad, { secret: SECRET, now: 2000 });
    assert.equal(r.ok, false, `${String(bad)} must be refused`);
  }
});

test('minting without a secret is refused — an unsigned token is no token', () => {
  assert.throws(() => bt.mint('203.0.113.10', { secret: '', now: 1000, ttlMs: 60_000 }));
  assert.equal(bt.verify('a.b', { secret: '', now: 1000 }).ok, false);
});
