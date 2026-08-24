const test = require('node:test');
const assert = require('node:assert/strict');
const db = require('./db');
const sync = require('./sync');
const { renderConfig } = require('./caddy');

// This file exists because of a real outage, not a hypothetical one. caddy.js
// resolves BLOCK_ACTION_* once at module load. A cleanup script reloaded Caddy
// from a plain `node -e` that had DB_PATH but not BLOCK_ACTION_HOST, which
// re-pushed a config with no block route at all. The button went dead eight
// minutes before it was tapped, and the tap landed on the site's 404.
//
// Note that this test process is itself the failing condition: nothing sets
// BLOCK_ACTION_HOST in its environment, so caddy.js's own default is empty.

const ENV = { BLOCK_ACTION_HOST: 'link.example.com', BLOCK_ACTION_PATH: '/684uzarswlds' };

test('the block route survives a reload from a process with no BLOCK_ACTION_ env', () => {
  const d = db.open(':memory:');
  sync.seedBlockAction(d, ENV);
  const cfg = renderConfig([], sync.blockActionOpts(d));
  const blob = JSON.stringify(cfg);
  assert.ok(blob.includes('/684uzarswlds/*'),
    'the published route has to come from the database, not from whatever environment did the reload');
  assert.ok(blob.includes('link.example.com'));
});

test('seeding stores the host and a normalized path', () => {
  const d = db.open(':memory:');
  const seeded = sync.seedBlockAction(d, { ...ENV, BLOCK_ACTION_PATH: 'no-slash/trailing/' });
  assert.equal(seeded.host, 'link.example.com');
  assert.equal(db.getMeta(d, sync.META_BLOCK_PATH), '/no-slash/trailing');
});

test('no configured host means nothing is published, and it is stored as such', () => {
  const d = db.open(':memory:');
  sync.seedBlockAction(d, {});
  assert.equal(db.getMeta(d, sync.META_BLOCK_HOST), '');
  const cfg = renderConfig([], sync.blockActionOpts(d));
  assert.ok(!JSON.stringify(cfg).includes('/api/block/'), 'an empty stored host means deliberately unpublished');
});

test('a database that was never seeded leaves the environment in charge', () => {
  const d = db.open(':memory:');
  assert.deepEqual(sync.blockActionOpts(d), {},
    'absent keys must not be mistaken for "unpublish" on an older database');
});

test('turning the button off in the env turns it off in the database too', () => {
  const d = db.open(':memory:');
  sync.seedBlockAction(d, ENV);
  sync.seedBlockAction(d, {});
  assert.ok(!JSON.stringify(renderConfig([], sync.blockActionOpts(d))).includes('684uzarswlds'));
});
