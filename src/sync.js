const db = require('./db');
const { renderConfig, pushConfig } = require('./caddy');

// Render the current DB state (rules + global blocklist) into a Caddy config
// and hot-load it via the admin API. Shared by the API routes, the startup
// sync, and the activity/blocklist endpoints so there is one code path.
async function reloadCaddy(database) {
  const rules = db.listRules(database);
  const globalBlocks = db.listGlobalBlocks(database).map((b) => b.ip);
  await pushConfig(renderConfig(rules, { globalBlocks }));
  db.setMeta(database, 'last_reload_at', Date.now());
  return { rules: rules.length, blocks: globalBlocks.length };
}

module.exports = { reloadCaddy };
