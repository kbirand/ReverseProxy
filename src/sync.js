const db = require('./db');
const { renderConfig, pushConfig, normalizeBlockPath } = require('./caddy');

// Where the notification block button is published. Kept in the DATABASE rather
// than read from the environment at render time, because caddy.js resolves
// BLOCK_ACTION_* once at module load: any process that renders a config without
// those variables in its environment — a maintenance script, a one-off
// `node -e`, anything not started by the unit file — pushes a config with the
// route silently missing and takes the button offline until the next restart.
// That is exactly how it broke the first time it was tested: a cleanup script
// re-pushed the config eight minutes before the button was tapped, and the tap
// landed on the site's 404 instead.
//
// Storing it means every reload through this function republishes the route,
// whatever the environment of the process doing the reloading. The service
// still seeds these from the environment at startup, so BLOCK_ACTION_HOST and
// BLOCK_ACTION_PATH remain how you configure it.
const META_BLOCK_HOST = 'block_action_host';
const META_BLOCK_PATH = 'block_action_path';

function seedBlockAction(database, env = process.env) {
  const host = (env.BLOCK_ACTION_HOST || '').trim();
  db.setMeta(database, META_BLOCK_HOST, host);
  db.setMeta(database, META_BLOCK_PATH, host ? normalizeBlockPath(env.BLOCK_ACTION_PATH) : '');
  return { host, path: db.getMeta(database, META_BLOCK_PATH) };
}

// Absent keys (a database that predates this, or one never seeded) leave the
// option off entirely so caddy.js falls back to the environment as before. An
// empty stored value is different: it means "seeded, and not published".
function blockActionOpts(database) {
  const host = db.getMeta(database, META_BLOCK_HOST);
  const path = db.getMeta(database, META_BLOCK_PATH);
  const opts = {};
  if (host !== null) opts.blockActionHost = host;
  if (path !== null && path !== '') opts.blockActionPath = path;
  return opts;
}

// Render the current DB state (rules + global blocklist) into a Caddy config
// and hot-load it via the admin API. Shared by the API routes, the startup
// sync, and the activity/blocklist endpoints so there is one code path.
async function reloadCaddy(database) {
  const rules = db.listRules(database);
  const globalBlocks = db.listGlobalBlocks(database).map((b) => b.ip);
  const maintenance = db.getMaintenance(database);
  // Parked block page for IP-rejected visitors. On unless explicitly disabled,
  // so a fresh install does not advertise "Forbidden" on protected hostnames.
  const blockPage = db.getMeta(database, 'block_page') !== '0';
  await pushConfig(renderConfig(rules, {
    globalBlocks, maintenance, blockPage, ...blockActionOpts(database),
  }));
  db.setMeta(database, 'last_reload_at', Date.now());
  return { rules: rules.length, blocks: globalBlocks.length, maintenance };
}

// In-process timer that flips maintenance off when its `until` deadline passes
// and reloads Caddy. Re-armable so changing the window cancels the prior fire.
// Survives restarts via the startup sync (server.js calls this once Caddy is
// healthy), so a reboot mid-maintenance still ends on schedule.
let maintenanceTimer = null;
function scheduleMaintenanceAutoEnd(database) {
  if (maintenanceTimer) { clearTimeout(maintenanceTimer); maintenanceTimer = null; }
  const m = db.getMaintenance(database);
  if (!m.active || !m.until) return;
  const delay = m.until - Date.now();
  if (delay <= 0) { endMaintenance(database).catch(() => {}); return; }
  maintenanceTimer = setTimeout(() => {
    maintenanceTimer = null;
    endMaintenance(database).catch((e) => console.error('[maintenance] auto-end failed:', e.message));
  }, delay);
}

async function endMaintenance(database) {
  const cur = db.getMaintenance(database);
  if (!cur.active) return;
  db.setMaintenance(database, { active: false, until: null, hosts: [] });
  await reloadCaddy(database);
  console.log('[maintenance] auto-ended on schedule');
}

module.exports = {
  reloadCaddy, scheduleMaintenanceAutoEnd, seedBlockAction, blockActionOpts,
  META_BLOCK_HOST, META_BLOCK_PATH,
};
