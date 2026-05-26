const db = require('./db');
const { renderConfig, pushConfig } = require('./caddy');

// Render the current DB state (rules + global blocklist) into a Caddy config
// and hot-load it via the admin API. Shared by the API routes, the startup
// sync, and the activity/blocklist endpoints so there is one code path.
async function reloadCaddy(database) {
  const rules = db.listRules(database);
  const globalBlocks = db.listGlobalBlocks(database).map((b) => b.ip);
  const maintenance = db.getMaintenance(database);
  await pushConfig(renderConfig(rules, { globalBlocks, maintenance }));
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

module.exports = { reloadCaddy, scheduleMaintenanceAutoEnd };
