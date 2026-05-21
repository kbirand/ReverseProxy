const path = require('node:path');
const express = require('express');
const db = require('./db');
const auth = require('./auth');
const { caddyHealthy } = require('./caddy');
const { reloadCaddy } = require('./sync');
const { startIngester } = require('./access-log');
const rulesRoute = require('./routes/rules');
const systemRoute = require('./routes/system');
const activityRoute = require('./routes/activity');
const authRoute = require('./routes/auth');

const PORT = Number(process.env.PORT || 8080);
const BIND = process.env.BIND || '0.0.0.0';

const database = db.open();
auth.ensureAuthSeed(database);
const app = express();

app.use(express.json({ limit: '1mb' }));
// Auth router is public (its routes self-guard); everything else under /api
// requires a valid session. Static files stay public — they hold no secrets.
app.use('/api/auth', authRoute.buildRouter(database));
app.use('/api', auth.requireAuth(database));
app.use('/api/rules', rulesRoute.buildRouter(database));
app.use('/api/system', systemRoute.buildRouter(database));
app.use('/api/activity', activityRoute.buildRouter(database));
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => {
  console.error('[server] uncaught', err);
  res.status(500).json({ error: 'server_error', message: String(err.message || err) });
});

// On startup, push the database's rules into Caddy. Caddy boots from a minimal
// bootstrap Caddyfile that knows nothing about user rules — without this, a
// reboot would leave every rule down until someone opened the UI. Waits for
// Caddy's admin API to come up first (systemd orders us After=caddy.service,
// but the admin socket may still be initializing).
async function syncOnStartup() {
  for (let i = 0; i < 30; i++) {
    if (await caddyHealthy()) break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  try {
    const { rules, blocks } = await reloadCaddy(database);
    console.log(`[rproxy-ui] startup sync: ${rules} rules, ${blocks} global blocks pushed to Caddy`);
  } catch (e) {
    console.error(`[rproxy-ui] startup sync failed (UI still up, use Reload): ${e.message}`);
  }
}

app.listen(PORT, BIND, () => {
  console.log(`[rproxy-ui] listening on ${BIND}:${PORT}`);
  syncOnStartup();
  // Tail Caddy's access log into SQLite for the activity view.
  startIngester(database);
});
