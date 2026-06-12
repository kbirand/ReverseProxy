const express = require('express');
const fsp = require('node:fs/promises');

// ufw needs root for everything, including reading status, so the UI never
// runs it directly. It drops a JSON action file that rproxy-ufw-helper.path
// turns into a privileged run of scripts/ufw-helper.sh, then reads the helper's
// result + status files back. Mirrors the Caddy snapshot/restore helper.
const UFW_ACTION_FILE = process.env.UFW_ACTION_FILE || '/var/lib/rproxy/.ufw-action';
const UFW_RESULT_FILE = process.env.UFW_RESULT_FILE || '/var/lib/rproxy/.ufw-action-result';
const UFW_STATUS_FILE = process.env.UFW_STATUS_FILE || '/var/lib/rproxy/.ufw-status';

// Drop any stale result, write the action so the .path unit fires, then poll
// for a fresh result. The helper stamps `ts`; we ignore a leftover result by
// requiring its ts to be at/after when we asked.
async function triggerUfw(action, timeoutMs = 30_000) {
  const asked = Math.floor(Date.now() / 1000);
  try { await fsp.unlink(UFW_RESULT_FILE); } catch (_) {}
  await fsp.writeFile(UFW_ACTION_FILE, JSON.stringify(action) + '\n');
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const result = JSON.parse(await fsp.readFile(UFW_RESULT_FILE, 'utf8'));
      if (typeof result.ts !== 'number' || result.ts >= asked - 1) return result;
    } catch (_) { /* not ready yet */ }
    await new Promise((r) => setTimeout(r, 200));
  }
  throw new Error('ufw helper timed out — is rproxy-ufw-helper.path enabled?');
}

// Parse `ufw status numbered` into rows. Lines look like:
//   [ 2] 80/tcp            ALLOW IN    Anywhere            # Caddy HTTP
//   [ 5] Anywhere          ALLOW IN    192.168.1.0/24      # LAN trusted
async function readStatus() {
  let text;
  try { text = await fsp.readFile(UFW_STATUS_FILE, 'utf8'); } catch (_) { return { active: false, rules: [] }; }
  const active = /^Status:\s*active/m.test(text);
  const rules = [];
  for (const line of text.split('\n')) {
    const m = /^\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT|FWD)\s+(.+?)\s*(?:#\s*(.*))?$/.exec(line);
    if (!m) continue;
    rules.push({
      num: Number(m[1]),
      to: m[2].trim(),
      action: m[3],
      direction: m[4],
      from: m[5].trim(),
      comment: (m[6] || '').trim(),
    });
  }
  return { active, rules };
}

// Field validation — the route is the first gate; ufw-helper.sh re-checks.
function validatePort(v) {
  if (v === undefined || v === null || v === '') return '';
  const n = Number(v);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error('port must be 1–65535');
  return String(n);
}
function validateProto(v) {
  if (!v) return '';
  if (v !== 'tcp' && v !== 'udp') throw new Error('proto must be tcp or udp');
  return v;
}
function validateFrom(v) {
  if (!v) return '';
  const s = String(v).trim();
  if (s === 'any') return s;
  // IPv4/IPv6 address or CIDR — the helper enforces the same shape.
  if (!/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(s)) throw new Error('source must be an IP or CIDR');
  return s;
}
function validateComment(v) {
  if (!v) return '';
  const s = String(v).trim();
  if (!/^[A-Za-z0-9 _.:/+-]{1,64}$/.test(s)) throw new Error('comment: letters, digits, spaces and _.:/+- only (max 64)');
  return s;
}

function buildRouter() {
  const r = express.Router();

  // Current firewall state + parsed rules. Triggers a status refresh so the
  // numbers are live (deletes renumber rules under us).
  r.get('/', async (req, res) => {
    try {
      const result = await triggerUfw({ action: 'status' });
      if (result.status !== 'ok') return res.status(500).json({ error: 'ufw_error', message: result.message });
      res.json(await readStatus());
    } catch (e) {
      res.status(503).json({
        error: 'helper_unavailable',
        message: `${e.message}. Re-run install.sh to set up rproxy-ufw-helper.`,
      });
    }
  });

  // Add an allow/deny rule. Body: { action, port?, proto?, from?, comment? }
  r.post('/rule', async (req, res) => {
    const b = req.body || {};
    if (b.action !== 'allow' && b.action !== 'deny') {
      return res.status(400).json({ error: 'bad_action', message: 'action must be allow or deny' });
    }
    let action;
    try {
      action = {
        action: b.action,
        port: validatePort(b.port),
        proto: validateProto(b.proto),
        from: validateFrom(b.from),
        comment: validateComment(b.comment),
      };
    } catch (e) {
      return res.status(400).json({ error: 'invalid_rule', message: e.message });
    }
    if (!action.port && !action.from) {
      return res.status(400).json({ error: 'invalid_rule', message: 'specify a port, a source, or both' });
    }
    try {
      const result = await triggerUfw(action);
      if (result.status !== 'ok') return res.status(400).json({ error: 'ufw_rejected', message: result.message });
      res.json({ ok: true, ...(await readStatus()) });
    } catch (e) {
      res.status(503).json({ error: 'helper_unavailable', message: e.message });
    }
  });

  // Delete a rule by its current number.
  r.delete('/rule/:num', async (req, res) => {
    const num = Number(req.params.num);
    if (!Number.isInteger(num) || num < 1 || num > 9999) {
      return res.status(400).json({ error: 'bad_num', message: 'invalid rule number' });
    }
    try {
      const result = await triggerUfw({ action: 'delete', num });
      if (result.status !== 'ok') return res.status(400).json({ error: 'ufw_rejected', message: result.message });
      res.json({ ok: true, ...(await readStatus()) });
    } catch (e) {
      res.status(503).json({ error: 'helper_unavailable', message: e.message });
    }
  });

  // Enable / disable the firewall. Body: { enable: bool }
  r.post('/toggle', async (req, res) => {
    const enable = !!(req.body && req.body.enable);
    try {
      const result = await triggerUfw({ action: enable ? 'enable' : 'disable' });
      if (result.status !== 'ok') return res.status(400).json({ error: 'ufw_rejected', message: result.message });
      res.json({ ok: true, ...(await readStatus()) });
    } catch (e) {
      res.status(503).json({ error: 'helper_unavailable', message: e.message });
    }
  });

  return r;
}

module.exports = { buildRouter };
