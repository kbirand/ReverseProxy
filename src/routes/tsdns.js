// Tailnet DNS: which hosts resolve to this machine's tailnet address.
//
// The panel already showed which hosts are gated by IP. It did not show how a
// host is REACHED — and those are different questions with different answers.
// A host can allow the whole tailnet range and still be unreachable from a
// tailnet device, because Tailscale only carries traffic addressed to 100.x and
// a publicly-resolving name never takes that road. That gap is what this screen
// closes: reachability and gating, side by side.
//
// Applying is delegated to the privileged helper (scripts/tsdns-helper.sh) via
// an action file, exactly as the ufw and Caddy routes do — the UI cannot write
// /etc/dnsmasq.d or restart a service itself.

const express = require('express');
const fs = require('fs');
const { execFileSync } = require('child_process');
const db = require('../db');
const tsdns = require('../tailnetDns');

const ACTION_FILE = process.env.TSDNS_ACTION_FILE || '/var/lib/rproxy/.tsdns-action';
const RESULT_FILE = process.env.TSDNS_RESULT_FILE || '/var/lib/rproxy/.tsdns-action-result';

// This machine's tailnet address. Read from tailscale rather than configured, so
// it cannot drift from reality; empty when Tailscale is not running, which the
// UI reports rather than papering over.
function tailscaleIp() {
  if (process.env.TAILSCALE_IP) return process.env.TAILSCALE_IP.trim();
  try {
    return execFileSync('tailscale', ['ip', '-4'], { timeout: 4000 })
      .toString().split('\n')[0].trim();
  } catch { return ''; }
}

function readInstalled() {
  try { return fs.readFileSync(tsdns.CONF_PATH, 'utf8'); } catch { return null; }
}

function readResult() {
  try { return JSON.parse(fs.readFileSync(RESULT_FILE, 'utf8')); } catch { return null; }
}

// Write the rendered config and wait for the helper to report back. The .path
// unit fires on file creation, so the wait is short; a timeout is reported as
// such rather than being mistaken for success.
function applyConf(conf, { timeoutMs = 15000 } = {}) {
  try { fs.unlinkSync(RESULT_FILE); } catch { /* nothing to clear */ }
  fs.writeFileSync(ACTION_FILE, conf, { mode: 0o640 });
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const r = readResult();
    if (r) return r;
    try { execFileSync('sleep', ['0.2']); } catch { /* best effort */ }
  }
  return { status: 'error', message: 'the helper did not respond within 15s' };
}

function buildRouter(database) {
  const r = express.Router();

  r.get('/', (req, res) => {
    const ip = tailscaleIp();
    const rules = db.listRules(database);
    res.json({
      tailscaleIp: ip,
      dnsmasqRunning: (() => {
        try { execFileSync('systemctl', ['is-active', '--quiet', 'dnsmasq']); return true; }
        catch { return false; }
      })(),
      // The apex domains that need a split-DNS entry in the Tailscale console.
      // Derived from the hosts actually enabled, so the list cannot go stale.
      splitDnsDomains: tsdns.splitDnsDomains(rules),
      hosts: tsdns.statusFor(rules, { tailscaleIp: ip }),
      // What dnsmasq was actually given, against what the rules ask for. A
      // panel that reads only its own database cannot tell you the config was
      // never written — which is exactly how a ticked box sat there doing
      // nothing.
      drift: tsdns.driftFrom(rules, readInstalled(), { tailscaleIp: ip }),
      lastApply: readResult(),
    });
  });

  // Regenerate from whatever the rules currently say. Idempotent by design: the
  // config is always rendered whole from the database, never patched, so the
  // file and the rules cannot disagree.
  r.post('/apply', (req, res) => {
    const ip = tailscaleIp();
    const conf = tsdns.renderDnsmasqConf(db.listRules(database), { tailscaleIp: ip });
    const result = applyConf(conf);
    res.status(result.status === 'ok' ? 200 : 502).json(result);
  });

  return r;
}

module.exports = { buildRouter, tailscaleIp };
