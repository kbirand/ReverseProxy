const dns = require('node:dns').promises;
const db = require('./db');

// Re-fetch enrichment data older than this (geo/ISP data drifts slowly).
const STALE_MS = 7 * 24 * 60 * 60 * 1000;
// ip-api.com free tier: 45 requests/minute. Stay well under it.
const RATE_WINDOW_MS = 60_000;
const RATE_MAX = 40;
const callTimes = [];

function rateOk() {
  const now = Date.now();
  while (callTimes.length && callTimes[0] < now - RATE_WINDOW_MS) callTimes.shift();
  return callTimes.length < RATE_MAX;
}

function isPrivateIp(ip) {
  if (!ip || ip === '?') return true;
  if (ip === '127.0.0.1' || ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && +m[1] >= 16 && +m[1] <= 31) return true;
  return false;
}

async function reverseDns(ip) {
  try {
    const names = await Promise.race([
      dns.reverse(ip),
      new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 2500)),
    ]);
    return (names && names[0]) || null;
  } catch {
    return null;
  }
}

// Geolocation + network info via ip-api.com (free, no key, HTTP).
async function geoLookup(ip) {
  if (!rateOk()) return null;
  callTimes.push(Date.now());
  const fields = 'status,message,country,countryCode,region,city,isp,org,as,mobile,proxy,hosting';
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const d = await res.json();
    if (d.status !== 'success') return null;
    return {
      country: d.country || null,
      country_code: d.countryCode || null,
      region: d.region || null,
      city: d.city || null,
      isp: d.isp || null,
      org: d.org || null,
      asn: d.as || null,
      is_proxy: d.proxy ? 1 : 0,
      is_hosting: d.hosting ? 1 : 0,
      is_mobile: d.mobile ? 1 : 0,
    };
  } catch {
    return null;
  }
}

// Enrich one IP and cache it. Returns the cached/fresh ip_info row.
async function enrich(database, ip, { force = false } = {}) {
  const cached = db.getIpInfo(database, ip);
  if (cached && !force && Date.now() - cached.fetched_at < STALE_MS) return cached;

  const info = { ip, fetched_at: Date.now() };
  info.rdns = await reverseDns(ip);
  if (isPrivateIp(ip)) {
    info.country = 'Private / LAN';
    info.country_code = null;
  } else {
    const geo = await geoLookup(ip);
    if (geo) Object.assign(info, geo);
    else if (cached) return cached; // lookup failed — keep whatever we had
  }
  db.upsertIpInfo(database, info);
  return db.getIpInfo(database, ip);
}

// Fire-and-forget background enrichment for IPs with no cached info yet.
// Bounded by `max` so a busy activity view doesn't burn the rate limit.
function enrichMissing(database, ips, max = 6) {
  const todo = [];
  for (const ip of ips) {
    if (todo.length >= max) break;
    if (!db.getIpInfo(database, ip)) todo.push(ip);
  }
  (async () => {
    for (const ip of todo) {
      try { await enrich(database, ip); } catch { /* ignore */ }
    }
  })();
}

module.exports = { enrich, enrichMissing, isPrivateIp };
