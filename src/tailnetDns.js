// Which hosts are reachable over the tailnet, and the dnsmasq config that makes
// it so.
//
// The distinction this module exists to make explicit: being ON the tailnet does
// not mean traffic TRAVELS over it. Tailscale carries only packets addressed to
// 100.x. A host whose name resolves publicly is reached over the ordinary
// internet, and arrives at Caddy with the visitor's carrier address — which the
// allowlist then refuses, even when that allowlist contains the whole tailnet
// range. DNS decides which road traffic takes; the allowlist only judges who
// arrives. lab.artandistai.com worked from a phone and catalog.koraybirand.com
// did not, purely because one had a DNS override and the other did not.
//
// Tailscale's split DNS points a DOMAIN at a nameserver, so it is configured
// once per apex domain (artandistai.com, koraybirand.com) and left alone. This
// file then decides host by host: an `address=` line sends one name to the
// tailnet, and anything without a line is forwarded and answers publicly. No
// Tailscale API token is needed at runtime.

const CONF_PATH = '/etc/dnsmasq.d/rproxy-tailnet.conf';

// Deliberately strict. These names are written into a config file that dnsmasq
// parses line by line, so a hostname carrying a newline could otherwise append
// a directive of its own.
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/i;

function isValidHostname(h) {
  return typeof h === 'string' && h.length <= 253 && HOSTNAME_RE.test(h);
}

// Every name a rule answers to, including the www alias when add_www is set —
// the alias is served by the same rule, so it must resolve the same way or it
// silently falls back to the public address.
function namesFor(rule) {
  const out = [];
  if (isValidHostname(rule.hostname)) out.push(rule.hostname);
  if (rule.add_www && isValidHostname(`www.${rule.hostname}`) && !/^www\./i.test(rule.hostname)) {
    out.push(`www.${rule.hostname}`);
  }
  return out;
}

function active(rules) {
  return (rules || []).filter((r) => r && r.enabled && r.tailnet_dns);
}

function renderDnsmasqConf(rules, opts = {}) {
  const ip = (opts.tailscaleIp || '').trim();
  const head = [
    '# Managed by rproxy — do not edit by hand; the UI rewrites this file.',
    '#',
    '# Each line sends one hostname to this machine\'s tailnet address instead of',
    '# its public one, so tailnet devices reach it over Tailscale and everyone',
    '# else keeps getting the public answer. Hosts absent from this file are',
    '# forwarded upstream unchanged.',
    '#',
    '# Requires a Tailscale split-DNS entry for each apex domain below, pointing',
    '# at this machine. Without that, tailnet clients never ask this resolver.',
    '',
  ];
  if (!ip) {
    return head.concat([
      '# No tailnet address is configured, so nothing is overridden. Set',
      '# TAILSCALE_IP (or let the UI detect it) and save a rule to regenerate.',
      '',
    ]).join('\n');
  }
  const lines = [];
  for (const rule of active(rules)) {
    for (const name of namesFor(rule)) lines.push(`address=/${name}/${ip}`);
  }
  const domains = splitDnsDomains(rules);
  return head.concat([
    domains.length
      ? `# Split-DNS domains to configure in Tailscale: ${domains.join(', ')}`
      : '# No hosts are currently served over the tailnet.',
    '',
    ...lines,
    '',
  ]).join('\n');
}

// The apex domains that need a Tailscale split-DNS entry, derived from the hosts
// actually enabled rather than typed in somewhere and left to drift.
function splitDnsDomains(rules) {
  const set = new Set();
  for (const rule of active(rules)) {
    for (const name of namesFor(rule)) {
      const parts = name.split('.');
      if (parts.length >= 2) set.add(parts.slice(-2).join('.'));
    }
  }
  return [...set].sort();
}

function parseIpList(text) {
  if (!text) return [];
  return String(text).split(/[\n,]+/).map((s) => s.replace(/#.*$/, '').trim()).filter(Boolean);
}

// One row per rule describing how it can actually be reached, which is the thing
// no single screen showed before.
function statusFor(rules, opts = {}) {
  const ip = (opts.tailscaleIp || '').trim();
  return (rules || []).map((r) => {
    const allow = parseIpList(r.deny_ips);
    const gated = r.access_mode === 'whitelist' && allow.length > 0;
    const overTailnet = !!(r.enabled && r.tailnet_dns && ip);
    // 100.64.0.0/10 is the whole CGNAT range Tailscale draws from: allowing it
    // admits every member of the tailnet, staff included, not just your own
    // devices. Paired with a tailnet DNS override that is a real exposure, and
    // it is invisible unless the two are shown together.
    const wholeTailnetAllowed = allow.some((e) => e.startsWith('100.64.0.0/'));
    return {
      hostname: r.hostname,
      enabled: !!r.enabled,
      overTailnet,
      publicly: true,
      gated,
      allowCount: allow.length,
      wholeTailnetAllowed,
      warnOpenToAllTailnet: overTailnet && wholeTailnetAllowed,
    };
  });
}


// What the rules say, versus what dnsmasq was actually given.
//
// These can disagree for reasons a screen reading only the database cannot see:
// the helper refused the config, the service failed to restart, someone edited
// the file, or — as happened here — the regeneration hook was handed the wrong
// argument and quietly did nothing while the panel went on showing the host as
// reachable. `installed` is the raw file content, or null when it cannot be
// read; unreadable counts as drift, because not knowing is not the same as
// agreeing.
function driftFrom(rules, installed, opts = {}) {
  const want = new Set();
  const ip = (opts.tailscaleIp || '').trim();
  if (ip) for (const rule of active(rules)) for (const n of namesFor(rule)) want.add(n);

  if (typeof installed !== 'string') {
    return { inSync: false, unreadable: true, missing: [...want].sort(), extra: [] };
  }
  const have = new Set();
  for (const line of installed.split('\n')) {
    const m = /^address=\/([^/]+)\//.exec(line.trim());
    if (m) have.add(m[1]);
  }
  const missing = [...want].filter((h) => !have.has(h)).sort();
  const extra = [...have].filter((h) => !want.has(h)).sort();
  return { inSync: missing.length === 0 && extra.length === 0, unreadable: false, missing, extra };
}

module.exports = {
  CONF_PATH, renderDnsmasqConf, splitDnsDomains, statusFor, isValidHostname, namesFor,
  driftFrom,
};
