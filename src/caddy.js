const path = require('node:path');

// Optional fallback upstream for requests whose Host doesn't match any rule
// but does match FALLBACK_HOSTS (bare IP / loopback). Empty => no fallback,
// unmatched requests get a clean 404. APACHE_PORT is kept as a legacy alias.
const DEFAULT_FALLBACK_UPSTREAM = process.env.FALLBACK_UPSTREAM
  || (process.env.APACHE_PORT ? `127.0.0.1:${process.env.APACHE_PORT}` : '');
const DEFAULT_CERT_DIR = process.env.CERT_DIR || '/etc/rproxy/certs';
const DEFAULT_ADMIN = process.env.CADDY_ADMIN || 'http://127.0.0.1:2019';
const DEFAULT_DNS_PROVIDER = process.env.ACME_DNS_PROVIDER || ''; // 'cloudflare' enables DNS-01
const DEFAULT_ACME_EMAIL = process.env.ACME_EMAIL || '';
// Hosts that fall through to FALLBACK_UPSTREAM (typically a bare LAN IP /
// loopback). Anything else (unknown hostname) gets a clean 404. The installer
// writes the machine's own LAN IP into FALLBACK_HOSTS; APACHE_FALLBACK_HOSTS
// is kept as a legacy alias.
const DEFAULT_FALLBACK_HOSTS = (process.env.FALLBACK_HOSTS
  || process.env.APACHE_FALLBACK_HOSTS
  || '127.0.0.1,localhost,::1')
  .split(',').map((s) => s.trim()).filter(Boolean);

// Cloudflare edge IP ranges (https://www.cloudflare.com/ips/). Registered as
// trusted_proxies so the `client_ip` matcher resolves the *real* visitor IP
// from X-Forwarded-For instead of seeing Cloudflare's edge address. Without
// this, per-rule IP blocklists would match CF edge IPs, never the visitor.
const CLOUDFLARE_IPS = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
  '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
];

function hostsFor(rule) {
  const hosts = [rule.hostname];
  if (rule.add_www) hosts.push(`www.${rule.hostname}`);
  return hosts;
}

// Parse a free-text IP/CIDR blocklist (newline- or comma-separated) into a
// clean array. Comments (# ...) and blank lines are ignored.
function parseIpList(text) {
  if (!text) return [];
  return String(text)
    .split(/[\n,]+/)
    .map((s) => s.replace(/#.*$/, '').trim())
    .filter(Boolean);
}

// A route for blocklisted client IPs hitting this rule's hostname(s). Placed
// BEFORE the rule's proxy route so it wins. Returns null when the rule has no
// blocklist. If deny_redirect is set, blocked IPs get a 302 to that URL;
// otherwise they get a plain 403.
function buildDenyRoute(rule) {
  const ranges = parseIpList(rule.deny_ips);
  if (!ranges.length) return null;
  const redirect = (rule.deny_redirect || '').trim();
  const handler = redirect
    ? {
        handler: 'static_response',
        status_code: 302,
        headers: { Location: [redirect] },
      }
    : {
        handler: 'static_response',
        status_code: 403,
        headers: { 'Content-Type': ['text/plain; charset=utf-8'] },
        body: 'Forbidden\n',
      };
  return {
    match: [{ host: hostsFor(rule), client_ip: { ranges } }],
    handle: [handler],
    terminal: true,
  };
}

function reverseProxyHandler(rule) {
  const handler = {
    handler: 'reverse_proxy',
    upstreams: [{ dial: `${rule.backend_host}:${rule.backend_port}` }],
    // Preserve the original Host header to the upstream. Caddy's default is
    // to overwrite it with the upstream's dial address (e.g. "192.168.1.239:443"),
    // which breaks virtual-host-based backends like Synology Web Station,
    // Apache name-vhosts, nginx server_name routing, etc. Plain TCP backends
    // (most node apps here) ignore the Host header, so this is safe globally.
    headers: {
      request: {
        set: { Host: ['{http.request.host}'] },
      },
    },
  };

  if (rule.backend_tls) {
    handler.transport = {
      protocol: 'http',
      tls: {
        insecure_skip_verify: true,
        // Send SNI matching the original request Host, not the upstream's IP.
        // Synology and similar nginx-backed origins route Web Station by SNI;
        // without this they return their default vhost (often 403).
        server_name: '{http.request.host}',
      },
    };
  }

  const transport = handler.transport || { protocol: 'http' };
  if (rule.read_timeout && rule.read_timeout > 0) {
    transport.read_timeout = `${rule.read_timeout}s`;
    transport.write_timeout = `${rule.read_timeout}s`;
    transport.dial_timeout = '10s';
    handler.transport = transport;
  } else {
    handler.transport = transport;
  }

  if (rule.websocket) {
    handler.headers = handler.headers || {};
    handler.headers.request = handler.headers.request || {};
    handler.headers.request.set = handler.headers.request.set || {};
    handler.headers.request.set.Connection = ['{http.request.header.Connection}'];
    handler.headers.request.set.Upgrade = ['{http.request.header.Upgrade}'];
  }

  return handler;
}

function hstsHandler() {
  return {
    handler: 'headers',
    response: {
      set: {
        'Strict-Transport-Security': ['max-age=31536000; includeSubDomains'],
      },
    },
  };
}

function buildRouteForRule(rule, certDir) {
  const hosts = hostsFor(rule);
  const handlers = [];
  if (rule.hsts && rule.tls_mode !== 'http') {
    handlers.push(hstsHandler());
  }
  handlers.push(reverseProxyHandler(rule));

  return {
    match: [{ host: hosts }],
    handle: handlers,
    terminal: true,
  };
}

function tlsConnPolicyForRule(rule) {
  const hosts = hostsFor(rule);
  if (rule.tls_mode === 'manual') {
    return {
      match: { sni: hosts },
      certificate_selection: { any_tag: [`manual:${rule.hostname}`] },
    };
  }
  return null;
}

function tlsLoadDirectivesForRule(rule, certDir) {
  if (rule.tls_mode !== 'manual') return null;
  const baseDir = rule.cert_path && rule.cert_path.trim()
    ? rule.cert_path.trim()
    : path.join(certDir, rule.hostname);
  return {
    certificate: path.join(baseDir, 'fullchain.pem'),
    key: path.join(baseDir, 'privkey.pem'),
    tags: [`manual:${rule.hostname}`],
  };
}

function acmeIssuer(opts) {
  const issuer = { module: 'acme' };
  if (opts.acmeEmail) issuer.email = opts.acmeEmail;
  if (opts.dnsProvider === 'cloudflare') {
    issuer.challenges = {
      dns: {
        provider: {
          name: 'cloudflare',
          api_token: '{env.CF_API_TOKEN}',
        },
      },
    };
  }
  return issuer;
}

function automationPoliciesForRules(rules, opts = {}) {
  const policies = [];

  const internalHosts = rules
    .filter((r) => r.enabled && r.tls_mode === 'self')
    .flatMap(hostsFor);
  if (internalHosts.length) {
    policies.push({
      subjects: internalHosts,
      issuers: [{ module: 'internal' }],
    });
  }

  const leHosts = rules
    .filter((r) => r.enabled && r.tls_mode === 'letsencrypt')
    .flatMap(hostsFor);
  if (leHosts.length && opts.dnsProvider) {
    policies.push({
      subjects: leHosts,
      issuers: [acmeIssuer(opts)],
    });
  }

  const skipHosts = rules
    .filter((r) => r.enabled && (r.tls_mode === 'http' || r.tls_mode === 'manual'))
    .flatMap(hostsFor);
  if (skipHosts.length) {
    policies.push({
      subjects: skipHosts,
      on_demand: false,
      issuers: [],
    });
  }

  return policies;
}

function renderConfig(rules, opts = {}) {
  const fallbackUpstream = opts.fallbackUpstream !== undefined
    ? opts.fallbackUpstream : DEFAULT_FALLBACK_UPSTREAM;
  const certDir = opts.certDir || DEFAULT_CERT_DIR;
  const dnsProvider = opts.dnsProvider !== undefined ? opts.dnsProvider : DEFAULT_DNS_PROVIDER;
  const acmeEmail = opts.acmeEmail !== undefined ? opts.acmeEmail : DEFAULT_ACME_EMAIL;
  const enabled = rules.filter((r) => r.enabled);

  const httpRoutes = [];
  const httpsRoutes = [];

  // Match the Synology DSM behavior: serve both :80 and :443 for every rule
  // (when the rule has TLS), routed to the same backend. No automatic
  // HTTP -> HTTPS redirect — that breaks Cloudflare "Flexible" SSL zones,
  // where CF talks plain HTTP to origin. Visitors that hit the public
  // hostname via https:// still get TLS at the edge (CF) regardless.
  for (const rule of enabled) {
    const route = buildRouteForRule(rule, certDir);
    const denyRoute = buildDenyRoute(rule); // null when no blocklist
    // Deny route must precede the proxy route so a blocked IP is rejected
    // before it can be proxied. Non-http rules live on both :80 and :443.
    if (denyRoute) httpRoutes.push(denyRoute);
    httpRoutes.push(route);
    if (rule.tls_mode !== 'http') {
      if (denyRoute) httpsRoutes.push(denyRoute);
      httpsRoutes.push(route);
    }
  }

  // Optional fallback: requests to a bare IP / loopback host (FALLBACK_HOSTS)
  // are proxied to FALLBACK_UPSTREAM — e.g. a pre-existing Apache/nginx serving
  // a local admin dashboard. When FALLBACK_UPSTREAM is empty, this is skipped
  // and those requests get the clean 404 below, same as any unknown host.
  const fallbackHosts = opts.fallbackHosts || DEFAULT_FALLBACK_HOSTS;
  if (fallbackUpstream && fallbackHosts.length) {
    httpRoutes.push({
      match: [{ host: fallbackHosts }],
      handle: [
        {
          handler: 'reverse_proxy',
          upstreams: [{ dial: fallbackUpstream }],
        },
      ],
      terminal: true,
    });
  }
  httpRoutes.push({
    handle: [
      {
        handler: 'static_response',
        status_code: 404,
        headers: { 'Content-Type': ['text/plain; charset=utf-8'] },
        body: 'Not Found\n',
      },
    ],
    terminal: true,
  });

  const tlsLoadFiles = [];
  for (const rule of enabled) {
    const d = tlsLoadDirectivesForRule(rule, certDir);
    if (d) tlsLoadFiles.push(d);
  }

  const tlsConnPolicies = [];
  for (const rule of enabled) {
    const p = tlsConnPolicyForRule(rule);
    if (p) tlsConnPolicies.push(p);
  }

  // Trust Cloudflare's edge ranges so the `client_ip` matcher (used by
  // per-rule IP blocklists) resolves the real visitor IP from X-Forwarded-For.
  const trustedProxies = { source: 'static', ranges: CLOUDFLARE_IPS };

  const servers = {
    srv_http: {
      listen: [':80'],
      routes: httpRoutes,
      trusted_proxies: trustedProxies,
      automatic_https: { disable_redirects: true },
    },
  };

  if (httpsRoutes.length) {
    servers.srv_https = {
      listen: [':443'],
      routes: httpsRoutes,
      trusted_proxies: trustedProxies,
    };
    if (tlsConnPolicies.length) {
      servers.srv_https.tls_connection_policies = tlsConnPolicies;
    }
  }

  const config = {
    admin: {
      listen: '127.0.0.1:2019',
      // Bound to loopback, so the network boundary is the trust boundary.
      // Caddy 2.10+ rejects empty-Origin requests by default; turn the check off.
      enforce_origin: false,
      origins: ['127.0.0.1:2019', 'localhost:2019', '[::1]:2019'],
    },
    logging: {
      logs: {
        default: { level: 'INFO' },
      },
    },
    apps: {
      http: { servers },
    },
  };

  const automation = automationPoliciesForRules(enabled, { dnsProvider, acmeEmail });
  if (automation.length || tlsLoadFiles.length) {
    config.apps.tls = {};
    if (automation.length) {
      config.apps.tls.automation = { policies: automation };
    }
    if (tlsLoadFiles.length) {
      config.apps.tls.certificates = { load_files: tlsLoadFiles };
    }
  }

  return config;
}

async function pushConfig(config, adminUrl = DEFAULT_ADMIN) {
  const res = await fetch(`${adminUrl}/load`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      // Caddy 2.10+ rejects an empty Origin even though the listener is
      // bound to 127.0.0.1. Send one that matches the admin listen address.
      'Origin': adminUrl,
    },
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    const err = new Error(`Caddy /load failed: ${res.status} ${res.statusText} - ${body}`);
    err.status = res.status;
    err.body = body;
    throw err;
  }
  return true;
}

async function caddyHealthy(adminUrl = DEFAULT_ADMIN) {
  try {
    const res = await fetch(`${adminUrl}/config/`, {
      method: 'GET',
      headers: { 'Origin': adminUrl },
    });
    return res.ok;
  } catch {
    return false;
  }
}

module.exports = {
  renderConfig,
  pushConfig,
  caddyHealthy,
  DEFAULT_FALLBACK_UPSTREAM,
  DEFAULT_CERT_DIR,
  DEFAULT_ADMIN,
};
