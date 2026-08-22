const test = require('node:test');
const assert = require('node:assert/strict');
const { renderConfig } = require('./caddy');

const baseRule = {
  id: 1,
  hostname: 'example.com',
  backend_host: '127.0.0.1',
  backend_port: 3000,
  backend_tls: 0,
  add_www: 0,
  tls_mode: 'http',
  cert_path: null,
  websocket: 0,
  hsts: 0,
  read_timeout: 60,
  enabled: 1,
};

function findRoute(config, hostname, server) {
  const servers = server ? [config.apps.http.servers[server]] : [
    config.apps.http.servers.srv_https,
    config.apps.http.servers.srv_http,
  ].filter(Boolean);
  for (const s of servers) {
    const hit = (s.routes || []).find((r) =>
      r.match && r.match[0].host && r.match[0].host.includes(hostname)
      && r.handle.find((h) => h.handler === 'reverse_proxy'));
    if (hit) return hit;
  }
  return null;
}

test('http rule lives on srv_http only', () => {
  const cfg = renderConfig([{ ...baseRule, hostname: 'example.com', tls_mode: 'http' }]);
  assert.equal(cfg.apps.http.servers.srv_http.listen[0], ':80');
  assert.equal(cfg.apps.http.servers.srv_https, undefined);
  const route = findRoute(cfg, 'example.com');
  assert.ok(route);
  assert.deepEqual(route.match[0].host, ['example.com']);
});

test('add_www adds www. alias to host matcher', () => {
  const cfg = renderConfig([{ ...baseRule, hostname: 'example.com', add_www: 1 }]);
  const route = findRoute(cfg, 'example.com');
  assert.deepEqual(route.match[0].host, ['example.com', 'www.example.com']);
});

test('websocket toggle injects Upgrade/Connection headers', () => {
  const cfg = renderConfig([{ ...baseRule, websocket: 1 }]);
  const route = findRoute(cfg, 'example.com');
  const rp = route.handle.find((h) => h.handler === 'reverse_proxy');
  assert.ok(rp.headers.request.set.Connection);
  assert.ok(rp.headers.request.set.Upgrade);
});

test('self TLS uses internal issuer', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'self' }]);
  assert.ok(cfg.apps.http.servers.srv_https);
  const policies = cfg.apps.tls.automation.policies;
  const internal = policies.find((p) => p.issuers && p.issuers[0]?.module === 'internal');
  assert.ok(internal);
  assert.ok(internal.subjects.includes('example.com'));
});

test('letsencrypt has no explicit tls automation override', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'letsencrypt' }]);
  assert.ok(cfg.apps.http.servers.srv_https);
  const policies = (cfg.apps.tls && cfg.apps.tls.automation && cfg.apps.tls.automation.policies) || [];
  const internal = policies.find((p) => p.issuers && p.issuers[0]?.module === 'internal');
  assert.equal(internal, undefined);
});

test('manual TLS adds load_files and connection policy', () => {
  const cfg = renderConfig([
    { ...baseRule, tls_mode: 'manual', cert_path: '/tmp/example/' },
  ]);
  assert.ok(cfg.apps.tls.certificates.load_files);
  const f = cfg.apps.tls.certificates.load_files[0];
  assert.equal(f.certificate, '/tmp/example/fullchain.pem');
  assert.equal(f.key, '/tmp/example/privkey.pem');
  assert.ok(cfg.apps.http.servers.srv_https.tls_connection_policies);
});

test('hsts adds Strict-Transport-Security only when TLS is on', () => {
  const httpsCfg = renderConfig([{ ...baseRule, hsts: 1, tls_mode: 'letsencrypt' }]);
  const httpsRoute = findRoute(httpsCfg, 'example.com');
  const hdr = httpsRoute.handle.find((h) => h.handler === 'headers');
  assert.ok(hdr.response.set['Strict-Transport-Security']);

  const httpCfg = renderConfig([{ ...baseRule, hsts: 1, tls_mode: 'http' }]);
  const httpRoute = findRoute(httpCfg, 'example.com');
  const hdr2 = httpRoute.handle.find((h) => h.handler === 'headers');
  assert.equal(hdr2, undefined);
});

test('disabled rule is excluded', () => {
  const cfg = renderConfig([{ ...baseRule, enabled: 0 }]);
  assert.equal(findRoute(cfg, 'example.com'), null);
});

test('fallback upstream only matches bare-IP / loopback hosts', () => {
  const cfg = renderConfig([], { fallbackUpstream: '127.0.0.1:8081', fallbackHosts: ['192.168.1.99','127.0.0.1','localhost'] });
  const routes = cfg.apps.http.servers.srv_http.routes;
  const fbRoute = routes.find((r) => r.match && r.match[0].host?.includes('192.168.1.99')
    && r.handle.find((h) => h.handler === 'reverse_proxy'));
  assert.ok(fbRoute, 'expected a fallback route matching bare-IP/loopback');
  const rp = fbRoute.handle.find((h) => h.handler === 'reverse_proxy');
  assert.equal(rp.upstreams[0].dial, '127.0.0.1:8081');
});

test('empty fallbackUpstream => no fallback route, bare IP also 404s', () => {
  const cfg = renderConfig([], { fallbackUpstream: '', fallbackHosts: ['192.168.1.99'] });
  const routes = cfg.apps.http.servers.srv_http.routes;
  assert.equal(routes.find((r) => r.match && r.match[0].host?.includes('192.168.1.99')), undefined);
  const last = routes[routes.length - 1];
  assert.equal(last.handle.find((h) => h.handler === 'static_response').status_code, 404);
});

test('unknown hostname falls through to a clean 404 (not the fallback)', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], { fallbackUpstream: '127.0.0.1:8081' });
  const routes = cfg.apps.http.servers.srv_http.routes;
  const last = routes[routes.length - 1];
  assert.equal(last.match, undefined, 'final catch-all has no host match');
  const sr = last.handle.find((h) => h.handler === 'static_response');
  assert.ok(sr, 'final catch-all is a static_response');
  assert.equal(sr.status_code, 404);
});

test('deny_ips produces a 403 route before the proxy route', () => {
  const cfg = renderConfig([
    { ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4\n10.0.0.0/8  # office' },
  ]);
  const routes = cfg.apps.http.servers.srv_http.routes;
  const denyIdx = routes.findIndex((r) =>
    r.match && r.match[0].client_ip && r.handle.find((h) => h.handler === 'static_response' && h.status_code === 403));
  const proxyIdx = routes.findIndex((r) =>
    r.match && r.match[0].host?.includes('example.com') && r.handle.find((h) => h.handler === 'reverse_proxy'));
  assert.ok(denyIdx >= 0, 'expected a 403 deny route');
  assert.ok(proxyIdx >= 0);
  assert.ok(denyIdx < proxyIdx, 'deny route must come before proxy route');
  const deny = routes[denyIdx];
  assert.deepEqual(deny.match[0].client_ip.ranges, ['1.2.3.4', '10.0.0.0/8']);
  assert.deepEqual(deny.match[0].host, ['example.com']);
});

test('whitelist mode rejects the unlisted (not + client_ip matcher)', () => {
  const cfg = renderConfig([
    { ...baseRule, tls_mode: 'http', access_mode: 'whitelist', deny_ips: '1.2.3.4\n10.0.0.0/8' },
  ]);
  const routes = cfg.apps.http.servers.srv_http.routes;
  const acl = routes.find((r) => r.match && r.match[0].not);
  assert.ok(acl, 'whitelist ACL route uses a not-matcher');
  assert.deepEqual(acl.match[0].host, ['example.com']);
  assert.deepEqual(acl.match[0].not[0].client_ip.ranges, ['1.2.3.4', '10.0.0.0/8']);
  // and it comes before the proxy route
  const proxyIdx = routes.findIndex((r) => r.match && r.match[0].host?.includes('example.com')
    && r.handle.find((h) => h.handler === 'reverse_proxy'));
  const aclIdx = routes.indexOf(acl);
  assert.ok(aclIdx < proxyIdx, 'ACL route precedes proxy route');
});

test('blacklist mode (default) rejects the listed (plain client_ip matcher)', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4' }]);
  const acl = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  assert.ok(acl, 'blacklist uses a direct client_ip matcher');
  assert.equal(acl.match[0].not, undefined, 'blacklist has no not-matcher');
});

test('empty IP list disables ACL even in whitelist mode (no lockout)', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', access_mode: 'whitelist', deny_ips: '' }]);
  const routes = cfg.apps.http.servers.srv_http.routes;
  assert.equal(routes.find((r) => r.match && (r.match[0].not || r.match[0].client_ip)), undefined);
});

test('deny_redirect turns the deny route into a 302', () => {
  const cfg = renderConfig([
    { ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4', deny_redirect: 'https://example.com/blocked' },
  ]);
  const routes = cfg.apps.http.servers.srv_http.routes;
  const deny = routes.find((r) => r.match && r.match[0].client_ip);
  assert.ok(deny);
  const sr = deny.handle.find((h) => h.handler === 'static_response');
  assert.equal(sr.status_code, 302);
  assert.deepEqual(sr.headers.Location, ['https://example.com/blocked']);
  assert.equal(sr.body, undefined, 'redirect has no body');
});

test('deny_ips without deny_redirect stays a plain 403', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4' }]);
  const deny = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const sr = deny.handle.find((h) => h.handler === 'static_response');
  assert.equal(sr.status_code, 403);
  assert.equal(sr.body, 'Forbidden\n');
});

test('no deny_ips => no deny route', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }]);
  const routes = cfg.apps.http.servers.srv_http.routes;
  assert.equal(routes.find((r) => r.match && r.match[0].client_ip), undefined);
});

test('servers carry Cloudflare trusted_proxies', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'letsencrypt' }]);
  const tp = cfg.apps.http.servers.srv_http.trusted_proxies;
  assert.equal(tp.source, 'static');
  assert.ok(tp.ranges.includes('104.16.0.0/13'), 'CF range present');
  assert.ok(cfg.apps.http.servers.srv_https.trusted_proxies, 'https server too');
});

test('deny route on non-http rule appears on both :80 and :443', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'letsencrypt', deny_ips: '9.9.9.9' }]);
  const httpDeny  = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const httpsDeny = cfg.apps.http.servers.srv_https.routes.find((r) => r.match && r.match[0].client_ip);
  assert.ok(httpDeny,  'deny route on :80');
  assert.ok(httpsDeny, 'deny route on :443');
});

test('global blocklist emits a first-priority client_ip reject route', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'letsencrypt' }], {
    globalBlocks: ['1.2.3.4', '10.0.0.0/8'],
  });
  const httpFirst  = cfg.apps.http.servers.srv_http.routes[0];
  const httpsFirst = cfg.apps.http.servers.srv_https.routes[0];
  for (const route of [httpFirst, httpsFirst]) {
    assert.ok(route.match[0].client_ip, 'first route matches client_ip');
    assert.deepEqual(route.match[0].client_ip.ranges, ['1.2.3.4', '10.0.0.0/8']);
    assert.equal(route.handle[0].status_code, 403);
    assert.equal(route.match[0].host, undefined, 'global block matches any host');
  }
});

test('no global blocks => no global block route', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], { globalBlocks: [] });
  const first = cfg.apps.http.servers.srv_http.routes[0];
  assert.ok(!(first.match && first.match[0] && first.match[0].client_ip && !first.match[0].host),
    'no host-less client_ip route at the top');
});

test('access logging writes JSON to a file, kept out of journald', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], { accessLogPath: '/tmp/a.log' });
  const access = cfg.logging.logs.access;
  assert.equal(access.writer.output, 'file');
  assert.equal(access.writer.filename, '/tmp/a.log');
  assert.equal(access.encoder.format, 'json');
  assert.ok(cfg.logging.logs.default.exclude.includes('http.log.access'));
  assert.ok(cfg.logging.logs.access.include.includes('http.log.access'));
  assert.deepEqual(cfg.apps.http.servers.srv_http.logs, {});
});

test('user rules + fallback + 404 are ordered correctly', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], {
    fallbackUpstream: '127.0.0.1:8081',
    fallbackHosts: ['10.0.0.5'],
  });
  const routes = cfg.apps.http.servers.srv_http.routes;
  const userIdx     = routes.findIndex((r) => r.match && r.match[0].host?.includes('example.com'));
  const fbIdx       = routes.findIndex((r) => r.match && r.match[0].host?.includes('10.0.0.5'));
  const notFoundIdx = routes.findIndex((r) => !r.match && r.handle?.find((h) => h.handler === 'static_response'));
  assert.ok(userIdx >= 0 && fbIdx >= 0 && notFoundIdx >= 0);
  assert.ok(userIdx < fbIdx, 'user rules before fallback');
  assert.ok(fbIdx < notFoundIdx, 'fallback before 404 catch-all');
});

test('backend_tls sets transport tls with skip_verify', () => {
  const cfg = renderConfig([{ ...baseRule, backend_tls: 1 }]);
  const route = findRoute(cfg, 'example.com');
  const rp = route.handle.find((h) => h.handler === 'reverse_proxy');
  assert.equal(rp.transport.tls.insecure_skip_verify, true);
});

test('non-http rule serves both :80 and :443 with no redirect (Synology-compat)', () => {
  for (const mode of ['self','letsencrypt','manual']) {
    const cfg = renderConfig([{ ...baseRule, tls_mode: mode, cert_path: '/tmp/x' }]);
    const httpRoutes = cfg.apps.http.servers.srv_http.routes;
    const httpsRoutes = cfg.apps.http.servers.srv_https.routes;
    const httpHit  = httpRoutes.find((r) => r.match && r.match[0].host?.includes('example.com')
      && r.handle.find((h) => h.handler === 'reverse_proxy'));
    const httpsHit = httpsRoutes.find((r) => r.match && r.match[0].host?.includes('example.com')
      && r.handle.find((h) => h.handler === 'reverse_proxy'));
    assert.ok(httpHit,  `${mode}: expected reverse_proxy on :80 (no redirect)`);
    assert.ok(httpsHit, `${mode}: expected reverse_proxy on :443`);
    const anyRedirect = httpRoutes.find((r) => r.handle.find((h) => h.handler === 'static_response' && h.status_code === 308));
    assert.equal(anyRedirect, undefined, `${mode}: should NOT emit 308 redirect`);
  }
});

// ---- parked "domain for sale" block page -----------------------------------

test('blockPage off (default): rejected visitors still get a plain 403', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4' }]);
  const deny = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const resp = deny.handle.find((h) => h.handler === 'static_response');
  assert.equal(resp.status_code, 403);
  assert.equal(resp.body, 'Forbidden\n');
});

test('blockPage on: rejected visitors get a 200 HTML parked page', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4' }], { blockPage: true });
  const deny = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const resp = deny.handle.find((h) => h.handler === 'static_response');
  assert.equal(resp.status_code, 200, 'a parked domain answers 200, not 403');
  assert.match(resp.headers['Content-Type'][0], /text\/html/);
  assert.match(resp.body, /available for sale/i);
});

test('blockPage renders the visited hostname via a Caddy placeholder', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4' }], { blockPage: true });
  const deny = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const resp = deny.handle.find((h) => h.handler === 'static_response');
  assert.match(resp.body, /\{http\.request\.host\}/, 'one page body must serve every hostname');
});

test('blockPage carries no third-party branding and no data-collection form', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4' }], { blockPage: true });
  const deny = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const body = deny.handle.find((h) => h.handler === 'static_response').body;
  assert.doesNotMatch(body, /godaddy|trustpilot/i, 'must not impersonate a real company');
  assert.doesNotMatch(body, /<form|<input/i, 'must not collect visitor details');
});

test('blockPage does not override an explicit deny_redirect', () => {
  const cfg = renderConfig(
    [{ ...baseRule, tls_mode: 'http', deny_ips: '1.2.3.4', deny_redirect: 'https://example.net/gone' }],
    { blockPage: true },
  );
  const deny = cfg.apps.http.servers.srv_http.routes.find((r) => r.match && r.match[0].client_ip);
  const resp = deny.handle.find((h) => h.handler === 'static_response');
  assert.equal(resp.status_code, 302);
  assert.equal(resp.headers.Location[0], 'https://example.net/gone');
});

test('blockPage also covers the global blocklist route', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], {
    blockPage: true,
    globalBlocks: ['9.9.9.9'],
  });
  const route = cfg.apps.http.servers.srv_http.routes.find(
    (r) => r.match && r.match[0].client_ip && !r.match[0].host);
  const resp = route.handle.find((h) => h.handler === 'static_response');
  assert.equal(resp.status_code, 200);
  assert.match(resp.body, /available for sale/i);
});

// ---- fallback route is loopback-only ---------------------------------------
// The fallback serves a local admin dashboard (ProxySQL) that has NO
// authentication of its own and can fail over the database cluster via sudo.
// Matching on Host alone is not access control: any LAN client can send
// `Host: localhost` and reach it. The route must also require a loopback
// CLIENT address.

test('the fallback route requires a loopback client IP, not just a matching Host', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], {
    fallbackUpstream: '127.0.0.1:8081',
    fallbackHosts: ['127.0.0.1', 'localhost', '::1', '192.168.1.99'],
  });
  const fb = cfg.apps.http.servers.srv_http.routes.find((r) =>
    r.handle && r.handle.some((h) => h.handler === 'reverse_proxy'
      && h.upstreams && h.upstreams[0].dial === '127.0.0.1:8081'));
  assert.ok(fb, 'fallback route exists');
  const m = fb.match[0];
  assert.ok(m.client_ip, 'fallback must constrain the client address');
  assert.deepEqual(m.client_ip.ranges.sort(), ['127.0.0.1/32', '::1/128'].sort());
  assert.ok(m.host.includes('192.168.1.99'), 'host matching still applies');
});

test('the loopback constraint can be widened deliberately, not by accident', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], {
    fallbackUpstream: '127.0.0.1:8081',
    fallbackHosts: ['127.0.0.1'],
    fallbackClientIps: ['127.0.0.1/32', '::1/128', '192.168.1.0/24'],
  });
  const fb = cfg.apps.http.servers.srv_http.routes.find((r) =>
    r.match && r.match[0] && r.match[0].client_ip && r.match[0].host
    && r.handle.some((h) => h.handler === 'reverse_proxy'
      && h.upstreams && h.upstreams[0].dial === '127.0.0.1:8081'));
  assert.ok(fb, 'fallback route exists');
  assert.ok(fb.match[0].client_ip.ranges.includes('192.168.1.0/24'));
});

test('no fallback upstream means no fallback route at all', () => {
  const cfg = renderConfig([{ ...baseRule, tls_mode: 'http' }], { fallbackUpstream: '' });
  const fb = cfg.apps.http.servers.srv_http.routes.find((r) =>
    r.match && r.match[0] && r.match[0].client_ip && r.match[0].host);
  assert.equal(fb, undefined);
});
