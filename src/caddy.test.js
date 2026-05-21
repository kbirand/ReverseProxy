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
