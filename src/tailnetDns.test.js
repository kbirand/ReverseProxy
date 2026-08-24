const test = require('node:test');
const assert = require('node:assert/strict');
const tsdns = require('./tailnetDns');

// Being ON the tailnet does not mean traffic TRAVELS over it. Tailscale carries
// only packets addressed to 100.x, so a host whose name resolves publicly is
// reached over the ordinary internet and arrives at Caddy with the visitor's
// carrier address — which the allowlist then refuses. That is the whole reason
// lab.artandistai.com worked from a phone and catalog.koraybirand.com did not,
// despite both allowing the tailnet range. DNS decides which road the traffic
// takes; the allowlist only judges who arrives.
const TS_IP = '100.67.156.28';

test('only hosts with the toggle on are pointed at the tailnet', () => {
  const conf = tsdns.renderDnsmasqConf([
    { hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 1 },
    { hostname: 'catalog.koraybirand.com', tailnet_dns: 0, enabled: 1 },
  ], { tailscaleIp: TS_IP });
  assert.match(conf, /^address=\/lab\.artandistai\.com\/100\.67\.156\.28$/m);
  assert.doesNotMatch(conf, /catalog/);
});

test('www aliases follow the rule they belong to', () => {
  const conf = tsdns.renderDnsmasqConf([
    { hostname: 'artandistai.com', tailnet_dns: 1, enabled: 1, add_www: 1 },
  ], { tailscaleIp: TS_IP });
  assert.match(conf, /address=\/artandistai\.com\/100\.67\.156\.28/);
  assert.match(conf, /address=\/www\.artandistai\.com\/100\.67\.156\.28/,
    'add_www serves the www name too, so it must resolve the same way');
});

test('a disabled rule is not published', () => {
  const conf = tsdns.renderDnsmasqConf([
    { hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 0 },
  ], { tailscaleIp: TS_IP });
  assert.doesNotMatch(conf, /lab\.artandistai\.com/);
});

test('no tailnet address means no file content, not a broken one', () => {
  const conf = tsdns.renderDnsmasqConf(
    [{ hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 1 }], { tailscaleIp: '' });
  assert.doesNotMatch(conf, /address=/, 'without an address there is nothing safe to write');
  assert.match(conf, /#/, 'but the file should still explain itself');
});

test('hostnames are validated — a crafted one cannot inject config', () => {
  const conf = tsdns.renderDnsmasqConf([
    { hostname: 'ok.example.com', tailnet_dns: 1, enabled: 1 },
    { hostname: 'evil.com/\nserver=8.8.4.4', tailnet_dns: 1, enabled: 1 },
    { hostname: 'has space.com', tailnet_dns: 1, enabled: 1 },
    { hostname: '', tailnet_dns: 1, enabled: 1 },
  ], { tailscaleIp: TS_IP });
  assert.match(conf, /address=\/ok\.example\.com\//);
  assert.doesNotMatch(conf, /server=8\.8\.4\.4/, 'a newline in a hostname must not become a directive');
  assert.doesNotMatch(conf, /has space/);
});

test('the apex domains needing a Tailscale split-DNS entry are derived, not guessed', () => {
  const domains = tsdns.splitDnsDomains([
    { hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 1 },
    { hostname: 'music.artandistai.com', tailnet_dns: 1, enabled: 1 },
    { hostname: 'catalog.koraybirand.com', tailnet_dns: 1, enabled: 1 },
    { hostname: 'off.example.com', tailnet_dns: 0, enabled: 1 },
  ]);
  assert.deepEqual(domains, ['artandistai.com', 'koraybirand.com']);
});

// The trap that cost an evening: a host reachable over the tailnet AND allowing
// the whole tailnet range is reachable by every tailnet member, staff included.
test('a host open to the whole tailnet range is flagged', () => {
  const rows = tsdns.statusFor([
    { hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 1,
      access_mode: 'whitelist', deny_ips: '212.154.84.86\n100.64.0.0/10' },
    { hostname: 'esc.koraybirand.com', tailnet_dns: 1, enabled: 1,
      access_mode: 'whitelist', deny_ips: '212.154.84.86\n100.67.156.28' },
  ], { tailscaleIp: TS_IP });
  const lab = rows.find((r) => r.hostname === 'lab.artandistai.com');
  const esc = rows.find((r) => r.hostname === 'esc.koraybirand.com');
  assert.equal(lab.wholeTailnetAllowed, true, 'lab allows 100.64.0.0/10 — every member reaches it');
  assert.equal(esc.wholeTailnetAllowed, false, 'esc lists individual devices instead');
});

test('status says how each host is reachable', () => {
  const rows = tsdns.statusFor([
    { hostname: 'a.example.com', tailnet_dns: 1, enabled: 1, access_mode: 'whitelist', deny_ips: '1.2.3.4' },
    { hostname: 'b.example.com', tailnet_dns: 0, enabled: 1, access_mode: 'whitelist', deny_ips: '1.2.3.4' },
    { hostname: 'c.example.com', tailnet_dns: 0, enabled: 1, access_mode: 'blacklist', deny_ips: '' },
  ], { tailscaleIp: TS_IP });
  assert.equal(rows.find((r) => r.hostname === 'a.example.com').overTailnet, true);
  assert.equal(rows.find((r) => r.hostname === 'b.example.com').overTailnet, false);
  assert.equal(rows.find((r) => r.hostname === 'c.example.com').gated, false, 'no allowlist = open to the internet');
  assert.equal(rows.find((r) => r.hostname === 'a.example.com').gated, true);
});

// The regeneration hook silently passed a rule COUNT where an array was
// expected, so the config was never rewritten and the panel happily showed a
// host as tailnet-reachable while dnsmasq had never heard of it. The database
// and the installed file can drift for any number of reasons — a helper that
// failed, a hand edit, a service that did not restart — and a screen that only
// reads the database cannot tell. Comparing the two is what makes that visible.
test('drift between the rules and the installed config is detected', () => {
  const rules = [
    { hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 1 },
    { hostname: 'catalog.koraybirand.com', tailnet_dns: 1, enabled: 1 },
  ];
  const installed = 'address=/lab.artandistai.com/100.67.156.28\n';
  const d = tsdns.driftFrom(rules, installed, { tailscaleIp: '100.67.156.28' });
  assert.equal(d.inSync, false);
  assert.deepEqual(d.missing, ['catalog.koraybirand.com'], 'ticked in the panel, absent from dnsmasq');
  assert.deepEqual(d.extra, []);
});

test('a config carrying a host the rules no longer want is also drift', () => {
  const installed = 'address=/old.example.com/100.67.156.28\n';
  const d = tsdns.driftFrom([], installed, { tailscaleIp: '100.67.156.28' });
  assert.equal(d.inSync, false);
  assert.deepEqual(d.extra, ['old.example.com'], 'still resolving over the tailnet with no rule behind it');
});

test('matching state reports in sync', () => {
  const rules = [{ hostname: 'lab.artandistai.com', tailnet_dns: 1, enabled: 1 }];
  const installed = 'address=/lab.artandistai.com/100.67.156.28\n';
  assert.equal(tsdns.driftFrom(rules, installed, { tailscaleIp: '100.67.156.28' }).inSync, true);
});

test('an unreadable config counts as drift, never as agreement', () => {
  const d = tsdns.driftFrom([{ hostname: 'a.example.com', tailnet_dns: 1, enabled: 1 }], null,
    { tailscaleIp: '100.67.156.28' });
  assert.equal(d.inSync, false, 'not being able to read the file is not the same as it being correct');
});
