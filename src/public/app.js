const state = {
  rules: [],
  certs: {},
  sort: { key: 'hostname', dir: 'asc' },
  filter: '',
  activity: [],
  activityMeta: null,
  activitySort: { key: null, dir: 'desc' },
  activityFilter: '',
  activitySelected: new Set(),
  hostDetail: { host: null, hours: 24, hosts: [], liveCount: 0, total: 0 },
  ipDetail: { ip: null, hours: 24 },
  live: { stream: null, connected: false },
  view: 'rules',
  version: null,
  auth: null,
  maintenance: { active: false, until: null, hosts: [] },
  maintenanceTick: null,
};

function compileFilter(pattern) {
  const p = (pattern || '').trim().toLowerCase();
  if (!p) return null;
  // Treat bare text as a substring match. Allow `*` as a wildcard.
  // Examples: "xxx" -> contains xxx; "xxx*" -> starts with xxx;
  //           "*xxx" -> ends with xxx; "*x*y*" -> contains x then y.
  const hasGlob = p.includes('*');
  const escape = (s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&');
  let regexSrc;
  if (hasGlob) {
    regexSrc = '^' + p.split('*').map(escape).join('.*') + '$';
  } else {
    regexSrc = escape(p); // anywhere
  }
  try { return new RegExp(regexSrc, 'i'); } catch (_) { return null; }
}

function matchRule(rule, re) {
  if (!re) return true;
  // Match against hostname, backend, port, tls_mode, and notes
  const haystack = [
    rule.hostname,
    rule.backend_host,
    String(rule.backend_port),
    `${rule.backend_host}:${rule.backend_port}`,
    rule.tls_mode,
    rule.notes || '',
    rule.deny_ips || '',
    rule.add_www ? `www.${rule.hostname}` : '',
  ].join(' ').toLowerCase();
  return re.test(haystack);
}

const SORT_ACCESSORS = {
  enabled:      (r) => r.enabled ? 1 : 0,
  hostname:     (r) => r.hostname.toLowerCase(),
  backend_host: (r) => r.backend_host.toLowerCase(),
  backend_port: (r) => r.backend_port,
  tls_mode:     (r) => r.tls_mode,
  cert_days: (r) => {
    if (r.tls_mode === 'http') return Number.POSITIVE_INFINITY; // sort to bottom asc, top desc
    const c = state.certs[r.hostname];
    if (!c) return Number.POSITIVE_INFINITY;
    if (c.error) return -1;
    return c.days_remaining;
  },
  add_www:      (r) => r.add_www ? 1 : 0,
  websocket:    (r) => r.websocket ? 1 : 0,
  hsts:         (r) => r.hsts ? 1 : 0,
};

function sortedRules() {
  const { key, dir } = state.sort;
  const accessor = SORT_ACCESSORS[key] || SORT_ACCESSORS.hostname;
  const mult = dir === 'desc' ? -1 : 1;
  const re = compileFilter(state.filter);
  return state.rules.filter((r) => matchRule(r, re)).sort((a, b) => {
    const av = accessor(a);
    const bv = accessor(b);
    if (av < bv) return -1 * mult;
    if (av > bv) return  1 * mult;
    return a.hostname.localeCompare(b.hostname) * mult;
  });
}

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function fmtBadge(value, options) {
  return options[value] || `<span class="badge off">${value}</span>`;
}

const tlsBadges = {
  http:        `<span class="badge http">HTTP</span>`,
  self:        `<span class="badge self">self</span>`,
  letsencrypt: `<span class="badge le">LE</span>`,
  manual:      `<span class="badge manual">manual</span>`,
};

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  })[c]);
}

function denyCount(rule) {
  if (!rule.deny_ips) return 0;
  return rule.deny_ips
    .split(/[\n,]+/)
    .map((s) => s.replace(/#.*$/, '').trim())
    .filter(Boolean).length;
}

function aclBadge(rule) {
  const n = denyCount(rule);
  if (!n) return '';
  const whitelist = rule.access_mode === 'whitelist';
  const cls = whitelist ? 'cert-ok' : 'cert-crit';
  const icon = whitelist ? '🔒' : '⛔';
  const word = whitelist ? 'whitelisted' : 'blocked';
  return ` <span class="badge ${cls}" title="${n} ${word} IP/CIDR entr${n === 1 ? 'y' : 'ies'} (${whitelist ? 'allow-only' : 'block'} mode)">${icon} ${n}</span>`;
}

function certCellHtml(rule) {
  if (rule.tls_mode === 'http') return '<span class="muted">—</span>';
  const cert = state.certs[rule.hostname];
  if (!cert) return '<span class="muted">…</span>';
  if (cert.error) {
    return `<span class="badge cert-err" title="${escapeHtml(cert.error)}">probe ${escapeHtml(cert.error)}</span>`;
  }
  const days = cert.days_remaining;
  const date = new Date(cert.not_after);
  const dateStr = date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  let cls = 'cert-ok';
  if (days < 14) cls = 'cert-crit';
  else if (days < 30) cls = 'cert-warn';
  const issuerShort = cert.issuer ? cert.issuer.replace(/^.*?·\s*/, '').slice(0, 24) : '';
  const title = `Issuer: ${cert.issuer}\nValid until: ${date.toISOString()}\nDays remaining: ${days}`;
  return `<span class="badge ${cls}" title="${escapeHtml(title)}">${dateStr} · <strong>${days}d</strong></span>`;
}

function renderHeaderArrows() {
  for (const th of $$('#rules-table thead th[data-sort]')) {
    const key = th.dataset.sort;
    th.classList.toggle('sorted-asc', state.sort.key === key && state.sort.dir === 'asc');
    th.classList.toggle('sorted-desc', state.sort.key === key && state.sort.dir === 'desc');
  }
}

function render() {
  renderHeaderArrows();
  const tbody = $('#rules-body');
  if (!state.rules.length) {
    tbody.innerHTML = `<tr><td colspan="10" class="muted">No rules yet. Click <strong>+ New rule</strong> to add one.</td></tr>`;
    return;
  }
  const visible = sortedRules();
  if (!visible.length) {
    tbody.innerHTML = `<tr><td colspan="10" class="muted">No rules match <code>${escapeHtml(state.filter)}</code>. Press Esc to clear.</td></tr>`;
    return;
  }
  tbody.innerHTML = visible.map((r) => `
    <tr data-id="${r.id}">
      <td>
        <button class="enable-toggle ${r.enabled ? 'on' : 'off'}" data-action="toggle" title="Click to ${r.enabled ? 'disable' : 'enable'}">
          ${r.enabled ? 'on' : 'off'}
        </button>
      </td>
      <td><a href="#" class="host-link" data-action="hostlog" data-host="${escapeHtml(r.hostname)}" title="View the access log for this host"><strong>${escapeHtml(r.hostname)}</strong></a>${r.add_www ? ` <span class="muted">+www</span>` : ''}${aclBadge(r)}</td>
      <td>${escapeHtml(r.backend_host)}${r.backend_tls ? ' <span class="muted">(tls)</span>' : ''}</td>
      <td class="num">${r.backend_port}</td>
      <td>${fmtBadge(r.tls_mode, tlsBadges)}</td>
      <td>${certCellHtml(r)}</td>
      <td>${r.add_www ? '<span class="badge on">on</span>' : '<span class="badge off">off</span>'}</td>
      <td>${r.websocket ? '<span class="badge on">ws</span>' : ''}</td>
      <td>${r.hsts ? '<span class="badge on">hsts</span>' : ''}</td>
      <td class="row-actions">
        <button data-action="edit">Edit</button>
        <button data-action="delete" class="danger">Delete</button>
      </td>
    </tr>
  `).join('');
}

function onHeaderClick(ev) {
  const th = ev.target.closest('th[data-sort]');
  if (!th) return;
  const key = th.dataset.sort;
  if (state.sort.key === key) {
    state.sort.dir = state.sort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.sort.key = key;
    state.sort.dir = 'asc';
  }
  render();
}

async function api(method, path, body) {
  const res = await fetch(`/api${path}`, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    // Session expired mid-use — drop back to the login screen.
    if (res.status === 401 && !path.startsWith('/auth/')) {
      $('#login-overlay').hidden = false;
    }
    const msg = data.message || data.error || `${res.status} ${res.statusText}`;
    throw new Error(`${msg}${data.body ? `\n\n${data.body}` : ''}`);
  }
  return data;
}

function showError(msg) {
  const el = $('#error');
  if (!msg) { el.hidden = true; el.textContent = ''; return; }
  el.hidden = false;
  el.textContent = msg;
}

async function refresh() {
  showError('');
  const data = await api('GET', '/rules');
  state.rules = data.rules;
  render();
  refreshCerts();
}

async function refreshCerts(force = false) {
  try {
    const path = force ? '/system/certs?refresh=1' : '/system/certs';
    const data = await api('GET', path);
    const map = {};
    for (const c of (data.certs || [])) map[c.hostname] = c;
    state.certs = map;
    render();
  } catch (e) {
    // soft-fail: keep prior cert state, don't show a banner for this
    console.warn('cert probe failed', e.message);
  }
}

async function refreshStatus() {
  try {
    const s = await api('GET', '/system/health');
    const el = $('#status');
    el.classList.toggle('ok', s.caddy);
    el.classList.toggle('err', !s.caddy);
    const ts = s.last_reload_at ? new Date(s.last_reload_at).toLocaleString() : 'never';
    const fb = s.fallback_upstream ? `fallback: ${s.fallback_upstream}` : 'fallback: off';
    el.textContent = `caddy: ${s.caddy ? 'up' : 'DOWN'} • ${fb} • last reload: ${ts}`;
  } catch (e) {
    $('#status').textContent = `status check failed: ${e.message}`;
  }
}

function openEditor(rule) {
  const form = $('#editor-form');
  form.reset();
  $('#editor-title').textContent = rule ? `Edit ${rule.hostname}` : 'New rule';
  form.id.value = rule?.id ?? '';
  if (rule) {
    form.hostname.value = rule.hostname;
    form.backend_host.value = rule.backend_host;
    form.backend_port.value = rule.backend_port;
    form.backend_tls.checked = !!rule.backend_tls;
    form.add_www.checked = !!rule.add_www;
    form.querySelector(`input[name=tls_mode][value=${rule.tls_mode}]`).checked = true;
    form.cert_path.value = rule.cert_path || '';
    form.websocket.checked = !!rule.websocket;
    form.hsts.checked = !!rule.hsts;
    form.read_timeout.value = rule.read_timeout;
    form.enabled.checked = !!rule.enabled;
    form.deny_ips.value = rule.deny_ips || '';
    form.deny_redirect.value = rule.deny_redirect || '';
    form.querySelector(`input[name=access_mode][value=${rule.access_mode === 'whitelist' ? 'whitelist' : 'blacklist'}]`).checked = true;
    form.notes.value = rule.notes || '';
  }
  $('#editor').showModal();
}

function readForm() {
  const f = $('#editor-form');
  const data = {
    hostname: f.hostname.value.trim(),
    backend_host: f.backend_host.value.trim(),
    backend_port: Number(f.backend_port.value),
    backend_tls: f.backend_tls.checked ? 1 : 0,
    add_www: f.add_www.checked ? 1 : 0,
    tls_mode: f.querySelector('input[name=tls_mode]:checked').value,
    cert_path: f.cert_path.value.trim() || null,
    websocket: f.websocket.checked ? 1 : 0,
    hsts: f.hsts.checked ? 1 : 0,
    read_timeout: Number(f.read_timeout.value) || 60,
    enabled: f.enabled.checked ? 1 : 0,
    deny_ips: f.deny_ips.value.trim() || null,
    deny_redirect: f.deny_redirect.value.trim() || null,
    access_mode: f.querySelector('input[name=access_mode]:checked').value,
    notes: f.notes.value.trim() || null,
  };
  const id = f.id.value;
  return { id: id ? Number(id) : null, data };
}

async function onSubmit(ev) {
  ev.preventDefault();
  showError('');
  const { id, data } = readForm();
  try {
    if (id) await api('PUT', `/rules/${id}`, data);
    else    await api('POST', '/rules', data);
    $('#editor').close();
    await refresh();
    await refreshStatus();
  } catch (e) {
    showError(`Save failed: ${e.message}`);
  }
}

async function onTableClick(ev) {
  const hostLink = ev.target.closest('a[data-action="hostlog"]');
  if (hostLink) {
    ev.preventDefault();
    openHostDetail(hostLink.dataset.host);
    return;
  }
  const btn = ev.target.closest('button[data-action]');
  if (!btn) return;
  const tr = ev.target.closest('tr');
  const id = Number(tr.dataset.id);
  const rule = state.rules.find((r) => r.id === id);
  if (!rule) return;
  const action = btn.dataset.action;
  try {
    if (action === 'edit') {
      openEditor(rule);
    } else if (action === 'toggle') {
      await api('PUT', `/rules/${id}`, { enabled: rule.enabled ? 0 : 1 });
      await refresh(); await refreshStatus();
    } else if (action === 'delete') {
      if (!confirm(`Delete ${rule.hostname}?`)) return;
      await api('DELETE', `/rules/${id}`);
      await refresh(); await refreshStatus();
    }
  } catch (e) {
    showError(`${action} failed: ${e.message}`);
  }
}

async function onReload() {
  showError('');
  try {
    await api('POST', '/rules/reload');
    await refreshStatus();
  } catch (e) {
    showError(`Reload failed: ${e.message}`);
  }
}

function buildSnapshot() {
  const now = new Date();
  const rules = sortedRules();
  const lines = [];
  lines.push(`# Reverse Proxy Configuration Snapshot`);
  lines.push(`Generated: ${now.toISOString()}`);
  lines.push(`Total rules: ${rules.length}`);
  lines.push(`UI:          ${location.origin}`);
  lines.push(`Caddy admin: http://127.0.0.1:2019 (localhost only)`);
  lines.push(`Engine:      Caddy + custom Node.js admin UI (no Docker)`);
  lines.push(`Cert renewal: DNS-01 via Cloudflare, auto-renewed by Caddy`);
  lines.push('');

  lines.push('## Rules table');
  lines.push('');
  lines.push('| ID | Enabled | Hostname | +www | Backend | TLS mode | Cert expiry | WS | HSTS | Read timeout | IP ACL | Notes |');
  lines.push('|---:|---|---|---|---|---|---|---|---|---:|---|---|');
  for (const r of rules) {
    const cert = state.certs[r.hostname];
    let certCol = '—';
    if (r.tls_mode !== 'http') {
      if (cert?.error) certCol = `probe error: ${cert.error}`;
      else if (cert)   certCol = `${new Date(cert.not_after).toISOString().slice(0,10)} (${cert.days_remaining}d) — ${cert.issuer}`;
      else             certCol = '(no probe yet)';
    }
    const aclIps = (r.deny_ips || '')
      .split(/[\n,]+/).map((s) => s.replace(/#.*$/, '').trim()).filter(Boolean);
    const aclCol = aclIps.length
      ? `${r.access_mode === 'whitelist' ? 'whitelist' : 'blacklist'}: ${aclIps.join('; ')}`
      : '—';
    const cells = [
      r.id,
      r.enabled ? 'yes' : 'no',
      r.hostname,
      r.add_www ? 'yes' : 'no',
      `${r.backend_host}:${r.backend_port}${r.backend_tls ? ' (tls)' : ''}`,
      r.tls_mode,
      certCol,
      r.websocket ? 'yes' : '',
      r.hsts ? 'yes' : '',
      `${r.read_timeout}s`,
      aclCol,
      (r.notes || '').replace(/\|/g, '\\|'),
    ];
    lines.push('| ' + cells.join(' | ') + ' |');
  }

  lines.push('');
  lines.push('## Full record JSON');
  lines.push('');
  lines.push('```json');
  const enriched = rules.map((r) => {
    const cert = state.certs[r.hostname];
    return {
      ...r,
      cert: r.tls_mode === 'http' ? null : (cert || null),
    };
  });
  lines.push(JSON.stringify(enriched, null, 2));
  lines.push('```');

  return lines.join('\n');
}

async function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    try { await navigator.clipboard.writeText(text); return true; } catch (_) {}
  }
  // Fallback for non-secure contexts (plain http LAN access)
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.focus(); ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (_) {}
  document.body.removeChild(ta);
  return ok;
}

async function onCopy() {
  const text = buildSnapshot();
  const btn = $('#btn-copy');
  const orig = btn.textContent;
  const ok = await copyToClipboard(text);
  btn.textContent = ok ? `Copied ${text.length.toLocaleString()} chars` : 'Copy failed';
  btn.classList.add(ok ? 'flash-ok' : 'flash-err');
  setTimeout(() => {
    btn.textContent = orig;
    btn.classList.remove('flash-ok', 'flash-err');
  }, 1800);
}

// ---- activity view ---------------------------------------------------------

function fmtAgo(ts) {
  if (!ts) return '—';
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function flagEmoji(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return '';
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function countryLabel(ip) {
  if (ip.country_code) return `${flagEmoji(ip.country_code)} ${escapeHtml(ip.country_code)}`;
  if (ip.country) return escapeHtml(ip.country);
  return '<span class="muted">…</span>';
}

function switchView(view) {
  state.view = view;
  for (const v of ['rules', 'activity', 'blocklist']) {
    $(`#view-${v}`).hidden = view !== v;
    $(`#nav-${v}`).classList.toggle('active', view === v);
  }
  for (const el of $$('.rules-only')) el.style.display = view === 'rules' ? '' : 'none';
  if (view === 'activity') loadActivity();
  if (view === 'blocklist') loadBlocklist();
}

async function loadActivity(opts = {}) {
  if (!opts.quiet) showError('');
  const hours = $('#activity-window').value;
  try {
    const [act, rec] = await Promise.all([
      api('GET', `/activity?hours=${hours}`),
      api('GET', '/activity/recent?limit=200'),
    ]);
    renderActivity(act);
    renderRecent(rec.events || []);
  } catch (e) {
    if (opts.quiet) console.warn('live activity refresh failed:', e.message);
    else showError(`Activity load failed: ${e.message}`);
  }
}

async function loadBlocklist() {
  showError('');
  try {
    const data = await api('GET', '/activity/blocklist');
    renderBlocklist(data.blocks || []);
  } catch (e) {
    showError(`Blocklist load failed: ${e.message}`);
  }
}

// Sort accessors for the activity table. Numeric IP sort packs each octet so
// e.g. 9.x sorts before 80.x; non-IPv4 strings fall back to lexical.
function ipSortKey(ip) {
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(ip || '');
  if (!m) return ip || '';
  return m.slice(1).map((n) => n.padStart(3, '0')).join('.');
}
const ACTIVITY_SORT = {
  client_ip: (r) => ipSortKey(r.client_ip),
  country:   (r) => (r.country || '￿').toLowerCase(),
  top_host:  (r) => (r.top_host || '￿').toLowerCase(),
  total:     (r) => r.total,
  c4xx:      (r) => r.c4xx || 0,
  c404:      (r) => r.c404 || 0,
  probes:    (r) => r.probes || 0,
  hosts:     (r) => r.hosts || 0,
  last_seen: (r) => r.last_seen || 0,
  suspicion: (r) => (r.suspicious ? 1000 : 0) + (r.flags ? r.flags.length : 0),
};

// Matches an activity row against the search box: IP, country, domain, the
// rule hostnames it touched, suspicion flags, and blocked state.
function matchActivity(ip, re) {
  if (!re) return true;
  const haystack = [
    ip.client_ip,
    ip.country || '',
    ip.country_code || '',
    ip.top_host || '',
    (ip.rules || []).map((r) => r.hostname).join(' '),
    (ip.flags || []).join(' '),
    ip.blocked ? 'blocked' : '',
  ].join(' ').toLowerCase();
  return re.test(haystack);
}

function activitySorted() {
  const re = compileFilter(state.activityFilter);
  const rows = re ? state.activity.filter((ip) => matchActivity(ip, re)) : state.activity;
  const { key, dir } = state.activitySort;
  if (!key || !ACTIVITY_SORT[key]) return rows; // server order: suspicious first
  const acc = ACTIVITY_SORT[key];
  const mult = dir === 'desc' ? -1 : 1;
  return [...rows].sort((a, b) => {
    const av = acc(a), bv = acc(b);
    if (av < bv) return -1 * mult;
    if (av > bv) return 1 * mult;
    return ipSortKey(a.client_ip) < ipSortKey(b.client_ip) ? -1 : 1;
  });
}

function renderActivityArrows() {
  for (const th of $$('#activity-table thead th[data-sort]')) {
    const key = th.dataset.sort;
    th.classList.toggle('sorted-asc', state.activitySort.key === key && state.activitySort.dir === 'asc');
    th.classList.toggle('sorted-desc', state.activitySort.key === key && state.activitySort.dir === 'desc');
  }
}

function onActivityHeaderClick(ev) {
  const th = ev.target.closest('th[data-sort]');
  if (!th) return;
  const key = th.dataset.sort;
  if (state.activitySort.key === key) {
    state.activitySort.dir = state.activitySort.dir === 'asc' ? 'desc' : 'asc';
  } else {
    state.activitySort = { key, dir: 'desc' };
  }
  drawActivity();
}

function renderActivity(data) {
  state.activity = data.ips || [];
  state.activityMeta = { count: data.count, window: data.window_hours, stats: data.stats || {} };
  // Drop selections for IPs no longer present in the current window.
  const present = new Set(state.activity.map((ip) => ip.client_ip));
  for (const ip of [...state.activitySelected]) {
    if (!present.has(ip)) state.activitySelected.delete(ip);
  }
  drawActivity();
}

function drawActivity() {
  renderActivityArrows();
  const m = state.activityMeta || { stats: {} };
  const s = m.stats || {};
  const tbody = $('#activity-body');
  const ips = activitySorted();
  const filtered = !!compileFilter(state.activityFilter);
  $('#activity-count').textContent = filtered
    ? `(${ips.length} of ${m.count} in last ${m.window}h)`
    : `(${m.count} in last ${m.window}h)`;
  $('#activity-stats').textContent = s.count
    ? `${s.count.toLocaleString()} events stored, oldest ${fmtAgo(s.oldest)}`
    : 'no events captured yet';
  renderLiveIndicators();
  if (!ips.length) {
    const msg = filtered
      ? `No client IPs match <code>${escapeHtml(state.activityFilter)}</code>. Press Esc to clear.`
      : 'No traffic recorded in this window. The access log fills as requests arrive.';
    tbody.innerHTML = `<tr><td colspan="12" class="muted">${msg}</td></tr>`;
    return;
  }
  tbody.innerHTML = ips.map((ip) => {
    const flags = ip.flags.map((f) => `<span class="flag">${escapeHtml(f)}</span>`).join(' ');
    let action;
    if (ip.blocked) {
      action = `<button data-act="unblock" data-ip="${escapeHtml(ip.client_ip)}">Unblock</button>`;
    } else {
      const hasRules = ip.rules && ip.rules.length;
      // Most-requested rule is first in ip.rules — pre-select it.
      const ruleOpts = (ip.rules || []).map((rl, i) =>
        `<option value="rule:${rl.id}"${i === 0 ? ' selected' : ''}>${escapeHtml(rl.hostname)}</option>`).join('');
      action = `<select class="rule-block" title="Where to block this IP">`
        + ruleOpts
        + `<option value="global"${hasRules ? '' : ' selected'}>Globally — all hosts</option>`
        + `</select>`
        + `<button class="danger" data-act="blockscope" data-ip="${escapeHtml(ip.client_ip)}">Block</button>`;
    }
    const checked = state.activitySelected.has(ip.client_ip) ? ' checked' : '';
    return `
      <tr class="${ip.suspicious ? 'suspicious' : ''}">
        <td class="check-col"><input type="checkbox" class="row-check" data-ip="${escapeHtml(ip.client_ip)}"${checked}></td>
        <td class="ip">
          <a href="#" data-act="detail" data-ip="${escapeHtml(ip.client_ip)}">${escapeHtml(ip.client_ip)}</a>
          ${ip.blocked ? ' <span class="badge cert-crit">blocked</span>' : ''}
        </td>
        <td>${countryLabel(ip)}</td>
        <td>${ip.top_host ? escapeHtml(ip.top_host) : '<span class="muted">—</span>'}${ip.hosts > 1 ? ` <span class="muted">+${ip.hosts - 1}</span>` : ''}</td>
        <td class="num">${ip.total}</td>
        <td class="num">${ip.c4xx || ''}</td>
        <td class="num">${ip.c404 || ''}</td>
        <td class="num">${ip.probes || ''}</td>
        <td class="num">${ip.hosts}</td>
        <td>${fmtAgo(ip.last_seen)}</td>
        <td>${flags}</td>
        <td class="row-actions">${action}</td>
      </tr>`;
  }).join('');
  updateActivityBulkBar();
}

// ---- activity multi-select -------------------------------------------------

function updateActivityBulkBar() {
  const n = state.activitySelected.size;
  const bar = $('#activity-bulk');
  if (bar) {
    bar.hidden = n === 0;
    const cnt = $('#activity-bulk-count');
    if (cnt) cnt.textContent = `${n} IP${n === 1 ? '' : 's'} selected`;
  }
  const all = $('#activity-check-all');
  if (all) {
    const visible = activitySorted();
    const sel = visible.filter((ip) => state.activitySelected.has(ip.client_ip)).length;
    all.checked = visible.length > 0 && sel === visible.length;
    all.indeterminate = sel > 0 && sel < visible.length;
  }
}

function onActivitySelectChange(ev) {
  const cb = ev.target.closest('input.row-check');
  if (!cb) return;
  if (cb.checked) state.activitySelected.add(cb.dataset.ip);
  else state.activitySelected.delete(cb.dataset.ip);
  updateActivityBulkBar();
}

// Header checkbox — select/deselect every IP currently visible (i.e. matching
// the search filter), not the whole window.
function onActivityToggleAll(ev) {
  for (const ip of activitySorted()) {
    if (ev.target.checked) state.activitySelected.add(ip.client_ip);
    else state.activitySelected.delete(ip.client_ip);
  }
  drawActivity();
}

function clearActivitySelection() {
  state.activitySelected.clear();
  drawActivity();
}

async function onActivityBulkBlock() {
  const ips = [...state.activitySelected];
  if (!ips.length) return;
  if (!confirm(`Block ${ips.length} IP${ips.length === 1 ? '' : 's'} globally?\n\n`
    + 'They will be rejected for every host, ahead of all rules.')) return;
  try {
    await api('POST', '/activity/blocklist/bulk', { ips, note: 'bulk block from activity' });
    state.activitySelected.clear();
    await loadActivity();
  } catch (e) {
    showError(`Bulk block failed: ${e.message}`);
  }
}

function renderBlocklist(blocks) {
  $('#blocklist-count').textContent = `(${blocks.length})`;
  const tbody = $('#blocklist-body');
  if (!blocks.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="muted">Empty — add an IP above, or block one from the Activity tab.</td></tr>`;
    return;
  }
  tbody.innerHTML = blocks.map((b) => `
    <tr>
      <td class="ip">${escapeHtml(b.ip)}</td>
      <td>${fmtAgo(b.added_at)}</td>
      <td class="muted">${escapeHtml(b.note || '')}</td>
      <td class="row-actions"><button data-act="unblock" data-ip="${escapeHtml(b.ip)}">Unblock</button></td>
    </tr>`).join('');
}

function renderRecent(events) {
  const tbody = $('#recent-body');
  if (!events.length) {
    tbody.innerHTML = `<tr><td colspan="6" class="muted">No requests recorded yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = events.map((e) => `
    <tr>
      <td>${new Date(e.ts).toLocaleTimeString()}</td>
      <td class="ip">${escapeHtml(e.client_ip)}</td>
      <td>${escapeHtml(e.host || '')}</td>
      <td>${escapeHtml(e.method || '')}</td>
      <td class="uri" title="${escapeHtml(e.uri || '')}">${escapeHtml(e.uri || '')}${e.suspicious_path ? ' <span class="flag">probe</span>' : ''}</td>
      <td class="num st${String(e.status).charAt(0)}">${e.status || ''}</td>
    </tr>`).join('');
}

async function refreshBlockViews() {
  if (state.view === 'blocklist') await loadBlocklist();
  else if (state.view === 'activity') await loadActivity();
}

async function blockIp(ip, note) {
  await api('POST', '/activity/blocklist', { ip, note: note || 'manual block' });
  await refreshBlockViews();
}

async function unblockIp(ip) {
  await api('DELETE', `/activity/blocklist/${encodeURIComponent(ip)}`);
  await refreshBlockViews();
}

async function onActivityClick(ev) {
  const link = ev.target.closest('a[data-act="detail"]');
  if (link) {
    ev.preventDefault();
    openIpDetail(link.dataset.ip);
    return;
  }
  const btn = ev.target.closest('button[data-act]');
  if (!btn) return;
  const ip = btn.dataset.ip;
  try {
    if (btn.dataset.act === 'blockscope') {
      const sel = btn.closest('td').querySelector('select.rule-block');
      const val = sel ? sel.value : 'global';
      if (val === 'global') {
        if (!confirm(`Block ${ip} globally? It will be rejected for every host.`)) return;
        await blockIp(ip);
      } else if (val.startsWith('rule:')) {
        const ruleId = Number(val.slice(5));
        const hostname = sel.options[sel.selectedIndex].textContent.trim();
        if (!confirm(`Block ${ip} on the "${hostname}" rule only?`)) return;
        const r = await api('POST', '/activity/block-rule', { ip, rule_id: ruleId });
        await loadActivity();
        if (r.already) showError(`${ip} was already blocked on ${hostname}.`);
      }
    } else if (btn.dataset.act === 'unblock') {
      await unblockIp(ip);
    }
  } catch (e) {
    showError(`block failed: ${e.message}`);
  }
}

function kvRow(k, v) {
  if (v === null || v === undefined || v === '') return '';
  return `<div class="kv"><span class="kv-k">${escapeHtml(k)}</span><span class="kv-v">${v}</span></div>`;
}

function miniTable(rows) {
  if (!rows.length) return '<div class="muted">none</div>';
  return `<table class="mini">${rows.join('')}</table>`;
}

// Top-paths table shared by the IP- and host-detail dialogs. Each row is
// prefixed with the host the path was requested on, so a path is never
// ambiguous when an IP — or a host's www. alias — spans multiple hostnames.
function pathsTable(paths) {
  return miniTable(paths.map((p) => {
    const host = p.host || '—';
    return `<tr><td class="uri" title="${escapeHtml(host + ' ' + p.uri)}">`
      + `<span class="path-host">${escapeHtml(host)}</span> ${escapeHtml(p.uri)}`
      + `${p.probe ? ' <span class="flag">probe</span>' : ''}</td>`
      + `<td class="num">${p.c}</td>`
      + `<td class="num ${p.errors ? 'st4' : ''}">${p.errors || ''}</td></tr>`;
  }));
}

function renderIpDetail(d) {
  const info = d.info || {};
  const s = d.summary || {};
  const cc = info.country_code;
  const title = `${flagEmoji(cc)} ${escapeHtml(d.ip)}`.trim();
  $('#ip-detail-title').innerHTML = title +
    (d.blocked ? ' <span class="badge cert-crit">blocked</span>' : '') +
    (d.suspicious ? ' <span class="badge cert-crit">suspicious</span>' : '');

  const tags = [];
  if (info.is_hosting) tags.push('<span class="flag">datacenter / hosting</span>');
  if (info.is_proxy)   tags.push('<span class="flag">proxy / VPN / Tor</span>');
  if (info.is_mobile)  tags.push('<span class="flag">mobile network</span>');

  const geo = [
    kvRow('Country', info.country ? `${flagEmoji(cc)} ${escapeHtml(info.country)}${cc ? ` (${escapeHtml(cc)})` : ''}` : null),
    kvRow('Region / City', [info.region, info.city].filter(Boolean).map(escapeHtml).join(' · ') || null),
    kvRow('ISP', info.isp ? escapeHtml(info.isp) : null),
    kvRow('Organization', info.org && info.org !== info.isp ? escapeHtml(info.org) : null),
    kvRow('ASN', info.asn ? escapeHtml(info.asn) : null),
    kvRow('Reverse DNS', info.rdns ? `<code>${escapeHtml(info.rdns)}</code>` : '<span class="muted">no PTR record</span>'),
    kvRow('Classification', tags.join(' ') || '<span class="muted">none flagged</span>'),
  ].join('');

  const summary = [
    kvRow('Requests', `${s.total || 0} in last ${d.window_hours}h`),
    kvRow('First seen', s.first_seen ? new Date(s.first_seen).toLocaleString() : '—'),
    kvRow('Last seen', s.last_seen ? `${new Date(s.last_seen).toLocaleString()} (${fmtAgo(s.last_seen)})` : '—'),
    kvRow('Errors', `${s.c4xx || 0} × 4xx · ${s.c404 || 0} × 404 · ${s.c5xx || 0} × 5xx`),
    kvRow('Probe-path hits', String(s.probes || 0)),
    kvRow('Distinct hosts', String(s.hosts || 0)),
    kvRow('Suspicion flags', d.flags.length ? d.flags.map((f) => `<span class="flag">${escapeHtml(f)}</span>`).join(' ') : '<span class="muted">none</span>'),
  ].join('');

  const hosts = miniTable(d.hosts.map((h) =>
    `<tr><td>${escapeHtml(h.host)}</td><td class="num">${h.c}</td></tr>`));

  const paths = pathsTable(d.paths);

  const methods = d.methods.map((m) => `${escapeHtml(m.method || '?')}×${m.c}`).join('  ');
  const statuses = d.statuses.map((x) => `<span class="st${String(x.status).charAt(0)}">${x.status}×${x.c}</span>`).join('  ');
  const uas = miniTable(d.user_agents.map((u) =>
    `<tr><td class="uri" title="${escapeHtml(u.user_agent || '')}">${escapeHtml(u.user_agent || '(none)')}</td><td class="num">${u.c}</td></tr>`));

  const recent = miniTable(d.recent.map((e) =>
    `<tr><td>${new Date(e.ts).toLocaleTimeString()}</td>`
    + `<td>${escapeHtml(e.host || '')}</td><td>${escapeHtml(e.method || '')}</td>`
    + `<td class="uri" title="${escapeHtml(e.uri || '')}">${escapeHtml(e.uri || '')}</td>`
    + `<td class="num st${String(e.status).charAt(0)}">${e.status || ''}</td></tr>`));

  const blockBtn = d.blocked
    ? `<button data-act="unblock" data-ip="${escapeHtml(d.ip)}">Unblock globally</button>`
    : `<button class="danger" data-act="block" data-ip="${escapeHtml(d.ip)}">Block globally</button>`;

  $('#ip-detail-body').innerHTML = `
    <div class="detail-grid">
      <section><h4>Network &amp; location</h4>${geo}</section>
      <section><h4>Activity summary</h4>${summary}</section>
    </div>
    <section><h4>Hosts accessed</h4>${hosts}</section>
    <section><h4>Top paths</h4>${paths}</section>
    <div class="detail-grid">
      <section><h4>Methods</h4><div class="mono">${methods || '—'}</div></section>
      <section><h4>Status codes</h4><div class="mono">${statuses || '—'}</div></section>
    </div>
    <section><h4>User agents</h4>${uas}</section>
    <section><h4>Recent requests</h4>${recent}</section>
    <div class="dialog-actions">
      <button id="ip-detail-refresh" data-ip="${escapeHtml(d.ip)}">Refresh geo</button>
      ${blockBtn}
    </div>`;
}

async function openIpDetail(ip) {
  const hours = $('#activity-window').value;
  state.ipDetail = { ip, hours };
  $('#ip-detail-title').textContent = ip;
  $('#ip-detail-body').innerHTML = '<div class="muted">Looking up geolocation &amp; activity…</div>';
  $('#ip-detail').showModal();
  renderLiveIndicators();
  try {
    const d = await api('GET', `/activity/ip/${encodeURIComponent(ip)}?hours=${hours}`);
    renderIpDetail(d);
  } catch (e) {
    $('#ip-detail-body').innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
  }
}

async function onIpDetailClick(ev) {
  const btn = ev.target.closest('button[data-act], button#ip-detail-refresh');
  if (!btn) return;
  const ip = btn.dataset.ip;
  try {
    if (btn.id === 'ip-detail-refresh') {
      $('#ip-detail-body').innerHTML = '<div class="muted">Refreshing…</div>';
      const hours = $('#activity-window').value;
      renderIpDetail(await api('GET', `/activity/ip/${encodeURIComponent(ip)}?hours=${hours}&refresh=1`));
    } else if (btn.dataset.act === 'block') {
      if (!confirm(`Block ${ip} globally?`)) return;
      await blockIp(ip);
      renderIpDetail(await api('GET', `/activity/ip/${encodeURIComponent(ip)}?hours=${$('#activity-window').value}`));
    } else if (btn.dataset.act === 'unblock') {
      await unblockIp(ip);
      renderIpDetail(await api('GET', `/activity/ip/${encodeURIComponent(ip)}?hours=${$('#activity-window').value}`));
    }
  } catch (e) {
    showError(`${btn.dataset.act || 'refresh'} failed: ${e.message}`);
  }
}

// ---- host access log -------------------------------------------------------

const HOST_WINDOWS = [[1, 'last 1 h'], [24, 'last 24 h'], [168, 'last 7 d'], [720, 'last 30 d']];

function hostWindowSelect(hours) {
  return `<select id="host-detail-window">`
    + HOST_WINDOWS.map(([v, l]) =>
        `<option value="${v}"${v === hours ? ' selected' : ''}>${l}</option>`).join('')
    + `</select>`;
}

function renderHostDetail(d) {
  state.hostDetail.hosts = (d.hosts && d.hosts.length) ? d.hosts : [d.host];
  const hours = state.hostDetail.hours;
  $('#host-detail-title').textContent = d.host;
  const others = (d.hosts || []).filter((h) => h !== d.host);
  const aliasNote = others.length
    ? ` <span class="muted">+ ${others.map(escapeHtml).join(', ')}</span>` : '';
  const toolbar = `<div class="activity-toolbar">`
    + `<label class="inline">Window ${hostWindowSelect(hours)}</label>${aliasNote}`
    + `<span class="grow"></span>`
    + `<span id="host-live" class="live-dot off">○ offline</span></div>`;
  const recentRows = d.recent.map((e) => recentRowHtml(e)).join('');

  $('#host-detail-body').innerHTML = toolbar
    + `<div id="host-aggregates">${hostAggregatesHtml(d)}</div>`
    + `<section><h4>Recent requests</h4>`
    + `<table class="mini" id="host-recent">${recentRows
        || '<tr><td class="muted">No requests yet — new ones stream in here live.</td></tr>'}</table>`
    + `</section>`;
  $('#host-detail-window').addEventListener('change', onHostWindowChange);
  renderLiveIndicators();
}

// The aggregate sections (summary, client IPs, paths, methods, statuses).
// Split out so the live refresh can replace them without disturbing the
// SSE-fed Recent-requests table below. Side effect: re-baselines the live
// counters to this snapshot.
function hostAggregatesHtml(d) {
  const s = d.summary || {};
  state.hostDetail.total = s.total || 0;
  state.hostDetail.liveCount = 0;

  const summary = [
    `<div class="kv"><span class="kv-k">Requests</span>`
      + `<span class="kv-v" id="host-sum-total">${s.total || 0} in last ${d.window_hours}h</span></div>`,
    kvRow('First seen', s.first_seen ? new Date(s.first_seen).toLocaleString() : '—'),
    `<div class="kv"><span class="kv-k">Last seen</span>`
      + `<span class="kv-v" id="host-sum-last">`
      + `${s.last_seen ? `${new Date(s.last_seen).toLocaleString()} (${fmtAgo(s.last_seen)})` : '—'}</span></div>`,
    kvRow('Errors', `${s.c4xx || 0} × 4xx · ${s.c404 || 0} × 404 · ${s.c5xx || 0} × 5xx`),
    kvRow('Probe-path hits', String(s.probes || 0)),
    kvRow('Distinct client IPs', String(s.ips || 0)),
  ].join('');

  const clients = miniTable(d.clients.map((c) => {
    const cc = c.info && c.info.country_code;
    const loc = cc ? ` ${flagEmoji(cc)} ${escapeHtml(cc)}` : '';
    const cls = c.blocked ? ' class="ip-blocked"' : '';
    const badge = c.blocked ? ' <span class="badge cert-crit">blocked</span>' : '';
    return `<tr>`
      + `<td class="ip"><a href="#"${cls} data-host-ip="${escapeHtml(c.client_ip)}">${escapeHtml(c.client_ip)}</a>${loc}${badge}</td>`
      + `<td class="num">${c.c}</td>`
      + `<td class="num ${c.errors ? 'st4' : ''}">${c.errors || ''}</td>`
      + `<td class="num">${c.probes || ''}</td>`
      + `<td>${fmtAgo(c.last_seen)}</td></tr>`;
  }));

  const paths = pathsTable(d.paths);
  const methods = d.methods.map((m) => `${escapeHtml(m.method || '?')}×${m.c}`).join('  ');
  const statuses = d.statuses.map((x) => `<span class="st${String(x.status).charAt(0)}">${x.status}×${x.c}</span>`).join('  ');

  return `
    <section><h4>Summary</h4>${summary}</section>
    <section><h4>Client IPs <span class="muted">(top ${d.clients.length})</span></h4>${clients}</section>
    <section><h4>Top paths</h4>${paths}</section>
    <div class="detail-grid">
      <section><h4>Methods</h4><div class="mono">${methods || '—'}</div></section>
      <section><h4>Status codes</h4><div class="mono">${statuses || '—'}</div></section>
    </div>`;
}

// Re-fetch the host snapshot and swap in fresh aggregate sections, leaving the
// live Recent-requests feed untouched.
async function refreshHostAggregates() {
  const { host, hours } = state.hostDetail;
  if (!host || !$('#host-detail').open) return;
  try {
    const d = await api('GET', `/activity/host/${encodeURIComponent(host)}?hours=${hours}`);
    const box = $('#host-aggregates');
    if (box) box.innerHTML = hostAggregatesHtml(d);
    renderLiveIndicators();
  } catch (_) { /* keep prior content on a transient failure */ }
}

// One row of the host log's Recent-requests table. `isNew` flags a live
// arrival so it gets the brief highlight flash.
function recentRowHtml(e, isNew) {
  return `<tr${isNew ? ' class="row-new"' : ''}>`
    + `<td>${new Date(e.ts).toLocaleTimeString()}</td>`
    + `<td class="ip"><span${e.blocked ? ' class="ip-blocked"' : ''}>${escapeHtml(e.client_ip)}</span></td>`
    + `<td>${escapeHtml(e.method || '')}</td>`
    + `<td class="uri" title="${escapeHtml(e.uri || '')}">${escapeHtml(e.uri || '')}${e.suspicious_path ? ' <span class="flag">probe</span>' : ''}</td>`
    + `<td class="num st${String(e.status).charAt(0)}">${e.status || ''}</td></tr>`;
}

// Append one live request to the host log's Recent table — instant feedback;
// the aggregate sections catch up on the debounced refresh.
function appendHostRecent(e) {
  const table = $('#host-recent');
  if (!table) return;
  const ph = table.querySelector('td.muted');
  if (ph) ph.closest('tr').remove();
  table.insertAdjacentHTML('afterbegin', recentRowHtml(e, true));
  while (table.rows.length > 80) table.deleteRow(table.rows.length - 1);

  state.hostDetail.liveCount += 1;
  const total = $('#host-sum-total');
  if (total) {
    total.textContent =
      `${state.hostDetail.total + state.hostDetail.liveCount} in last ${state.hostDetail.hours}h`;
  }
  const last = $('#host-sum-last');
  if (last) last.textContent = `${new Date(e.ts).toLocaleString()} (just now)`;
  renderLiveIndicators();
}

function hostDetailMatches(host) {
  return state.hostDetail.hosts.includes(host);
}

async function loadHostDetail() {
  const { host, hours } = state.hostDetail;
  try {
    const d = await api('GET', `/activity/host/${encodeURIComponent(host)}?hours=${hours}`);
    renderHostDetail(d);
  } catch (e) {
    $('#host-detail-body').innerHTML = `<div class="error">Failed to load: ${escapeHtml(e.message)}</div>`;
  }
}

function onHostWindowChange(ev) {
  state.hostDetail.hours = Number(ev.target.value);
  loadHostDetail();
}

async function openHostDetail(host) {
  state.hostDetail = { host, hours: 24, hosts: [host], liveCount: 0, total: 0 };
  $('#host-detail-title').textContent = host;
  $('#host-detail-body').innerHTML = '<div class="muted">Loading access log…</div>';
  $('#host-detail').showModal();
  await loadHostDetail();
}

// Clicking a client IP inside the host log opens the full IP-detail dialog.
function onHostDetailClick(ev) {
  const link = ev.target.closest('a[data-host-ip]');
  if (!link) return;
  ev.preventDefault();
  openIpDetail(link.dataset.hostIp);
}

// ---- live updates ----------------------------------------------------------
// One shared SSE connection drives every live view. Whatever is on screen —
// the Activity page, the IP-detail dialog, the host access log — refreshes
// when matching traffic arrives, plus a slow heartbeat so idle views stay
// honest.

const LIVE_DEBOUNCE_MS = 2000;
const liveTimers = {};

function startLiveStream() {
  if (state.live.stream) return;
  let es;
  try { es = new EventSource('/api/activity/stream'); } catch (_) { return; }
  state.live.stream = es;
  es.addEventListener('open', () => { state.live.connected = true; renderLiveIndicators(); });
  es.addEventListener('error', () => { state.live.connected = false; renderLiveIndicators(); });
  es.addEventListener('access', onLiveEvent);
}

function onLiveEvent(ev) {
  let e;
  try { e = JSON.parse(ev.data); } catch (_) { return; }
  if ($('#host-detail').open && hostDetailMatches(e.host)) {
    appendHostRecent(e);   // instant — append to the recent feed
    scheduleLive('host');  // debounced — refresh the aggregate sections
  }
  if ($('#ip-detail').open && e.client_ip === state.ipDetail.ip) {
    scheduleLive('ip');
  }
  if (state.view === 'activity') {
    scheduleLive('activity');
  }
}

// Coalesce bursts: the first event arms a timer; later events within the
// window fold into the same refresh.
function scheduleLive(target) {
  if (liveTimers[target]) return;
  liveTimers[target] = setTimeout(() => {
    liveTimers[target] = null;
    runLiveRefresh(target);
  }, LIVE_DEBOUNCE_MS);
}

function runLiveRefresh(target) {
  if (target === 'activity') {
    if (state.view !== 'activity') return;
    // Don't yank the table out from under an open block-menu / focused control.
    const ae = document.activeElement;
    const body = $('#activity-body');
    if (ae && body && body.contains(ae)) return;
    loadActivity({ quiet: true });
  } else if (target === 'host' && $('#host-detail').open) {
    refreshHostAggregates();
  } else if (target === 'ip' && $('#ip-detail').open) {
    refreshIpDetail();
  }
}

// Even with no traffic, tick the open views so relative times stay honest.
function liveHeartbeat() {
  if ($('#host-detail').open) scheduleLive('host');
  if ($('#ip-detail').open) scheduleLive('ip');
  if (state.view === 'activity') scheduleLive('activity');
}

function renderLiveIndicators() {
  const on = state.live.connected;
  const setDot = (el, extra) => {
    if (!el) return;
    el.className = on ? 'live-dot' : 'live-dot off';
    el.textContent = on ? `● live${extra || ''}` : '○ offline';
  };
  setDot($('#host-live'), state.hostDetail.liveCount ? ` · ${state.hostDetail.liveCount} new` : '');
  setDot($('#activity-live'), '');
  setDot($('#ip-live'), '');
}

// Re-fetch the IP-detail snapshot in place, preserving scroll position.
async function refreshIpDetail() {
  const ip = state.ipDetail.ip;
  if (!ip || !$('#ip-detail').open) return;
  const dlg = $('#ip-detail');
  const keepScroll = dlg.scrollTop;
  try {
    const d = await api('GET', `/activity/ip/${encodeURIComponent(ip)}?hours=${state.ipDetail.hours}`);
    renderIpDetail(d);
    dlg.scrollTop = keepScroll;
    renderLiveIndicators();
  } catch (_) { /* keep prior content on a transient failure */ }
}

async function onGlobalBlockAdd() {
  const ipEl = $('#gb-ip');
  const noteEl = $('#gb-note');
  const ip = ipEl.value.trim();
  if (!ip) { ipEl.focus(); return; }
  try {
    await blockIp(ip, noteEl.value.trim() || 'manually added');
    ipEl.value = '';
    noteEl.value = '';
    ipEl.focus();
  } catch (e) {
    showError(`Add to blocklist failed: ${e.message}`);
  }
}

// ---- maintenance mode ------------------------------------------------------

function fmtCountdown(ms) {
  if (ms <= 0) return 'ending now…';
  const s = Math.floor(ms / 1000);
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (d) return `${d}d ${h}h ${m}m left`;
  if (h) return `${h}h ${m}m left`;
  if (m) return `${m}m ${sec}s left`;
  return `${sec}s left`;
}

function renderMaintenanceBanner() {
  const banner = $('#maintenance-banner');
  const m = state.maintenance;
  if (!m || !m.active) {
    banner.hidden = true;
    if (state.maintenanceTick) { clearInterval(state.maintenanceTick); state.maintenanceTick = null; }
    return;
  }
  const txt = $('#maint-banner-text');
  const scope = (m.hosts && m.hosts.length)
    ? `${m.hosts.length} domain${m.hosts.length === 1 ? '' : 's'}`
    : 'all domains';
  if (m.until) {
    const left = m.until - Date.now();
    if (left <= 0) {
      txt.textContent = `Maintenance ending — ${scope}.`;
    } else {
      txt.textContent = `Maintenance active on ${scope} — ${fmtCountdown(left)}.`;
    }
  } else {
    txt.textContent = `Maintenance active on ${scope} — open-ended.`;
  }
  banner.hidden = false;
  if (!state.maintenanceTick) {
    state.maintenanceTick = setInterval(renderMaintenanceBanner, 1000);
  }
}

async function refreshMaintenance() {
  try {
    const data = await api('GET', '/system/maintenance');
    state.maintenance = data.maintenance || { active: false, until: null, hosts: [] };
    renderMaintenanceBanner();
  } catch (_) { /* best-effort */ }
}

function toLocalDatetimeInput(ts) {
  // datetime-local needs YYYY-MM-DDTHH:MM in *local* time.
  const d = new Date(ts);
  const pad = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
    + `T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function selectPreset(min) {
  for (const b of $$('#maint-presets button')) {
    b.classList.toggle('selected', Number(b.dataset.min) === min);
  }
  const until = $('#maint-until');
  const hint = $('#maint-until-hint');
  if (min === 0) {
    until.value = '';
    hint.textContent = '(no automatic end — stays on until you stop it)';
  } else {
    until.value = toLocalDatetimeInput(Date.now() + min * 60_000);
    hint.textContent = '';
  }
}

function renderHostPicker(selected) {
  const box = $('#maint-host-picker');
  const enabled = state.rules.filter((r) => r.enabled);
  if (!enabled.length) {
    box.innerHTML = '<div class="hint">No enabled rules.</div>';
    return;
  }
  const sel = new Set(selected || []);
  box.innerHTML = enabled.map((r) => {
    const hosts = [r.hostname].concat(r.add_www ? [`www.${r.hostname}`] : []);
    // A rule is "checked" when every one of its hostnames is in the selection.
    const checked = hosts.every((h) => sel.has(h));
    return `<label><input type="checkbox" data-hosts="${escapeHtml(hosts.join(','))}"`
      + `${checked ? ' checked' : ''}> ${escapeHtml(r.hostname)}`
      + `${r.add_www ? ' <span class="muted">+www</span>' : ''}</label>`;
  }).join('');
}

function openMaintenanceDialog() {
  $('#maint-error').hidden = true;
  const m = state.maintenance || { active: false, until: null, hosts: [] };
  const status = $('#maint-status');
  if (m.active) {
    const scope = (m.hosts && m.hosts.length)
      ? `${m.hosts.length} domain${m.hosts.length === 1 ? '' : 's'}`
      : 'all domains';
    const tail = m.until ? ` — ${fmtCountdown(m.until - Date.now())}` : ' — open-ended';
    status.textContent = `Currently active on ${scope}${tail}.`;
    status.hidden = false;
    $('#maint-start').textContent = 'Update';
    $('#maint-stop').hidden = false;
  } else {
    status.hidden = true;
    $('#maint-start').textContent = 'Start maintenance';
    $('#maint-stop').hidden = true;
  }
  // Preselect prior choices, or default to 1 hour / all domains.
  if (m.until) {
    $('#maint-until').value = toLocalDatetimeInput(m.until);
    $('#maint-until-hint').textContent = '';
    for (const b of $$('#maint-presets button')) b.classList.remove('selected');
  } else if (m.active) {
    selectPreset(0);
  } else {
    selectPreset(60);
  }
  const scopeRadio = m.hosts && m.hosts.length ? 'some' : 'all';
  for (const r of $$('input[name="maint-scope"]')) r.checked = r.value === scopeRadio;
  renderHostPicker(m.hosts);
  $('#maint-host-picker').hidden = scopeRadio !== 'some';
  $('#maintenance-dialog').showModal();
}

function readMaintenanceForm() {
  const scope = document.querySelector('input[name="maint-scope"]:checked').value;
  let hosts = [];
  if (scope === 'some') {
    for (const cb of $$('#maint-host-picker input[type="checkbox"]')) {
      if (cb.checked) hosts = hosts.concat(cb.dataset.hosts.split(','));
    }
  }
  const v = $('#maint-until').value;
  const until = v ? new Date(v).getTime() : null;
  return { active: true, until, hosts };
}

async function onMaintenanceStart() {
  const err = $('#maint-error');
  err.hidden = true;
  const body = readMaintenanceForm();
  if (body.until && body.until <= Date.now()) {
    err.textContent = 'End time must be in the future.';
    err.hidden = false;
    return;
  }
  const scope = document.querySelector('input[name="maint-scope"]:checked').value;
  if (scope === 'some' && !body.hosts.length) {
    err.textContent = 'Pick at least one domain — or switch to All enabled domains.';
    err.hidden = false;
    return;
  }
  try {
    const r = await api('POST', '/system/maintenance', body);
    state.maintenance = r.maintenance;
    $('#maintenance-dialog').close();
    renderMaintenanceBanner();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
}

async function onMaintenanceStop() {
  const err = $('#maint-error');
  err.hidden = true;
  try {
    const r = await api('POST', '/system/maintenance', { active: false, until: null, hosts: [] });
    state.maintenance = r.maintenance;
    $('#maintenance-dialog').close();
    renderMaintenanceBanner();
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
}

// ---- update check ----------------------------------------------------------

async function checkVersion(force) {
  try {
    const v = await api('GET', `/system/version${force ? '?refresh=1' : ''}`);
    state.version = v;
    renderUpdateBanner(v);
  } catch (e) {
    /* version check is best-effort — stay quiet on failure */
  }
}

function renderUpdateBanner(v) {
  const banner = $('#update-banner');
  const changes = $('#update-changes');
  if (!v || !v.update_available) {
    banner.hidden = true;
    changes.hidden = true;
    return;
  }
  const n = (v.remote && v.remote.new_commits) || 0;
  $('#ub-text').textContent = n
    ? `Update available — ${n} new commit${n === 1 ? '' : 's'} on ${escapeHtml(v.branch)}.`
    : `An update is available on ${escapeHtml(v.branch)}.`;
  const commits = (v.remote && v.remote.commits) || [];
  $('#ub-details').hidden = commits.length === 0;
  changes.innerHTML = commits.length
    ? `<strong>New commits:</strong><ul>${commits.map((c) =>
        `<li><code>${escapeHtml(c.sha)}</code> ${escapeHtml(c.message)}</li>`).join('')}</ul>`
    : '';
  banner.hidden = false;
}

async function installUpdate() {
  if (!confirm('Pull the latest code from GitHub and restart rproxy?\n\nThe UI will be briefly unavailable, then this page reloads automatically.')) {
    return;
  }
  try {
    await api('POST', '/system/update');
    $('#ub-text').textContent = 'Updating… rproxy will restart shortly; this page reconnects automatically.';
    $('#ub-install').disabled = true;
    $('#ub-details').hidden = true;
    $('#update-changes').hidden = true;
    pollForRestart();
  } catch (e) {
    showError(`Update failed: ${e.message}`);
  }
}

// Wait for the service to go down and come back, then reload the page.
function pollForRestart() {
  let sawDown = false;
  let elapsed = 0;
  const iv = setInterval(async () => {
    elapsed += 2;
    let up = false;
    try { up = (await fetch('/api/system/health', { cache: 'no-store' })).ok; } catch { up = false; }
    if (!up) sawDown = true;
    if (up && sawDown) { clearInterval(iv); location.reload(); }
    if (elapsed > 240) { clearInterval(iv); location.reload(); } // fallback
  }, 2000);
}

document.addEventListener('DOMContentLoaded', () => {
  $('#btn-new').addEventListener('click', () => openEditor(null));
  $('#ub-install').addEventListener('click', installUpdate);
  $('#ub-details').addEventListener('click', () => {
    const c = $('#update-changes');
    c.hidden = !c.hidden;
  });
  $('#ub-dismiss').addEventListener('click', () => {
    $('#update-banner').hidden = true;
    $('#update-changes').hidden = true;
  });
  $('#btn-copy').addEventListener('click', onCopy);
  $('#btn-reload').addEventListener('click', onReload);
  $('#nav-rules').addEventListener('click', () => switchView('rules'));
  $('#nav-activity').addEventListener('click', () => switchView('activity'));
  $('#nav-blocklist').addEventListener('click', () => switchView('blocklist'));
  $('#activity-refresh').addEventListener('click', loadActivity);
  $('#activity-window').addEventListener('change', loadActivity);
  $('#activity-body').addEventListener('click', onActivityClick);
  $('#activity-body').addEventListener('change', onActivitySelectChange);
  $('#activity-table thead').addEventListener('click', onActivityHeaderClick);
  $('#activity-check-all').addEventListener('change', onActivityToggleAll);
  $('#activity-bulk-block').addEventListener('click', onActivityBulkBlock);
  $('#activity-bulk-clear').addEventListener('click', clearActivitySelection);
  const activitySearch = $('#activity-search');
  activitySearch.addEventListener('input', (ev) => {
    state.activityFilter = ev.target.value;
    drawActivity();
  });
  activitySearch.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      ev.target.value = '';
      state.activityFilter = '';
      drawActivity();
      ev.target.blur();
    }
  });
  $('#blocklist-body').addEventListener('click', onActivityClick);
  $('#blocklist-refresh').addEventListener('click', loadBlocklist);
  $('#gb-add').addEventListener('click', onGlobalBlockAdd);
  $('#gb-ip').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') onGlobalBlockAdd(); });
  $('#gb-note').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') onGlobalBlockAdd(); });
  $('#ip-detail-close').addEventListener('click', () => $('#ip-detail').close());
  $('#ip-detail').addEventListener('close', () => { state.ipDetail.ip = null; });
  $('#ip-detail-body').addEventListener('click', onIpDetailClick);
  $('#host-detail-close').addEventListener('click', () => $('#host-detail').close());
  $('#host-detail').addEventListener('close', () => { state.hostDetail.host = null; });
  $('#host-detail-body').addEventListener('click', onHostDetailClick);
  $('#editor-cancel').addEventListener('click', () => $('#editor').close());
  $('#editor-form').addEventListener('submit', onSubmit);
  $('#rules-body').addEventListener('click', onTableClick);
  $('#rules-table thead').addEventListener('click', onHeaderClick);
  const search = $('#search');
  search.addEventListener('input', (ev) => {
    state.filter = ev.target.value;
    render();
  });
  search.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') {
      ev.target.value = '';
      state.filter = '';
      render();
      ev.target.blur();
    }
  });
  // '/' anywhere focuses the search box (skip if a form input is already focused)
  document.addEventListener('keydown', (ev) => {
    if (ev.key === '/' && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName)) {
      ev.preventDefault();
      search.focus();
      search.select();
    }
  });

  // auth wiring
  $('#login-form').addEventListener('submit', onLogin);
  $('#btn-logout').addEventListener('click', onLogout);
  $('#btn-password').addEventListener('click', openPasswordDialog);
  $('#btn-maintenance').addEventListener('click', openMaintenanceDialog);
  $('#maint-cancel').addEventListener('click', () => $('#maintenance-dialog').close());
  $('#maint-start').addEventListener('click', onMaintenanceStart);
  $('#maint-stop').addEventListener('click', onMaintenanceStop);
  $('#maint-banner-edit').addEventListener('click', openMaintenanceDialog);
  $('#maint-banner-stop').addEventListener('click', onMaintenanceStop);
  $('#maint-presets').addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-min]');
    if (!b) return;
    selectPreset(Number(b.dataset.min));
  });
  $('#maint-until').addEventListener('input', () => {
    for (const b of $$('#maint-presets button')) b.classList.remove('selected');
    $('#maint-until-hint').textContent = '';
  });
  document.querySelectorAll('input[name="maint-scope"]').forEach((r) => {
    r.addEventListener('change', () => {
      $('#maint-host-picker').hidden = r.value !== 'some' || !r.checked;
    });
  });
  $('#btn-backup').addEventListener('click', openBackupDialog);
  $('#backup-close').addEventListener('click', () => $('#backup-dialog').close());
  $('#restore-btn').addEventListener('click', onRestore);
  $('#password-cancel').addEventListener('click', () => $('#password-dialog').close());
  $('#password-form').addEventListener('submit', onChangePassword);
  $('#pw-warning-change').addEventListener('click', openPasswordDialog);
  $('#pw-warning-dismiss').addEventListener('click', () => { $('#pw-warning').hidden = true; });

  gate();
});

// Gate the app behind a login. Runs first; only starts the app once authed.
async function gate() {
  let me;
  try {
    const res = await fetch('/api/auth/me', { credentials: 'same-origin' });
    me = await res.json().catch(() => ({}));
    if (!res.ok || !me.authenticated) { $('#login-overlay').hidden = false; return; }
  } catch (e) {
    $('#login-overlay').hidden = false;
    return;
  }
  $('#login-overlay').hidden = true;
  state.auth = me;
  if (me.password_is_default) $('#pw-warning').hidden = false;
  startApp();
}

let appStarted = false;
function startApp() {
  if (appStarted) return; // login after a mid-session expiry shouldn't double-init
  appStarted = true;
  refresh().catch((e) => showError(`Failed to load: ${e.message}`));
  refreshStatus();
  refreshMaintenance();
  checkVersion();
  startLiveStream();
  setInterval(refreshStatus, 5000);
  setInterval(refreshMaintenance, 30_000);
  setInterval(() => refreshCerts(false), 30_000);
  setInterval(() => checkVersion(), 6 * 60 * 60 * 1000);
  setInterval(liveHeartbeat, 20_000);
}

async function onLogin(ev) {
  ev.preventDefault();
  const f = ev.target;
  const err = $('#login-error');
  err.hidden = true;
  const btn = $('#login-submit');
  btn.disabled = true;
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ username: f.username.value, password: f.password.value }),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      err.textContent = res.status === 429
        ? `Too many attempts — wait ${data.retry_after_s || 30}s and try again.`
        : 'Invalid username or password.';
      err.hidden = false;
      return;
    }
    $('#login-overlay').hidden = true;
    f.password.value = '';
    state.auth = { authenticated: true, username: data.username, password_is_default: data.password_is_default };
    if (data.password_is_default) $('#pw-warning').hidden = false;
    startApp();
  } catch (e) {
    err.textContent = `Login failed: ${e.message}`;
    err.hidden = false;
  } finally {
    btn.disabled = false;
  }
}

async function onLogout() {
  try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } catch (_) {}
  location.reload();
}

function openPasswordDialog() {
  const f = $('#password-form');
  f.reset();
  $('#password-error').hidden = true;
  $('#password-dialog').showModal();
}

function openBackupDialog() {
  $('#backup-error').hidden = true;
  $('#restore-file').value = '';
  $('#backup-dialog').showModal();
}

async function onRestore() {
  const err = $('#backup-error');
  err.hidden = true;
  const file = $('#restore-file').files && $('#restore-file').files[0];
  if (!file) { err.textContent = 'Choose a backup file first.'; err.hidden = false; return; }
  let data;
  try {
    data = JSON.parse(await file.text());
  } catch {
    err.textContent = 'That file is not valid JSON.';
    err.hidden = false;
    return;
  }
  if (!data || data.format !== 'rproxy-backup') {
    err.textContent = 'That is not an rproxy backup file.';
    err.hidden = false;
    return;
  }
  const n = Array.isArray(data.rules) ? data.rules.length : 0;
  if (!confirm(`Restore ${n} rule(s) from this backup?\n\n`
    + 'This REPLACES all current rules, the global blocklist, and the login. '
    + 'You will be logged out and must sign in with the backup’s credentials.')) return;
  try {
    const r = await api('POST', '/system/restore', data);
    alert(`Restored ${r.rules} rule(s) and ${r.blocks} blocklist entr${r.blocks === 1 ? 'y' : 'ies'}. Reloading…`);
    location.reload();
  } catch (e) {
    err.textContent = `Restore failed: ${e.message}`;
    err.hidden = false;
  }
}

async function onChangePassword(ev) {
  ev.preventDefault();
  const f = ev.target;
  const err = $('#password-error');
  err.hidden = true;
  if (f.new_password.value !== f.confirm_password.value) {
    err.textContent = 'New password and confirmation do not match.';
    err.hidden = false;
    return;
  }
  try {
    await api('POST', '/auth/password', {
      current_password: f.current_password.value,
      new_password: f.new_password.value,
    });
    $('#password-dialog').close();
    $('#pw-warning').hidden = true;
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  }
}
