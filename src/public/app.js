const state = {
  rules: [],
  certs: {},
  sort: { key: 'hostname', dir: 'asc' },
  filter: '',
  activity: [],
  activityMeta: null,
  activitySort: { key: null, dir: 'desc' },
  view: 'rules',
  version: null,
  auth: null,
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
      <td><strong>${escapeHtml(r.hostname)}</strong>${r.add_www ? ` <span class="muted">+www</span>` : ''}${aclBadge(r)}</td>
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

async function loadActivity() {
  showError('');
  const hours = $('#activity-window').value;
  try {
    const [act, rec] = await Promise.all([
      api('GET', `/activity?hours=${hours}`),
      api('GET', '/activity/recent?limit=200'),
    ]);
    renderActivity(act);
    renderRecent(rec.events || []);
  } catch (e) {
    showError(`Activity load failed: ${e.message}`);
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

function activitySorted() {
  const { key, dir } = state.activitySort;
  if (!key || !ACTIVITY_SORT[key]) return state.activity; // server order: suspicious first
  const acc = ACTIVITY_SORT[key];
  const mult = dir === 'desc' ? -1 : 1;
  return [...state.activity].sort((a, b) => {
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
  drawActivity();
}

function drawActivity() {
  renderActivityArrows();
  const m = state.activityMeta || { stats: {} };
  const s = m.stats || {};
  $('#activity-count').textContent = `(${m.count} in last ${m.window}h)`;
  $('#activity-stats').textContent = s.count
    ? `${s.count.toLocaleString()} events stored, oldest ${fmtAgo(s.oldest)}`
    : 'no events captured yet';
  const tbody = $('#activity-body');
  const ips = activitySorted();
  if (!ips.length) {
    tbody.innerHTML = `<tr><td colspan="11" class="muted">No traffic recorded in this window. The access log fills as requests arrive.</td></tr>`;
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
    return `
      <tr class="${ip.suspicious ? 'suspicious' : ''}">
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

  const paths = miniTable(d.paths.map((p) =>
    `<tr><td class="uri" title="${escapeHtml(p.uri)}">${escapeHtml(p.uri)}${p.probe ? ' <span class="flag">probe</span>' : ''}</td>`
    + `<td class="num">${p.c}</td><td class="num ${p.errors ? 'st4' : ''}">${p.errors || ''}</td></tr>`));

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
  $('#ip-detail-title').textContent = ip;
  $('#ip-detail-body').innerHTML = '<div class="muted">Looking up geolocation &amp; activity…</div>';
  $('#ip-detail').showModal();
  try {
    const hours = $('#activity-window').value;
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
  $('#activity-table thead').addEventListener('click', onActivityHeaderClick);
  $('#blocklist-body').addEventListener('click', onActivityClick);
  $('#blocklist-refresh').addEventListener('click', loadBlocklist);
  $('#gb-add').addEventListener('click', onGlobalBlockAdd);
  $('#gb-ip').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') onGlobalBlockAdd(); });
  $('#gb-note').addEventListener('keydown', (ev) => { if (ev.key === 'Enter') onGlobalBlockAdd(); });
  $('#ip-detail-close').addEventListener('click', () => $('#ip-detail').close());
  $('#ip-detail-body').addEventListener('click', onIpDetailClick);
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
  checkVersion();
  setInterval(refreshStatus, 5000);
  setInterval(() => refreshCerts(false), 30_000);
  setInterval(() => checkVersion(), 6 * 60 * 60 * 1000);
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
