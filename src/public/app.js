const state = {
  rules: [],
  certs: {},
  sort: { key: 'hostname', dir: 'asc' },
  filter: '',
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
      <td><strong>${escapeHtml(r.hostname)}</strong>${r.add_www ? ` <span class="muted">+www</span>` : ''}${denyCount(r) ? ` <span class="badge cert-crit" title="${denyCount(r)} blocked IP/CIDR entr${denyCount(r) === 1 ? 'y' : 'ies'}">⛔ ${denyCount(r)}</span>` : ''}</td>
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
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
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
  lines.push('| ID | Enabled | Hostname | +www | Backend | TLS mode | Cert expiry | WS | HSTS | Read timeout | Blocked IPs | Notes |');
  lines.push('|---:|---|---|---|---|---|---|---|---|---:|---|---|');
  for (const r of rules) {
    const cert = state.certs[r.hostname];
    let certCol = '—';
    if (r.tls_mode !== 'http') {
      if (cert?.error) certCol = `probe error: ${cert.error}`;
      else if (cert)   certCol = `${new Date(cert.not_after).toISOString().slice(0,10)} (${cert.days_remaining}d) — ${cert.issuer}`;
      else             certCol = '(no probe yet)';
    }
    const blocked = (r.deny_ips || '')
      .split(/[\n,]+/).map((s) => s.replace(/#.*$/, '').trim()).filter(Boolean);
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
      blocked.length ? blocked.join('; ') : '—',
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

document.addEventListener('DOMContentLoaded', () => {
  $('#btn-new').addEventListener('click', () => openEditor(null));
  $('#btn-copy').addEventListener('click', onCopy);
  $('#btn-reload').addEventListener('click', onReload);
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
  refresh().catch((e) => showError(`Failed to load: ${e.message}`));
  refreshStatus();
  setInterval(refreshStatus, 5000);
  setInterval(() => refreshCerts(false), 30_000);
});
