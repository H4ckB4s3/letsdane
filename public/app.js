const $ = id => document.getElementById(id);

let settings = null;
let tlds = [];

function setText(id, value) {
  const el = $(id);
  if (el) el.textContent = value;
}

function updateActiveLabel() {
  const el = $('active-resolver');
  if (!el) {
    console.warn('[ui] #active-resolver element not found');
    return;
  }
  const s = settings || {};
  let value;
  if (s.useLocalNode) {
    const addr = s.localNodeAddress || '127.0.0.1';
    const p = s.localNodePort || 5350;
    value = `local (${addr}:${p})`;
  } else {
    value = s.activeResolver || '82.68.70.162';
  }
  el.textContent = value;
  console.log('[ui] active label =', value);
}

async function loadStatus() {
  try {
    const res = await fetch('/api/status');
    if (!res.ok) throw new Error(`/api/status ${res.status}`);
    const data = await res.json();
    setText('proxy-status', data?.proxy?.status === 'active' ? 'Active' : 'Stopped');
    setText('proxy-address', data?.proxy?.address || '127.0.0.1:8080');
    setText('ca-status', data?.ca?.ready ? 'Ready' : 'Not ready');
    if (settings) updateActiveLabel();
    if (data?.ca?.ready) {
      const el = $('ca-info');
      if (el) el.innerHTML = `
        <dt>Subject</dt><dd>${data.ca.subject ?? ''}</dd>
        <dt>Issuer</dt><dd>${data.ca.issuer ?? ''}</dd>
        <dt>Valid from</dt><dd>${data.ca.notBefore ? new Date(data.ca.notBefore).toLocaleDateString() : ''}</dd>
        <dt>Valid until</dt><dd>${data.ca.notAfter ? new Date(data.ca.notAfter).toLocaleDateString() : ''}</dd>
        <dt>SHA-256 fingerprint</dt><dd>${data.ca.fingerprint ?? ''}</dd>
      `;
    }
  } catch (err) {
    console.error('[status]', err);
  }
}

async function loadSettings() {
  try {
    const res = await fetch('/api/settings');
    if (!res.ok) throw new Error(`/api/settings ${res.status}`);
    settings = await res.json();

    settings.activeResolver = settings.activeResolver || settings.primary || '82.68.70.162';
    settings.resolverProfiles =
      Array.isArray(settings.resolverProfiles) && settings.resolverProfiles.length
        ? settings.resolverProfiles
        : [{ label: 'Handshake resolver', ip: '82.68.70.162' }];
    settings.localNodeAddress = settings.localNodeAddress || '127.0.0.1';
    settings.localNodePort = settings.localNodePort || 5350;
    settings.useLocalNode = !!settings.useLocalNode;
    settings.useSecondary = !!settings.useSecondary;
    settings.secondary = settings.secondary || '';
    settings.icannTlds = Array.isArray(settings.icannTlds) ? settings.icannTlds : [];

    const sel = $('active-resolver-select');
    if (sel) {
      sel.innerHTML = '';
      for (const p of settings.resolverProfiles) {
        const opt = document.createElement('option');
        opt.value = p.ip;
        opt.textContent = `${p.label} — ${p.ip}`;
        if (p.ip === settings.activeResolver) opt.selected = true;
        sel.appendChild(opt);
      }
    }

    const sec = $('secondary'); if (sec) sec.value = settings.secondary;
    const us = $('useSecondary'); if (us) us.checked = settings.useSecondary;
    const ln = $('useLocalNode'); if (ln) ln.checked = settings.useLocalNode;
    const la = $('localNodeAddress'); if (la) la.value = settings.localNodeAddress;
    const lp = $('localNodePort'); if (lp) lp.value = settings.localNodePort;

    renderTlds(settings.icannTlds);
    updateActiveLabel();
  } catch (err) {
    console.error('[settings]', err);
  }
}

function renderTlds(list) {
  tlds = [...new Set((list || []).map(t => String(t).toLowerCase()))].sort();
  const box = $('icann-tld-list');
  if (!box) return;
  box.innerHTML = '';
  for (const tld of tlds) {
    const chip = document.createElement('span');
    chip.className = 'tld-chip';
    chip.textContent = tld;
    const x = document.createElement('button');
    x.type = 'button';
    x.className = 'tld-chip-remove';
    x.textContent = '×';
    x.onclick = () => { tlds = tlds.filter(t => t !== tld); renderTlds(tlds); };
    chip.appendChild(x);
    box.appendChild(chip);
  }
  const c = $('tld-count');
  if (c) c.textContent = `(${tlds.length})`;
}

async function persistSettings(override) {
  const payload = {
    activeResolver: $('active-resolver-select')?.value || settings.activeResolver,
    resolverProfiles: settings.resolverProfiles,
    secondary: $('secondary')?.value.trim() || '',
    useSecondary: !!$('useSecondary')?.checked,
    useLocalNode: !!$('useLocalNode')?.checked,
    localNodeAddress: $('localNodeAddress')?.value.trim() || '127.0.0.1',
    localNodePort: Number($('localNodePort')?.value) || 5350,
    icannTlds: tlds,
    ...(override || {})
  };
  const res = await fetch('/api/settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  return res.json();
}

async function saveAll() {
  const out = $('trust-save-result');
  if (!out) return;
  out.textContent = 'Saving…';
  out.className = 'result';
  try {
    const data = await persistSettings();
    if (data.ok) {
      out.textContent = '✓ Saved and applied immediately';
      out.className = 'result success';
      await loadSettings();
    } else {
      out.textContent = `✗ ${data.error}`;
      out.className = 'result failure';
    }
  } catch (err) {
    out.textContent = `✗ ${err.message}`;
    out.className = 'result failure';
  }
}

async function testServer(server, outId, port) {
  const out = $(outId);
  if (!out) return;
  if (!server) { out.textContent = 'No address'; out.className = 'result failure'; return; }
  out.textContent = 'Testing…';
  out.className = 'result';
  try {
    const res = await fetch('/api/resolvers/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ server, port })
    });
    const data = await res.json();
    if (data.ok) {
      out.textContent = `✓ OK (${data.family === 6 ? 'IPv6' : 'IPv4'}) ${data.answers?.length || 0} answers`;
      out.className = 'result success';
    } else {
      out.textContent = `✗ ${data.error || data.responseCode}`;
      out.className = 'result failure';
    }
  } catch (err) {
    out.textContent = `✗ ${err.message}`;
    out.className = 'result failure';
  }
}

async function loadRecent() {
  try {
    const res = await fetch('/api/security/recent');
    if (!res.ok) return;
    const data = await res.json();
    const items = data.recent || [];
    const tbody = $('recent-verifications');
    if (!tbody) return;
    if (!items.length) {
      tbody.innerHTML = `<tr><td colspan="4" class="muted">No verifications yet.</td></tr>`;
      return;
    }
    tbody.innerHTML = items.slice(0, 50).map(it => {
      const time = new Date(it.at).toLocaleTimeString();
      const cls = it.result === 'verified' ? 'verified'
                : it.result === 'icann-pass' ? 'icann' : 'blocked';
      const label = it.result === 'verified' ? 'DANE ✓'
                  : it.result === 'icann-pass' ? 'ICANN pass' : 'Blocked';
      const detail = it.error || it.tlsa || it.spki || it.mode || '';
      return `<tr>
        <td class="muted">${time}</td>
        <td class="mono">${it.host}</td>
        <td><span class="verdict ${cls}">${label}</span></td>
        <td class="muted">${detail}</td>
      </tr>`;
    }).join('');
  } catch (err) {
    console.error('[recent]', err);
  }
}

function wire() {
  const on = (id, ev, fn) => { const el = $(id); if (el) el[ev] = fn; };

  on('test-active', 'onclick', () => testServer($('active-resolver-select')?.value, 'active-result'));
  on('test-secondary', 'onclick', () => testServer($('secondary')?.value.trim(), 'secondary-result'));
  on('test-local', 'onclick', () =>
    testServer($('localNodeAddress')?.value.trim(), 'local-result', Number($('localNodePort')?.value) || 5350));
  on('save-settings', 'onclick', saveAll);

  // AUTOSAVE: local node checkbox
  const localCb = $('useLocalNode');
  if (localCb) {
    localCb.addEventListener('change', async () => {
      const status = $('local-result');
      if (status) { status.textContent = 'Saving…'; status.className = 'result'; }
      try {
        const data = await persistSettings({ useLocalNode: !!localCb.checked });
        if (data.ok) {
          if (status) { status.textContent = '✓ Saved'; status.className = 'result success'; }
          await loadSettings();
        } else if (status) {
          status.textContent = '✗ ' + data.error;
          status.className = 'result failure';
        }
      } catch (e) {
        if (status) { status.textContent = '✗ ' + e.message; status.className = 'result failure'; }
      }
    });
  }

  // AUTOSAVE: active resolver dropdown
  const sel = $('active-resolver-select');
  if (sel) {
    sel.addEventListener('change', async () => {
      const status = $('active-result');
      if (status) { status.textContent = 'Saving…'; status.className = 'result'; }
      try {
        const data = await persistSettings({ activeResolver: sel.value });
        if (data.ok) {
          if (status) { status.textContent = '✓ Saved'; status.className = 'result success'; }
          await loadSettings();
        } else if (status) {
          status.textContent = '✗ ' + data.error;
          status.className = 'result failure';
        }
      } catch (e) {
        if (status) { status.textContent = '✗ ' + e.message; status.className = 'result failure'; }
      }
    });
  }

  on('add-resolver', 'onclick', async () => {
    const label = $('new-resolver-label')?.value.trim();
    const ip = $('new-resolver-ip')?.value.trim();
    const err = $('resolver-error');
    if (err) err.textContent = '';
    if (!label || !ip) { if (err) err.textContent = 'Label and IP required'; return; }
    if (settings.resolverProfiles.some(p => p.ip === ip)) {
      if (err) err.textContent = 'Resolver IP already saved'; return;
    }
    settings.resolverProfiles.push({ label, ip });
    try {
      const data = await persistSettings({ activeResolver: ip, resolverProfiles: settings.resolverProfiles });
      if (data.ok) {
        if ($('new-resolver-label')) $('new-resolver-label').value = '';
        if ($('new-resolver-ip')) $('new-resolver-ip').value = '';
        await loadSettings();
      } else if (err) err.textContent = data.error;
    } catch (e) { if (err) err.textContent = e.message; }
  });

  on('add-tld', 'onclick', () => {
    const raw = $('icann-tld')?.value.trim().toLowerCase().replace(/^\./, '');
    const err = $('tld-error');
    if (err) err.textContent = '';
    if (!raw || !/^[a-z0-9-]+$/.test(raw) || raw.includes('.')) {
      if (err) err.textContent = 'Invalid TLD'; return;
    }
    if (!tlds.includes(raw)) tlds.push(raw);
    renderTlds(tlds);
    if ($('icann-tld')) $('icann-tld').value = '';
  });

  const tldInput = $('icann-tld');
  if (tldInput) tldInput.addEventListener('keydown', e => { if (e.key === 'Enter') $('add-tld')?.click(); });

  const bulk = $('bulk-tld-apply');
  if (bulk) {
    bulk.onclick = async () => {
      const fi = $('bulk-tld-file');
      const out = $('bulk-tld-result');
      if (!out || !fi) return;
      out.textContent = '';
      out.className = 'result';
      if (!fi.files.length) {
        out.textContent = 'Select a file first.';
        out.className = 'result failure';
        return;
      }
      const text = await fi.files[0].text();
      const raw = text.split(/[\r\n,]+/).map(s => s.trim().toLowerCase().replace(/^\./, '')).filter(Boolean);
      const valid = [], invalid = [];
      for (const t of raw) {
        if (/^[a-z0-9-]+$/.test(t) && !t.startsWith('-') && !t.endsWith('-')) valid.push(t);
        else invalid.push(t);
      }
      for (const t of valid) if (!tlds.includes(t)) tlds.push(t);
      renderTlds(tlds);
      out.textContent = `Added ${valid.length} valid TLD(s)` +
        (invalid.length ? `, ignored ${invalid.length} invalid` : '');
      out.className = invalid.length ? 'result success-with-warnings' : 'result success';
    };
  }

  const restartBtn = $('restart-btn');
  if (restartBtn) {
    restartBtn.onclick = async () => {
      if (!confirm('Restart letsdane?')) return;
      restartBtn.disabled = true;
      const status = $('restart-status');
      if (status) { status.textContent = 'Restarting…'; status.className = 'result'; }
      try {
        const res = await fetch('/api/system/restart', { method: 'POST' });
        const data = await res.json();
        if (data.ok) {
          if (status) { status.textContent = 'Restarting — reloading in 3s…'; status.className = 'result success'; }
          setTimeout(() => location.reload(), 3000);
        } else {
          if (status) { status.textContent = 'Error: ' + data.error; status.className = 'result failure'; }
          restartBtn.disabled = false;
        }
      } catch (e) {
        if (status) { status.textContent = 'Restart failed: ' + e.message; status.className = 'result failure'; }
        restartBtn.disabled = false;
      }
    };
  }
}

function init() {
  wire();
  loadStatus();
  loadSettings();
  loadRecent();
  setInterval(loadStatus, 10000);
  setInterval(loadRecent, 3000);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
