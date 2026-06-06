// ISEC Audit Log — 100% real data from backend: DB events, real timestamps, real files

(function () {
  'use strict';

  let _all = [], _filtered = [], _page = 1;
  const PAGE = 30;

  // ── Init ─────────────────────────────────────────────────────
  async function initAuditLog() {
    const bind = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); };
    bind('audit-refresh-btn',  loadAuditLog);
    bind('audit-export-btn',   exportAuditCSV);
    bind('audit-page-prev',    () => { if (_page > 1) { _page--; renderPage(); } });
    bind('audit-page-next',    () => { const t = Math.ceil(_filtered.length / PAGE); if (_page < t) { _page++; renderPage(); } });

    const search = document.getElementById('audit-search');
    if (search) search.addEventListener('input', () => { _page = 1; applyFilter(); });

    const actFilter = document.getElementById('audit-action-filter');
    if (actFilter) actFilter.addEventListener('change', () => { _page = 1; applyFilter(); });

    const sortEl = document.getElementById('audit-sort');
    if (sortEl) sortEl.addEventListener('change', applyFilter);

    await loadAuditLog();
  }

  // ── Load real data from IPC ───────────────────────────────────
  async function loadAuditLog() {
    const bridge = window.isec;
    if (!bridge) return;

    // Show loading state
    const tbody = document.getElementById('audit-log-body');
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;">
      <div class="spinner" style="width:24px;height:24px;margin:0 auto;"></div></td></tr>`;

    try {
      // Call real IPC handler — reads from DB, disk, session events
      const resp = await bridge.invoke('get-audit-log');
      _all = (resp && Array.isArray(resp.events)) ? resp.events : [];

      if (!_all.length && resp && resp.message) {
        console.warn('Audit log warning:', resp.message);
      }

      updateStats();
      applyFilter();
    } catch (err) {
      console.error('Audit log error:', err);
      ISECNotify && ISECNotify.error('Failed to load audit log: ' + err.message);
    }
  }

  // ── Stats ─────────────────────────────────────────────────────
  function updateStats() {
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('audit-total',       _all.length);
    set('audit-collections', _all.filter(e => e.action === 'COLLECTION').length);
    set('audit-reports',     _all.filter(e => e.action === 'REPORT').length);
    const alerts = _all.filter(e => e.result === 'alert' || e.result === 'failed').length;
    set('audit-alerts', alerts);
    const alertEl = document.getElementById('audit-alerts');
    if (alertEl) alertEl.style.color = alerts > 0 ? 'var(--danger)' : 'var(--success)';
  }

  // ── Filter ────────────────────────────────────────────────────
  function applyFilter() {
    const q    = ((document.getElementById('audit-search')        || {}).value || '').toLowerCase().trim();
    const act  = ((document.getElementById('audit-action-filter') || {}).value || 'all');
    const sort = ((document.getElementById('audit-sort')          || {}).value || 'desc');

    let filtered = [..._all];
    if (act !== 'all') filtered = filtered.filter(e => (e.action || '').toUpperCase() === act.toUpperCase());
    if (q) filtered = filtered.filter(e =>
      (e.title  || '').toLowerCase().includes(q) ||
      (e.detail || '').toLowerCase().includes(q) ||
      (e.actor  || '').toLowerCase().includes(q)
    );
    filtered.sort((a, b) => sort === 'asc' ? a.ts - b.ts : b.ts - a.ts);
    _filtered = filtered;

    const countEl = document.getElementById('audit-count');
    if (countEl) countEl.textContent = `${_filtered.length} event${_filtered.length !== 1 ? 's' : ''}`;
    renderPage();
  }

  // ── Render ────────────────────────────────────────────────────
  function renderPage() {
    const tbody = document.getElementById('audit-log-body');
    if (!tbody) return;

    const totalPages = Math.ceil(_filtered.length / PAGE);
    const start = (_page - 1) * PAGE;
    const slice = _filtered.slice(start, start + PAGE);

    if (!slice.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center;padding:40px;
        font-family:var(--font-mono);font-size:0.72rem;color:var(--text-muted);">
        No audit events found.</td></tr>`;
      const pag = document.getElementById('audit-pagination');
      if (pag) pag.classList.add('hidden');
      return;
    }

    const AC = {
      COLLECTION: 'var(--cyan-bright)', REPORT: 'var(--purple)',
      EXPORT: 'var(--teal)',    AUTH: 'var(--warning)',
      INTEGRITY: 'var(--orange)', SYSTEM: 'var(--text-muted)',
    };
    const RC = { success: 'var(--success)', failed: 'var(--danger)', alert: 'var(--warning)' };

    tbody.innerHTML = slice.map(e => {
      const ac  = AC[(e.action || '').toUpperCase()] || 'var(--text-muted)';
      const rc  = RC[e.result] || 'var(--text-muted)';
      const ts  = e.ts ? new Date(e.ts).toLocaleString() : '—';
      const act = (e.action || 'SYSTEM').toUpperCase();
      return `<tr onmouseenter="this.style.background='rgba(0,200,255,0.03)'" onmouseleave="this.style.background='transparent'" style="border-bottom:1px solid rgba(255,255,255,0.03);transition:background 0.1s;">
        <td style="padding:9px 12px;font-family:var(--font-mono);font-size:9px;color:var(--text-muted);text-align:center;">${e.seq || '—'}</td>
        <td style="padding:9px 12px;font-family:var(--font-mono);font-size:9px;color:var(--text-muted);white-space:nowrap;">${ts}</td>
        <td style="padding:9px 12px;"><span style="background:${ac}15;color:${ac};border:1px solid ${ac}33;padding:2px 7px;border-radius:3px;font-family:var(--font-mono);font-size:8px;letter-spacing:0.06em;">${act}</span></td>
        <td style="padding:9px 12px;max-width:260px;overflow:hidden;">
          <div style="font-weight:600;font-size:0.78rem;color:var(--text-primary);">${escHtml(e.title || '')}</div>
          <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(e.detail || '')}">${escHtml(e.detail || '')}</div>
        </td>
        <td style="padding:9px 12px;font-family:var(--font-mono);font-size:0.68rem;color:var(--text-secondary);">${escHtml(e.actor || 'system')}</td>
        <td style="padding:9px 12px;"><span style="background:${rc}15;color:${rc};border:1px solid ${rc}33;padding:2px 7px;border-radius:3px;font-family:var(--font-mono);font-size:8px;">${e.result || '—'}</span></td>
      </tr>`;
    }).join('');

    // Pagination
    const pag = document.getElementById('audit-pagination');
    if (totalPages > 1) {
      pag && pag.classList.remove('hidden');
      const pi   = document.getElementById('audit-page-info');
      const prev = document.getElementById('audit-page-prev');
      const next = document.getElementById('audit-page-next');
      if (pi)   pi.textContent  = `Page ${_page} of ${totalPages}`;
      if (prev) prev.disabled   = _page <= 1;
      if (next) next.disabled   = _page >= totalPages;
    } else {
      pag && pag.classList.add('hidden');
    }
  }

  // ── Export ────────────────────────────────────────────────────
  function exportAuditCSV() {
    const rows = [['Seq','Timestamp','Action','Title','Detail','Actor','Result']];
    _filtered.forEach(e => rows.push([
      e.seq || '',
      e.ts ? new Date(e.ts).toISOString() : '',
      e.action || '',
      (e.title  || '').replace(/,/g,' '),
      (e.detail || '').replace(/,/g,' '),
      e.actor || '',
      e.result || '',
    ]));
    const csv  = rows.map(r => r.map(v => `"${v}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `isec-audit-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
    ISECNotify && ISECNotify.success(`Exported ${_filtered.length} real audit events`);
  }

  function escHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  window.initAuditLog = initAuditLog;
})();
