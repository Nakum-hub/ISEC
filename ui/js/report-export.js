// ISEC Report Generator — Full-featured forensic report engine with live preview

(function () {
  'use strict';

  let _evidenceData = null;
  let _reportHistory = JSON.parse(localStorage.getItem('isec_reports') || '[]');

  function initReportExport() {
    setupCheckboxes();
    setupFormatToggle();
    setupButtons();
    updatePreview();
    renderReportHistory();
  }

  function setupCheckboxes() {
    document.querySelectorAll('#report-section input[type="checkbox"], input[id^="type-"], input[id^="section-"]').forEach(cb => {
      cb.addEventListener('change', updatePreview);
    });
  }

  function setupFormatToggle() {
    document.querySelectorAll('[name="report-format"]').forEach(radio => {
      radio.addEventListener('change', updatePreview);
    });
  }

  function setupButtons() {
    const genBtn = document.getElementById('generate-report-btn');
    if (genBtn) genBtn.addEventListener('click', generateReport);

    const previewBtn = document.getElementById('preview-report-btn');
    if (previewBtn) previewBtn.addEventListener('click', previewInWindow);

    const clearHistBtn = document.getElementById('clear-history-btn');
    if (clearHistBtn) clearHistBtn.addEventListener('click', () => { _reportHistory = []; localStorage.setItem('isec_reports', '[]'); renderReportHistory(); });
  }

  // ── Live Preview Update ───────────────────────────────────────
  async function updatePreview() {
    const panel = document.getElementById('report-preview');
    if (!panel) return;

    const types = getSelectedTypes();
    const format = getSelectedFormat();
    const sections = getSelectedSections();

    if (!types.length) {
      panel.innerHTML = `
        <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;gap:12px;color:var(--text-muted);font-family:var(--font-mono);font-size:0.72rem;">
          <div style="font-size:32px;opacity:0.3;">📄</div>
          <span>Select evidence types above to preview report structure</span>
        </div>`;
      return;
    }

    const bridge = window.isec;
    let evidenceCount = 0;
    let timeline = [];

    if (bridge) {
      try {
        const [status, tl] = await Promise.all([
          bridge.invoke('get-backend-status').catch(() => null),
          bridge.invoke('get-evidence-timeline').catch(() => null),
        ]);
        evidenceCount = (status && status.evidenceItemsCount) || 0;
        timeline = (tl && Array.isArray(tl.items)) ? tl.items : [];
        _evidenceData = { status, timeline };
      } catch (_) {}
    }

    const filteredItems = timeline.filter(it => types.includes(it.type));
    renderPreview(panel, types, format, sections, filteredItems, evidenceCount);
  }

  function renderPreview(panel, types, format, sections, items, total) {
    const now = new Date().toLocaleString();
    const sevCounts = { critical:0, high:0, medium:0, low:0, info:0 };
    items.forEach(it => { const s=(it.severity||'info').toLowerCase(); if(sevCounts[s]!==undefined) sevCounts[s]++; });

    const typeLabels = { system_logs:'System Logs', browser_history:'Browser History', network_connections:'Network Connections', file_metadata:'File Metadata' };

    panel.innerHTML = `
      <div style="font-family:var(--font-mono);font-size:0.65rem;background:rgba(0,0,0,0.3);border-radius:8px;padding:16px;height:100%;overflow-y:auto;line-height:1.8;">
        <div style="color:var(--cyan-bright);font-size:0.8rem;font-weight:700;letter-spacing:0.15em;text-transform:uppercase;border-bottom:1px solid rgba(0,200,255,0.2);padding-bottom:8px;margin-bottom:12px;">
          ██ ISEC FORENSIC REPORT — PREVIEW ██
        </div>
        <div style="color:var(--text-muted);">Generated: ${now}</div>
        <div style="color:var(--text-muted);">Format: ${format.toUpperCase()}</div>
        <div style="color:var(--text-muted);">Evidence Types: ${types.map(t=>typeLabels[t]||t).join(', ')}</div>
        <div style="color:var(--text-muted);">Items: ${items.length} (of ${total} total)</div>
        <div style="margin:12px 0;border-top:1px solid rgba(255,255,255,0.06);"></div>
        ${sections.includes('summary') ? `
          <div style="color:var(--success);font-weight:700;margin-bottom:6px;">[ EXECUTIVE SUMMARY ]</div>
          <div style="color:var(--text-secondary);margin-bottom:4px;">Total evidence items analysed: ${items.length}</div>
          <div style="color:var(--text-secondary);margin-bottom:4px;">Critical findings: ${sevCounts.critical} | High: ${sevCounts.high} | Medium: ${sevCounts.medium}</div>
          <div style="margin:10px 0;border-top:1px solid rgba(255,255,255,0.04);"></div>` : ''}
        ${sections.includes('chain') ? `
          <div style="color:var(--warning);font-weight:700;margin-bottom:6px;">[ CHAIN OF CUSTODY ]</div>
          <div style="color:var(--text-muted);">Evidence collection → HMAC signing → Hash chain link → DB encryption</div>
          <div style="margin:10px 0;border-top:1px solid rgba(255,255,255,0.04);"></div>` : ''}
        ${sections.includes('evidence') ? `
          <div style="color:var(--cyan-bright);font-weight:700;margin-bottom:6px;">[ EVIDENCE RECORDS ]</div>
          ${items.slice(0,5).map((it,i) => `<div style="color:var(--text-muted);margin-bottom:2px;">${i+1}. [${(it.severity||'INFO').toUpperCase()}] ${it.description||'—'} (${new Date(it.timestamp||Date.now()).toLocaleDateString()})</div>`).join('')}
          ${items.length > 5 ? `<div style="color:var(--text-muted);">  … and ${items.length-5} more records</div>` : ''}
          <div style="margin:10px 0;border-top:1px solid rgba(255,255,255,0.04);"></div>` : ''}
        ${sections.includes('integrity') ? `
          <div style="color:var(--teal);font-weight:700;margin-bottom:6px;">[ INTEGRITY VERIFICATION ]</div>
          <div style="color:var(--text-muted);">Hash chain verification, HMAC validation, and digital signature status will appear here.</div>
          <div style="margin:10px 0;border-top:1px solid rgba(255,255,255,0.04);"></div>` : ''}
        <div style="color:var(--text-muted);font-size:0.6rem;text-align:center;margin-top:8px;">END OF PREVIEW — ${items.length} records will be included</div>
      </div>`;
  }

  // ── Generate Report ───────────────────────────────────────────
  async function generateReport() {
    const types = getSelectedTypes();
    const format = getSelectedFormat();
    const sections = getSelectedSections();
    const caseName = (document.getElementById('report-case-name') || {}).value || '';
    const analyst  = (document.getElementById('report-analyst') || {}).value  || '';

    if (!types.length) { ISECNotify && ISECNotify.warning('Select at least one evidence type.'); return; }

    const bridge = window.isec;
    if (!bridge) { ISECNotify && ISECNotify.error('IPC bridge not available.'); return; }

    const btn = document.getElementById('generate-report-btn');
    if (btn) { btn.disabled = true; btn.textContent = 'Generating…'; }

    showProgress(0, 'Initialising report…');

    const notify = ISECNotify && ISECNotify.loading('Generating forensic report…');

    try {
      showProgress(20, 'Collecting evidence data…');
      const tl = await bridge.invoke('get-evidence-timeline').catch(() => null);
      const items = (tl && Array.isArray(tl.items)) ? tl.items.filter(it => types.includes(it.type)) : [];

      showProgress(50, 'Building report structure…');
      const result = await bridge.invoke('generate-report', { types, format, sections, evidenceIds: items.map(i=>i.id), caseName, analyst });
      showProgress(90, 'Finalising…');

      notify && notify.dismiss();

      if (result && result.success) {
        showProgress(100, 'Report generated!');
        ISECNotify && ISECNotify.success(`Report exported: ${result.reportPath || 'report generated'}`);

        addToHistory({ types, format, sections, caseName, analyst, path: result.reportPath, ts: new Date().toISOString(), count: items.length });
      } else {
        ISECNotify && ISECNotify.error((result && result.message) || 'Report generation failed.');
      }
    } catch (err) {
      notify && notify.dismiss();
      ISECNotify && ISECNotify.error('Report error: ' + err.message);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '⬇ Generate Report'; }
      setTimeout(() => hideProgress(), 2000);
    }
  }

  function showProgress(pct, msg) {
    const bar = document.getElementById('report-progress-bar');
    const lbl = document.getElementById('report-progress-label');
    const con = document.getElementById('report-progress');
    if (con) con.style.display = 'block';
    if (bar) bar.style.width = pct + '%';
    if (lbl) lbl.textContent = msg;
  }

  function hideProgress() {
    const con = document.getElementById('report-progress');
    if (con) con.style.display = 'none';
  }

  async function previewInWindow() {
    const types = getSelectedTypes();
    if (!types.length) { ISECNotify && ISECNotify.warning('Select at least one evidence type.'); return; }
    ISECNotify && ISECNotify.info('Full preview will open when a report is generated.');
  }

  // ── Report History ────────────────────────────────────────────
  function addToHistory(entry) {
    _reportHistory.unshift(entry);
    if (_reportHistory.length > 20) _reportHistory = _reportHistory.slice(0, 20);
    try { localStorage.setItem('isec_reports', JSON.stringify(_reportHistory)); } catch(_) {}
    renderReportHistory();
    updateReportsCount();
  }

  function updateReportsCount() {
    const reportsCountEl = document.getElementById('reports-count');
    if (reportsCountEl) {
      if (typeof ISECCharts !== 'undefined') ISECCharts.animateValue(reportsCountEl, parseInt(reportsCountEl.textContent)||0, _reportHistory.length, 500);
      else reportsCountEl.textContent = _reportHistory.length;
    }
  }

  function renderReportHistory() {
    const container = document.getElementById('report-history-list');
    if (!container) return;

    if (!_reportHistory.length) {
      container.innerHTML = '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);text-align:center;padding:20px;">No reports generated yet.</div>';
      return;
    }

    const typeLabels = { system_logs:'Sys', browser_history:'Browser', network_connections:'Net', file_metadata:'Files' };
    const fmtColors  = { pdf:'var(--danger)', csv:'var(--success)', json:'var(--cyan-bright)', html:'var(--warning)' };

    container.innerHTML = _reportHistory.map((r, i) => `
      <div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
        <div style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);flex-shrink:0;width:16px;text-align:right;">${i+1}</div>
        <div style="flex:1;min-width:0;">
          <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-secondary);">${r.caseName || 'Untitled Case'}</div>
          <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);margin-top:2px;">${new Date(r.ts).toLocaleString()} · ${r.count||0} items</div>
        </div>
        <div style="display:flex;gap:4px;">
          ${(r.types||[]).map(t=>`<span class="badge" style="font-size:0.55rem;padding:1px 5px;">${typeLabels[t]||t}</span>`).join('')}
        </div>
        <span class="badge" style="background:${(fmtColors[r.format]||'var(--text-muted)')}15;color:${fmtColors[r.format]||'var(--text-muted)'};border:1px solid ${(fmtColors[r.format]||'rgba(255,255,255,0.1)')}33;font-size:0.6rem;">${(r.format||'?').toUpperCase()}</span>
      </div>
    `).join('');
  }

  // ── Helpers ───────────────────────────────────────────────────
  function getSelectedTypes() {
    return ['system_logs','browser_history','network_connections','file_metadata'].filter(t => {
      const cb = document.getElementById('type-' + t.replace(/_/g,'-'));
      return cb && cb.checked;
    });
  }

  function getSelectedFormat() {
    const r = document.querySelector('[name="report-format"]:checked');
    return r ? r.value : 'pdf';
  }

  function getSelectedSections() {
    return ['summary','chain','evidence','integrity','metadata'].filter(s => {
      const cb = document.getElementById('section-' + s);
      return cb && cb.checked;
    });
  }

  window.initReportExport = initReportExport;
})();
