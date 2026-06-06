// ISEC Navigation — 7-view router, window controls, top-bar live updates

(function () {
  'use strict';

  const VIEW_INIT = {
    dashboard:        () => typeof initializeDashboard === 'function' && initializeDashboard(),
    timeline:         () => typeof initTimeline        === 'function' && initTimeline(),
    'threat-analysis':() => typeof initThreatAnalysis  === 'function' && initThreatAnalysis(),
    'audit-log':      () => typeof initAuditLog         === 'function' && initAuditLog(),
    cases:            () => typeof initCases            === 'function' && initCases(),
    compliance:       () => typeof initCompliance       === 'function' && initCompliance(),
    report:           () => typeof initReportExport     === 'function' && initReportExport(),
  };

  const _inited = new Set();

  // ── Navigate ──────────────────────────────────────────────────
  function navigateTo(viewId) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewId);
    });

    const target = document.getElementById(viewId);
    if (target) {
      target.classList.add('active');
      // Scroll main content to top on view switch
      const main = document.getElementById('main-content');
      if (main) main.scrollTop = 0;
    }

    // Lazy-init each view once; always re-init dashboard for fresh data
    if (viewId === 'dashboard') {
      VIEW_INIT.dashboard();
    } else if (VIEW_INIT[viewId] && !_inited.has(viewId)) {
      _inited.add(viewId);
      VIEW_INIT[viewId]();
    }

    // Close detail panel on navigation
    const dp = document.getElementById('detail-panel');
    if (dp && !dp.classList.contains('hidden')) {
      dp.classList.add('hidden');
      dp.style.display = 'none';
    }
  }

  // ── Window Controls ───────────────────────────────────────────
  function bindWindowControls() {
    const bridge = window.isec;
    if (!bridge) return;
    const actions = { 'minimize-window-btn':'window-minimize', 'maximize-window-btn':'window-maximize', 'close-window-btn':'window-close' };
    Object.entries(actions).forEach(([id, evt]) => {
      const btn = document.getElementById(id);
      if (btn) btn.addEventListener('click', () => bridge.invoke(evt).catch(() => {}));
    });
  }

  // ── Top Bar Live Update ───────────────────────────────────────
  async function updateTopBar() {
    const bridge = window.isec;
    if (!bridge) return;
    try {
      const [status, integrity] = await Promise.all([
        bridge.invoke('get-backend-status').catch(() => null),
        bridge.invoke('get-system-integrity').catch(() => null),
      ]);

      const compromised = (integrity && integrity.status === 'compromised') || (status && status.tamperingDetected);
      const dot   = document.getElementById('top-chain-dot');
      const label = document.getElementById('top-chain-label');
      const evLbl = document.getElementById('top-evidence-label');

      if (dot) {
        dot.style.background  = compromised ? 'var(--danger)' : 'var(--success)';
        dot.style.boxShadow   = compromised ? '0 0 6px var(--danger)' : '0 0 6px var(--success)';
        dot.style.animation   = compromised ? 'pulse-danger 1s ease-in-out infinite' : 'pulse-success 2s ease-in-out infinite';
      }
      if (label) label.textContent = compromised ? '⚠ Chain Broken' : 'Chain Intact';
      if (label) label.style.color = compromised ? 'var(--danger)' : '';

      const count = (status && typeof status.evidenceItemsCount === 'number') ? status.evidenceItemsCount : 0;
      if (evLbl) evLbl.textContent = count.toLocaleString() + ' Evidence Item' + (count !== 1 ? 's' : '');

      // Threat badge
      const badge = document.getElementById('threat-badge');
      if (badge) badge.style.display = (compromised || (status && status.tamperingDetected)) ? 'block' : 'none';
    } catch (_) {}
  }

  // ── Init ──────────────────────────────────────────────────────
  function initNavigation() {
    document.querySelectorAll('.nav-item[data-view]').forEach(item => {
      item.addEventListener('click', () => navigateTo(item.dataset.view));
    });
    bindWindowControls();
    updateTopBar();
    setInterval(updateTopBar, 30000);
  }

  window.navigateTo     = navigateTo;
  window.initNavigation = initNavigation;
  window.updateTopBar   = updateTopBar;
})();
