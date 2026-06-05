// ISEC Navigation — View routing, window controls, top-bar updates

(function () {
  'use strict';

  const VIEW_INIT_MAP = {
    dashboard:       () => typeof initializeDashboard === 'function' && initializeDashboard(),
    timeline:        () => typeof initTimeline        === 'function' && initTimeline(),
    'threat-analysis': () => typeof initThreatAnalysis === 'function' && initThreatAnalysis(),
    'audit-log':     () => typeof initAuditLog        === 'function' && initAuditLog(),
    report:          () => typeof initReportExport    === 'function' && initReportExport(),
  };

  const _initialised = new Set();

  // ── Public navigateTo ─────────────────────────────────────────
  function navigateTo(viewId) {
    // Hide all views
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

    // Show target
    const target = document.getElementById(viewId);
    if (target) target.classList.add('active');

    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.toggle('active', item.dataset.view === viewId);
    });

    // Lazy init each view once
    if (VIEW_INIT_MAP[viewId] && !_initialised.has(viewId)) {
      _initialised.add(viewId);
      VIEW_INIT_MAP[viewId]();
    } else if (viewId === 'dashboard') {
      // Always refresh dashboard on revisit
      typeof initializeDashboard === 'function' && initializeDashboard();
    }

    // Close detail panel when navigating away
    if (viewId !== 'detail') {
      const panel = document.getElementById('detail-panel');
      if (panel && !panel.classList.contains('hidden')) {
        panel.classList.add('hidden');
        panel.style.display = 'none';
      }
    }
  }

  // ── Bind Nav Items ────────────────────────────────────────────
  function bindNavItems() {
    document.querySelectorAll('.nav-item[data-view]').forEach(item => {
      item.addEventListener('click', () => navigateTo(item.dataset.view));
    });
  }

  // ── Window Controls ───────────────────────────────────────────
  function bindWindowControls() {
    const bridge = window.isec;
    if (!bridge) return;

    const minBtn = document.getElementById('minimize-window-btn');
    const maxBtn = document.getElementById('maximize-window-btn');
    const clsBtn = document.getElementById('close-window-btn');

    if (minBtn) minBtn.addEventListener('click', () => bridge.invoke('window-minimize').catch(() => {}));
    if (maxBtn) maxBtn.addEventListener('click', () => bridge.invoke('window-maximize').catch(() => {}));
    if (clsBtn) clsBtn.addEventListener('click', () => bridge.invoke('window-close').catch(() => {}));
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

      const dot   = document.getElementById('top-chain-dot');
      const label = document.getElementById('top-chain-label');
      const evLbl = document.getElementById('top-evidence-label');

      const compromised = (integrity && integrity.status === 'compromised') || (status && status.tamperingDetected);

      if (dot) {
        dot.style.background  = compromised ? 'var(--danger)' : 'var(--success)';
        dot.style.boxShadow   = compromised ? '0 0 6px var(--danger)' : '0 0 6px var(--success)';
        dot.style.animation   = compromised ? 'pulse-danger 1s ease-in-out infinite' : 'pulse-success 2s ease-in-out infinite';
      }
      if (label) label.textContent = compromised ? 'Chain Broken!' : 'Chain Intact';

      // Evidence count
      const count = (status && typeof status.evidenceItemsCount === 'number')
        ? status.evidenceItemsCount
        : 0;
      if (evLbl) evLbl.textContent = count.toLocaleString() + ' Evidence Item' + (count !== 1 ? 's' : '');

      // Threat badge
      const badge = document.getElementById('threat-badge');
      if (badge) {
        if (compromised || (status && status.tamperingDetected)) {
          badge.style.display = 'block';
        } else {
          badge.style.display = 'none';
        }
      }
    } catch (_) {}
  }

  // ── Init ─────────────────────────────────────────────────────
  function initNavigation() {
    bindNavItems();
    bindWindowControls();
    updateTopBar();
    setInterval(updateTopBar, 30000);
  }

  window.navigateTo   = navigateTo;
  window.initNavigation = initNavigation;
  window.updateTopBar = updateTopBar;
})();
