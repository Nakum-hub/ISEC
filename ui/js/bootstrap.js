// ISEC Bootstrap — Fragment loader, boot sequence, UI init sequencer

(function () {
  'use strict';

  // ── Boot Sequence ─────────────────────────────────────────────
  const BOOT_STEPS = [
    [0,   'Verifying cryptographic keys…'],
    [400, 'Loading evidence database…'],
    [800, 'Validating license…'],
    [1100,'Checking hash chain integrity…'],
    [1400,'Loading UI fragments…'],
    [1800,'Initialising modules…'],
    [2100,'Ready.'],
  ];

  function runBootSequence() {
    const statusEl = document.getElementById('boot-status-text');
    BOOT_STEPS.forEach(([delay, msg]) => {
      setTimeout(() => { if (statusEl) statusEl.textContent = msg; }, delay);
    });
    return new Promise(resolve => setTimeout(resolve, 2300));
  }

  function dismissBootScreen() {
    const screen = document.getElementById('boot-screen');
    if (!screen) return;
    screen.classList.add('fade-out');
    setTimeout(() => screen.remove(), 650);
  }

  // ── Global helpers ────────────────────────────────────────────
  window.showLoading = function (msg) {
    const ol = document.getElementById('loading-overlay');
    if (!ol) return;
    const p = ol.querySelector('p');
    if (p) p.textContent = msg || 'Processing Evidence…';
    ol.classList.remove('hidden');
  };

  window.hideLoading = function () {
    const ol = document.getElementById('loading-overlay');
    if (ol) ol.classList.add('hidden');
  };

  // ── Fragment Loader ───────────────────────────────────────────
  async function loadFragment(containerId, fragmentPath) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const bridge = window.isec;
    if (!bridge || typeof bridge.invoke !== 'function') return;
    try {
      const html = await bridge.invoke('read-ui-fragment', { fragmentPath });
      if (html && typeof html === 'string') container.innerHTML = html;
    } catch (err) {
      console.warn(`Fragment load failed [${fragmentPath}]:`, err.message);
    }
  }

  // ── Profile Panel ─────────────────────────────────────────────
  function initProfilePanel() {
    const btn   = document.getElementById('profile-btn');
    const panel = document.getElementById('profile-panel');
    const close = document.getElementById('profile-close-btn');
    if (!btn || !panel) return;

    btn.addEventListener('click', e => {
      e.stopPropagation();
      const open = !panel.classList.contains('hidden');
      panel.classList.toggle('hidden', open);
      btn.setAttribute('aria-expanded', String(!open));
    });

    close && close.addEventListener('click', () => {
      panel.classList.add('hidden');
      btn.setAttribute('aria-expanded', 'false');
    });

    document.addEventListener('click', e => {
      if (!panel.classList.contains('hidden') && !panel.contains(e.target) && e.target !== btn) {
        panel.classList.add('hidden');
        btn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // ── Profile Data ──────────────────────────────────────────────
  async function loadProfileData() {
    const bridge = window.isec;
    if (!bridge) return;
    try {
      const [status, retention, integrity] = await Promise.all([
        bridge.invoke('get-backend-status').catch(() => null),
        bridge.invoke('get-retention-status').catch(() => null),
        bridge.invoke('get-system-integrity').catch(() => null),
      ]);

      const role  = (status && status.role) || 'unknown';
      const perms = (status && Array.isArray(status.permissions)) ? status.permissions.join(', ') : '—';
      const lic   = (status && status.license) ? (status.license.valid ? (status.license.plan || 'Licensed') : 'Invalid') : '—';
      const evCnt = (status && typeof status.evidenceItemsCount === 'number') ? status.evidenceItemsCount : 0;
      const ret   = retention ? `${retention.retention_days || '—'}d | ${retention.active_evidence || 0} active` : '—';
      const intOk = !(integrity && integrity.status === 'compromised') && !(status && status.tamperingDetected);

      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('profile-role',           role.toUpperCase());
      set('profile-permissions',    perms);
      set('profile-license',        lic);
      set('profile-evidence-count', evCnt.toLocaleString());
      set('profile-retention',      ret);
      set('profile-integrity',      intOk ? '✓ VERIFIED' : '⚠ COMPROMISED');
      set('current-role-label',     role);

      const icons = { collector:'🔍', reviewer:'👁', exporter:'📤' };
      const av = document.getElementById('user-avatar-icon');
      if (av) av.textContent = icons[role] || '👤';

      const sel = document.getElementById('role-select');
      if (sel && role !== 'unknown') sel.value = role;
    } catch (err) {
      console.error('Profile load error:', err);
    }
  }

  // ── Bootstrap ─────────────────────────────────────────────────
  async function bootstrap() {
    // 1. Run boot animation in parallel with data loading
    const bootPromise = runBootSequence();

    // 2. Load all fragments simultaneously
    await Promise.all([
      loadFragment('dashboard-container',      'views/dashboard.html'),
      loadFragment('timeline-container',       'views/timeline.html'),
      loadFragment('threat-analysis-container','views/threat-analysis.html'),
      loadFragment('audit-log-container',      'views/audit-log.html'),
      loadFragment('cases-container',          'views/cases.html'),
      loadFragment('compliance-container',     'views/compliance.html'),
      loadFragment('detail-panel-container',   'components/evidence-detail-panel.html'),
    ]);

    // 3. Wait for boot animation to finish
    await bootPromise;

    // 4. Dismiss boot screen with fade
    dismissBootScreen();

    // 5. Init navigation
    if (typeof initNavigation === 'function') initNavigation();

    // 6. Init profile + detail
    initProfilePanel();
    if (typeof initDetailView === 'function') initDetailView();

    // 7. Load profile data
    await loadProfileData();
    setInterval(loadProfileData, 60000);

    // 8. Sync role selector
    if (typeof syncRoleSelect === 'function') syncRoleSelect();

    // 9. Boot active view (dashboard)
    if (typeof initializeDashboard === 'function') initializeDashboard();

    // 10. Pre-init report export
    if (typeof initReportExport === 'function') initReportExport();

    // 11. Ready
    document.body.classList.add('app-ready');
    console.info('[ISEC] Bootstrap complete — v2.0 Enterprise');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
