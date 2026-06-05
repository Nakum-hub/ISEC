// ISEC Bootstrap — Fragment loader, UI init sequencer, global helpers

(function () {
  'use strict';

  // ── Global helpers (used by multiple modules) ─────────────────
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
    if (!bridge || typeof bridge.invoke !== 'function') {
      container.innerHTML = `<div class="empty-state"><span>IPC bridge unavailable — running in standalone mode.</span></div>`;
      return;
    }

    try {
      const html = await bridge.invoke('read-ui-fragment', { fragmentPath });
      if (html && typeof html === 'string') {
        container.innerHTML = html;
      } else {
        container.innerHTML = `<div class="empty-state"><span>Fragment not found: ${fragmentPath}</span></div>`;
      }
    } catch (err) {
      console.error(`Fragment load error [${fragmentPath}]:`, err);
      // Fallback: try finding the view already in DOM (for dev/standalone)
      const id = fragmentPath.replace('views/', '').replace('.html', '').replace('components/', '');
      const existing = document.getElementById(id);
      if (!existing) {
        container.innerHTML = `<div class="empty-state"><span>Failed to load: ${fragmentPath}</span></div>`;
      }
    }
  }

  // ── Profile Panel ─────────────────────────────────────────────
  function initProfilePanel() {
    const btn      = document.getElementById('profile-btn');
    const panel    = document.getElementById('profile-panel');
    const closeBtn = document.getElementById('profile-close-btn');

    if (!btn || !panel) return;

    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const open = !panel.classList.contains('hidden');
      panel.classList.toggle('hidden', open);
      btn.setAttribute('aria-expanded', String(!open));
    });

    if (closeBtn) closeBtn.addEventListener('click', () => {
      panel.classList.add('hidden');
      btn.setAttribute('aria-expanded', 'false');
    });

    document.addEventListener('click', (e) => {
      if (!panel.classList.contains('hidden') && !panel.contains(e.target) && e.target !== btn) {
        panel.classList.add('hidden');
        btn.setAttribute('aria-expanded', 'false');
      }
    });
  }

  // ── Profile Data Loader ───────────────────────────────────────
  async function loadProfileData() {
    const bridge = window.isec;
    if (!bridge) return;
    try {
      const [status, retention, integrity] = await Promise.all([
        bridge.invoke('get-backend-status').catch(() => null),
        bridge.invoke('get-retention-status').catch(() => null),
        bridge.invoke('get-system-integrity').catch(() => null),
      ]);

      const role = (status && status.role) || 'unknown';
      const perms = (status && Array.isArray(status.permissions)) ? status.permissions.join(', ') : '—';
      const lic = (status && status.license) ? (status.license.valid ? `${status.license.plan || 'Licensed'}` : 'Invalid') : '—';
      const evCount = (status && typeof status.evidenceItemsCount === 'number') ? status.evidenceItemsCount : 0;
      const ret = retention ? `${retention.retention_days || '—'}d | ${retention.active_evidence || 0} active` : '—';
      const intLabel = (integrity && integrity.status === 'compromised') || (status && status.tamperingDetected) ? '⚠ COMPROMISED' : '✓ VERIFIED';

      setText('profile-role',           role.toUpperCase());
      setText('profile-permissions',     perms);
      setText('profile-license',         lic);
      setText('profile-evidence-count',  evCount.toLocaleString());
      setText('profile-retention',       ret);
      setText('profile-integrity',       intLabel);
      setText('current-role-label',      role);

      // Avatar role icon
      const avatarEl = document.getElementById('user-avatar-icon');
      if (avatarEl) {
        const icons = { collector:'🔍', reviewer:'👁', exporter:'📤' };
        avatarEl.textContent = icons[role] || '👤';
      }
    } catch (err) {
      console.error('Profile load error:', err);
    }
  }

  function setText(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
  }

  // ── Main Bootstrap Sequence ───────────────────────────────────
  async function bootstrap() {
    // 1. Load HTML fragments
    await Promise.all([
      loadFragment('dashboard-container',     'views/dashboard.html'),
      loadFragment('timeline-container',      'views/timeline.html'),
      loadFragment('threat-analysis-container','views/threat-analysis.html'),
      loadFragment('audit-log-container',     'views/audit-log.html'),
      loadFragment('detail-panel-container',  'components/evidence-detail-panel.html'),
    ]);

    // 2. Boot navigation
    if (typeof initNavigation === 'function') initNavigation();

    // 3. Boot profile
    initProfilePanel();
    await loadProfileData();
    setInterval(loadProfileData, 60000);

    // 4. Boot detail view
    if (typeof initDetailView === 'function') initDetailView();

    // 5. Boot dashboard (active view on load)
    if (typeof initializeDashboard === 'function') initializeDashboard();

    // 6. Boot report export (pre-init so preview works immediately)
    if (typeof initReportExport === 'function') initReportExport();

    // 7. Sync role selector to current backend role
    if (typeof syncRoleSelect === 'function') syncRoleSelect();

    // 8. Mark app ready
    document.body.classList.add('app-ready');
    console.info('[ISEC] Bootstrap complete');
  }

  // Run after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
