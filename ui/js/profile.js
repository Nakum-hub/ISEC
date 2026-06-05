// ISEC Profile Module — role display and profile panel population
// Profile panel init is now handled by bootstrap.js
// This file ensures legacy compatibility with role-manager.js

(function () {
  'use strict';

  // updateProfileDisplay is called by role-manager after role changes
  async function updateProfileDisplay() {
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
      const lic = (status && status.license) ? (status.license.valid ? (status.license.plan || 'Licensed') : 'Invalid') : '—';
      const evCount = (status && typeof status.evidenceItemsCount === 'number') ? status.evidenceItemsCount : 0;
      const ret = retention ? `${retention.retention_days || '—'}d | ${retention.active_evidence || 0} active` : '—';
      const intOk = !(integrity && integrity.status === 'compromised') && !(status && status.tamperingDetected);

      const set = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
      set('profile-role',           role.toUpperCase());
      set('profile-permissions',     perms);
      set('profile-license',         lic);
      set('profile-evidence-count',  evCount.toLocaleString());
      set('profile-retention',       ret);
      set('profile-integrity',       intOk ? '✓ VERIFIED' : '⚠ COMPROMISED');
      set('current-role-label',      role);

      const avatarEl = document.getElementById('user-avatar-icon');
      if (avatarEl) {
        const icons = { collector:'🔍', reviewer:'👁', exporter:'📤' };
        avatarEl.textContent = icons[role] || '👤';
      }

      // Sync role selector
      const roleSelect = document.getElementById('role-select');
      if (roleSelect && role !== 'unknown') roleSelect.value = role;

    } catch (err) {
      console.error('Profile update error:', err);
    }
  }

  window.updateProfileDisplay = updateProfileDisplay;
})();
