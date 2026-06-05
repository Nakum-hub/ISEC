// ISEC Role Manager — Switch roles with validation and permission refresh

(function () {
  'use strict';

  async function switchRole() {
    const bridge = window.isec;
    if (!bridge) { ISECNotify && ISECNotify.error('IPC bridge not available.'); return; }

    const select = document.getElementById('role-select');
    if (!select) return;
    const newRole = select.value;
    if (!newRole) return;

    const btn = document.getElementById('switch-role-btn');
    if (btn) { btn.disabled = true; btn.textContent = '…'; }

    try {
      const result = await bridge.invoke('set-user-role', { role: newRole });
      if (result && result.success) {
        ISECNotify && ISECNotify.success(`Role switched to ${newRole.toUpperCase()}`);
        // Refresh profile + dashboard
        await Promise.all([
          typeof updateProfileDisplay === 'function' && updateProfileDisplay(),
          typeof loadDashboardStats   === 'function' && loadDashboardStats(),
          typeof updateTopBar         === 'function' && updateTopBar(),
        ]);
      } else {
        ISECNotify && ISECNotify.error((result && result.message) || 'Role switch failed.');
        // Revert select to actual role
        const statusR = await bridge.invoke('get-backend-status').catch(() => null);
        if (statusR && statusR.role && select) select.value = statusR.role;
      }
    } catch (err) {
      ISECNotify && ISECNotify.error('Role switch error: ' + err.message);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '⟳'; }
    }
  }

  function initRoleManager() {
    const switchBtn = document.getElementById('switch-role-btn');
    if (switchBtn) switchBtn.addEventListener('click', switchRole);

    const roleSelect = document.getElementById('role-select');
    if (roleSelect) roleSelect.addEventListener('change', () => {});  // change applies on button click
  }

  // Wait for DOM
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initRoleManager);
  } else {
    initRoleManager();
  }

  window.switchRole = switchRole;
})();
