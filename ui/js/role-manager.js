// ISEC Role Manager — Switch roles with admin-token-backed validation

(function () {
  'use strict';

  const ROLE_LABELS = {
    collector: { emoji: '🔍', label: 'Collector',  desc: 'Collect & view evidence' },
    reviewer:  { emoji: '👁',  label: 'Reviewer',   desc: 'View evidence only' },
    exporter:  { emoji: '📤', label: 'Exporter',   desc: 'Export & report evidence' },
  };

  // ── Core Switch ───────────────────────────────────────────────
  async function switchRole() {
    const bridge = window.isec;
    if (!bridge) { notify('error', 'IPC bridge not available.'); return; }

    const select = document.getElementById('role-select');
    if (!select) return;
    const newRole = select.value.trim();
    if (!newRole) return;

    const btn = document.getElementById('switch-role-btn');
    if (btn) { btn.disabled = true; btn.textContent = '…'; }

    try {
      // 1. Check auth is configured before attempting switch
      const currentStatus = await bridge.invoke('get-backend-status').catch(() => null);
      if (currentStatus && currentStatus.tamperingDetected) {
        notify('error', 'Role change blocked: tampering detected.');
        revertSelect(currentStatus.role);
        return;
      }

      // 2. If currently the same role, skip
      if (currentStatus && currentStatus.role === newRole) {
        notify('info', `Already in ${newRole.toUpperCase()} role.`);
        return;
      }

      // 3. Attempt the role switch (Electron auto-injects admin token from disk)
      notify('loading-role', `Switching to ${ROLE_LABELS[newRole]?.label || newRole}…`);
      const result = await bridge.invoke('set-user-role', { role: newRole });

      if (result && result.success) {
        notify('success', `Role → ${ROLE_LABELS[newRole]?.emoji || ''} ${(ROLE_LABELS[newRole]?.label || newRole).toUpperCase()}`);
        applyRoleUI(newRole, result);
      } else {
        const msg = result && result.message ? result.message : 'Role switch failed.';
        handleRoleError(msg, newRole, currentStatus);
      }

    } catch (err) {
      console.error('Role switch error:', err);
      notify('error', 'Role switch error: ' + err.message);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = '⟳'; }
    }
  }

  // ── Apply successful role change across the whole UI ──────────
  function applyRoleUI(newRole, result) {
    // Update sidebar avatar + role label
    const meta = ROLE_LABELS[newRole] || {};
    const avatarEl = document.getElementById('user-avatar-icon');
    if (avatarEl) avatarEl.textContent = meta.emoji || '👤';

    const roleLabel = document.getElementById('current-role-label');
    if (roleLabel) roleLabel.textContent = newRole;

    // Keep select in sync
    const select = document.getElementById('role-select');
    if (select) select.value = newRole;

    // Refresh dashboard, profile, top bar, and permissions
    const promises = [
      typeof updateProfileDisplay === 'function' && updateProfileDisplay(),
      typeof loadDashboardStats   === 'function' && loadDashboardStats(),
      typeof updateTopBar         === 'function' && updateTopBar(),
    ].filter(Boolean);
    Promise.all(promises).catch(e => console.warn('UI refresh after role change:', e));

    // Update profile panel rows immediately from result.status if available
    if (result && result.status) {
      updateProfileRows(result.status);
    }
  }

  // ── Handle errors with helpful messages ───────────────────────
  function handleRoleError(msg, attemptedRole, currentStatus) {
    const currentRole = currentStatus && currentStatus.role;
    revertSelect(currentRole);

    if (msg.includes('token not configured') || msg.includes('admin token not configured')) {
      showTokenSetupDialog();
    } else if (msg.includes('invalid') || msg.includes('blocked')) {
      notify('error', msg);
    } else if (msg.includes('locked')) {
      notify('error', '🔒 Role change locked — too many failed attempts. Restart ISEC.');
    } else {
      notify('error', msg || 'Role switch failed.');
    }
  }

  // ── Token Setup Dialog (shown when admin token not configured) ─
  function showTokenSetupDialog() {
    const existing = document.getElementById('token-setup-modal');
    if (existing) existing.remove();

    const modal = document.createElement('div');
    modal.id = 'token-setup-modal';
    modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.7);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;z-index:8000;';
    modal.innerHTML = `
      <div style="background:#0a1422;border:1px solid rgba(0,200,255,0.3);border-radius:14px;padding:24px;min-width:380px;max-width:460px;box-shadow:0 20px 60px rgba(0,0,0,0.6),0 0 30px rgba(0,200,255,0.08);">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:18px;">
          <div style="font-family:var(--font-mono,monospace);font-size:0.8rem;font-weight:700;text-transform:uppercase;letter-spacing:0.1em;color:#00c8ff;">Admin Token Required</div>
          <button id="close-token-modal" style="background:none;border:none;color:rgba(255,255,255,0.4);font-size:20px;cursor:pointer;line-height:1;">×</button>
        </div>
        <p style="font-size:0.8rem;color:#8da0bf;margin-bottom:16px;line-height:1.6;">
          Role switching requires an admin token. This is set by your IT administrator during ISEC installation. Paste the token below to configure it for this session.
        </p>
        <div style="margin-bottom:14px;">
          <label style="display:block;font-family:monospace;font-size:0.62rem;text-transform:uppercase;letter-spacing:0.1em;color:#4d6080;margin-bottom:6px;">Admin Token</label>
          <input id="admin-token-input" type="password"
            placeholder="Paste admin token here…"
            style="width:100%;background:rgba(255,255,255,0.03);border:1px solid rgba(0,200,255,0.2);border-radius:7px;color:#e8f0ff;font-family:monospace;font-size:0.82rem;padding:9px 12px;box-sizing:border-box;"
            autocomplete="off" spellcheck="false">
          <div id="token-error" style="display:none;font-size:0.7rem;color:#ff1744;margin-top:5px;"></div>
        </div>
        <div style="display:flex;gap:10px;justify-content:flex-end;">
          <button id="cancel-token-btn" style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:7px;color:#8da0bf;padding:8px 18px;cursor:pointer;font-family:inherit;font-size:0.78rem;">Cancel</button>
          <button id="apply-token-btn" style="background:linear-gradient(135deg,#0071c7,#004a8f);border:1px solid rgba(0,200,255,0.3);border-radius:7px;color:#fff;padding:8px 18px;cursor:pointer;font-family:inherit;font-size:0.78rem;font-weight:600;">Apply & Retry</button>
        </div>
      </div>
    `;

    const close = () => { modal.style.opacity = '0'; setTimeout(() => modal.remove(), 200); };
    modal.querySelector('#close-token-modal').addEventListener('click', close);
    modal.querySelector('#cancel-token-btn').addEventListener('click', close);
    modal.addEventListener('click', e => { if (e.target === modal) close(); });

    modal.querySelector('#apply-token-btn').addEventListener('click', async () => {
      const tokenInput = modal.querySelector('#admin-token-input');
      const errEl      = modal.querySelector('#token-error');
      const token = tokenInput ? tokenInput.value.trim() : '';

      if (!token) {
        errEl.textContent = 'Token cannot be empty.';
        errEl.style.display = 'block';
        return;
      }

      const applyBtn = modal.querySelector('#apply-token-btn');
      applyBtn.disabled = true;
      applyBtn.textContent = 'Verifying…';
      errEl.style.display = 'none';

      const bridge = window.isec;
      const select = document.getElementById('role-select');
      const newRole = select ? select.value : '';

      try {
        // Re-attempt role switch with explicit token
        const result = await bridge.invoke('set-user-role', { role: newRole, authToken: token });
        if (result && result.success) {
          close();
          notify('success', `Role → ${ROLE_LABELS[newRole]?.emoji || ''} ${(ROLE_LABELS[newRole]?.label || newRole).toUpperCase()}`);
          applyRoleUI(newRole, result);
        } else {
          errEl.textContent = (result && result.message) || 'Token rejected.';
          errEl.style.display = 'block';
          applyBtn.disabled = false;
          applyBtn.textContent = 'Apply & Retry';
        }
      } catch (err) {
        errEl.textContent = 'Error: ' + err.message;
        errEl.style.display = 'block';
        applyBtn.disabled = false;
        applyBtn.textContent = 'Apply & Retry';
      }
    });

    // Enter key submits
    modal.querySelector('#admin-token-input').addEventListener('keydown', e => {
      if (e.key === 'Enter') modal.querySelector('#apply-token-btn').click();
    });

    document.body.appendChild(modal);
    requestAnimationFrame(() => {
      modal.style.transition = 'opacity 0.2s';
      modal.style.opacity = '0';
      requestAnimationFrame(() => { modal.style.opacity = '1'; });
    });
    setTimeout(() => modal.querySelector('#admin-token-input').focus(), 100);
  }

  // ── Profile Row Updater ───────────────────────────────────────
  function updateProfileRows(status) {
    const safe = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val || '—'; };
    if (!status) return;
    const role = status.role || 'unknown';
    const perms = Array.isArray(status.permissions) ? status.permissions.join(', ') : '—';
    safe('profile-role', role.toUpperCase());
    safe('profile-permissions', perms);
    safe('current-role-label', role);
    const sel = document.getElementById('role-select');
    if (sel && role !== 'unknown') sel.value = role;
  }

  // ── Sync select to current role on page load ──────────────────
  async function syncRoleSelect() {
    const bridge = window.isec;
    if (!bridge) return;
    try {
      const status = await bridge.invoke('get-backend-status').catch(() => null);
      if (!status) return;
      const role = status.role;
      const select = document.getElementById('role-select');
      if (select && role && role !== 'unknown') select.value = role;

      const avatarEl = document.getElementById('user-avatar-icon');
      const meta = ROLE_LABELS[role] || {};
      if (avatarEl) avatarEl.textContent = meta.emoji || '👤';

      const roleLabel = document.getElementById('current-role-label');
      if (roleLabel) roleLabel.textContent = role || '—';
    } catch (e) {
      console.warn('syncRoleSelect error:', e);
    }
  }

  // ── Helpers ───────────────────────────────────────────────────
  function revertSelect(role) {
    const select = document.getElementById('role-select');
    if (select && role && role !== 'unknown') select.value = role;
  }

  let _loadingToast = null;
  function notify(type, msg) {
    if (!window.ISECNotify) return;
    if (type === 'loading-role') {
      _loadingToast = ISECNotify.loading(msg);
      return;
    }
    if (_loadingToast) { _loadingToast.dismiss(); _loadingToast = null; }
    if (type === 'success') ISECNotify.success(msg);
    else if (type === 'error') ISECNotify.error(msg);
    else ISECNotify.info(msg);
  }

  // ── Init ──────────────────────────────────────────────────────
  function initRoleManager() {
    const switchBtn = document.getElementById('switch-role-btn');
    if (switchBtn) switchBtn.addEventListener('click', switchRole);

    // Allow pressing Enter in the select to switch role
    const select = document.getElementById('role-select');
    if (select) select.addEventListener('keydown', e => { if (e.key === 'Enter') switchRole(); });

    // Sync dropdown to current backend role
    syncRoleSelect();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initRoleManager);
  } else {
    initRoleManager();
  }

  window.switchRole    = switchRole;
  window.syncRoleSelect = syncRoleSelect;
})();
