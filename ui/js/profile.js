// Profile panel behavior
function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

let profilePanelOpen = false;

function setProfilePanelOpen(open) {
  const panel = document.getElementById('profile-panel');
  const btn = document.getElementById('profile-btn');
  if (!panel || !btn) {
    return;
  }

  profilePanelOpen = open;
  if (open) {
    panel.classList.remove('hidden');
    panel.classList.add('open');
    btn.setAttribute('aria-expanded', 'true');
    refreshProfilePanel().catch(() => {});
  } else {
    panel.classList.add('hidden');
    panel.classList.remove('open');
    btn.setAttribute('aria-expanded', 'false');
  }
}

function handleProfileOutsideClick(event) {
  if (!profilePanelOpen) {
    return;
  }
  const panel = document.getElementById('profile-panel');
  const btn = document.getElementById('profile-btn');
  if (!panel || !btn) {
    return;
  }
  if (panel.contains(event.target) || btn.contains(event.target)) {
    return;
  }
  setProfilePanelOpen(false);
}

async function refreshProfilePanel() {
  const bridge = getIsecBridge();
  if (!bridge) {
    return;
  }

  const status = await bridge.invoke('get-backend-status');

  const roleEl = document.getElementById('profile-role');
  const permsEl = document.getElementById('profile-permissions');
  const licenseEl = document.getElementById('profile-license');
  const evidenceEl = document.getElementById('profile-evidence-count');
  const retentionEl = document.getElementById('profile-retention');
  const integrityEl = document.getElementById('profile-integrity');

  if (roleEl) {
    const roleName = status && status.roleName ? status.roleName : (status && status.role ? status.role : 'unknown');
    roleEl.textContent = roleName;
  }

  if (permsEl) {
    const perms = status && Array.isArray(status.permissions) ? status.permissions : [];
    permsEl.textContent = perms.length ? perms.join(', ') : 'none';
  }

  if (licenseEl) {
    if (!status || !status.license) {
      licenseEl.textContent = 'unknown';
    } else if (status.license.valid) {
      const plan = status.license.plan ? ` (${status.license.plan})` : '';
      licenseEl.textContent = `licensed${plan}`;
    } else {
      licenseEl.textContent = 'unlicensed';
    }
  }

  if (evidenceEl) {
    const count = status && typeof status.evidenceItemsCount === 'number' ? status.evidenceItemsCount : 0;
    evidenceEl.textContent = String(count);
  }

  if (retentionEl) {
    const retention = status && status.retention ? status.retention : null;
    if (retention && retention.policy) {
      const days = retention.retention_days != null ? `${retention.retention_days} days` : 'permanent';
      retentionEl.textContent = `${retention.policy} (${days})`;
    } else {
      retentionEl.textContent = 'unknown';
    }
  }

  if (integrityEl) {
    const compromised = status && (status.tamperingDetected || status.hashChainValid === false);
    integrityEl.textContent = compromised ? 'compromised' : 'valid';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const btn = document.getElementById('profile-btn');
  const closeBtn = document.getElementById('profile-close-btn');

  if (btn) {
    btn.addEventListener('click', () => {
      setProfilePanelOpen(!profilePanelOpen);
    });
  }

  if (closeBtn) {
    closeBtn.addEventListener('click', () => setProfilePanelOpen(false));
  }

  document.addEventListener('click', handleProfileOutsideClick);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && profilePanelOpen) {
      setProfilePanelOpen(false);
    }
  });
});
