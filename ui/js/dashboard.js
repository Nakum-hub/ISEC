// Dashboard functionality (IPC provided via window.isec IPC bridge)

function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

let dashboardRefreshTimer = null;

async function initializeDashboard() {
  // Add event listeners
  const collectBtn = document.getElementById('collect-btn');
  if (collectBtn) {
    collectBtn.addEventListener('click', () => startEvidenceCollection());
  }

  // Add quick action buttons
  document.querySelectorAll('.action-btn[data-action]').forEach(btn => {
    btn.addEventListener('click', function () {
      const action = this.getAttribute('data-action');
      performQuickAction(action);
    });
  });

  const checkUpdatesBtn = document.getElementById('check-updates-btn');
  if (checkUpdatesBtn) {
    checkUpdatesBtn.addEventListener('click', checkForUpdates);
  }

  const applyUpdateBtn = document.getElementById('apply-update-btn');
  if (applyUpdateBtn) {
    applyUpdateBtn.addEventListener('click', applyUpdate);
  }

  if (!dashboardRefreshTimer) {
    dashboardRefreshTimer = setInterval(() => {
      loadDashboardStats();
    }, 15000);
  }

  checkForUpdates();
}

function openBrowserConsentModal() {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h3>Browser History Consent</h3>
          <button class="close" type="button" aria-label="Close">×</button>
        </div>
        <div class="modal-body">
          <p>Browser history collection requires explicit consent.</p>
          <div class="modal-field">
            <label for="consent-time-range">Time range</label>
            <select id="consent-time-range">
              <option value="last_24h">Last 24 hours</option>
              <option value="last_7d" selected>Last 7 days</option>
              <option value="last_30d">Last 30 days</option>
              <option value="all_time">All time</option>
            </select>
          </div>
          <div class="modal-field">
            <label for="consent-browsers">Browsers (optional)</label>
            <input id="consent-browsers" type="text" placeholder="Chrome, Firefox" />
            <small class="modal-note">Leave blank to include all detected browsers.</small>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" type="button" data-action="cancel">Skip</button>
          <button class="btn btn-primary" type="button" data-action="confirm">Grant Consent</button>
        </div>
      </div>
    `;

    const closeModal = (result) => {
      modal.classList.remove('show');
      setTimeout(() => modal.remove(), 150);
      resolve(result);
    };

    modal.addEventListener('click', (event) => {
      if (event.target === modal) {
        closeModal(null);
      }
    });

    const closeBtn = modal.querySelector('.close');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => closeModal(null));
    }

    const cancelBtn = modal.querySelector('[data-action="cancel"]');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => closeModal(null));
    }

    const confirmBtn = modal.querySelector('[data-action="confirm"]');
    if (confirmBtn) {
      confirmBtn.addEventListener('click', () => {
        const timeRangeEl = modal.querySelector('#consent-time-range');
        const browsersEl = modal.querySelector('#consent-browsers');
        const timeRange = timeRangeEl ? timeRangeEl.value : '';
        const browsersRaw = browsersEl ? String(browsersEl.value || '') : '';
        const browsers = browsersRaw
          .split(',')
          .map((b) => b.trim())
          .filter(Boolean);

        if (!timeRange) {
          alert('Please select a time range.');
          return;
        }
        closeModal({ timeRange, browsers });
      });
    }

    document.body.appendChild(modal);
    requestAnimationFrame(() => {
      modal.classList.add('show');
    });
  });
}

async function loadDashboardStats() {
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      return;
    }

    const status = await bridge.invoke('get-backend-status');
    const retention = await bridge.invoke('get-retention-status');
    const integrity = await bridge.invoke('get-system-integrity');

    const totalEvidence = status && typeof status.evidenceItemsCount === 'number'
      ? status.evidenceItemsCount
      : (retention && typeof retention.total_evidence === 'number' ? retention.total_evidence : 0);

    // Safety check for elements before updating
    const totalEl = document.getElementById('total-evidence');
    if (totalEl) totalEl.textContent = String(totalEvidence);

    const integrityEl = document.getElementById('integrity-status');
    if (integrityEl) integrityEl.textContent = integrity && integrity.status ? integrity.status : 'unknown';

    const lastCollectEl = document.getElementById('last-collect');
    if (lastCollectEl && lastCollectEl.textContent === 'Never' && totalEvidence > 0) {
      lastCollectEl.textContent = 'Recently';
    }

    const reportEl = document.getElementById('reports-count');
    if (reportEl) reportEl.textContent = 'N/A'; // Placeholder

    const license = status && status.license ? status.license : null;
    updateLicenseUI(license);
    updatePermissionUI(status);
  } catch (error) {
    console.error('Error loading dashboard stats:', error);
  }
}

function updateLicenseUI(license) {
  const licenseStatusEl = document.getElementById('license-status');
  const licensePlanEl = document.getElementById('license-plan');

  if (!licenseStatusEl || !licensePlanEl) {
    return;
  }

  if (!license) {
    licenseStatusEl.textContent = 'Unknown';
    licensePlanEl.textContent = 'License Status';
    return;
  }

  licenseStatusEl.textContent = license.valid ? 'Licensed' : 'Unlicensed';
  licensePlanEl.textContent = license.plan ? `Plan: ${license.plan}` : (license.message || 'License Status');

}

function updatePermissionUI(status) {
  const collectBtn = document.getElementById('collect-btn');
  const actionBtns = document.querySelectorAll('.action-btn');

  if (!status) return;

  const permissions = Array.isArray(status.permissions) ? status.permissions : [];
  const canCollect = permissions.includes('collect');
  const tampered = !!status.tamperingDetected;
  const licenseValid = status.license ? !!status.license.valid : true;

  const disabledState = !canCollect || tampered || !licenseValid;
  let titleText = '';

  if (!licenseValid) {
    titleText = (status.license && status.license.message) ? status.license.message : 'Valid license required';
  } else if (tampered) {
    titleText = 'Evidence collection locked due to tampering detection.';
  } else if (!canCollect) {
    titleText = 'Collector role required to collect evidence.';
  }

  if (collectBtn) {
    collectBtn.disabled = disabledState;
    if (titleText) collectBtn.title = titleText;
  }

  actionBtns.forEach(btn => {
    btn.disabled = disabledState;
    if (titleText) btn.title = titleText;

    // Visual feedback for disabled state
    if (disabledState) {
      btn.style.opacity = '0.5';
      btn.style.cursor = 'not-allowed';
    } else {
      btn.style.opacity = '1';
      btn.style.cursor = 'pointer';
    }
  });
}

// Role logic moved to role-manager.js

async function checkForUpdates() {
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      return;
    }
    const status = await bridge.invoke('check-for-updates');
    const updateStatus = document.getElementById('update-status');
    const applyBtn = document.getElementById('apply-update-btn');

    if (!updateStatus || !applyBtn) {
      return;
    }

    if (status && status.available) {
      updateStatus.textContent = `Update available: v${status.availableVersion} (current v${status.currentVersion})`;
      applyBtn.disabled = false;
    } else {
      const reason = status && status.reason ? status.reason.replace(/_/g, ' ') : 'no update available';
      updateStatus.textContent = `No update available (${reason}).`;
      applyBtn.disabled = true;
    }
  } catch (error) {
    console.error('Update check failed:', error);
  }
}

async function applyUpdate() {
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      return;
    }
    const result = await bridge.invoke('apply-update');
    alert(result && result.message ? result.message : 'Update could not be started.');
  } catch (error) {
    console.error('Apply update failed:', error);
    alert('Apply update failed: ' + error.message);
  }
}

async function startEvidenceCollection(options = {}) {
  const bridge = getIsecBridge();
  if (!bridge) {
    console.error('Dashboard: Cannot start evidence collection, IPC not available');
    alert('Evidence collection is not available in this environment.');
    return;
  }

  const collectTypes = Array.isArray(options.types) && options.types.length > 0 ? options.types : null;

  try {
    const backendStatus = await bridge.invoke('get-backend-status');
    if (backendStatus && backendStatus.license && !backendStatus.license.valid) {
      alert(backendStatus.license.message || 'Valid license required to collect evidence.');
      return;
    }
    const consent = backendStatus && backendStatus.browserConsent ? backendStatus.browserConsent : null;
    const needsBrowserConsent = !collectTypes || collectTypes.includes('browser_history');
    if (needsBrowserConsent && consent && (consent.status === 'PENDING' || consent.status === 'EXPIRED')) {
      const consentInput = await openBrowserConsentModal();
      if (consentInput && consentInput.timeRange) {
        const consentResult = await bridge.invoke('set-browser-consent', {
          timeRange: consentInput.timeRange,
          browsers: consentInput.browsers || []
        });
        if (!consentResult || !consentResult.success) {
          alert((consentResult && consentResult.message) ? consentResult.message : 'Failed to update browser consent.');
        }
      }
    }

    showLoading();
    const result = await bridge.invoke('start-evidence-collection', { types: collectTypes || [] });

    if (result.success) {
      // Update dashboard stats
      document.getElementById('total-evidence').textContent = result.evidenceCount;
      document.getElementById('integrity-status').textContent = result.integrityStatus;
      document.getElementById('last-collect').textContent = new Date().toLocaleTimeString();
      const reportsEl = document.getElementById('reports-count');
      if (reportsEl) {
        const current = parseInt(reportsEl.textContent, 10);
        if (!Number.isNaN(current)) {
          reportsEl.textContent = String(current + 1);
        }
      }

      alert('Evidence collection completed successfully!');
    } else {
      // Show a clear message when collection is denied or blocked
      alert(result.message || 'Evidence collection could not be started.');
    }
  } catch (error) {
    console.error('Error during evidence collection:', error);
    alert('Error during evidence collection: ' + error.message);
  } finally {
    hideLoading();
  }
}

function performQuickAction(action) {
  const labels = {
    'system-logs': 'System Logs',
    'browser-history': 'Browser History',
    'network-connections': 'Network Connections',
    'file-metadata': 'File Metadata'
  };
  const label = labels[action] || 'Evidence';
  const typeMap = {
    'system-logs': 'system_logs',
    'browser-history': 'browser_history',
    'network-connections': 'network_connections',
    'file-metadata': 'file_metadata'
  };
  const type = typeMap[action];

  if (confirm(`Start secure evidence collection for ${label}?`)) {
    const types = type ? [type] : [];
    startEvidenceCollection({ types });
  }
}
