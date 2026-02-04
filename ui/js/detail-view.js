// Detail view functionality
function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

async function initializeDetailView() {
  // Add tab listeners
  document.querySelectorAll('.tab-btn').forEach(tab => {
    tab.addEventListener('click', function() {
      const tabId = this.getAttribute('data-tab');
      
      // Update active tab
      document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
      this.classList.add('active');
      
      // Show corresponding content
      document.querySelectorAll('.tab-pane').forEach(pane => pane.classList.remove('active'));
      const targetPane = document.getElementById(`${tabId}-content`);
      if (targetPane) {
        targetPane.classList.add('active');
      }
    });
  });
  
  // Add action listeners
  const refreshBtn = document.getElementById('refresh-detail');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', refreshDetailData);
  }
  const exportBtn = document.getElementById('export-evidence');
  if (exportBtn) {
    exportBtn.addEventListener('click', exportEvidence);
  }

  await refreshDetailPermissions();
}

async function refreshDetailData() {
  alert('Evidence detail refresh is not available in this build. Use Evidence Timeline for verified records.');
}

async function exportEvidence() {
  showLoading();
  
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      alert('Export is not available in this environment.');
      return;
    }

    const result = await bridge.invoke('export-evidence', {});
    if (result && result.success) {
      alert(`Evidence exported successfully!\nLocation: ${result.filePath || 'N/A'}`);
    } else {
      alert((result && result.message) ? result.message : 'Export failed.');
    }
  } catch (error) {
    console.error('Error exporting evidence:', error);
    alert('Error exporting evidence: ' + error.message);
  } finally {
    hideLoading();
    refreshDetailPermissions().catch(() => {});
  }
}

async function refreshDetailPermissions() {
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      return;
    }
    const status = await bridge.invoke('get-backend-status');
    const exportBtn = document.getElementById('export-evidence');
    if (!exportBtn) {
      return;
    }

    const licenseValid = status && status.license ? !!status.license.valid : true;
    const permissions = status && Array.isArray(status.permissions) ? status.permissions : [];
    const canExport = permissions.includes('export');
    const features = status && status.license ? (status.license.features || []) : [];
    const licenseAllows = features.length === 0 || features.includes('export') || features.includes('all');

    const allowed = licenseValid && canExport && licenseAllows;
    exportBtn.disabled = !allowed;
    if (!allowed) {
      exportBtn.title = (status && status.license && status.license.message)
        ? status.license.message
        : 'Exporter role and valid license required.';
    } else {
      exportBtn.title = '';
    }
  } catch (error) {
    console.error('Detail permission refresh failed:', error);
  }
}
