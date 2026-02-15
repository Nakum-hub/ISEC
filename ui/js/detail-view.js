// Detail view functionality
function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

let selectedEvidenceId = null;

function setSelectedEvidenceId(recordId) {
  selectedEvidenceId = recordId;
  refreshDetailData();
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
  showLoading();

  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      alert('Evidence detail refresh is not available in this environment.');
      return;
    }

    const result = await bridge.invoke('get-evidence-detail', { recordId: selectedEvidenceId });
    if (!result || !result.success || !result.item) {
      const msg = (result && result.message) ? result.message : 'Unable to load evidence detail.';
      console.error('Detail refresh failed:', msg);
      alert(msg);
      return;
    }

    const item = result.item;
    const idEl = document.getElementById('evidence-id');
    const typeEl = document.getElementById('evidence-type');
    const tsEl = document.getElementById('evidence-timestamp');
    const sizeEl = document.getElementById('evidence-size');
    const hashEl = document.getElementById('evidence-hash');

    if (idEl) idEl.textContent = item.id ? `#${item.id}` : 'N/A';
    if (typeEl) typeEl.textContent = item.type ? item.type.replace(/_/g, ' ') : 'N/A';
    if (tsEl) tsEl.textContent = item.timestamp ? formatDate(item.timestamp) : 'N/A';
    if (sizeEl) {
      const sizeBytes = (typeof item.sizeBytes === 'number') ? item.sizeBytes : null;
      sizeEl.textContent = (sizeBytes !== null) ? formatFileSize(sizeBytes) : 'N/A';
    }
    if (hashEl) {
      const hash = item.currentRecordHash || item.hmacSignature || 'N/A';
      hashEl.textContent = hash;
    }
  } catch (error) {
    console.error('Detail refresh error:', error);
    alert('Evidence detail refresh failed: ' + error.message);
  } finally {
    hideLoading();
  }
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

    const licenseValid = status && status.license ? !!status.license.valid : false;
    const permissions = status && Array.isArray(status.permissions) ? status.permissions : [];
    const canExport = permissions.includes('export');
    const features = status && status.license ? (status.license.features || []) : [];
    const licenseAllows = features.includes('export') || features.includes('all');

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
