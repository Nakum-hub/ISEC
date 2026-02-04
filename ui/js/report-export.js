// Report export functionality (IPC provided via window.isec bridge from main.js)

function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

async function initializeReportExport() {
  // Add event listeners
  const generateBtn = document.getElementById('generate-report');
  if (generateBtn) {
    generateBtn.addEventListener('click', generateReport);
  }
  
  // Add checkbox listeners to update preview
  document.querySelectorAll('#report input[type="checkbox"]').forEach(checkbox => {
    checkbox.addEventListener('change', updatePreview);
  });
  
  // Add format selection listener
  document.getElementById('export-format').addEventListener('change', updatePreview);
  
  // Initial preview update
  updatePreview();

  await refreshReportPermissions();
}

function updatePreview() {
  const includeSystemLogs = document.getElementById('include-system-logs').checked;
  const includeBrowserHistory = document.getElementById('include-browser-history').checked;
  const includeNetworkData = document.getElementById('include-network-data').checked;
  const includeFileMetadata = document.getElementById('include-file-metadata').checked;
  const format = document.getElementById('export-format').value;
  
  let previewHTML = '<h4>Report Contents Preview</h4>';
  
  previewHTML += '<ul>';
  if (includeSystemLogs) previewHTML += '<li>System Logs</li>';
  if (includeBrowserHistory) previewHTML += '<li>Browser History</li>';
  if (includeNetworkData) previewHTML += '<li>Network Connection Data</li>';
  if (includeFileMetadata) previewHTML += '<li>File Metadata</li>';
  previewHTML += '</ul>';
  
  previewHTML += `<p><strong>Export Format:</strong> ${format.toUpperCase()}</p>`;
  
  document.getElementById('preview-content').innerHTML = previewHTML;
}

async function generateReport() {
  const includeSystemLogs = document.getElementById('include-system-logs').checked;
  const includeBrowserHistory = document.getElementById('include-browser-history').checked;
  const includeNetworkData = document.getElementById('include-network-data').checked;
  const includeFileMetadata = document.getElementById('include-file-metadata').checked;
  const format = document.getElementById('export-format').value;
  
  const options = {
    includeSystemLogs,
    includeBrowserHistory,
    includeNetworkData,
    includeFileMetadata,
    format
  };
  
  showLoading();
  
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      console.error('ReportExport: Cannot generate report, IPC not available');
      alert('Report generation is not available in this environment.');
      return;
    }

    const result = await bridge.invoke('generate-report', options);
    
    if (result.success) {
      alert(`Report generated successfully!\nLocation: ${result.filePath}\nSize: ${result.size}`);
    } else {
      alert(result.message || 'Report generation failed.');
    }
  } catch (error) {
    console.error('Error generating report:', error);
    alert('Error generating report: ' + error.message);
  } finally {
    hideLoading();
    refreshReportPermissions().catch(() => {});
  }
}

async function refreshReportPermissions() {
  try {
    const bridge = getIsecBridge();
    if (!bridge) {
      return;
    }
    const status = await bridge.invoke('get-backend-status');
    const generateBtn = document.getElementById('generate-report');
    if (!generateBtn) {
      return;
    }

    const licenseValid = status && status.license ? !!status.license.valid : true;
    const canView = status && Array.isArray(status.permissions) ? status.permissions.includes('view') : true;
    const features = status && status.license ? (status.license.features || []) : [];
    const canReport = features.length === 0 || features.includes('report') || features.includes('all');

    const allowed = licenseValid && canView && canReport;
    generateBtn.disabled = !allowed;
    if (!allowed) {
      generateBtn.title = (status && status.license && status.license.message)
        ? status.license.message
        : 'Valid license and view permission required.';
    } else {
      generateBtn.title = '';
    }
  } catch (error) {
    console.error('Report permission refresh failed:', error);
  }
}
