// Timeline functionality (IPC provided via window._ipcRenderer from main.js)

function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

let timelineRefreshTimer = null;

async function initializeTimeline() {
  // Load timeline data
  loadTimelineData();

  const filterEl = document.getElementById('timeline-filter');
  if (filterEl) {
    filterEl.addEventListener('change', function() {
      loadTimelineData(this.value);
    });
  }

  if (!timelineRefreshTimer) {
    timelineRefreshTimer = setInterval(() => {
      const activeFilter = filterEl ? filterEl.value : 'all';
      loadTimelineData(activeFilter);
    }, 15000);
  }
}

async function loadTimelineData(filter = 'all') {
  try {
    showLoading();

    const bridge = getIsecBridge();
    if (!bridge) {
      console.error('Timeline: Cannot load data, IPC not available');
      alert('Timeline is not available in this environment.');
      return;
    }

    // Get timeline data
    const result = await bridge.invoke('get-evidence-timeline');
    if (!result || result.success !== true) {
      const msg = (result && result.message) ? result.message : 'Failed to load timeline.';
      console.error('Timeline: backend failed:', msg);
      alert(msg);
      renderTimeline([]);
      return;
    }

    const timelineData = Array.isArray(result.items) ? result.items : [];

    // Filter data if needed
    let filteredData = timelineData;
    if (filter !== 'all') {
      filteredData = timelineData.filter(item => item.type === filter);
    }
    
    // Render timeline
    renderTimeline(filteredData);
  } catch (error) {
    console.error('Error loading timeline data:', error);
  } finally {
    hideLoading();
  }
}

function renderTimeline(timelineItems) {
  const container = document.getElementById('timeline-items');
  container.innerHTML = '';

  if (!timelineItems || timelineItems.length === 0) {
    container.innerHTML = '<div class="empty-state">No evidence found</div>';
    return;
  }
  
  timelineItems.forEach((item, index) => {
    const timelineItem = document.createElement('div');
    timelineItem.className = 'timeline-item';
    timelineItem.style.animationDelay = `${index * 0.1}s`;
    
    timelineItem.innerHTML = `
      <div class="timeline-marker"></div>
      <div class="timeline-content">
        <div class="timeline-type type-${item.type}">${formatEvidenceType(item.type)}</div>
        <div class="timeline-title">${item.description}</div>
        <div class="timeline-description">
          Collected ${formatDate(item.timestamp)}
          ${item.data.entries ? `(${item.data.entries} entries)` : ''}
          ${item.data.connections ? `(${item.data.connections} connections)` : ''}
          ${item.data.files ? `(${item.data.files} files)` : ''}
        </div>
        <div class="timeline-meta">
          <span>${formatSeverity(item.severity)}</span>
          <span>${new Date(item.timestamp).toLocaleDateString()}</span>
        </div>
      </div>
    `;
    
    container.appendChild(timelineItem);
  });
}

function formatEvidenceType(type) {
  const typeMap = {
    'system_logs': 'System Logs',
    'browser_history': 'Browser History',
    'network_connections': 'Network Connections',
    'file_metadata': 'File Metadata'
  };
  return typeMap[type] || type;
}

function formatSeverity(severity) {
  const severityMap = {
    'info': 'Info',
    'low': 'Low Risk',
    'medium': 'Medium Risk',
    'high': 'High Risk'
  };
  return severityMap[severity] || severity;
}