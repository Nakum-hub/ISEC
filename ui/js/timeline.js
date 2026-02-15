// Timeline functionality (IPC provided via window._ipcRenderer from main.js)

function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

function escapeHtml(value) {
  const raw = String(value == null ? '' : value);
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function sanitizeClassToken(value, fallback = 'unknown') {
  const token = String(value == null ? '' : value).toLowerCase().replace(/[^a-z0-9_-]/g, '');
  return token || fallback;
}

let timelineRefreshTimer = null;

async function initializeTimeline() {
  const filterEl = document.getElementById('timeline-filter');
  if (filterEl) {
    filterEl.addEventListener('change', function() {
      loadTimelineData(this.value, { force: true });
    });
  }

  if (!timelineRefreshTimer) {
    timelineRefreshTimer = setInterval(() => {
      const activeFilter = filterEl ? filterEl.value : 'all';
      loadTimelineData(activeFilter);
    }, 15000);
  }
}

function isTimelineActive() {
  const timelineSection = document.getElementById('timeline');
  return !!(timelineSection && timelineSection.classList.contains('active'));
}

function renderTimelineLoading() {
  const container = document.getElementById('timeline-items');
  if (!container) return;
  container.innerHTML = '<div class="empty-state">Loading evidence timeline...</div>';
}

async function loadTimelineData(filter = 'all', options = {}) {
  const force = !!(options && options.force);
  if (!force && !isTimelineActive()) {
    return;
  }

  try {
    if (isTimelineActive()) {
      renderTimelineLoading();
    }

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

    const itemData = item && typeof item === 'object' ? item : {};
    const itemType = formatEvidenceType(itemData.type || '');
    const itemDescription = itemData.description || 'No description';
    const itemTimestamp = itemData.timestamp || '';
    const itemDataObj = (itemData.data && typeof itemData.data === 'object') ? itemData.data : {};
    const entriesText = Number.isFinite(itemDataObj.entries) ? `(${itemDataObj.entries} entries)` : '';
    const connectionsText = Number.isFinite(itemDataObj.connections) ? `(${itemDataObj.connections} connections)` : '';
    const filesText = Number.isFinite(itemDataObj.files) ? `(${itemDataObj.files} files)` : '';
    const severityText = formatSeverity(itemData.severity || '');
    const dateText = itemTimestamp ? new Date(itemTimestamp).toLocaleDateString() : 'N/A';

    timelineItem.innerHTML = `
      <div class="timeline-marker"></div>
      <div class="timeline-content">
        <div class="timeline-type type-${sanitizeClassToken(itemData.type)}">${escapeHtml(itemType)}</div>
        <div class="timeline-title">${escapeHtml(itemDescription)}</div>
        <div class="timeline-description">
          Collected ${escapeHtml(itemTimestamp ? formatDate(itemTimestamp) : 'Unknown')}
          ${escapeHtml(entriesText)}
          ${escapeHtml(connectionsText)}
          ${escapeHtml(filesText)}
        </div>
        <div class="timeline-meta">
          <span>${escapeHtml(severityText)}</span>
          <span>${escapeHtml(dateText)}</span>
        </div>
      </div>
    `;

    timelineItem.addEventListener('click', () => {
      if (typeof setSelectedEvidenceId === 'function') {
        setSelectedEvidenceId(itemData.id);
      }
      const detailNav = document.querySelector('[data-view="detail"]');
      if (detailNav) {
        detailNav.click();
      }
    });
    
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
