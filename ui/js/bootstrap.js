document.addEventListener('DOMContentLoaded', function() {
  function getIsecBridge() {
    if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
      return null;
    }
    return window.isec;
  }

  async function loadFragment(relativePath, containerId) {
    const bridge = getIsecBridge();
    if (!bridge) {
      throw new Error('ISEC IPC bridge not available');
    }

    const res = await bridge.invoke('read-ui-fragment', relativePath);
    if (!res || res.success !== true) {
      throw new Error((res && res.message) ? res.message : `Failed to load fragment: ${relativePath}`);
    }

    const el = document.getElementById(containerId);
    if (!el) {
      throw new Error(`Missing container element: ${containerId}`);
    }

    el.innerHTML = res.html;
  }

  const dashboardPromise = loadFragment('views/dashboard.html', 'dashboard-container')
    .catch(error => console.error('Error loading dashboard:', error));

  const timelinePromise = loadFragment('views/timeline.html', 'timeline-container')
    .catch(error => console.error('Error loading timeline:', error));

  const detailPromise = loadFragment('components/evidence-detail-panel.html', 'detail-panel-container')
    .catch(error => console.error('Error loading detail panel:', error));

  Promise.all([dashboardPromise, timelinePromise, detailPromise]).then(() => {
    if (typeof initializeDashboard === 'function') {
      initializeDashboard();
    }
    if (typeof initializeTimeline === 'function') {
      initializeTimeline();
    }
    if (typeof initializeDetailView === 'function') {
      initializeDetailView();
    }
    if (typeof initializeReportExport === 'function') {
      initializeReportExport();
    }
    if (typeof initializeNavigation === 'function') {
      initializeNavigation();
    }
    if (typeof loadDashboardStats === 'function') {
      loadDashboardStats();
    }
  });
});
