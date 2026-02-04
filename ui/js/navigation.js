// Navigation and view switching
function initializeNavigation() {
  function setActiveView(viewId) {
    // Hide all views (both static sections and injected sections)
    document.querySelectorAll('.view').forEach((view) => {
      view.classList.remove('active');
    });

    // Show the selected view
    if (viewId === 'dashboard') {
      const dashboardSection = document.getElementById('dashboard');
      if (dashboardSection) {
        dashboardSection.classList.add('active');
      }
      return;
    }

    if (viewId === 'timeline') {
      const timelineSection = document.getElementById('timeline');
      if (timelineSection) {
        timelineSection.classList.add('active');
      }
      return;
    }

    const staticSection = document.getElementById(viewId);
    if (staticSection) {
      staticSection.classList.add('active');
    }
  }

  // Add click listeners to navigation items
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.addEventListener('click', function() {
      const viewId = this.getAttribute('data-view');

      // Update active nav item
      document.querySelectorAll('.nav-item').forEach((nav) => {
        nav.classList.remove('active');
      });
      this.classList.add('active');

      setActiveView(viewId);
    });
  });

  // Add keyboard shortcuts
  document.addEventListener('keydown', function(e) {
    if (e.ctrlKey || e.metaKey) {
      switch(e.key) {
        case '1':
          e.preventDefault();
          document.querySelector('[data-view="dashboard"]').click();
          break;
        case '2':
          e.preventDefault();
          document.querySelector('[data-view="timeline"]').click();
          break;
        case '3':
          e.preventDefault();
          document.querySelector('[data-view="detail"]').click();
          break;
        case '4':
          e.preventDefault();
          document.querySelector('[data-view="report"]').click();
          break;
      }
    }
  });

  // Ensure we start on dashboard
  setActiveView('dashboard');
}