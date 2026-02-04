// Main application initialization
function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') {
    return null;
  }
  return window.isec;
}

document.addEventListener('DOMContentLoaded', function() {
  console.log('ISEC UI loaded successfully');

  const bridge = getIsecBridge();
  if (!bridge) {
    console.error('ISEC IPC bridge not available');
    return;
  }

  const minimizeBtn = document.getElementById('minimize-window-btn');
  if (minimizeBtn) {
    minimizeBtn.addEventListener('click', () => bridge.invoke('minimize-window'));
  }

  const maximizeBtn = document.getElementById('maximize-window-btn');
  if (maximizeBtn) {
    maximizeBtn.addEventListener('click', () => bridge.invoke('maximize-window'));
  }

  const closeBtn = document.getElementById('close-window-btn');
  if (closeBtn) {
    closeBtn.addEventListener('click', () => bridge.invoke('close-window'));
  }
});

// Loading overlay functions
function showLoading() {
  document.getElementById('loading-overlay').classList.remove('hidden');
}

function hideLoading() {
  document.getElementById('loading-overlay').classList.add('hidden');
}

// Utility functions
function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleString();
}

function formatFileSize(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}