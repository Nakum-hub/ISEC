/**
 * ISEC Renderer — Core Utilities
 * Provides global helpers; window controls are handled by navigation.js
 */

// ── IPC Bridge Helper ─────────────────────────────────────────────
function getIsecBridge() {
  if (typeof window !== 'undefined' && window.isec && typeof window.isec.invoke === 'function') {
    return window.isec;
  }
  return null;
}

// ── Loading Overlay ───────────────────────────────────────────────
// Note: bootstrap.js exposes these as window.showLoading / window.hideLoading
// Defined here as fallback for any legacy call sites
function showLoading(msg) {
  const ol = document.getElementById('loading-overlay');
  if (!ol) return;
  const p = ol.querySelector('p');
  if (p && msg) p.textContent = msg;
  ol.classList.remove('hidden');
}

function hideLoading() {
  const ol = document.getElementById('loading-overlay');
  if (ol) ol.classList.add('hidden');
}

// ── Date / Size Formatters ────────────────────────────────────────
function formatDate(dateString) {
  if (!dateString) return '—';
  return new Date(dateString).toLocaleString();
}

function formatFileSize(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ── DOM Ready guard ───────────────────────────────────────────────
// Window control buttons are bound in navigation.js (initNavigation)
// This file intentionally does NOT rebind them to avoid duplicate listeners.
document.addEventListener('DOMContentLoaded', function () {
  const bridge = getIsecBridge();
  if (!bridge) {
    console.warn('[ISEC] IPC bridge not available — running in standalone mode');
  } else {
    console.info('[ISEC] IPC bridge connected');
  }
});
