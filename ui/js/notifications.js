/**
 * ISEC Notification System
 * Toast notifications with stacking, progress bars, and animations
 */
const ISECNotify = (function () {
  'use strict';

  let container = null;
  let stack = [];

  const ICONS = {
    success: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><path d="M7 12l3 3 7-7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    error:   `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><path d="M15 9l-6 6M9 9l6 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    warning: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 3L2 21h20L12 3z" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"/><path d="M12 9v5M12 17v1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    info:    `<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5"/><path d="M12 8v1M12 11v5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>`,
    loading: `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" class="spin"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="1.5" stroke-dasharray="31" stroke-dashoffset="10"/></svg>`,
  };

  const PALETTE = {
    success: { border: '#00e676', glow: 'rgba(0,230,118,0.15)', icon: '#00e676' },
    error:   { border: '#ff1744', glow: 'rgba(255,23,68,0.15)',   icon: '#ff1744' },
    warning: { border: '#ffd600', glow: 'rgba(255,214,0,0.15)',   icon: '#ffd600' },
    info:    { border: '#00c8ff', glow: 'rgba(0,200,255,0.15)',   icon: '#00c8ff' },
    loading: { border: '#7c4dff', glow: 'rgba(124,77,255,0.15)', icon: '#7c4dff' },
  };

  function ensureContainer() {
    if (container && document.body.contains(container)) return;
    container = document.createElement('div');
    container.id = 'isec-toast-container';
    container.style.cssText = `
      position: fixed;
      bottom: 24px;
      right: 24px;
      display: flex;
      flex-direction: column-reverse;
      gap: 10px;
      z-index: 99999;
      pointer-events: none;
      max-width: 380px;
    `;
    document.body.appendChild(container);
  }

  function show(message, type = 'info', durationMs = 4000) {
    ensureContainer();
    const pal = PALETTE[type] || PALETTE.info;
    const icon = ICONS[type] || ICONS.info;

    const toast = document.createElement('div');
    toast.style.cssText = `
      background: rgba(10, 16, 30, 0.95);
      border: 1px solid ${pal.border};
      border-radius: 10px;
      padding: 13px 16px;
      display: flex;
      align-items: flex-start;
      gap: 12px;
      min-width: 280px;
      max-width: 380px;
      pointer-events: all;
      cursor: pointer;
      position: relative;
      overflow: hidden;
      box-shadow: 0 0 20px ${pal.glow}, 0 4px 20px rgba(0,0,0,0.5);
      transform: translateX(120%);
      opacity: 0;
      transition: transform 0.35s cubic-bezier(0.34, 1.56, 0.64, 1), opacity 0.3s ease;
    `;

    const iconEl = document.createElement('div');
    iconEl.innerHTML = icon;
    iconEl.style.cssText = `color: ${pal.icon}; flex-shrink: 0; margin-top: 1px;`;

    const msgEl = document.createElement('div');
    msgEl.style.cssText = `
      color: #e0e7ff;
      font-size: 13px;
      font-family: 'Rajdhani', 'Segoe UI', sans-serif;
      font-weight: 500;
      line-height: 1.4;
      flex: 1;
    `;
    msgEl.textContent = message;

    const closeBtn = document.createElement('button');
    closeBtn.innerHTML = '×';
    closeBtn.style.cssText = `
      background: none; border: none; color: rgba(255,255,255,0.35);
      cursor: pointer; font-size: 18px; padding: 0; line-height: 1;
      flex-shrink: 0; margin-top: -1px;
      transition: color 0.2s;
    `;
    closeBtn.addEventListener('mouseenter', () => closeBtn.style.color = 'rgba(255,255,255,0.8)');
    closeBtn.addEventListener('mouseleave', () => closeBtn.style.color = 'rgba(255,255,255,0.35)');

    // Progress bar
    const progress = document.createElement('div');
    progress.style.cssText = `
      position: absolute;
      bottom: 0; left: 0;
      height: 2px;
      width: 100%;
      background: ${pal.border};
      transform-origin: left;
      transform: scaleX(1);
    `;

    toast.appendChild(iconEl);
    toast.appendChild(msgEl);
    toast.appendChild(closeBtn);
    toast.appendChild(progress);

    container.appendChild(toast);
    stack.push(toast);

    // Animate in
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        toast.style.transform = 'translateX(0)';
        toast.style.opacity = '1';
      });
    });

    const dismiss = () => {
      toast.style.transform = 'translateX(120%)';
      toast.style.opacity = '0';
      setTimeout(() => {
        if (toast.parentNode) toast.parentNode.removeChild(toast);
        stack = stack.filter(t => t !== toast);
      }, 350);
    };

    closeBtn.addEventListener('click', (e) => { e.stopPropagation(); dismiss(); });
    toast.addEventListener('click', dismiss);

    if (durationMs > 0) {
      // Animate progress bar
      const startTime = performance.now();
      function tickProgress(now) {
        const elapsed = now - startTime;
        const remaining = Math.max(0, 1 - elapsed / durationMs);
        progress.style.transform = `scaleX(${remaining})`;
        progress.style.transition = 'none';
        if (remaining > 0) requestAnimationFrame(tickProgress);
      }
      requestAnimationFrame(tickProgress);

      setTimeout(dismiss, durationMs);
    }

    return { dismiss };
  }

  function success(msg, ms) { return show(msg, 'success', ms !== undefined ? ms : 4000); }
  function error(msg, ms)   { return show(msg, 'error',   ms !== undefined ? ms : 6000); }
  function warning(msg, ms) { return show(msg, 'warning', ms !== undefined ? ms : 5000); }
  function info(msg, ms)    { return show(msg, 'info',    ms !== undefined ? ms : 4000); }
  function loading(msg)     { return show(msg, 'loading', 0); }

  function dismissAll() {
    [...stack].forEach(t => {
      t.style.transform = 'translateX(120%)';
      t.style.opacity = '0';
      setTimeout(() => { if (t.parentNode) t.parentNode.removeChild(t); }, 350);
    });
    stack = [];
  }

  return { show, success, error, warning, info, loading, dismissAll };
})();
