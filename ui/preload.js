/**
 * ISEC Preload Script — Secure IPC Bridge
 * Exposes ONLY explicitly allowed channels to the renderer process.
 * contextIsolation: true ensures no direct Node.js access from renderer.
 */
'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// ── Allowed IPC invoke channels (renderer → main) ────────────────────────────
// SECURITY: Any channel not in this set is blocked with an error.
// Update this list whenever a new ipcMain.handle() is added to main.js.
const ALLOWED_INVOKE = new Set([
  // Window controls
  'window-minimize',
  'window-maximize',
  'window-close',

  // UI fragment loading
  'read-ui-fragment',

  // Backend status & health
  'get-backend-status',
  'get-system-integrity',
  'get-evidence-confidence',
  'get-tampering-status',
  'get-retention-status',
  'get-export-readiness',

  // Evidence operations
  'start-evidence-collection',
  'get-evidence-timeline',
  'get-evidence-detail',
  'get-evidence-stats',

  // Report & export
  'generate-report',
  'export-evidence',
  'get-reports-list',

  // Evidence interoperability & transparency
  'export-case',
  'get-transparency-status',

  // Audit log
  'get-audit-log',

  // User & role management
  'set-user-role',
  'set-browser-consent',

  // Updates
  'check-for-updates',
  'apply-update',

  // First-run setup wizard
  'setup-activate-license',
  'setup-test-backend',
  'setup-generate-token',
  'setup-complete',
]);

// ── Allowed event channels (main → renderer) ─────────────────────────────────
const ALLOWED_ON = new Set([
  'tampering-detected',
  'update-available',
  'collection-progress',
]);

// ── Security validation ───────────────────────────────────────────────────────
function validateChannel(channel, allowedSet, direction) {
  if (typeof channel !== 'string' || channel.length === 0) {
    throw new Error(`ISEC Security: Invalid channel name`);
  }
  if (!allowedSet.has(channel)) {
    // Log blocked attempt (visible in main process devtools)
    console.warn(`[ISEC Preload] Blocked ${direction} on channel: "${channel}"`);
    throw new Error(`ISEC Security: Channel "${channel}" is not permitted`);
  }
}

function sanitizeArgs(args) {
  // Prevent prototype pollution and circular references
  return args.map(arg => {
    if (arg === null || arg === undefined) return arg;
    if (typeof arg === 'string' || typeof arg === 'number' || typeof arg === 'boolean') return arg;
    // Deep clone objects to prevent prototype pollution
    try { return JSON.parse(JSON.stringify(arg)); }
    catch (_) { return String(arg); }
  });
}

// ── Expose secure bridge to renderer ─────────────────────────────────────────
contextBridge.exposeInMainWorld('isec', {
  /**
   * Invoke an IPC channel and get a response.
   * Only channels in ALLOWED_INVOKE are permitted.
   */
  invoke: (channel, ...args) => {
    validateChannel(channel, ALLOWED_INVOKE, 'invoke');
    return ipcRenderer.invoke(channel, ...sanitizeArgs(args));
  },

  /**
   * Listen for events pushed from the main process.
   * Only channels in ALLOWED_ON are permitted.
   */
  on: (channel, listener) => {
    validateChannel(channel, ALLOWED_ON, 'on');
    if (typeof listener !== 'function') {
      throw new Error('ISEC Security: Listener must be a function');
    }
    const safeListener = (event, ...args) => {
      // Never expose the raw IPC event object to renderer
      listener(...sanitizeArgs(args));
    };
    ipcRenderer.on(channel, safeListener);
    // Return a cleanup function
    return () => ipcRenderer.removeListener(channel, safeListener);
  },

  /**
   * Get the application version.
   * Exposed directly — no IPC needed.
   */
  getVersion: () => process.env.npm_package_version || '2.0.0',
});
