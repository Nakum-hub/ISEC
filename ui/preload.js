const { contextBridge, ipcRenderer } = require('electron');

const allowedInvokeChannels = new Set([
  'minimize-window',
  'maximize-window',
  'close-window',
  'read-ui-fragment',
  'get-backend-status',
  'set-browser-consent',
  'start-evidence-collection',
  'get-evidence-timeline',
  'generate-report',
  'export-evidence',
  'get-tampering-status',
  'get-user-role',
  'set-user-role',
  'get-retention-settings',
  'set-retention-settings',
  'get-retention-status',
  'get-system-integrity',
  'get-evidence-confidence',
  'get-export-readiness',
  'check-for-updates',
  'apply-update'
]);

const allowedOnChannels = new Set([
  'tampering-detected'
]);

contextBridge.exposeInMainWorld('isec', {
  invoke: (channel, ...args) => {
    if (!allowedInvokeChannels.has(channel)) {
      return Promise.reject(new Error('Blocked IPC channel'));
    }
    return ipcRenderer.invoke(channel, ...args);
  },
  on: (channel, listener) => {
    if (!allowedOnChannels.has(channel)) {
      throw new Error('Blocked IPC channel');
    }
    ipcRenderer.on(channel, (event, ...args) => listener(...args));
  }
});
