const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');
let isDev = false;
try {
  isDev = require('electron-is-dev');
} catch (err) {
  isDev = !!(process.env.ELECTRON_IS_DEV === '1' || process.defaultApp || process.versions.electron);
}
const crypto = require('crypto');

const allowedUiFragments = new Set([
  'views/dashboard.html',
  'views/timeline.html',
  'components/evidence-detail-panel.html',
  'components/stat-card.html',
  'components/timeline-item.html'
]);

let mainWindow;
let tamperingDetected = false; // Track tampering status
let currentRole = 'reviewer'; // Default role
let userPermissions = ['view']; // Default permissions
let lastBackendStatus = null;
let pythonBusy = false;
let statusRefreshPromise = null;
let pythonQueue = Promise.resolve();

const pythonPath = 'python';
const scriptPath = path.join(__dirname, '..', 'main.py');
const evidenceDir = path.join(__dirname, '..', 'evidence_output');
const roleFilePath = path.join(__dirname, '..', 'user_roles.encrypted');
const licenseFilePath = path.join(__dirname, '..', 'license.json');
const updatesDir = path.join(__dirname, '..', 'updates');
let uiLogStream = null;

const originalConsole = {
  log: console.log,
  info: console.info,
  warn: console.warn,
  error: console.error
};

function formatLogArg(arg) {
  if (typeof arg === 'string') return arg;
  if (arg instanceof Error) return arg.stack || arg.message || String(arg);
  try {
    return JSON.stringify(arg);
  } catch (err) {
    return String(arg);
  }
}

function setupUiLogging() {
  if (uiLogStream) return;
  try {
    const logDir = path.join(app.getPath('userData'), 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    const logPath = path.join(logDir, 'isec-ui.log');
    if (fs.existsSync(logPath)) {
      try {
        const { size } = fs.statSync(logPath);
        const maxBytes = 50 * 1024 * 1024;
        if (size > maxBytes) {
          const stamp = new Date().toISOString().replace(/[:.]/g, '-');
          fs.renameSync(logPath, `${logPath}.${stamp}`);
        }
      } catch (err) {
        // ignore rotation errors
      }
    }
    uiLogStream = fs.createWriteStream(logPath, { flags: 'a' });

    const swallowEpipe = (stream) => {
      if (!stream || typeof stream.on !== 'function') return;
      stream.on('error', (err) => {
        if (err && err.code === 'EPIPE') {
          return;
        }
      });
    };

    swallowEpipe(process.stdout);
    swallowEpipe(process.stderr);

    const writeLine = (level, args) => {
      if (!uiLogStream) return;
      const message = args.map(formatLogArg).join(' ');
      uiLogStream.write(`${new Date().toISOString()} [${level}] ${message}\n`);
    };

    const canWrite = (stream) => !!(stream && !stream.destroyed && stream.writable && stream.isTTY);
    const wrap = (level, original, stream) => (...args) => {
      try {
        writeLine(level, args);
      } catch (err) {
        // ignore logging errors
      }
      if (canWrite(stream)) {
        try {
          original.apply(console, args);
        } catch (err) {
          // ignore console errors
        }
      }
    };

    console.log = wrap('INFO', originalConsole.log, process.stdout);
    console.info = wrap('INFO', originalConsole.info, process.stdout);
    console.warn = wrap('WARN', originalConsole.warn, process.stderr);
    console.error = wrap('ERROR', originalConsole.error, process.stderr);

    writeLine('INFO', ['UI logging initialized']);
  } catch (err) {
    try {
      if (process.stderr && process.stderr.writable && !process.stderr.destroyed) {
        originalConsole.error('UI logging initialization failed:', err);
      }
    } catch (e) {
      // ignore
    }
  }
}

function extractJsonMarker(output) {
  const marker = 'ISEC_JSON:';
  const lines = output.split(/\r?\n/).filter(Boolean);
  const line = lines.find((l) => l.startsWith(marker));
  if (!line) return null;
  const jsonText = line.slice(marker.length).trim();
  try {
    return JSON.parse(jsonText);
  } catch (e) {
    return null;
  }
}

function applyBackendStatus(status) {
  if (!status) return;
  lastBackendStatus = status;
  if (status.tamperingDetected !== undefined) {
    tamperingDetected = !!status.tamperingDetected;
  }
  if (status.role) {
    currentRole = status.role;
  }
  if (Array.isArray(status.permissions)) {
    userPermissions = status.permissions;
  }
}

function runPythonAction(action, extraArgs = []) {
  const task = () => new Promise((resolve, reject) => {
    pythonBusy = true;

    const defaultRoleArgs = fs.existsSync(roleFilePath) ? [] : ['--default-role', 'collector'];
    const licenseArgs = ['--license-file', licenseFilePath];
    const allowUnlicensedArgs = isDev ? ['--allow-unlicensed'] : [];

    const timeoutMsMap = {
      status: 60000,
      timeline: 60000,
      collect: 10 * 60 * 1000,
      report: 5 * 60 * 1000,
      export: 5 * 60 * 1000,
      set_role: 60000
    };
    const timeoutMs = timeoutMsMap[action] || 30000;

    const args = [
      scriptPath,
      '--output-dir',
      evidenceDir,
      '--electron-mode',
      ...defaultRoleArgs,
      ...licenseArgs,
      ...allowUnlicensedArgs,
      '--action',
      action,
      ...extraArgs
    ];
    const proc = spawn(pythonPath, args, { cwd: path.join(__dirname, '..') });

    let stdout = '';
    let stderr = '';

    const killTimer = setTimeout(() => {
      try {
        proc.kill();
      } catch (e) {
        // ignore
      }
    }, timeoutMs);

    proc.stdout.on('data', (data) => {
      const chunk = data.toString();
      stdout += chunk;

      console.log(`Python stdout: ${chunk}`);
      if (chunk.includes('TAMPERING DETECTED')) {
        tamperingDetected = true;
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('tampering-detected', chunk);
        }
      }
    });

    proc.stderr.on('data', (data) => {
      const chunk = data.toString();
      stderr += chunk;

      console.error(`Python stderr: ${chunk}`);
      if (chunk.includes('TAMPERING DETECTED')) {
        tamperingDetected = true;
        if (mainWindow && !mainWindow.isDestroyed()) {
          mainWindow.webContents.send('tampering-detected', chunk);
        }
      }
    });

    proc.on('close', (code, signal) => {
      pythonBusy = false;
      clearTimeout(killTimer);
      const jsonPayload = extractJsonMarker(stdout);
      if (!jsonPayload) {
        const err = new Error(
          code === 0
            ? 'Invalid backend response'
            : (code === null
              ? `Python process was terminated${signal ? ` (signal: ${signal})` : ''}`
              : `Python exited with code ${code}`)
        );
        err.backendStdout = stdout;
        err.backendStderr = stderr;
        reject(err);
        return;
      }
      resolve({ code, json: jsonPayload, stdout, stderr });
    });

    proc.on('error', (err) => {
      pythonBusy = false;
      clearTimeout(killTimer);
      reject(err);
    });
  });

  pythonQueue = pythonQueue.then(task, task);
  return pythonQueue;
}

function readJsonFile(filePath) {
  try {
    const content = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(content);
  } catch (err) {
    return null;
  }
}

function compareVersions(a, b) {
  const aParts = String(a || '0').split('.').map(Number);
  const bParts = String(b || '0').split('.').map(Number);
  const maxLen = Math.max(aParts.length, bParts.length);
  for (let i = 0; i < maxLen; i += 1) {
    const av = aParts[i] || 0;
    const bv = bParts[i] || 0;
    if (av > bv) return 1;
    if (av < bv) return -1;
  }
  return 0;
}

function computeSha256(filePath) {
  const hash = crypto.createHash('sha256');
  const data = fs.readFileSync(filePath);
  hash.update(data);
  return hash.digest('hex');
}

function checkOfflineUpdate() {
  const manifestPath = path.join(updatesDir, 'manifest.json');
  const currentVersion = app.getVersion();

  if (!fs.existsSync(manifestPath)) {
    return { available: false, reason: 'manifest_not_found', currentVersion };
  }

  const manifest = readJsonFile(manifestPath);
  if (!manifest || !manifest.version || !manifest.package) {
    return { available: false, reason: 'manifest_invalid', currentVersion };
  }

  const cmp = compareVersions(manifest.version, currentVersion);
  if (cmp <= 0) {
    return { available: false, reason: 'up_to_date', currentVersion, availableVersion: manifest.version };
  }

  const packagePath = path.join(updatesDir, manifest.package);
  if (!fs.existsSync(packagePath)) {
    return { available: false, reason: 'package_missing', currentVersion, availableVersion: manifest.version };
  }

  if (manifest.sha256) {
    const actualHash = computeSha256(packagePath);
    if (actualHash.toLowerCase() !== String(manifest.sha256).toLowerCase()) {
      return { available: false, reason: 'checksum_mismatch', currentVersion, availableVersion: manifest.version };
    }
  }

  return {
    available: true,
    reason: 'update_available',
    currentVersion,
    availableVersion: manifest.version,
    notes: manifest.notes || '',
    packagePath
  };
}

async function refreshBackendStatus() {
  if (statusRefreshPromise) {
    return statusRefreshPromise;
  }

  if (pythonBusy) {
    return;
  }

  statusRefreshPromise = (async () => {
    const res = await runPythonAction('status');
    if (res.json && res.json.success && res.json.role) {
      applyBackendStatus(res.json);
    } else if (res.json && res.json.status) {
      applyBackendStatus(res.json.status);
    }
  })();

  try {
    await statusRefreshPromise;
  } finally {
    statusRefreshPromise = null;
  }
}

function createWindow() {
  mainWindow = new BrowserWindow({

    width: 1400,
    height: 900,
    minWidth: 1024,
    minHeight: 768,
    backgroundColor: '#0a0a0f',
    icon: path.join(__dirname, 'assets/icon.png'),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },

    frame: false, // Custom window frame for modern look
    transparent: true, // Enable transparency for glass effect
    vibrancy: 'dark' // macOS vibrancy effect
  });

  // Load the index.html file
  const indexPath = path.join(__dirname, 'index.html');
  mainWindow.loadFile(indexPath);

  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  // Handle window closing
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Create window when Electron is ready
app.whenReady().then(() => {
  setupUiLogging();

  process.on('uncaughtException', (err) => {
    console.error('Uncaught exception:', err);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('Unhandled rejection:', reason);
  });

  createWindow();

  refreshBackendStatus().catch((err) => {
    console.error('Failed to refresh backend status:', err);
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers for window controls
ipcMain.handle('minimize-window', async () => {
  if (mainWindow) {
    mainWindow.minimize();
  }
});

ipcMain.handle('maximize-window', async () => {
  if (mainWindow) {
    if (mainWindow.isMaximized()) {
      mainWindow.unmaximize();
    } else {
      mainWindow.maximize();
    }
  }
});

ipcMain.handle('close-window', async () => {
  if (mainWindow) {
    mainWindow.close();
  }
});

ipcMain.handle('read-ui-fragment', async (event, relativePath) => {
  try {
    const requested = String(relativePath || '');
    if (!allowedUiFragments.has(requested)) {
      return { success: false, message: 'Blocked UI fragment path.' };
    }

    const absPath = path.join(__dirname, requested);
    const html = await fs.promises.readFile(absPath, 'utf8');
    return { success: true, html };
  } catch (err) {
    console.error('read-ui-fragment failed:', err);
    return { success: false, message: err.message || 'Failed to load UI fragment.' };
  }
});

ipcMain.handle('get-backend-status', async () => {
  try {
    await refreshBackendStatus();
    return lastBackendStatus || null;
  } catch (err) {
    console.error('get-backend-status failed:', err);
    return lastBackendStatus || null;
  }
});

ipcMain.handle('set-browser-consent', async (event, payload) => {
  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('collect')) {
      return { success: false, message: 'Permission denied: Collector role required to update consent.' };
    }
    if (tamperingDetected) {
      return { success: false, message: 'Consent update blocked due to tampering detection.' };
    }

    const timeRange = payload && payload.timeRange ? String(payload.timeRange) : '';
    const browsers = payload && Array.isArray(payload.browsers) ? payload.browsers.map(String) : [];

    const extraArgs = ['--consent-time-range', timeRange];
    if (browsers.length > 0) {
      extraArgs.push('--consent-browsers', browsers.join(','));
    }

    const res = await runPythonAction('set_browser_consent', extraArgs);
    const json = res.json;
    if (json && json.status) {
      applyBackendStatus(json.status);
    }
    return json || { success: false, message: 'Consent update failed.' };
  } catch (err) {
    console.error('set-browser-consent failed:', err);
    return { success: false, message: err.message || 'Consent update failed.' };
  }
});

// IPC handlers for real evidence collection
ipcMain.handle('start-evidence-collection', async (event, options) => {

  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('collect')) {
      return { success: false, message: 'Permission denied: Collector role required to collect evidence', evidenceCount: 0, integrityStatus: 'ACCESS_DENIED' };
    }
    if (tamperingDetected) {
      return { success: false, message: 'Evidence collection locked due to tampering detection!', evidenceCount: 0, integrityStatus: 'LOCKED' };
    }

    const res = await runPythonAction('collect');
    const json = res.json;

    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    if (json && json.success) {
      const integrityStatus = (json.status && json.status.hashChainValid) ? 'verified' : 'COMPROMISED';
      return {
        success: true,
        message: json.message || 'Evidence collection completed.',
        evidenceCount: (json.status && json.status.evidenceCount) || 0,
        integrityStatus
      };
    }

    return {
      success: false,
      message: (json && json.message) ? json.message : 'Evidence collection failed.',
      evidenceCount: (json && json.status && json.status.evidenceCount) || 0,
      integrityStatus: tamperingDetected ? 'LOCKED' : 'ERROR'
    };
  } catch (err) {
    console.error('start-evidence-collection failed:', err);
    return { success: false, message: err.message || 'Evidence collection failed.', evidenceCount: 0, integrityStatus: 'ERROR' };
  }
});

ipcMain.handle('get-evidence-timeline', async () => {
  try {
    await refreshBackendStatus();
    const res = await runPythonAction('timeline');
    if (res.json && res.json.success && Array.isArray(res.json.items)) {
      return { success: true, items: res.json.items };
    }
    return { success: false, items: [], message: (res.json && res.json.message) ? res.json.message : 'Failed to load timeline.' };
  } catch (err) {
    console.error('get-evidence-timeline failed:', err);
    return { success: false, items: [], message: err.message || 'Failed to load timeline.' };
  }
});

ipcMain.handle('generate-report', async (event, options) => {

  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('view')) {
      return { success: false, filePath: null, size: '0 KB', message: 'Permission denied: Insufficient permissions to generate reports!' };
    }
    if (tamperingDetected) {
      return { success: false, filePath: null, size: '0 KB', message: 'Report generation blocked due to tampering detection!' };
    }
    if (lastBackendStatus && typeof lastBackendStatus.evidenceItemsCount === 'number' && lastBackendStatus.evidenceItemsCount <= 0) {
      return { success: false, filePath: null, size: '0 KB', message: 'Report generation blocked: no evidence available.' };
    }

    const res = await runPythonAction('report');
    const json = res.json;

    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    if (json && json.success) {
      return { success: true, filePath: json.filePath, size: 'N/A' };
    }
    return { success: false, filePath: null, size: '0 KB', message: (json && json.message) ? json.message : 'Report generation failed.' };
  } catch (err) {
    console.error('generate-report failed:', err);
    return { success: false, filePath: null, size: '0 KB', message: err.message || 'Report generation failed.' };
  }
});

// IPC handler to get tampering status
ipcMain.handle('get-tampering-status', async () => {
  return tamperingDetected;
});

// IPC handler to get user role
ipcMain.handle('get-user-role', async () => {
  try {
    await refreshBackendStatus();
  } catch (e) {
    // keep last known role
  }
  return {
    role: currentRole,
    permissions: userPermissions
  };
});

// IPC handler to set user role (would typically require admin privileges in real app)
ipcMain.handle('set-user-role', async (event, role) => {
  try {
    await refreshBackendStatus();

    if (tamperingDetected) {
      return { success: false, message: 'Role change blocked due to tampering detection.' };
    }

    const roleValue = String(role || '').toLowerCase();
    if (!['collector', 'reviewer', 'exporter'].includes(roleValue)) {
      return { success: false, message: 'Invalid role selection.' };
    }

    const res = await runPythonAction('set_role', ['--role', roleValue]);
    const json = res.json;

    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    return json || { success: false, message: 'Role change failed.' };
  } catch (err) {
    console.error('set-user-role failed:', err);
    return { success: false, message: err.message || 'Role change failed.' };
  }
});

// IPC handler to export evidence
ipcMain.handle('export-evidence', async (event, options) => {
  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('export')) {
      return { success: false, filePath: null, message: 'Permission denied: Exporter role required to export evidence' };
    }
    if (tamperingDetected) {
      return { success: false, filePath: null, message: 'Export blocked due to tampering detection!' };
    }
    if (lastBackendStatus && typeof lastBackendStatus.evidenceItemsCount === 'number' && lastBackendStatus.evidenceItemsCount <= 0) {
      return { success: false, filePath: null, message: 'Export blocked: no evidence available.' };
    }

    const exportDir = (options && options.exportDir) ? options.exportDir : app.getPath('documents');
    const res = await runPythonAction('export', ['--export-dir', exportDir]);
    const json = res.json;
    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    if (json && json.success) {
      return { success: true, filePath: json.filePath, message: 'Evidence exported successfully' };
    }
    return { success: false, filePath: null, message: (json && json.message) ? json.message : 'Export failed.' };
  } catch (err) {
    console.error('export-evidence failed:', err);
    return { success: false, filePath: null, message: err.message || 'Export failed.' };
  }
});

// IPC handler to get retention settings
ipcMain.handle('get-retention-settings', async () => {
  try {
    await refreshBackendStatus();
    const retention = (lastBackendStatus && lastBackendStatus.retention) ? lastBackendStatus.retention : null;
    return retention || {
      policy: 'unknown',
      retention_days: 0,
      total_evidence: 0,
      active_evidence: 0,
      expired_evidence: 0,
      next_expiry_check: null
    };
  } catch (err) {
    console.error('get-retention-settings failed:', err);
    return {
      policy: 'unknown',
      retention_days: 0,
      total_evidence: 0,
      active_evidence: 0,
      expired_evidence: 0,
      next_expiry_check: null
    };
  }
});

// IPC handler to set retention settings
ipcMain.handle('set-retention-settings', async (event, settings) => {
  return {
    success: false,
    message: 'Retention policy changes are not supported from the UI in this build. Use the CLI retention flow.'
  };
});

// IPC handler to get retention status
ipcMain.handle('get-retention-status', async () => {
  try {
    await refreshBackendStatus();
    const retention = (lastBackendStatus && lastBackendStatus.retention) ? lastBackendStatus.retention : null;
    return retention || {
      policy: 'unknown',
      retention_days: 0,
      total_evidence: 0,
      active_evidence: 0,
      expired_evidence: 0,
      next_expiry_check: null
    };
  } catch (err) {
    console.error('get-retention-status failed:', err);
    return {
      policy: 'unknown',
      retention_days: 0,
      total_evidence: 0,
      active_evidence: 0,
      expired_evidence: 0,
      next_expiry_check: null
    };
  }
});

// IPC handler to get system integrity status
ipcMain.handle('get-system-integrity', async () => {
  try {
    await refreshBackendStatus();
    const hashChainValid = lastBackendStatus ? !!lastBackendStatus.hashChainValid : true;
    const compromised = tamperingDetected || !hashChainValid;
    return {
      status: compromised ? 'compromised' : 'valid',
      chainIntegrity: hashChainValid ? 'valid' : 'invalid',
      verificationResult: hashChainValid ? 'passed' : 'failed',
      lastVerified: new Date().toISOString(),
      totalChecks: 0,
      failedChecks: compromised ? 1 : 0
    };
  } catch (err) {
    console.error('get-system-integrity failed:', err);
    return {
      status: 'unknown',
      chainIntegrity: 'unknown',
      verificationResult: 'unknown',
      lastVerified: null,
      totalChecks: 0,
      failedChecks: 0
    };
  }
});

// IPC handler to get evidence confidence
ipcMain.handle('get-evidence-confidence', async () => {
  try {
    await refreshBackendStatus();
    const evidenceCount = (lastBackendStatus && typeof lastBackendStatus.evidenceItemsCount === 'number') ? lastBackendStatus.evidenceItemsCount : 0;
    const hashChainValid = lastBackendStatus ? !!lastBackendStatus.hashChainValid : true;

    // Conservative, non-deceptive default: we do not claim a computed confidence model.
    // We only reflect basic availability + integrity.
    const score = (!hashChainValid || tamperingDetected) ? 0 : (evidenceCount > 0 ? 50 : 0);
    const confidenceLevel = score >= 50 ? 'medium' : 'low';

    return {
      confidenceLevel,
      score,
      factors: {
        completeness: evidenceCount > 0 ? 50 : 0,
        accuracy: hashChainValid ? 50 : 0,
        relevance: 0,
        timeliness: 0
      },
      timestamp: new Date().toISOString()
    };
  } catch (err) {
    console.error('get-evidence-confidence failed:', err);
    return {
      confidenceLevel: 'low',
      score: 0,
      factors: { completeness: 0, accuracy: 0, relevance: 0, timeliness: 0 },
      timestamp: new Date().toISOString()
    };
  }
});

// IPC handler to get export readiness
ipcMain.handle('get-export-readiness', async () => {
  try {
    await refreshBackendStatus();
    const reasons = [];
    const evidenceCount = (lastBackendStatus && typeof lastBackendStatus.evidenceItemsCount === 'number') ? lastBackendStatus.evidenceItemsCount : 0;
    const hashChainValid = lastBackendStatus ? !!lastBackendStatus.hashChainValid : true;

    if (!userPermissions.includes('export')) {
      reasons.push('Insufficient permissions');
    }
    if (tamperingDetected || !hashChainValid) {
      reasons.push('Integrity compromised');
    }
    if (evidenceCount <= 0) {
      reasons.push('No evidence available');
    }

    const ready = reasons.length === 0;
    return {
      ready,
      status: ready ? 'ready' : 'not_ready',
      reasons,
      evidenceCount,
      verificationStatus: (tamperingDetected || !hashChainValid) ? 'integrity_failed' : (evidenceCount > 0 ? 'available' : 'empty')
    };
  } catch (err) {
    console.error('get-export-readiness failed:', err);
    return {
      ready: false,
      status: 'not_ready',
      reasons: ['Backend status unavailable'],
      evidenceCount: 0,
      verificationStatus: 'unknown'
    };
  }
});

ipcMain.handle('check-for-updates', async () => {
  try {
    return checkOfflineUpdate();
  } catch (err) {
    return { available: false, reason: 'check_failed', message: err.message || 'Update check failed.' };
  }
});

ipcMain.handle('apply-update', async () => {
  try {
    const status = checkOfflineUpdate();
    if (!status.available || !status.packagePath) {
      return { success: false, message: 'No valid update package available.' };
    }
    const openResult = await shell.openPath(status.packagePath);
    if (openResult) {
      return { success: false, message: openResult };
    }
    return { success: true, message: 'Installer launched. Follow the installer prompts to complete the update.' };
  } catch (err) {
    return { success: false, message: err.message || 'Failed to launch update installer.' };
  }
});
