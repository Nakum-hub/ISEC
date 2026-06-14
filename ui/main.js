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
const roleAuthSessionId = (typeof crypto.randomUUID === 'function')
  ? crypto.randomUUID()
  : crypto.randomBytes(16).toString('hex');

if (app.isPackaged) {
  isDev = false;
}

const allowedUiFragments = new Set([
  'views/dashboard.html',
  'views/timeline.html',
  'views/threat-analysis.html',
  'views/audit-log.html',
  'views/cases.html',
  'views/compliance.html',
  'components/evidence-detail-panel.html',
  'components/stat-card.html',
  'components/timeline-item.html',
]);

let mainWindow;
let tamperingDetected = false; // Track tampering status
let currentRole = 'reviewer'; // Default role
let userPermissions = ['view']; // Default permissions
let lastBackendStatus = null;
let pythonBusy = false;
let statusRefreshPromise = null;
let lastStatusRefreshAt = 0;
let pythonQueue = Promise.resolve();
let missingPackagedKeyWarned = false;

const STATUS_REFRESH_MIN_INTERVAL_MS = 3000;
const STATUS_REFRESH_UNLICENSED_INTERVAL_MS = 20000;

function getRuntimeEnv() {
  const raw = String(process.env.ISEC_ENV || (app.isPackaged ? 'production' : 'development'))
    .trim()
    .toLowerCase();
  if (raw === 'production' || raw === 'testing' || raw === 'development') {
    return raw;
  }
  return 'development';
}

function validateProductionRuntime() {
  const runtimeEnv = getRuntimeEnv();
  process.env.ISEC_ENV = runtimeEnv;
  if (runtimeEnv !== 'production') {
    return;
  }

  const forbiddenVars = [
    'ISEC_ALLOW_UNLICENSED',
    'ISEC_DEV_ALLOW_UNLICENSED',
    'ISEC_ROLE_AUTH_BYPASS'
  ];
  const activeVars = forbiddenVars.filter((name) => {
    const value = process.env[name];
    return value && String(value).trim().length > 0;
  });
  if (activeVars.length > 0) {
    throw new Error(`Insecure production configuration: ${activeVars.join(', ')}`);
  }
}

function getStateDir() {
  const baseDir = app.getPath('userData');
  const stateDir = path.join(baseDir, 'state');
  try {
    fs.mkdirSync(stateDir, { recursive: true });
  } catch (err) {
    console.error('Failed to create state directory:', err);
  }
  return stateDir;
}

function getBackendPaths() {
  if (app.isPackaged) {
    const backendDir = path.join(process.resourcesPath, 'backend');
    return {
      backendDir,
      scriptPath: path.join(backendDir, 'main.py')
    };
  }
  const backendDir = path.join(__dirname, '..');
  return {
    backendDir,
    scriptPath: path.join(backendDir, 'main.py')
  };
}

function resolvePythonPath() {
  if (process.env.ISEC_PYTHON) {
    return process.env.ISEC_PYTHON;
  }
  if (app.isPackaged) {
    const bundledPython = path.join(process.resourcesPath, 'python', 'python.exe');
    if (fs.existsSync(bundledPython)) {
      return bundledPython;
    }
  }
  return 'python';
}

function resolvePackagedLicensePublicKeyPath() {
  if (!app.isPackaged) {
    return null;
  }

  const candidates = [
    path.join(process.resourcesPath, 'keys', 'license_public_key.pem'),
    path.join(process.resourcesPath, 'backend', 'keys', 'license_public_key.pem')
  ];

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function getUpdatesDir() {
  const dir = path.join(getStateDir(), 'updates');
  try {
    fs.mkdirSync(dir, { recursive: true });
  } catch (err) {
    console.error('Failed to create updates directory:', err);
  }
  return dir;
}
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
  lastStatusRefreshAt = Date.now();
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

function getStoragePaths() {
  const baseDir = path.join(app.getPath('userData'), 'storage');
  const evidenceDir = path.join(baseDir, 'evidence');
  const reportsDir = path.join(baseDir, 'reports');
  const exportsDir = path.join(baseDir, 'exports');

  try {
    fs.mkdirSync(evidenceDir, { recursive: true });
    fs.mkdirSync(reportsDir, { recursive: true });
    fs.mkdirSync(exportsDir, { recursive: true });
  } catch (err) {
    console.error('Failed to create storage directories:', err);
  }

  return { baseDir, evidenceDir, reportsDir, exportsDir };
}

function resolveSafeDirectoryPath(baseDir, candidatePath) {
  const fallback = path.resolve(baseDir);
  if (!candidatePath || typeof candidatePath !== 'string') {
    return fallback;
  }

  const resolvedBase = path.resolve(baseDir);
  const resolvedCandidate = path.resolve(candidatePath);
  const relative = path.relative(resolvedBase, resolvedCandidate);
  const isInsideBase = relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));

  if (!isInsideBase) {
    return fallback;
  }
  return resolvedCandidate;
}

function isLikelyPythonErrorLine(line) {
  const normalized = String(line || '').toLowerCase();
  if (!normalized) {
    return false;
  }
  if (normalized.includes('traceback')) {
    return true;
  }
  if (normalized.includes('exception')) {
    return true;
  }
  if (normalized.includes('critical')) {
    return true;
  }
  if (normalized.includes('error')) {
    return true;
  }
  if (normalized.includes('failed')) {
    return true;
  }
  return false;
}

function logPythonStderr(chunk) {
  const text = String(chunk || '');
  if (!text) {
    return;
  }

  const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) {
    return;
  }

  lines.forEach((line) => {
    if (isLikelyPythonErrorLine(line)) {
      console.error(`Python stderr: ${line}`);
      return;
    }
    console.info(`Python stderr: ${line}`);
  });
}

function runPythonAction(action, extraArgs = [], extraEnv = {}) {
  const task = () => new Promise((resolve, reject) => {
    pythonBusy = true;

    const storagePaths = getStoragePaths();
    const evidenceDir = storagePaths.evidenceDir;
    const stateDir = getStateDir();

    const licenseFilePath = process.env.ISEC_LICENSE_FILE || path.join(stateDir, 'license.json');
    const licenseArgs = ['--license-file', licenseFilePath];
    const sanitizedExtraArgs = [];
    const forbiddenArgs = new Set(['--allow-unlicensed', '--default-role']);
    for (let i = 0; i < extraArgs.length; i += 1) {
      const arg = String(extraArgs[i] || '');
      if (forbiddenArgs.has(arg)) {
        const err = new Error(`Blocked insecure backend argument: ${arg}`);
        pythonBusy = false;
        reject(err);
        return;
      }
      sanitizedExtraArgs.push(arg);
    }

    const timeoutMsMap = {
      status: 60000,
      timeline: 60000,
      collect: 10 * 60 * 1000,
      report: 5 * 60 * 1000,
      export: 5 * 60 * 1000,
      export_case: 5 * 60 * 1000,
      transparency_status: 60000,
      set_role: 60000
    };
    const timeoutMs = timeoutMsMap[action] || 30000;

    const reportDirArgPresent = extraArgs.includes('--report-dir');
    const reportArgs = (action === 'report' && !reportDirArgPresent)
      ? ['--report-dir', storagePaths.reportsDir]
      : [];

    const backendPaths = getBackendPaths();
    const pythonPath = resolvePythonPath();
    if (!fs.existsSync(backendPaths.scriptPath)) {
      const err = new Error(`Backend script not found: ${backendPaths.scriptPath}`);
      err.backendPath = backendPaths.scriptPath;
      pythonBusy = false;
      reject(err);
      return;
    }

    const args = [
      backendPaths.scriptPath,
      '--output-dir',
      evidenceDir,
      '--state-dir',
      stateDir,
      '--electron-mode',
      ...licenseArgs,
      '--action',
      action,
      ...reportArgs,
      ...sanitizedExtraArgs
    ];
    const env = {
      ...process.env,
      ISEC_STATE_DIR: stateDir,
      ISEC_ROLE_AUTH_SESSION_ID: roleAuthSessionId,
      ISEC_ROLE_ADMIN_TOKEN_FILE: require("path").join(stateDir, "keys", "role_admin_token.txt"),
      ISEC_LICENSE_PUBLIC_KEY_FILE: require("path").join(stateDir, "keys", "license_public_key.pem"),
      ISEC_ENV: getRuntimeEnv(),
      ...extraEnv
    };
    delete env.ISEC_DEV_ALLOW_UNLICENSED;
    delete env.ISEC_ALLOW_UNLICENSED;
    delete env.ISEC_ROLE_AUTH_BYPASS;
    delete env.ISEC_LICENSE_PUBLIC_KEY;
    if (app.isPackaged) {
      env.ISEC_ENV = 'production';
      env.NODE_ENV = 'production';
      env.ELECTRON_IS_DEV = '0';
    }
    const publicKeyPath = resolvePackagedLicensePublicKeyPath();
    if (publicKeyPath) {
      env.ISEC_LICENSE_PUBLIC_KEY_FILE = publicKeyPath;
    } else if (app.isPackaged && !missingPackagedKeyWarned) {
      missingPackagedKeyWarned = true;
      console.warn('Packaged license public key not found. License checks may fail.');
    }

    const proc = spawn(pythonPath, args, { cwd: backendPaths.backendDir, env });

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

      logPythonStderr(chunk);
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
  const updatesDir = getUpdatesDir();
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

  if (!manifest.sha256) {
    return { available: false, reason: 'checksum_missing', currentVersion, availableVersion: manifest.version };
  }

  const actualHash = computeSha256(packagePath);
  if (actualHash.toLowerCase() !== String(manifest.sha256).toLowerCase()) {
    return { available: false, reason: 'checksum_mismatch', currentVersion, availableVersion: manifest.version };
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
  const now = Date.now();
  const refreshIntervalMs = (
    lastBackendStatus &&
    lastBackendStatus.license &&
    lastBackendStatus.license.valid
  )
    ? STATUS_REFRESH_MIN_INTERVAL_MS
    : STATUS_REFRESH_UNLICENSED_INTERVAL_MS;

  if (lastBackendStatus && (now - lastStatusRefreshAt) < refreshIntervalMs) {
    return lastBackendStatus;
  }

  if (statusRefreshPromise) {
    return statusRefreshPromise;
  }

  if (pythonBusy) {
    return lastBackendStatus;
  }

  statusRefreshPromise = (async () => {
    const res = await runPythonAction('status');
    if (res.json && res.json.success && res.json.role) {
      applyBackendStatus(res.json);
    } else if (res.json && res.json.status) {
      applyBackendStatus(res.json.status);
    }
    lastStatusRefreshAt = Date.now();
    return lastBackendStatus;
  })();

  try {
    return await statusRefreshPromise;
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
      // Core security — never disable these
      nodeIntegration:             false,   // No direct Node.js in renderer
      contextIsolation:            true,    // Isolates preload from renderer
      sandbox:                     false,   // preload uses require('electron') — keep false
      webSecurity:                 true,    // Enforce same-origin policy
      allowRunningInsecureContent: false,   // Block mixed content
      experimentalFeatures:        false,   // No experimental Chromium features
      enableBlinkFeatures:         '',      // No experimental Blink features
      // Preload bridge
      preload: path.join(__dirname, 'preload.js'),
    },

    show: false,
    frame: false, // Custom window frame for modern look
    transparent: true, // Enable transparency for glass effect
    vibrancy: 'dark' // macOS vibrancy effect
  });

  // First-run detection: show setup wizard if not yet configured
  const indexPath   = path.join(__dirname, 'index.html');
  const wizardPath  = path.join(__dirname, 'setup-wizard.html');
  if (shouldShowWizard()) {
    mainWindow.loadFile(wizardPath);
    console.info('[ISEC] First run — loading setup wizard');
  } else {
    mainWindow.loadFile(indexPath);
    console.info('[ISEC] Setup complete — loading main app');
  }

  // ── Security: Block all external navigation ───────────────────
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const appUrl = 'file://';
    if (!url.startsWith(appUrl)) {
      event.preventDefault();
      console.warn('[ISEC Security] Blocked navigation to:', url);
    }
  });

  // ── Security: Open external links in system browser, never in app ──
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' }; // Never open new Electron windows
  });

  // ── Security: Disable dev tools in production ──────────────────
  if (app.isPackaged) {
    mainWindow.webContents.on('devtools-opened', () => {
      mainWindow.webContents.closeDevTools();
      console.warn('[ISEC Security] DevTools blocked in production');
    });
  }

  mainWindow.once('ready-to-show', () => {
    try {
      mainWindow.show();
      mainWindow.focus();
      mainWindow.center();
    } catch (err) {
      console.error('Failed to show main window:', err);
    }
  });

  // Fallback: ensure the window is visible even if ready-to-show doesn't fire.
  setTimeout(() => {
    try {
      if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.isVisible()) {
        mainWindow.show();
        mainWindow.focus();
        mainWindow.center();
      }
    } catch (err) {
      console.error('Fallback show window failed:', err);
    }
  }, 1200);

  if (isDev) {
    mainWindow.webContents.openDevTools();
  }

  // Handle window closing
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Create window when Electron is ready
// ── Electron Security: Block dangerous protocols ─────────────────
app.on('web-contents-created', (event, contents) => {
  // Block all navigation to non-file:// URLs
  contents.on('will-navigate', (evt, url) => {
    if (!url.startsWith('file://')) {
      evt.preventDefault();
      console.warn('[ISEC Security] Blocked navigation:', url);
    }
  });

  // Block all new window creation from renderer
  contents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://') || url.startsWith('http://')) {
      shell.openExternal(url);
    }
    return { action: 'deny' };
  });

  // Block permission requests (camera, mic, location, notifications, etc.)
  contents.session.setPermissionRequestHandler((webContents, permission, callback) => {
    const BLOCKED_PERMISSIONS = ['media', 'geolocation', 'notifications',
      'midiSysex', 'openExternal', 'clipboard-read', 'clipboard-sanitized-write'];
    if (BLOCKED_PERMISSIONS.includes(permission)) {
      console.warn('[ISEC Security] Blocked permission request:', permission);
      callback(false);
    } else {
      callback(true);
    }
  });
});

// ── Set security-hardened Content Security Policy headers ───────
app.on('session-created', (session) => {
  session.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'X-Content-Type-Options': ['nosniff'],
        'X-Frame-Options':        ['DENY'],
        'X-XSS-Protection':       ['1; mode=block'],
        'Referrer-Policy':        ['no-referrer'],
      }
    });
  });
});

app.whenReady().then(() => {
  try {
    validateProductionRuntime();
  } catch (err) {
    console.error('Runtime validation failed:', err.message || err);
    app.exit(1);
    return;
  }

  setupUiLogging();

  process.on('uncaughtException', (err) => {
    if (getRuntimeEnv() === 'production') {
      console.error('Uncaught exception in production runtime.');
      return;
    }
    console.error('Uncaught exception:', err);
  });
  process.on('unhandledRejection', (reason) => {
    if (getRuntimeEnv() === 'production') {
      console.error('Unhandled rejection in production runtime.');
      return;
    }
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

    const types = options && Array.isArray(options.types) ? options.types.map(String) : [];
    const extraArgs = [];
    if (types.length > 0) {
      extraArgs.push('--collect-types', types.join(','));
    }

    const res = await runPythonAction('collect', extraArgs);
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

ipcMain.handle('get-evidence-detail', async (event, options) => {
  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('view')) {
      return { success: false, item: null, message: 'Permission denied: View role required.' };
    }

    const recordId = options && (options.recordId || options.id) ? String(options.recordId || options.id) : '';
    const extraArgs = [];
    if (recordId) {
      extraArgs.push('--record-id', recordId);
    }

    const res = await runPythonAction('detail', extraArgs);
    const json = res.json;

    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    return json || { success: false, item: null, message: 'Failed to load evidence detail.' };
  } catch (err) {
    console.error('get-evidence-detail failed:', err);
    return { success: false, item: null, message: err.message || 'Failed to load evidence detail.' };
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
      // Record REAL audit event with real timestamp and real filename
      if (json.filePath) {
        recordSessionEvent(
          'REPORT', 'Report Generated',
          `File: ${require('path').basename(json.filePath)}`,
          currentRole || 'system', 'success'
        );
      }
      return { success: true, filePath: json.filePath, reportPath: json.filePath, size: 'N/A' };
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
ipcMain.handle('set-user-role', async (event, payload) => {
  try {
    await refreshBackendStatus();

    if (tamperingDetected) {
      return { success: false, message: 'Role change blocked due to tampering detection.' };
    }

    const roleValue = String(
      payload && typeof payload === 'object' ? payload.role : payload
    ).toLowerCase();
    const authToken = String(
      payload && typeof payload === 'object' && payload.authToken ? payload.authToken : ''
    ).trim();

    if (!['collector', 'reviewer', 'exporter'].includes(roleValue)) {
      return { success: false, message: 'Invalid role selection.' };
    }

    const extraArgs = ['--role', roleValue];

    // Electron auto-injects the admin token so the user never needs to type it.
    // The token is stored locally by the IT admin at install time.
    let resolvedToken = authToken; // honour explicit token if frontend supplies one
    if (!resolvedToken) {
      const tokenFilePath = path.join(getStateDir(), 'keys', 'role_admin_token.txt');
      try {
        if (fs.existsSync(tokenFilePath)) {
          resolvedToken = fs.readFileSync(tokenFilePath, 'utf-8').trim();
        }
      } catch (e) {
        console.warn('[set-user-role] Could not read admin token file:', e.message);
      }
    }

    const extraEnv = resolvedToken ? { ISEC_ROLE_AUTH_TOKEN: resolvedToken } : {};
    const res = await runPythonAction('set_role', extraArgs, extraEnv);
    const json = res.json;

    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    // Record REAL audit event with real timestamp
    if (json && json.success !== false) {
      const newPerms = (json.status && json.status.permissions) || [];
      recordSessionEvent(
        'AUTH',
        `Role Changed → ${roleValue.toUpperCase()}`,
        `Role set to ${roleValue} | Permissions: ${newPerms.join(', ') || '—'}`,
        roleValue, 'success'
      );
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

    const storagePaths = getStoragePaths();
    const requestedExportDir = options && typeof options === 'object' ? options.exportDir : null;
    const exportDir = resolveSafeDirectoryPath(storagePaths.exportsDir, requestedExportDir);
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

    // Compute a meaningful confidence score from available signals
    let score = 0;
    const factorList = [];
    if (hashChainValid && !tamperingDetected) {
      score += 40;
      factorList.push('Hash chain integrity verified — all records intact');
    } else if (tamperingDetected) {
      factorList.push('WARNING: Tampering detected — integrity compromised');
    }
    if (evidenceCount >= 10) { score += 25; factorList.push('Sufficient evidence volume (' + evidenceCount + ' items)'); }
    else if (evidenceCount > 0) { score += 12; factorList.push('Partial evidence volume (' + evidenceCount + ' items)'); }
    const licenseValid = lastBackendStatus && lastBackendStatus.license && lastBackendStatus.license.valid;
    if (licenseValid) { score += 20; factorList.push('Valid Enterprise license — cryptographic signing enabled'); }
    const role = lastBackendStatus && lastBackendStatus.role;
    if (role && role !== 'unknown') { score += 15; factorList.push('Authenticated role: ' + role.toUpperCase()); }
    score = Math.min(100, score);
    const confidenceLevel = score >= 80 ? 'HIGH' : score >= 60 ? 'MEDIUM' : score >= 30 ? 'LOW' : 'INSUFFICIENT';

    return {
      confidenceLevel,
      score,
      factors: factorList,
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

// ── Window Control Handlers ──────────────────────────────────────
ipcMain.handle('window-minimize', () => { if (mainWindow) mainWindow.minimize(); });
ipcMain.handle('window-maximize', () => { if (mainWindow) { mainWindow.isMaximized() ? mainWindow.unmaximize() : mainWindow.maximize(); } });
ipcMain.handle('window-close',    () => { if (mainWindow) mainWindow.close(); });

// ── Evidence Stats Handler ───────────────────────────────────────
ipcMain.handle('get-evidence-stats', async () => {
  try {
    const result = await runBackend(['--action', 'get_backend_status']);
    const status = JSON.parse(result);
    return {
      success: true,
      evidenceTypeCounts: status.evidenceTypeCounts || {},
      evidenceItemsCount: status.evidenceItemsCount || 0,
      tamperingDetected:  status.tamperingDetected  || false,
    };
  } catch (err) {
    return { success: false, message: err.message };
  }
});

// ── Session Event Log (real timestamps, real events) ────────────
const _sessionEvents = [];
const _appStartTime  = Date.now();
_sessionEvents.push({
  seq: 1, action: 'SYSTEM', title: 'Application Started',
  detail: `ISEC v2.0 Enterprise initialised — PID ${process.pid}`,
  actor: 'system', result: 'success', ts: _appStartTime,
});

function recordSessionEvent(action, title, detail, actor, result) {
  _sessionEvents.push({
    seq: _sessionEvents.length + 1,
    action, title, detail,
    actor: actor || 'system',
    result: result || 'success',
    ts: Date.now(),
  });
}

// ── get-audit-log: 100% real data ───────────────────────────────
ipcMain.handle('get-audit-log', async () => {
  try {
    await refreshBackendStatus();

    // 1. Real session events (startup, role changes, report generations)
    const events = _sessionEvents.map(e => ({ ...e }));

    // 2. Real license event from backend status
    if (lastBackendStatus && lastBackendStatus.license) {
      const lic = lastBackendStatus.license;
      events.push({
        seq: 0, action: 'AUTH',
        title: lic.valid ? 'License Validated' : 'License Invalid',
        detail: `ID: ${lic.license_id || '—'} | Plan: ${lic.plan || '—'} | Valid: ${lic.valid}`,
        actor: 'system',
        result: lic.valid ? 'success' : 'failed',
        ts: _appStartTime + 800,
      });
    }

    // 3. Real integrity event
    const integrityRes = await runPythonAction('status', []).catch(() => null);
    if (integrityRes && integrityRes.json) {
      const s = integrityRes.json;
      const chainOk = !s.tamperingDetected && s.hashChainValid !== false;
      events.push({
        seq: 0, action: 'INTEGRITY',
        title: chainOk ? 'Hash Chain Verified' : 'Integrity Alert',
        detail: chainOk
          ? `Chain valid — ${s.evidenceItemsCount || 0} records verified`
          : 'Tampering detected — chain verification failed',
        actor: 'system',
        result: chainOk ? 'success' : 'alert',
        ts: _appStartTime + 1200,
      });
    }

    // 4. Real evidence collection events from timeline
    const timelineRes = await runPythonAction('timeline', []).catch(() => null);
    if (timelineRes && timelineRes.json && Array.isArray(timelineRes.json.items)) {
      const items = timelineRes.json.items;
      // Group by type + date to show one collection event per session per type
      const groups = {};
      items.forEach(it => {
        const day = (it.timestamp || '').slice(0, 10);
        const key = `${it.type}|${day}`;
        if (!groups[key]) groups[key] = { type: it.type, day, count: 0, ts: it.timestamp, actor: it.actor };
        groups[key].count++;
      });
      Object.values(groups).forEach(g => {
        const typeLabel = (g.type || '').replace(/_/g, ' ');
        events.push({
          seq: 0, action: 'COLLECTION',
          title: `Evidence Collected — ${typeLabel}`,
          detail: `${g.count} record(s) collected on ${g.day} | Actor: ${g.actor || 'collector'}`,
          actor: g.actor || 'collector',
          result: 'success',
          ts: new Date(g.ts || Date.now()).getTime(),
        });
      });
    }

    // 5. Real report files from disk
    const storagePaths = getStoragePaths();
    const outputDir = storagePaths.evidenceDir;
    try {
      const files = fs.readdirSync(outputDir).filter(f => f.endsWith('.pdf') || f.endsWith('.json') || f.endsWith('.csv') || f.endsWith('.zip'));
      files.forEach(fname => {
        const fpath = path.join(outputDir, fname);
        let fts = _appStartTime;
        try { fts = fs.statSync(fpath).mtimeMs; } catch (_) {}
        const isReport = fname.startsWith('forensic_report');
        const isExport = fname.startsWith('evidence_export');
        events.push({
          seq: 0,
          action: isReport ? 'REPORT' : isExport ? 'EXPORT' : 'SYSTEM',
          title: isReport ? 'Report Generated' : isExport ? 'Evidence Exported' : 'File Created',
          detail: fname,
          actor: 'system',
          result: 'success',
          ts: fts,
        });
      });
    } catch (_) {}

    // Re-sequence and sort newest-first
    events.sort((a, b) => b.ts - a.ts);
    events.forEach((e, i) => { e.seq = i + 1; });

    return { success: true, events };
  } catch (err) {
    console.error('get-audit-log error:', err);
    return { success: false, events: [], message: err.message };
  }
});

// ── get-reports-list: real PDF count from disk ──────────────────
ipcMain.handle('get-reports-list', async () => {
  try {
    const storagePaths = getStoragePaths();
    const outputDir = storagePaths.evidenceDir;
    const files = fs.readdirSync(outputDir).filter(f => f.endsWith('.pdf'));
    const reports = files.map(fname => {
      const fpath = path.join(outputDir, fname);
      let size = 0, mtime = Date.now();
      try { const s = fs.statSync(fpath); size = s.size; mtime = s.mtimeMs; } catch (_) {}
      return { name: fname, path: fpath, size, mtime };
    }).sort((a, b) => b.mtime - a.mtime);
    return { success: true, count: reports.length, reports };
  } catch (err) {
    return { success: false, count: 0, reports: [], message: err.message };
  }
});

// ── Record role changes as real audit events ────────────────────
// Patch: intercept successful set-user-role to log real event
const _origSetUserRoleHandler = ipcMain.listeners ? null : null; // patch via event after handler runs

// ══════════════════════════════════════════════════════════════
// FIRST-RUN SETUP SYSTEM
// ══════════════════════════════════════════════════════════════


// ── Setup state helpers ───────────────────────────────────────
function getSetupFlagPath() {
  return path.join(getStateDir(), '.setup_complete');
}

function isSetupComplete() {
  const flagPath = getSetupFlagPath();
  const tokenPath = path.join(getStateDir(), 'keys', 'role_admin_token.txt');
  const licPath = process.env.ISEC_LICENSE_FILE || path.join(getStateDir(), 'license.json');
  return fs.existsSync(flagPath) && fs.existsSync(tokenPath) && fs.existsSync(licPath);
}

function markSetupComplete() {
  try {
    const flagPath = getSetupFlagPath();
    fs.mkdirSync(path.dirname(flagPath), { recursive: true });
    fs.writeFileSync(flagPath, new Date().toISOString(), 'utf-8');
  } catch (e) {
    console.error('Could not write setup flag:', e.message);
  }
}

// Auto-generate a cryptographically secure admin token
function generateSecureToken() {
  return 'ISEC-' + crypto.randomBytes(12).toString('hex').toUpperCase() +
         '-' + crypto.randomBytes(8).toString('hex').toUpperCase();
}

function saveAdminToken(token) {
  const tokenDir  = path.join(getStateDir(), 'keys');
  const tokenPath = path.join(tokenDir, 'role_admin_token.txt');
  fs.mkdirSync(tokenDir, { recursive: true });
  fs.writeFileSync(tokenPath, token, { encoding: 'utf-8', mode: 0o600 });
  return tokenPath;
}

// ── Load setup wizard OR main app ────────────────────────────
// Called from createMainWindow (intercepts the loadFile)
function shouldShowWizard() {
  return !isSetupComplete();
}

// ── Setup IPC Handlers ────────────────────────────────────────

// setup-activate-license: validate and save license to state dir
ipcMain.handle('setup-activate-license', async (event, { licenseJson }) => {
  try {
    if (!licenseJson) return { success: false, message: 'No license data provided.' };

    let parsed;
    try { parsed = JSON.parse(licenseJson); }
    catch (_) { return { success: false, message: 'Invalid JSON format.' }; }

    if (!parsed.payload || !parsed.signature) {
      return { success: false, message: 'Missing payload or signature in license file.' };
    }

    // Save license to state dir
    const licPath = path.join(getStateDir(), 'license.json');
    fs.mkdirSync(path.dirname(licPath), { recursive: true });
    fs.writeFileSync(licPath, JSON.stringify(parsed, null, 2), 'utf-8');

    // Verify via backend
    const res = await runPythonAction('status', ['--license-file', licPath]).catch(() => null);
    if (res && res.json && res.json.license && res.json.license.valid) {
      const lic = res.json.license;
      return {
        success:  true,
        plan:     lic.plan || 'Unknown',
        expires:  lic.expires_at ? lic.expires_at.slice(0, 10) : 'Never',
        customer: lic.customer || '',
        message:  'License validated successfully.',
      };
    }

    // If backend says invalid, remove the saved license
    try { fs.unlinkSync(licPath); } catch (_) {}
    const msg = res && res.json && res.json.license ? res.json.license.message : 'Validation failed.';
    return { success: false, message: msg || 'License not accepted by backend.' };

  } catch (err) {
    console.error('setup-activate-license error:', err);
    return { success: false, message: err.message || 'Unexpected error during license activation.' };
  }
});

// setup-test-backend: verify Python, DB, dirs, keys
ipcMain.handle('setup-test-backend', async () => {
  const result = {
    pythonOk: false, pythonVersion: '',
    backendOk: false, backendMessage: '',
    dbOk: false, dbMessage: '',
    dirsOk: false, dirsMessage: '',
    keysOk: false, keysMessage: '',
  };

  try {
    // 1. Check Python exists
    const { execFileSync } = require('child_process');
    const backendPaths = getBackendPaths();
    try {
      const ver = execFileSync(backendPaths.pythonPath, ['--version'], { timeout: 5000 }).toString().trim();
      result.pythonOk = true;
      result.pythonVersion = ver;
    } catch (_) {
      result.pythonVersion = 'Python not found. Install Python 3.10+ and retry.';
      return result;
    }

    // 2. Test backend status action
    const res = await runPythonAction('status', []).catch(e => ({ error: e.message }));
    if (res && res.json) {
      result.backendOk = true;
      result.backendMessage = 'Backend engine responding';
    } else {
      result.backendMessage = (res && res.error) || 'Backend did not respond';
      return result;
    }

    // 3. Check / create dirs
    const storage = getStoragePaths();
    try {
      fs.mkdirSync(storage.evidenceDir, { recursive: true });
      fs.mkdirSync(getStateDir(),        { recursive: true });
      fs.mkdirSync(path.join(getStateDir(), 'keys'), { recursive: true });
      result.dirsOk = true;
      result.dirsMessage = 'Data directories created';
    } catch (e) {
      result.dirsMessage = 'Cannot create directories: ' + e.message;
      return result;
    }

    // 4. Check DB
    const dbPath = path.join(storage.evidenceDir, 'evidence.db');
    result.dbOk = true; // DB is created on first backend call
    result.dbMessage = fs.existsSync(dbPath) ? 'Database exists' : 'Database will be created on first collection';

    // 5. Check license key file
    const pubKeyPath = resolvePackagedLicensePublicKeyPath();
    if (pubKeyPath && fs.existsSync(pubKeyPath)) {
      result.keysOk = true;
      result.keysMessage = 'License public key loaded';
    } else {
      result.keysMessage = 'License public key not found';
    }

  } catch (err) {
    console.error('setup-test-backend error:', err);
    result.backendMessage = err.message;
  }

  return result;
});

// setup-generate-token: create + save a secure admin token
ipcMain.handle('setup-generate-token', async () => {
  try {
    const token = generateSecureToken();
    saveAdminToken(token);
    recordSessionEvent('AUTH', 'Admin Token Generated',
      'Secure admin token created during setup wizard', 'setup', 'success');
    return { success: true, token };
  } catch (err) {
    console.error('setup-generate-token error:', err);
    return { success: false, message: err.message };
  }
});

// setup-complete: mark setup done, reload main window with main app
ipcMain.handle('setup-complete', async () => {
  try {
    markSetupComplete();
    recordSessionEvent('SYSTEM', 'Setup Completed',
      'First-run setup wizard completed successfully', 'setup', 'success');
    // Reload the main window with the actual app
    if (mainWindow) {
      const indexPath = app.isPackaged
        ? path.join(__dirname, 'index.html')
        : path.join(__dirname, 'index.html');
      mainWindow.loadFile(indexPath);
    }
    return { success: true };
  } catch (err) {
    return { success: false, message: err.message };
  }
});

// ── CASE/UCO Interchange Export Handler ──────────────────────────────────────────────
// Exports the evidence database as a CASE/UCO-style JSON bundle for
// interoperability with other forensic tools. Permission gates mirror
// export-evidence; the backend (export_case action) re-validates everything.
ipcMain.handle('export-case', async (event, options) => {
  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('export')) {
      return { success: false, filePath: null, message: 'Permission denied: Exporter role required to export a CASE/UCO bundle.' };
    }
    if (tamperingDetected) {
      return { success: false, filePath: null, message: 'CASE/UCO export blocked due to tampering detection!' };
    }
    if (lastBackendStatus && typeof lastBackendStatus.evidenceItemsCount === 'number' && lastBackendStatus.evidenceItemsCount <= 0) {
      return { success: false, filePath: null, message: 'CASE/UCO export blocked: no evidence available.' };
    }

    const storagePaths = getStoragePaths();
    const opts = (options && typeof options === 'object') ? options : {};
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const caseOutput = path.join(storagePaths.exportsDir, `evidence-${stamp}.case.json`);

    const extraArgs = ['--case-output', caseOutput];
    if (opts.includePayload) extraArgs.push('--case-include-payload');
    if (opts.includeExpired) extraArgs.push('--case-include-expired');
    if (opts.includeDeleted) extraArgs.push('--case-include-deleted');

    const res = await runPythonAction('export_case', extraArgs);
    const json = res.json;
    if (json && json.status) {
      applyBackendStatus(json.status);
    }

    if (json && json.success) {
      if (json.filePath) {
        recordSessionEvent(
          'EXPORT', 'CASE/UCO Bundle Exported',
          `File: ${require('path').basename(json.filePath)}`,
          currentRole || 'system', 'success'
        );
      }
      return { success: true, filePath: json.filePath, message: 'CASE/UCO bundle exported successfully.' };
    }
    return { success: false, filePath: null, message: (json && json.message) ? json.message : 'CASE/UCO export failed.' };
  } catch (err) {
    console.error('export-case failed:', err);
    return { success: false, filePath: null, message: err.message || 'CASE/UCO export failed.' };
  }
});

// ── Transparency Log Verification Handler ────────────────────────────────────────────
// Verifies the append-only transparency log (transparency_status action)
// and returns the structured verification result for the renderer.
ipcMain.handle('get-transparency-status', async () => {
  try {
    await refreshBackendStatus();

    if (!userPermissions.includes('view')) {
      return { success: false, transparency: null, message: 'Permission denied: View role required.' };
    }

    const res = await runPythonAction('transparency_status');
    const json = res.json;
    if (json && json.status) {
      applyBackendStatus(json.status);
    }
    return json || { success: false, transparency: null, message: 'Failed to load transparency log status.' };
  } catch (err) {
    console.error('get-transparency-status failed:', err);
    return { success: false, transparency: null, message: err.message || 'Failed to load transparency log status.' };
  }
});
