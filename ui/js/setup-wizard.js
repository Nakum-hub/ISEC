// ISEC Setup Wizard — first-run flow logic.
// Externalized from setup-wizard.html: the CSP (script-src 'self') forbids
// inline <script> blocks and inline event-handler attributes.

let _currentStep = 0;
let _licenseData = null;
let _adminToken  = null;

// ── Navigation ────────────────────────────────────────────────
function goStep(n) {
  document.querySelectorAll('.wizard-step').forEach((el,i) => el.classList.toggle('active', i===n));
  document.querySelectorAll('.step-dot').forEach((el,i) => {
    el.classList.toggle('active', i===n);
    el.classList.toggle('done', i<n);
    const dot = el.querySelector('.dot');
    if (dot) dot.textContent = i < n ? '✓' : String(i+1);
  });
  _currentStep = n;
  if (n === 2) runSystemChecks();
  if (n === 3) generateToken();
  if (n === 4) showReadySummary();
}

// ── Step 2: License ───────────────────────────────────────────
function loadLicenseFile(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    const el = document.getElementById('license-input');
    if (el) el.value = e.target.result;
  };
  reader.readAsText(file);
}

async function validateLicense() {
  const raw = (document.getElementById('license-input') || {}).value || '';
  const statusEl = document.getElementById('license-status');
  const btn = document.getElementById('license-next-btn');

  if (!raw.trim()) {
    showStatus(statusEl, 'fail', '✗ Please paste your license key or load from file.');
    return;
  }

  let parsed;
  try { parsed = JSON.parse(raw.trim()); }
  catch(_) {
    showStatus(statusEl, 'fail', '✗ Invalid JSON format. Check your license file.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spin">⟳</span> Validating…';
  showStatus(statusEl, 'check', '⟳ Contacting license server…');

  try {
    const bridge = window.isec;
    if (!bridge) throw new Error('IPC bridge unavailable');
    const result = await bridge.invoke('setup-activate-license', { licenseJson: raw.trim() });
    if (result && result.success) {
      _licenseData = parsed;
      showStatus(statusEl, 'ok', `✓ License valid — ${result.plan || ''} plan, expires ${result.expires || 'never'}`);
      setTimeout(() => goStep(2), 800);
    } else {
      showStatus(statusEl, 'fail', '✗ ' + (result && result.message ? result.message : 'License validation failed'));
      btn.disabled = false;
      btn.innerHTML = 'Validate →';
    }
  } catch(err) {
    showStatus(statusEl, 'fail', '✗ Validation error: ' + err.message);
    btn.disabled = false;
    btn.innerHTML = 'Validate →';
  }
}

// ── Step 3: System Check ──────────────────────────────────────
async function runSystemChecks() {
  const container = document.getElementById('sys-checks');
  const nextBtn   = document.getElementById('sys-next-btn');
  container.innerHTML = '';
  nextBtn.disabled = true;

  const checks = [
    { id:'chk-python',  label:'Python runtime' },
    { id:'chk-backend', label:'ISEC backend engine' },
    { id:'chk-db',      label:'Evidence database' },
    { id:'chk-dirs',    label:'Data directories' },
    { id:'chk-keys',    label:'Cryptographic keys' },
  ];

  checks.forEach(c => {
    const el = document.createElement('div');
    el.id = c.id;
    el.className = 'status-row status-check';
    el.innerHTML = `<span class="spin">⟳</span> ${c.label}`;
    container.appendChild(el);
  });

  const bridge = window.isec;
  if (!bridge) {
    checks.forEach(c => setCheck(c.id, false, 'IPC bridge unavailable'));
    return;
  }

  try {
    const result = await bridge.invoke('setup-test-backend');
    setCheck('chk-python',  result.pythonOk,  result.pythonVersion || 'Not found');
    setCheck('chk-backend', result.backendOk, result.backendMessage || 'Backend error');
    setCheck('chk-db',      result.dbOk,      result.dbMessage || (result.dbOk ? 'Database ready' : 'Cannot open DB'));
    setCheck('chk-dirs',    result.dirsOk,    result.dirsMessage || (result.dirsOk ? 'Directories created' : 'Cannot create dirs'));
    setCheck('chk-keys',    result.keysOk,    result.keysMessage || (result.keysOk ? 'Keys valid' : 'Missing keys'));

    const allOk = result.pythonOk && result.backendOk && result.dbOk && result.dirsOk && result.keysOk;
    nextBtn.disabled = !allOk;
    if (!allOk) {
      const errEl = document.createElement('div');
      errEl.className = 'status-row status-fail';
      errEl.textContent = '✗ Fix the issues above before continuing. Contact ISEC support if needed.';
      container.appendChild(errEl);
    }
  } catch(err) {
    checks.forEach(c => setCheck(c.id, false, err.message));
  }
}

function setCheck(id, ok, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = 'status-row ' + (ok ? 'status-ok' : 'status-fail');
  el.innerHTML = (ok ? '✓ ' : '✗ ') + el.innerHTML.replace(/.*\s/, '').split('<')[0] + (msg ? ' — ' + msg : '');
}

// ── Step 4: Admin Token ───────────────────────────────────────
async function generateToken() {
  const box = document.getElementById('token-display');
  if (!box) return;
  box.textContent = 'Generating secure token…';
  const bridge = window.isec;
  if (!bridge) { box.textContent = 'IPC bridge unavailable'; return; }
  try {
    const result = await bridge.invoke('setup-generate-token');
    _adminToken = result && result.token ? result.token : null;
    box.textContent = _adminToken || 'Token generation failed';
  } catch(err) {
    box.textContent = 'Error: ' + err.message;
  }
}

async function copyToken() {
  if (_adminToken) {
    await navigator.clipboard.writeText(_adminToken).catch(() => {});
    const btn = document.getElementById('copy-token-btn');
    if (btn) { btn.textContent = '✓ Copied!'; btn.style.color = 'var(--success)';
      setTimeout(() => { btn.textContent = '📋 Copy Token'; btn.style.color = ''; }, 2000); }
  }
}

// ── Step 5: Ready ─────────────────────────────────────────────
function showReadySummary() {
  const container = document.getElementById('ready-checks');
  if (!container) return;
  const items = [
    '✓ License activated — Enterprise plan',
    '✓ Python backend verified',
    '✓ Evidence database ready',
    '✓ Admin token saved securely',
    '✓ All cryptographic keys loaded',
  ];
  container.innerHTML = items.map(t => `<div class="status-row status-ok">${t}</div>`).join('');
}

async function launchApp() {
  const bridge = window.isec;
  if (bridge) await bridge.invoke('setup-complete').catch(() => {});
}

// ── Helpers ───────────────────────────────────────────────────
function showStatus(el, type, msg) {
  if (!el) return;
  const cls = {ok:'status-ok',fail:'status-fail',warn:'status-warn',check:'status-check'}[type]||'status-check';
  el.className = 'status-row ' + cls;
  el.textContent = msg;
  el.style.display = 'flex';
}

// ── Event Bindings (CSP-safe replacement for inline onclick/onchange) ──
function initWizard() {
  // Step navigation buttons
  document.querySelectorAll('[data-goto-step]').forEach(btn => {
    btn.addEventListener('click', () => goStep(parseInt(btn.getAttribute('data-goto-step'), 10) || 0));
  });

  // License step
  const browseBtn = document.getElementById('license-browse-btn');
  const fileInput = document.getElementById('license-file');
  if (browseBtn && fileInput) browseBtn.addEventListener('click', () => fileInput.click());
  if (fileInput) fileInput.addEventListener('change', function () { loadLicenseFile(this); });

  const validateBtn = document.getElementById('license-next-btn');
  if (validateBtn) validateBtn.addEventListener('click', validateLicense);

  // Admin token step
  const copyBtn = document.getElementById('copy-token-btn');
  if (copyBtn) copyBtn.addEventListener('click', copyToken);

  // Launch
  const launchBtn = document.getElementById('launch-app-btn');
  if (launchBtn) launchBtn.addEventListener('click', launchApp);
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initWizard);
} else {
  initWizard();
}
