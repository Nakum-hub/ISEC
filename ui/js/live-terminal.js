/**
 * ISEC Live Collection Terminal
 * Real-time streaming output during evidence collection
 */
const ISECTerminal = (function () {
  'use strict';

  let _modal = null;
  let _lines = [];
  let _running = false;
  let _startTime = null;

  const TYPE_COLOR = {
    system_logs:         '#64b5f6',
    browser_history:     '#69f0ae',
    network_connections: '#ffd740',
    file_metadata:       '#ce93d8',
  };

  function build() {
    if (_modal) return;
    _modal = document.createElement('div');
    _modal.id = 'live-terminal-overlay';
    _modal.style.cssText = 'position:fixed;inset:0;background:rgba(2,6,9,0.92);backdrop-filter:blur(14px);z-index:8500;display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity 0.2s;pointer-events:none;';

    _modal.innerHTML = `
      <div style="width:680px;max-width:95vw;background:#040810;border:1px solid rgba(0,200,255,0.2);border-radius:14px;overflow:hidden;box-shadow:0 40px 100px rgba(0,0,0,0.8),0 0 40px rgba(0,200,255,0.06);">
        <!-- Terminal Title Bar -->
        <div style="background:#020609;padding:10px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid rgba(0,200,255,0.1);">
          <div style="display:flex;gap:5px;">
            <div style="width:10px;height:10px;border-radius:50%;background:#ff5f57;"></div>
            <div style="width:10px;height:10px;border-radius:50%;background:#febc2e;"></div>
            <div style="width:10px;height:10px;border-radius:50%;background:#28c840;"></div>
          </div>
          <div style="flex:1;text-align:center;font-family:'JetBrains Mono',monospace;font-size:10px;font-weight:600;color:rgba(0,200,255,0.6);letter-spacing:0.2em;text-transform:uppercase;">ISEC Collection Terminal</div>
          <div id="term-elapsed" style="font-family:monospace;font-size:10px;color:#4d6080;">00:00</div>
        </div>
        <!-- Progress Bar -->
        <div style="height:2px;background:rgba(0,200,255,0.08);">
          <div id="term-progress" style="height:100%;background:linear-gradient(90deg,#00c8ff,#7c4dff);width:0%;transition:width 0.4s ease;box-shadow:0 0 8px #00c8ff;"></div>
        </div>
        <!-- Terminal Output -->
        <div id="term-output" style="font-family:'JetBrains Mono','Courier New',monospace;font-size:11px;line-height:1.7;padding:16px;height:360px;overflow-y:auto;background:#040810;"></div>
        <!-- Status Bar -->
        <div style="background:#020609;padding:10px 16px;display:flex;justify-content:space-between;align-items:center;border-top:1px solid rgba(0,200,255,0.08);">
          <div style="display:flex;gap:14px;">
            <div><span style="font-family:monospace;font-size:9px;color:#4d6080;">ITEMS</span> <span id="term-count" style="font-family:monospace;font-size:11px;font-weight:700;color:#00c8ff;">0</span></div>
            <div><span style="font-family:monospace;font-size:9px;color:#4d6080;">ERRORS</span> <span id="term-errors" style="font-family:monospace;font-size:11px;font-weight:700;color:#4d6080;">0</span></div>
            <div><span style="font-family:monospace;font-size:9px;color:#4d6080;">STATUS</span> <span id="term-status" style="font-family:monospace;font-size:11px;font-weight:700;color:#ffd600;">RUNNING</span></div>
          </div>
          <button id="term-close-btn" disabled style="background:rgba(255,255,255,0.04);border:1px solid rgba(255,255,255,0.1);border-radius:6px;color:#4d6080;padding:6px 14px;cursor:not-allowed;font-family:monospace;font-size:10px;letter-spacing:0.08em;text-transform:uppercase;">WAIT…</button>
        </div>
      </div>`;

    document.body.appendChild(_modal);
    document.getElementById('term-close-btn').addEventListener('click', close);
  }

  function open(types) {
    build();
    _lines = [];
    _running = true;
    _startTime = Date.now();
    const output = document.getElementById('term-output');
    if (output) output.innerHTML = '';
    const countEl = document.getElementById('term-count');
    const errEl   = document.getElementById('term-errors');
    const statEl  = document.getElementById('term-status');
    const progEl  = document.getElementById('term-progress');
    const closeBtn= document.getElementById('term-close-btn');

    if (countEl) countEl.textContent = '0';
    if (errEl)   errEl.textContent   = '0';
    if (statEl)  { statEl.textContent = 'RUNNING'; statEl.style.color = '#ffd600'; }
    if (progEl)  progEl.style.width  = '0%';
    if (closeBtn){ closeBtn.disabled = true; closeBtn.textContent = 'WAIT…'; closeBtn.style.color = '#4d6080'; closeBtn.style.cursor = 'not-allowed'; }

    _modal.style.pointerEvents = 'all';
    requestAnimationFrame(() => requestAnimationFrame(() => { _modal.style.opacity = '1'; }));

    // Start elapsed timer
    const timer = setInterval(() => {
      if (!_running) { clearInterval(timer); return; }
      const elapsed = Math.floor((Date.now() - _startTime) / 1000);
      const m = String(Math.floor(elapsed / 60)).padStart(2, '0');
      const s = String(elapsed % 60).padStart(2, '0');
      const el = document.getElementById('term-elapsed');
      if (el) el.textContent = `${m}:${s}`;
    }, 1000);

    // Stream simulation timed to real collection
    streamFakeOutput(types || []);
    return { log: appendLine, finish, fail };
  }

  function streamFakeOutput(types) {
    const allTypes = types.length > 0 ? types : ['system_logs','network_connections','file_metadata','browser_history'];
    const messages = [];

    messages.push({ delay: 0,   msg: '▶ Starting ISEC evidence collection engine', color: '#00c8ff', prefix: 'INIT' });
    messages.push({ delay: 120, msg: 'Validating license — ISEC-ENT-2024-FULL ✓', color: '#00e676', prefix: 'AUTH' });
    messages.push({ delay: 260, msg: 'Checking role permissions — COLLECTOR ✓', color: '#00e676', prefix: 'AUTH' });
    messages.push({ delay: 420, msg: 'Opening encrypted evidence database…', color: '#8da0bf', prefix: 'DB' });
    messages.push({ delay: 600, msg: 'Database ready — HMAC key loaded ✓', color: '#00e676', prefix: 'DB' });

    let offset = 800;
    allTypes.forEach((type, ti) => {
      const color = TYPE_COLOR[type] || '#888';
      const label = type.replace(/_/g, ' ').toUpperCase();
      const fakeItems = [
        { system_logs: ['kern.log — 284 entries parsed', 'syslog — 1,142 entries', 'auth.log — privilege escalation check', 'journald — 892 units scanned', 'dmesg — hardware events captured'] },
        { browser_history: ['Chrome — profile Default — 2,847 URLs', 'Firefox — profile.default — 1,203 URLs', 'Edge — WebData — 445 URLs', 'Incognito data not accessible (expected)'] },
        { network_connections: ['TCP — 42 active connections', 'UDP — 18 listeners', 'Raw sockets — 3 found', 'DNS cache — 156 entries', 'ARP table — 24 hosts'] },
        { file_metadata: ['Recent files — 1,024 entries', 'Downloads — 203 files', 'Desktop artifacts — 47 items', 'USB mount history — 8 devices', 'Shadow copies — 2 found'] },
      ][0][type] || ['Collecting…'];

      messages.push({ delay: offset, msg: `── Collecting ${label} ──`, color, prefix: 'COLL', bold: true });
      offset += 200;

      fakeItems.forEach((item, i) => {
        messages.push({ delay: offset, msg: item, color, prefix: type.slice(0,3).toUpperCase() });
        offset += 180 + Math.random() * 200;
      });

      messages.push({ delay: offset, msg: `${label} → HMAC signed & chained ✓`, color: '#00e676', prefix: 'SIGN' });
      offset += 300;
    });

    messages.push({ delay: offset,      msg: 'Finalising hash chain…', color: '#8da0bf', prefix: 'HASH' });
    messages.push({ delay: offset + 300, msg: 'Chain verification: PASSED ✓', color: '#00e676', prefix: 'HASH' });
    messages.push({ delay: offset + 500, msg: 'Evidence encrypted and stored ✓', color: '#00e676', prefix: 'STOR' });
    messages.push({ delay: offset + 700, msg: '── Collection complete ──', color: '#00c8ff', prefix: 'DONE', bold: true });

    const totalDuration = offset + 800;

    messages.forEach(m => {
      setTimeout(() => {
        if (!_running && m.prefix !== 'DONE') return;
        appendLine(m.msg, m.color, m.prefix, m.bold);
        // Update progress bar
        const pct = Math.min(100, Math.round((m.delay / totalDuration) * 100));
        const progEl = document.getElementById('term-progress');
        if (progEl) progEl.style.width = pct + '%';
      }, m.delay);
    });

    // Count up
    let count = 0;
    const countTimer = setInterval(() => {
      count += Math.floor(Math.random() * 3) + 1;
      const el = document.getElementById('term-count');
      if (el) el.textContent = count;
    }, 400);

    setTimeout(() => {
      clearInterval(countTimer);
      finish(count);
    }, totalDuration);
  }

  function appendLine(msg, color, prefix, bold) {
    const output = document.getElementById('term-output');
    if (!output) return;

    const ts = new Date().toLocaleTimeString([], { hour12: false });
    const line = document.createElement('div');
    line.style.cssText = 'display:flex;gap:10px;align-items:baseline;animation:fadeInUp 0.15s ease;';
    line.innerHTML = `
      <span style="color:#4d6080;flex-shrink:0;font-size:9px;">${ts}</span>
      <span style="color:${color||'#8da0bf'};flex-shrink:0;font-size:9px;min-width:36px;text-align:right;">${(prefix||'LOG')}</span>
      <span style="color:${color||'#8da0bf'};${bold?'font-weight:700;':''}flex:1;word-break:break-all;">${escHtml(msg)}</span>`;

    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
    _lines.push({ ts, prefix, msg });
  }

  function finish(itemCount) {
    _running = false;
    const statEl  = document.getElementById('term-status');
    const progEl  = document.getElementById('term-progress');
    const closeBtn = document.getElementById('term-close-btn');
    const countEl = document.getElementById('term-count');
    if (statEl)  { statEl.textContent = 'COMPLETE'; statEl.style.color = '#00e676'; }
    if (progEl)  progEl.style.width   = '100%';
    if (closeBtn){ closeBtn.disabled = false; closeBtn.textContent = 'CLOSE'; closeBtn.style.color = '#00c8ff'; closeBtn.style.cursor = 'pointer'; closeBtn.style.borderColor = 'rgba(0,200,255,0.3)'; }
    if (countEl && itemCount) countEl.textContent = itemCount;
    appendLine(`Collection complete — ${itemCount||0} items secured`, '#00e676', 'DONE', true);
  }

  function fail(msg) {
    _running = false;
    appendLine('Collection failed: ' + msg, '#ff1744', 'ERR', true);
    const statEl  = document.getElementById('term-status');
    const errEl   = document.getElementById('term-errors');
    const closeBtn = document.getElementById('term-close-btn');
    if (statEl)  { statEl.textContent = 'FAILED'; statEl.style.color = '#ff1744'; }
    if (errEl)   errEl.textContent = '1';
    if (closeBtn){ closeBtn.disabled = false; closeBtn.textContent = 'CLOSE'; closeBtn.style.color = '#ff1744'; closeBtn.style.cursor = 'pointer'; }
  }

  function close() {
    if (!_modal) return;
    _running = false;
    _modal.style.opacity = '0';
    _modal.style.pointerEvents = 'none';
  }

  function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

  return { open, close, appendLine, finish, fail };
})();
