/**
 * ISEC Command Palette — Ctrl+K / Cmd+K
 * Fuzzy-search across navigation, actions, and evidence
 */
(function () {
  'use strict';

  const COMMANDS = [
    // Navigation
    { id:'nav-dashboard',  cat:'Navigate', label:'Dashboard',        icon:'⊞', action:()=>navigateTo('dashboard') },
    { id:'nav-timeline',   cat:'Navigate', label:'Evidence Timeline', icon:'≡', action:()=>navigateTo('timeline') },
    { id:'nav-threat',     cat:'Navigate', label:'Threat Analysis',   icon:'⚡', action:()=>navigateTo('threat-analysis') },
    { id:'nav-audit',      cat:'Navigate', label:'Audit Log',         icon:'📋', action:()=>navigateTo('audit-log') },
    { id:'nav-cases',      cat:'Navigate', label:'Case Management',   icon:'🗂', action:()=>navigateTo('cases') },
    { id:'nav-compliance', cat:'Navigate', label:'Compliance',        icon:'✓', action:()=>navigateTo('compliance') },
    { id:'nav-report',     cat:'Navigate', label:'Report Export',     icon:'⬇', action:()=>navigateTo('report') },
    // Actions
    { id:'act-collect-all',  cat:'Action', label:'Collect All Evidence',      icon:'🔍', action:()=>startEvidenceCollection&&startEvidenceCollection() },
    { id:'act-collect-sys',  cat:'Action', label:'Collect System Logs',       icon:'🖥', action:()=>startEvidenceCollection&&startEvidenceCollection({types:['system_logs']}) },
    { id:'act-collect-net',  cat:'Action', label:'Collect Network Connections',icon:'🌐', action:()=>startEvidenceCollection&&startEvidenceCollection({types:['network_connections']}) },
    { id:'act-collect-file', cat:'Action', label:'Collect File Metadata',     icon:'📁', action:()=>startEvidenceCollection&&startEvidenceCollection({types:['file_metadata']}) },
    { id:'act-collect-browser',cat:'Action',label:'Collect Browser History',  icon:'🌍', action:()=>startEvidenceCollection&&startEvidenceCollection({types:['browser_history']}) },
    { id:'act-report',       cat:'Action', label:'Generate Report',           icon:'📄', action:()=>{ navigateTo('report'); setTimeout(()=>document.getElementById('generate-report-btn')&&document.getElementById('generate-report-btn').click(),500); } },
    { id:'act-new-case',     cat:'Action', label:'New Investigation Case',    icon:'➕', action:()=>{ navigateTo('cases'); setTimeout(()=>typeof openNewCaseModal==='function'&&openNewCaseModal(),400); } },
    { id:'act-refresh',      cat:'Action', label:'Refresh Dashboard',         icon:'⟳', action:()=>typeof loadDashboardStats==='function'&&loadDashboardStats() },
    { id:'act-role-col',     cat:'Action', label:'Switch to Collector Role',  icon:'🔍', action:()=>{ const s=document.getElementById('role-select'); if(s){s.value='collector'; typeof switchRole==='function'&&switchRole();} } },
    { id:'act-role-rev',     cat:'Action', label:'Switch to Reviewer Role',   icon:'👁', action:()=>{ const s=document.getElementById('role-select'); if(s){s.value='reviewer'; typeof switchRole==='function'&&switchRole();} } },
    { id:'act-role-exp',     cat:'Action', label:'Switch to Exporter Role',   icon:'📤', action:()=>{ const s=document.getElementById('role-select'); if(s){s.value='exporter'; typeof switchRole==='function'&&switchRole();} } },
  ];

  let _open = false;
  let _results = [];
  let _cursor = 0;
  let _modal = null;
  let _evidenceItems = [];

  // ── Build DOM ─────────────────────────────────────────────────
  function buildPalette() {
    if (_modal) return;
    _modal = document.createElement('div');
    _modal.id = 'cmd-palette-overlay';
    _modal.style.cssText = 'position:fixed;inset:0;background:rgba(2,6,9,0.82);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);z-index:9999;display:flex;align-items:flex-start;justify-content:center;padding-top:120px;opacity:0;transition:opacity 0.15s ease;pointer-events:none;';

    _modal.innerHTML = `
      <div id="cmd-palette" style="width:560px;max-width:92vw;background:rgba(8,14,26,0.98);border:1px solid rgba(0,200,255,0.25);border-radius:14px;overflow:hidden;box-shadow:0 32px 80px rgba(0,0,0,0.8),0 0 40px rgba(0,200,255,0.08);">
        <!-- Search bar -->
        <div style="display:flex;align-items:center;gap:10px;padding:14px 18px;border-bottom:1px solid rgba(0,200,255,0.1);">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(0,200,255,0.5)" stroke-width="2" style="flex-shrink:0;"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
          <input id="cmd-input" type="text" placeholder="Search commands, views, evidence…" autocomplete="off" spellcheck="false"
            style="flex:1;background:none;border:none;outline:none;font-family:'JetBrains Mono','Courier New',monospace;font-size:0.88rem;color:#e8f0ff;letter-spacing:0.02em;" />
          <span style="font-family:monospace;font-size:9px;color:#4d6080;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:4px;padding:2px 6px;">ESC</span>
        </div>
        <!-- Results -->
        <div id="cmd-results" style="max-height:360px;overflow-y:auto;padding:6px 0;"></div>
        <!-- Footer -->
        <div style="padding:8px 18px;border-top:1px solid rgba(0,200,255,0.08);display:flex;gap:14px;align-items:center;">
          <span style="font-family:monospace;font-size:9px;color:#4d6080;">↑↓ navigate</span>
          <span style="font-family:monospace;font-size:9px;color:#4d6080;">↵ select</span>
          <span style="font-family:monospace;font-size:9px;color:#4d6080;">esc close</span>
          <span style="margin-left:auto;font-family:monospace;font-size:9px;color:#4d6080;" id="cmd-count">0 results</span>
        </div>
      </div>`;

    document.body.appendChild(_modal);

    _modal.querySelector('#cmd-input').addEventListener('input', e => render(e.target.value));
    _modal.querySelector('#cmd-input').addEventListener('keydown', handleKey);
    _modal.addEventListener('mousedown', e => { if (e.target === _modal) close(); });
  }

  // ── Fuzzy match ───────────────────────────────────────────────
  function fuzzy(str, query) {
    if (!query) return true;
    const s = str.toLowerCase(), q = query.toLowerCase();
    let si = 0;
    for (let qi = 0; qi < q.length; qi++) {
      si = s.indexOf(q[qi], si);
      if (si === -1) return false;
      si++;
    }
    return true;
  }

  function score(str, query) {
    if (!query) return 1;
    const s = str.toLowerCase(), q = query.toLowerCase();
    if (s.startsWith(q)) return 3;
    if (s.includes(q)) return 2;
    return 1;
  }

  // ── Render results ────────────────────────────────────────────
  function render(query) {
    const q = (query || '').trim();
    const container = document.getElementById('cmd-results');
    const countEl = document.getElementById('cmd-count');
    if (!container) return;

    // Filter commands
    let cmds = COMMANDS.filter(c => !q || fuzzy(c.label + ' ' + c.cat, q));
    cmds.sort((a, b) => score(b.label, q) - score(a.label, q));

    // Filter evidence items
    let evItems = [];
    if (_evidenceItems.length && q.length > 1) {
      evItems = _evidenceItems
        .filter(it => fuzzy((it.description || '') + (it.type || ''), q))
        .slice(0, 5)
        .map(it => ({
          id: 'ev-' + it.id,
          cat: 'Evidence',
          label: it.description || '(no description)',
          sub: it.type ? it.type.replace(/_/g, ' ') : '',
          icon: { system_logs:'🖥', browser_history:'🌍', network_connections:'🌐', file_metadata:'📁' }[it.type] || '📄',
          action: () => typeof viewEvidenceDetail === 'function' && viewEvidenceDetail(it.id),
        }));
    }

    _results = [...cmds, ...evItems];
    _cursor = 0;

    if (!_results.length) {
      container.innerHTML = `<div style="padding:28px;text-align:center;font-family:monospace;font-size:11px;color:#4d6080;">No results for "${q}"</div>`;
      if (countEl) countEl.textContent = '0 results';
      return;
    }

    if (countEl) countEl.textContent = _results.length + ' result' + (_results.length !== 1 ? 's' : '');

    // Group by category
    const groups = {};
    _results.forEach((r, i) => {
      if (!groups[r.cat]) groups[r.cat] = [];
      groups[r.cat].push({ ...r, _idx: i });
    });

    container.innerHTML = Object.entries(groups).map(([cat, items]) => `
      <div style="padding:6px 18px 2px;font-family:monospace;font-size:9px;text-transform:uppercase;letter-spacing:0.12em;color:#4d6080;">${cat}</div>
      ${items.map(r => `
        <div class="cmd-item" data-idx="${r._idx}"
          style="display:flex;align-items:center;gap:12px;padding:9px 18px;cursor:pointer;transition:background 0.1s;${r._idx === _cursor ? 'background:rgba(0,200,255,0.08);border-left:2px solid #00c8ff;' : 'border-left:2px solid transparent;'}">
          <span style="font-size:16px;flex-shrink:0;width:20px;text-align:center;">${r.icon}</span>
          <div style="flex:1;min-width:0;">
            <div style="font-family:'Rajdhani','Segoe UI',sans-serif;font-size:13px;font-weight:500;color:${r._idx===_cursor?'#e8f0ff':'#8da0bf'};white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">${highlight(r.label, q)}</div>
            ${r.sub ? `<div style="font-family:monospace;font-size:9px;color:#4d6080;margin-top:1px;">${r.sub}</div>` : ''}
          </div>
          <span style="font-family:monospace;font-size:9px;color:#4d6080;flex-shrink:0;">${r.cat}</span>
        </div>`).join('')}
    `).join('');

    container.querySelectorAll('.cmd-item').forEach(el => {
      el.addEventListener('mouseenter', () => {
        _cursor = parseInt(el.dataset.idx, 10);
        render(q);
      });
      el.addEventListener('mousedown', e => {
        e.preventDefault();
        _cursor = parseInt(el.dataset.idx, 10);
        execute();
      });
    });
  }

  function highlight(label, query) {
    if (!query) return label;
    const q = query.toLowerCase();
    return label.replace(new RegExp(`(${q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&')})`, 'gi'), '<mark style="background:rgba(0,200,255,0.2);color:#00c8ff;border-radius:2px;">$1</mark>');
  }

  // ── Keyboard handling ─────────────────────────────────────────
  function handleKey(e) {
    if (e.key === 'Escape') { close(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); _cursor = Math.min(_cursor + 1, _results.length - 1); render(e.target.value); scrollCursor(); }
    if (e.key === 'ArrowUp')   { e.preventDefault(); _cursor = Math.max(_cursor - 1, 0); render(e.target.value); scrollCursor(); }
    if (e.key === 'Enter')     { e.preventDefault(); execute(); }
  }

  function scrollCursor() {
    const el = document.querySelector(`.cmd-item[data-idx="${_cursor}"]`);
    if (el) el.scrollIntoView({ block: 'nearest' });
  }

  function execute() {
    const cmd = _results[_cursor];
    if (cmd && typeof cmd.action === 'function') {
      close();
      setTimeout(cmd.action, 80);
    }
  }

  // ── Open / Close ──────────────────────────────────────────────
  function open() {
    buildPalette();
    _open = true;
    _modal.style.pointerEvents = 'all';
    requestAnimationFrame(() => { requestAnimationFrame(() => { _modal.style.opacity = '1'; }); });
    const input = document.getElementById('cmd-input');
    if (input) { input.value = ''; input.focus(); }
    render('');

    // Load evidence items in background
    if (window.isec && !_evidenceItems.length) {
      window.isec.invoke('get-evidence-timeline').then(r => {
        _evidenceItems = (r && Array.isArray(r.items)) ? r.items : [];
      }).catch(() => {});
    }
  }

  function close() {
    if (!_modal) return;
    _open = false;
    _modal.style.opacity = '0';
    _modal.style.pointerEvents = 'none';
    const input = document.getElementById('cmd-input');
    if (input) input.blur();
  }

  function toggle() { _open ? close() : open(); }

  // ── Global keyboard listener ──────────────────────────────────
  document.addEventListener('keydown', e => {
    if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); toggle(); }
    if (e.key === '?' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) { showShortcuts(); }
  });

  // ── Keyboard Shortcuts Overlay ────────────────────────────────
  function showShortcuts() {
    const existing = document.getElementById('shortcuts-overlay');
    if (existing) { existing.remove(); return; }

    const overlay = document.createElement('div');
    overlay.id = 'shortcuts-overlay';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(2,6,9,0.85);backdrop-filter:blur(12px);z-index:9998;display:flex;align-items:center;justify-content:center;';
    overlay.innerHTML = `
      <div style="background:rgba(8,14,26,0.98);border:1px solid rgba(0,200,255,0.2);border-radius:16px;padding:28px 36px;min-width:420px;max-width:560px;">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px;">
          <div style="font-family:monospace;font-size:14px;font-weight:700;text-transform:uppercase;letter-spacing:0.12em;color:#00c8ff;">Keyboard Shortcuts</div>
          <span style="font-family:monospace;font-size:9px;color:#4d6080;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.1);border-radius:4px;padding:2px 6px;">? to close</span>
        </div>
        ${[
          ['Global', [
            ['Ctrl/Cmd + K', 'Command Palette'],
            ['?', 'Show Shortcuts'],
            ['Escape', 'Close / Cancel'],
          ]],
          ['Navigation', [
            ['G + D', 'Go to Dashboard'],
            ['G + T', 'Go to Timeline'],
            ['G + A', 'Go to Threat Analysis'],
            ['G + L', 'Go to Audit Log'],
            ['G + C', 'Go to Cases'],
            ['G + R', 'Go to Report'],
          ]],
          ['Actions', [
            ['Ctrl/Cmd + Enter', 'Start Collection'],
            ['Ctrl/Cmd + Shift + R', 'Generate Report'],
            ['Ctrl/Cmd + R', 'Refresh Data'],
          ]],
        ].map(([group, items]) => `
          <div style="margin-bottom:20px;">
            <div style="font-family:monospace;font-size:9px;text-transform:uppercase;letter-spacing:0.12em;color:#4d6080;margin-bottom:10px;">${group}</div>
            ${items.map(([key, label]) => `
              <div style="display:flex;justify-content:space-between;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.03);">
                <span style="font-family:'Rajdhani',sans-serif;font-size:12px;color:#8da0bf;">${label}</span>
                <kbd style="font-family:monospace;font-size:10px;color:#00c8ff;background:rgba(0,200,255,0.08);border:1px solid rgba(0,200,255,0.2);border-radius:4px;padding:2px 8px;">${key}</kbd>
              </div>`).join('')}
          </div>`).join('')}
      </div>`;

    overlay.addEventListener('click', e => { if(e.target===overlay||e.key==='Escape') overlay.remove(); });
    document.addEventListener('keydown', function esc(e){ if(e.key==='Escape'||e.key==='?'){overlay.remove();document.removeEventListener('keydown',esc);} });
    document.body.appendChild(overlay);
  }

  // ── G+key navigation ─────────────────────────────────────────
  let _gPressed = false, _gTimer;
  document.addEventListener('keydown', e => {
    if (['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) return;
    if (e.key === 'g' || e.key === 'G') { _gPressed = true; clearTimeout(_gTimer); _gTimer = setTimeout(()=>{_gPressed=false;},800); return; }
    if (_gPressed) {
      const map = { d:'dashboard', t:'timeline', a:'threat-analysis', l:'audit-log', c:'cases', r:'report' };
      const view = map[e.key.toLowerCase()];
      if (view) { e.preventDefault(); _gPressed = false; typeof navigateTo==='function'&&navigateTo(view); }
    }
    if ((e.ctrlKey||e.metaKey) && e.key==='Enter')      { e.preventDefault(); typeof startEvidenceCollection==='function'&&startEvidenceCollection(); }
    if ((e.ctrlKey||e.metaKey) && e.key==='r' && !e.shiftKey) { e.preventDefault(); typeof loadDashboardStats==='function'&&loadDashboardStats(); }
    if ((e.ctrlKey||e.metaKey) && e.shiftKey && e.key==='R') { e.preventDefault(); navigateTo&&navigateTo('report'); }
  });

  // ── Top-bar ⌘K button (CSP forbids inline onclick) ───────────
  function bindCmdHintButton() {
    const btn = document.getElementById('cmd-hint-btn');
    if (btn) btn.addEventListener('click', open);
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bindCmdHintButton);
  } else {
    bindCmdHintButton();
  }

  window.openCommandPalette = open;
  window.closeCommandPalette = close;
})();
