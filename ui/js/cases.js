// ISEC Case Management — Forensic Investigation Lifecycle
(function () {
  'use strict';

  const STORAGE_KEY = 'isec_cases_v2';
  let _cases = [];
  let _filter = 'all';

  // ── Lifecycle ─────────────────────────────────────────────────
  function initCases() {
    _cases = loadCases();
    const bind = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); };
    bind('new-case-btn', openNewCaseModal);
    bind('cases-empty-new-btn', openNewCaseModal);
    bind('cases-refresh-btn', renderCases);
    // Status filter buttons (CSP forbids inline onclick)
    document.querySelectorAll('#cases .section-actions .btn[data-filter]').forEach(btn => {
      btn.addEventListener('click', function () { filterCases(this.getAttribute('data-filter'), this); });
    });
    renderCases();
  }

  // ── Storage ───────────────────────────────────────────────────
  function loadCases() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]'); }
    catch(_) { return []; }
  }

  function saveCases() {
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(_cases)); } catch(_) {}
  }

  function generateId() {
    return 'CASE-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).slice(2,6).toUpperCase();
  }

  // ── Filter ────────────────────────────────────────────────────
  window.filterCases = function(status, btn) {
    _filter = status;
    document.querySelectorAll('#cases .section-actions .btn[data-filter]').forEach(b => {
      b.className = 'btn btn-secondary';
    });
    if (btn) btn.className = 'btn btn-primary';
    renderCases();
  };

  // ── Render ────────────────────────────────────────────────────
  function renderCases() {
    const grid  = document.getElementById('cases-grid');
    const empty = document.getElementById('cases-empty');
    if (!grid) return;

    updateStats();

    const filtered = _filter === 'all' ? _cases : _cases.filter(c => c.status === _filter);

    if (!filtered.length) {
      grid.innerHTML = '';
      empty && empty.classList.remove('hidden');
      return;
    }
    empty && empty.classList.add('hidden');

    const priorityColor = { CRITICAL:'var(--danger)', HIGH:'var(--orange)', MEDIUM:'var(--warning)', LOW:'var(--success)' };
    const statusColor   = { OPEN:'var(--cyan-bright)', ACTIVE:'var(--success)', CLOSED:'var(--text-muted)', ARCHIVED:'#4d6080' };

    grid.innerHTML = filtered.sort((a,b) => b.created - a.created).map(c => `
      <div class="glassmorphism case-card" data-case-id="${escHtml(c.id)}" style="padding:18px;cursor:pointer;transition:all 0.2s;border-left:3px solid ${statusColor[c.status]||'var(--border-dim)'};">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px;">
          <div>
            <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-bottom:3px;">${escHtml(c.id)}</div>
            <div style="font-size:0.9rem;font-weight:600;color:var(--text-primary);">${escHtml(c.name)}</div>
          </div>
          <div style="display:flex;gap:5px;flex-shrink:0;">
            <span class="badge" style="background:${(priorityColor[c.priority]||'#888')}15;color:${priorityColor[c.priority]||'#888'};border:1px solid ${(priorityColor[c.priority]||'#888')}30;font-size:0.58rem;">${c.priority||'MEDIUM'}</span>
            <span class="badge" style="background:${(statusColor[c.status]||'#888')}15;color:${statusColor[c.status]||'#888'};border:1px solid ${(statusColor[c.status]||'#888')}30;font-size:0.58rem;">${c.status}</span>
          </div>
        </div>
        <div style="font-size:0.75rem;color:var(--text-muted);margin-bottom:10px;line-height:1.4;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;">${escHtml(c.description||'No description.')}</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px;">
          <div><div style="font-family:var(--font-mono);font-size:0.58rem;color:var(--text-muted);margin-bottom:2px;">Subject</div><div style="font-size:0.72rem;color:var(--text-secondary);">${escHtml(c.subject||'—')}</div></div>
          <div><div style="font-family:var(--font-mono);font-size:0.58rem;color:var(--text-muted);margin-bottom:2px;">Investigator</div><div style="font-size:0.72rem;color:var(--text-secondary);">${escHtml(c.investigator||'—')}</div></div>
        </div>
        <div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid rgba(255,255,255,0.05);padding-top:10px;">
          <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);">📎 ${c.evidenceCount||0} items linked</div>
          <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);">${new Date(c.created).toLocaleDateString()}</div>
        </div>
      </div>`).join('');

    // Bind card interactions (CSP forbids inline handlers)
    grid.querySelectorAll('.case-card').forEach(card => {
      card.addEventListener('click', () => openCaseDetail(card.getAttribute('data-case-id')));
      card.addEventListener('mouseenter', () => {
        card.style.transform = 'translateY(-2px)';
        card.style.boxShadow = '0 8px 24px rgba(0,0,0,0.3)';
      });
      card.addEventListener('mouseleave', () => {
        card.style.transform = '';
        card.style.boxShadow = '';
      });
    });
  }

  function updateStats() {
    const setText = (id, v) => { const el=document.getElementById(id); if(el) el.textContent=v; };
    setText('cases-stat-total',   _cases.length);
    setText('cases-stat-active',  _cases.filter(c=>c.status==='ACTIVE').length);
    setText('cases-stat-closed',  _cases.filter(c=>c.status==='CLOSED').length);
    setText('cases-stat-evidence', _cases.reduce((s,c)=>s+(c.evidenceCount||0),0));
  }

  // ── New Case Modal ────────────────────────────────────────────
  window.openNewCaseModal = function() {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content" style="max-width:520px;">
        <div class="modal-header"><h3>New Investigation Case</h3><button class="close" type="button">×</button></div>
        <div class="modal-body" style="display:grid;gap:12px;">
          <div class="modal-field"><label>Case Name *</label><input id="nc-name" type="text" placeholder="e.g. HR-2026-Data-Leak-Investigation"></div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="modal-field"><label>Subject / Suspect</label><input id="nc-subject" type="text" placeholder="Full name or username"></div>
            <div class="modal-field"><label>Priority</label>
              <select id="nc-priority"><option value="LOW">Low</option><option value="MEDIUM" selected>Medium</option><option value="HIGH">High</option><option value="CRITICAL">Critical</option></select>
            </div>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div class="modal-field"><label>Investigator</label><input id="nc-investigator" type="text" placeholder="Your name"></div>
            <div class="modal-field"><label>Department</label><input id="nc-dept" type="text" placeholder="e.g. IT Security"></div>
          </div>
          <div class="modal-field"><label>Description</label>
            <textarea id="nc-desc" rows="3" placeholder="Brief description of the investigation…" style="resize:vertical;min-height:70px;"></textarea>
          </div>
          <div class="modal-field"><label>Tags (comma separated)</label><input id="nc-tags" type="text" placeholder="data-breach, insider-threat, phishing"></div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" type="button" data-action="cancel">Cancel</button>
          <button class="btn btn-primary" type="button" data-action="create">Create Case</button>
        </div>
      </div>`;

    const close = () => { modal.classList.remove('show'); setTimeout(()=>modal.remove(),250); };
    modal.querySelector('.close').addEventListener('click', close);
    modal.querySelector('[data-action="cancel"]').addEventListener('click', close);
    modal.addEventListener('click', e => { if(e.target===modal) close(); });

    modal.querySelector('[data-action="create"]').addEventListener('click', () => {
      const name = modal.querySelector('#nc-name').value.trim();
      if (!name) { ISECNotify && ISECNotify.warning('Case name is required.'); return; }

      const newCase = {
        id: generateId(),
        name,
        subject:     modal.querySelector('#nc-subject').value.trim(),
        priority:    modal.querySelector('#nc-priority').value,
        investigator:modal.querySelector('#nc-investigator').value.trim(),
        department:  modal.querySelector('#nc-dept').value.trim(),
        description: modal.querySelector('#nc-desc').value.trim(),
        tags:        modal.querySelector('#nc-tags').value.split(',').map(t=>t.trim()).filter(Boolean),
        status:      'OPEN',
        created:     Date.now(),
        updated:     Date.now(),
        evidenceCount: 0,
        notes:       [],
      };

      _cases.push(newCase);
      saveCases();
      renderCases();
      close();
      ISECNotify && ISECNotify.success(`Case ${newCase.id} created`);
    });

    document.body.appendChild(modal);
    requestAnimationFrame(() => requestAnimationFrame(() => modal.classList.add('show')));
    setTimeout(() => modal.querySelector('#nc-name').focus(), 150);
  };

  // ── Case Detail ───────────────────────────────────────────────
  window.openCaseDetail = function(id) {
    const c = _cases.find(x => x.id === id);
    if (!c) return;

    const modal = document.createElement('div');
    modal.className = 'modal';
    const statusOpts = ['OPEN','ACTIVE','CLOSED','ARCHIVED'].map(s => `<option value="${s}" ${c.status===s?'selected':''}>${s}</option>`).join('');
    modal.innerHTML = `
      <div class="modal-content" style="max-width:600px;">
        <div class="modal-header">
          <h3>${escHtml(c.id)}</h3>
          <div style="display:flex;gap:8px;align-items:center;">
            <select id="cd-status" class="role-select" style="width:120px;font-size:0.72rem;">${statusOpts}</select>
            <button class="close" type="button">×</button>
          </div>
        </div>
        <div class="modal-body">
          <div style="font-size:1rem;font-weight:600;color:var(--text-primary);margin-bottom:14px;">${escHtml(c.name)}</div>
          <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px;">
            <div><div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">Subject</div><div style="font-size:0.78rem;color:var(--text-secondary);">${escHtml(c.subject||'—')}</div></div>
            <div><div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">Priority</div><div style="font-size:0.78rem;color:var(--text-secondary);">${c.priority}</div></div>
            <div><div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">Investigator</div><div style="font-size:0.78rem;color:var(--text-secondary);">${escHtml(c.investigator||'—')}</div></div>
            <div><div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">Created</div><div style="font-size:0.78rem;color:var(--text-secondary);">${new Date(c.created).toLocaleDateString()}</div></div>
            <div><div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">Evidence</div><div style="font-size:0.78rem;color:var(--cyan-bright);">${c.evidenceCount||0} items</div></div>
            <div><div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">Tags</div><div style="font-size:0.72rem;color:var(--text-muted);">${(c.tags||[]).join(', ')||'—'}</div></div>
          </div>
          <div style="font-size:0.78rem;color:var(--text-muted);line-height:1.6;margin-bottom:14px;">${escHtml(c.description||'No description.')}</div>
          <!-- Notes -->
          <div style="font-family:var(--font-mono);font-size:0.62rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Investigation Notes</div>
          <div id="cd-notes" style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px;max-height:150px;overflow-y:auto;">
            ${(c.notes||[]).map(n=>`<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:8px 10px;"><div style="font-size:0.75rem;color:var(--text-secondary);">${escHtml(n.text)}</div><div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);margin-top:3px;">${new Date(n.ts).toLocaleString()} — ${escHtml(n.author||'Unknown')}</div></div>`).join('') || '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);">No notes yet.</div>'}
          </div>
          <div style="display:flex;gap:8px;">
            <input id="cd-note-input" type="text" placeholder="Add investigation note…" style="flex:1;">
            <button class="btn btn-secondary" id="cd-add-note" style="padding:6px 14px;font-size:0.75rem;">Add Note</button>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-danger"    type="button" data-action="delete">Delete Case</button>
          <button class="btn btn-secondary" type="button" data-action="cancel">Close</button>
          <button class="btn btn-primary"   type="button" data-action="save">Save Changes</button>
        </div>
      </div>`;

    const close = () => { modal.classList.remove('show'); setTimeout(()=>modal.remove(),250); };
    modal.querySelector('.close').addEventListener('click', close);
    modal.querySelector('[data-action="cancel"]').addEventListener('click', close);
    modal.addEventListener('click', e => { if(e.target===modal) close(); });

    modal.querySelector('[data-action="save"]').addEventListener('click', () => {
      c.status = modal.querySelector('#cd-status').value;
      c.updated = Date.now();
      saveCases();
      renderCases();
      close();
      ISECNotify && ISECNotify.success('Case updated');
    });

    modal.querySelector('[data-action="delete"]').addEventListener('click', () => {
      if (!confirm(`Delete case ${c.id}? This cannot be undone.`)) return;
      _cases = _cases.filter(x => x.id !== id);
      saveCases();
      renderCases();
      close();
      ISECNotify && ISECNotify.success('Case deleted');
    });

    modal.querySelector('#cd-add-note').addEventListener('click', () => {
      const input = modal.querySelector('#cd-note-input');
      const text = input ? input.value.trim() : '';
      if (!text) return;
      if (!c.notes) c.notes = [];
      c.notes.push({ text, ts: Date.now(), author: document.getElementById('profile-role')?.textContent || 'Investigator' });
      c.updated = Date.now();
      saveCases();
      input.value = '';
      const notesEl = modal.querySelector('#cd-notes');
      if (notesEl) notesEl.innerHTML = c.notes.map(n=>`<div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:8px 10px;"><div style="font-size:0.75rem;color:var(--text-secondary);">${escHtml(n.text)}</div><div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);margin-top:3px;">${new Date(n.ts).toLocaleString()}</div></div>`).join('');
    });

    document.body.appendChild(modal);
    requestAnimationFrame(() => requestAnimationFrame(() => modal.classList.add('show')));
  };

  function escHtml(s) { return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  window.initCases = initCases;
})();
