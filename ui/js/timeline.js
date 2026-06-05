// ISEC Evidence Timeline — Advanced Search, Filter, Paginate, Expand

(function () {
  'use strict';

  // ── State ────────────────────────────────────────────────────
  let _allItems     = [];
  let _filtered     = [];
  let _page         = 1;
  const PAGE_SIZE   = 25;

  let _filter = {
    search:   '',
    type:     'all',
    severity: null,
    from:     null,
    to:       null,
    sort:     'desc',
  };

  // ── Type Config ──────────────────────────────────────────────
  const TYPE_CONF = {
    system_logs:        { color: '#64b5f6', label: 'System', icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>` },
    browser_history:    { color: '#69f0ae', label: 'Browser', icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>` },
    network_connections:{ color: '#ffd740', label: 'Network', icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18"/></svg>` },
    file_metadata:      { color: '#ce93d8', label: 'Files',   icon: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"/><polyline points="13 2 13 9 20 9"/></svg>` },
  };

  const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

  // ── Init ─────────────────────────────────────────────────────
  async function initTimeline() {
    bindEvents();
    await loadTimeline();
  }

  // ── Data Load ────────────────────────────────────────────────
  async function loadTimeline() {
    showState('loading');
    const bridge = window.isec;
    if (!bridge) { showState('empty'); return; }

    try {
      const resp = await bridge.invoke('get-evidence-timeline');
      _allItems = Array.isArray(resp && resp.items) ? resp.items : [];
      applyFiltersAndRender();
    } catch (err) {
      console.error('Timeline load error:', err);
      showState('empty');
    }
  }

  // ── Events ───────────────────────────────────────────────────
  function bindEvents() {
    // Search
    const searchEl = document.getElementById('timeline-search');
    if (searchEl) {
      let debounce;
      searchEl.addEventListener('input', e => {
        clearTimeout(debounce);
        debounce = setTimeout(() => { _filter.search = e.target.value.trim().toLowerCase(); _page = 1; applyFiltersAndRender(); }, 260);
      });
    }

    // Sort
    const sortEl = document.getElementById('timeline-sort');
    if (sortEl) sortEl.addEventListener('change', e => { _filter.sort = e.target.value; applyFiltersAndRender(); });

    // Date range
    const fromEl = document.getElementById('timeline-from');
    const toEl   = document.getElementById('timeline-to');
    if (fromEl) fromEl.addEventListener('change', e => { _filter.from = e.target.value ? new Date(e.target.value).getTime() : null; _page = 1; applyFiltersAndRender(); });
    if (toEl)   toEl.addEventListener('change',   e => { _filter.to   = e.target.value ? new Date(e.target.value + 'T23:59:59').getTime() : null; _page = 1; applyFiltersAndRender(); });

    // Refresh
    const refreshBtn = document.getElementById('timeline-refresh-btn');
    if (refreshBtn) refreshBtn.addEventListener('click', loadTimeline);

    // Export
    const exportBtn = document.getElementById('timeline-export-btn');
    if (exportBtn) exportBtn.addEventListener('click', exportTimeline);

    // Clear filters
    const clearBtn = document.getElementById('clear-filters-btn');
    if (clearBtn) clearBtn.addEventListener('click', clearFilters);

    // Filter pills
    document.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', function () {
        const type = this.getAttribute('data-type');
        const sev  = this.getAttribute('data-severity');

        if (type) {
          document.querySelectorAll('.filter-pill[data-type]').forEach(p => p.classList.remove('active'));
          this.classList.add('active');
          _filter.type = type;
        } else if (sev) {
          if (this.classList.contains('active')) {
            this.classList.remove('active');
            _filter.severity = null;
          } else {
            document.querySelectorAll('.filter-pill[data-severity]').forEach(p => p.classList.remove('active'));
            this.classList.add('active');
            _filter.severity = sev;
          }
        }
        _page = 1;
        applyFiltersAndRender();
      });
    });

    // Pagination
    const prevBtn = document.getElementById('page-prev-btn');
    const nextBtn = document.getElementById('page-next-btn');
    if (prevBtn) prevBtn.addEventListener('click', () => { if (_page > 1) { _page--; renderPage(); scrollToTop(); } });
    if (nextBtn) nextBtn.addEventListener('click', () => { const totalPages = Math.ceil(_filtered.length / PAGE_SIZE); if (_page < totalPages) { _page++; renderPage(); scrollToTop(); } });
  }

  // ── Filter Logic ─────────────────────────────────────────────
  function applyFiltersAndRender() {
    let items = [..._allItems];

    // Type
    if (_filter.type && _filter.type !== 'all') {
      items = items.filter(it => it.type === _filter.type);
    }

    // Severity
    if (_filter.severity) {
      items = items.filter(it => (it.severity || '').toLowerCase() === _filter.severity);
    }

    // Search
    if (_filter.search) {
      const q = _filter.search;
      items = items.filter(it => {
        const desc  = (it.description || '').toLowerCase();
        const type  = (it.type || '').toLowerCase();
        const data  = JSON.stringify(it.data || '').toLowerCase();
        return desc.includes(q) || type.includes(q) || data.includes(q);
      });
    }

    // Date range
    if (_filter.from) items = items.filter(it => it.timestamp && new Date(it.timestamp).getTime() >= _filter.from);
    if (_filter.to)   items = items.filter(it => it.timestamp && new Date(it.timestamp).getTime() <= _filter.to);

    // Sort
    items.sort((a, b) => {
      const ta = a.timestamp ? new Date(a.timestamp).getTime() : 0;
      const tb = b.timestamp ? new Date(b.timestamp).getTime() : 0;
      return _filter.sort === 'asc' ? ta - tb : tb - ta;
    });

    _filtered = items;
    renderPage();
  }

  // ── Render Page ──────────────────────────────────────────────
  function renderPage() {
    const container = document.getElementById('timeline-items');
    const countEl   = document.getElementById('timeline-count');
    const pagination = document.getElementById('timeline-pagination');

    if (!container) return;

    if (_filtered.length === 0) {
      showState('empty');
      if (countEl) countEl.textContent = '0 items';
      if (pagination) pagination.classList.add('hidden');
      return;
    }

    showState('items');
    if (countEl) countEl.textContent = `${_filtered.length.toLocaleString()} item${_filtered.length !== 1 ? 's' : ''}`;

    const totalPages = Math.ceil(_filtered.length / PAGE_SIZE);
    if (_page > totalPages) _page = totalPages;

    const start = (_page - 1) * PAGE_SIZE;
    const slice = _filtered.slice(start, start + PAGE_SIZE);

    container.innerHTML = '';
    slice.forEach((item, idx) => {
      container.appendChild(buildItemEl(item, idx));
    });

    // Pagination
    if (totalPages > 1) {
      pagination.classList.remove('hidden');
      const pageInfo = document.getElementById('page-info');
      const prevBtn  = document.getElementById('page-prev-btn');
      const nextBtn  = document.getElementById('page-next-btn');
      if (pageInfo) pageInfo.textContent = `Page ${_page} of ${totalPages}`;
      if (prevBtn) prevBtn.disabled = _page <= 1;
      if (nextBtn) nextBtn.disabled = _page >= totalPages;
    } else {
      if (pagination) pagination.classList.add('hidden');
    }
  }

  // ── Build Item Element ────────────────────────────────────────
  function buildItemEl(item, idx) {
    const conf   = TYPE_CONF[item.type] || { color: '#888', label: item.type || 'Unknown', icon: '📄' };
    const sev    = (item.severity || 'info').toLowerCase();
    const ts     = item.timestamp ? new Date(item.timestamp) : null;
    const tsStr  = ts ? ts.toLocaleDateString([], { month: 'short', day: 'numeric', year: '2-digit' }) + ' ' + ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : 'Unknown';
    const itemId = item.id ? String(item.id).slice(0, 8) : '—';
    const desc   = item.description || '(no description)';

    const el = document.createElement('div');
    el.className = 'timeline-item';
    el.style.setProperty('--item-accent', conf.color);
    el.style.animationDelay = (idx * 30) + 'ms';

    const sevBadge = buildSeverityBadge(sev);

    el.innerHTML = `
      <div class="item-header">
        <div class="item-type-icon">${conf.icon}</div>
        <div class="item-meta">
          <div class="item-description" title="${escapeHtml(desc)}">${escapeHtml(desc)}</div>
          <div class="item-sub">
            <span class="item-timestamp">${tsStr}</span>
            <span class="item-id">#${itemId}</span>
          </div>
        </div>
        <div class="item-badges">
          <span class="badge" style="background:${conf.color}15;color:${conf.color};border:1px solid ${conf.color}33;font-size:0.6rem;">${conf.label}</span>
          ${sevBadge}
          <svg class="expand-chevron" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text-muted);transition:transform 0.2s;flex-shrink:0;"><path d="m6 9 6 6 6-6"/></svg>
        </div>
      </div>
      <div class="item-detail-expanded">
        ${buildExpandedDetail(item, conf, tsStr)}
      </div>
    `;

    el.addEventListener('click', (e) => {
      if (e.target.closest('.detail-actions button')) return;
      const expanded = el.classList.toggle('expanded');
      const chevron = el.querySelector('.expand-chevron');
      if (chevron) chevron.style.transform = expanded ? 'rotate(180deg)' : '';
    });

    // View full detail button
    el.querySelector('.view-detail-btn') && el.querySelector('.view-detail-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      if (typeof viewEvidenceDetail === 'function') viewEvidenceDetail(item.id);
    });

    return el;
  }

  function buildSeverityBadge(sev) {
    const classMap = { critical: 'severity-critical', high: 'severity-high', medium: 'severity-medium', low: 'severity-low', info: 'severity-info' };
    const cls = classMap[sev] || 'badge-muted';
    return `<span class="${cls}">${sev}</span>`;
  }

  function buildExpandedDetail(item, conf, tsStr) {
    const data = item.data || {};
    const fields = [];

    if (data.remote_address)      fields.push(['Remote Address', data.remote_address]);
    if (data.process_name)        fields.push(['Process', data.process_name]);
    if (data.pid)                 fields.push(['PID', data.pid]);
    if (data.url)                 fields.push(['URL', data.url]);
    if (data.browser)             fields.push(['Browser', data.browser]);
    if (data.file_path)           fields.push(['File Path', data.file_path]);
    if (data.file_size !== undefined) fields.push(['Size', formatBytes(data.file_size)]);
    if (data.message)             fields.push(['Message', data.message]);
    if (data.level)               fields.push(['Level', data.level]);
    if (data.source)              fields.push(['Source', data.source]);

    const gridHtml = fields.length > 0
      ? `<div class="detail-grid">${fields.slice(0, 6).map(([lbl, val]) => `
          <div class="detail-field">
            <span class="detail-label">${escapeHtml(lbl)}</span>
            <span class="detail-value" title="${escapeHtml(String(val))}">${escapeHtml(String(val))}</span>
          </div>`).join('')}</div>`
      : '<div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);margin-bottom:10px;">No additional metadata.</div>';

    return `
      ${gridHtml}
      <div class="detail-actions">
        <button class="btn btn-secondary view-detail-btn" style="padding:5px 12px;font-size:0.72rem;">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          Full Detail
        </button>
        <button class="btn btn-secondary" style="padding:5px 12px;font-size:0.72rem;" onclick="copyItemToClipboard(${item.id})">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg>
          Copy
        </button>
      </div>
    `;
  }

  // ── Helpers ──────────────────────────────────────────────────
  function showState(state) {
    const itemsEl   = document.getElementById('timeline-items');
    const loadingEl = document.getElementById('timeline-loading');
    const emptyEl   = document.getElementById('timeline-empty');
    if (itemsEl)   itemsEl.style.display   = state === 'items'   ? 'flex' : 'none';
    if (loadingEl) loadingEl.style.display = state === 'loading' ? 'flex' : 'none';
    if (emptyEl)   emptyEl.style.display   = state === 'empty'   ? 'flex' : 'none';
  }

  function clearFilters() {
    _filter = { search: '', type: 'all', severity: null, from: null, to: null, sort: 'desc' };
    const searchEl = document.getElementById('timeline-search'); if (searchEl) searchEl.value = '';
    const fromEl   = document.getElementById('timeline-from');   if (fromEl)   fromEl.value = '';
    const toEl     = document.getElementById('timeline-to');     if (toEl)     toEl.value = '';
    const sortEl   = document.getElementById('timeline-sort');   if (sortEl)   sortEl.value = 'desc';
    document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
    const allPill = document.querySelector('.filter-pill[data-type="all"]');
    if (allPill) allPill.classList.add('active');
    _page = 1;
    applyFiltersAndRender();
  }

  function scrollToTop() {
    const wrapper = document.getElementById('timeline-items-wrapper');
    if (wrapper) wrapper.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
      .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
  }

  function formatBytes(bytes) {
    if (!bytes || bytes < 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
    return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
  }

  async function copyItemToClipboard(id) {
    const bridge = window.isec;
    if (!bridge) return;
    try {
      const detail = await bridge.invoke('get-evidence-detail', { id });
      const text = JSON.stringify(detail, null, 2);
      await navigator.clipboard.writeText(text);
      ISECNotify && ISECNotify.success('Evidence JSON copied to clipboard');
    } catch (err) {
      ISECNotify && ISECNotify.error('Copy failed: ' + err.message);
    }
  }

  function exportTimeline() {
    if (!_filtered.length) { ISECNotify && ISECNotify.warning('No items to export.'); return; }
    const rows = [['ID','Type','Severity','Timestamp','Description']];
    _filtered.forEach(it => rows.push([it.id || '', it.type || '', it.severity || '', it.timestamp || '', (it.description || '').replace(/,/g,'')]) );
    const csv = rows.map(r => r.join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = `isec-timeline-${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    ISECNotify && ISECNotify.success(`Exported ${_filtered.length} items as CSV`);
  }

  window.copyItemToClipboard = copyItemToClipboard;
  window.initTimeline        = initTimeline;

})();

