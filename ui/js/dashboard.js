// ISEC Dashboard — Elite Evidence Command Center
// Real-time charts, animated stats, and live data from the backend

function getIsecBridge() {
  if (typeof window === 'undefined' || !window.isec || typeof window.isec.invoke !== 'function') return null;
  return window.isec;
}

// ── Module State ─────────────────────────────────────────────────
let _charts = { donut: null, line: null, gauge: null, sparkline: null };
let _dashRefresh = null;
let _chartRange = 30;
let _cachedTimeline = [];

// ── Lifecycle ────────────────────────────────────────────────────
async function initializeDashboard() {
  bindDashboardEvents();
  if (!_dashRefresh) {
    _dashRefresh = setInterval(() => loadDashboardStats(), 20000);
  }
  await loadDashboardStats();
  checkForUpdates();
}

function bindDashboardEvents() {
  const collectBtn = document.getElementById('collect-btn');
  if (collectBtn) collectBtn.addEventListener('click', () => startEvidenceCollection());

  const refreshBtn = document.getElementById('dashboard-refresh-btn');
  if (refreshBtn) refreshBtn.addEventListener('click', () => loadDashboardStats());

  document.querySelectorAll('.quick-collect-btn').forEach(btn => {
    btn.addEventListener('click', function() { performQuickAction(this.getAttribute('data-action')); });
    btn.addEventListener('mouseenter', function() {
      this.style.transform = 'translateY(-2px)';
      this.style.boxShadow = '0 6px 20px rgba(0,200,255,0.15)';
    });
    btn.addEventListener('mouseleave', function() {
      this.style.transform = '';
      this.style.boxShadow = '';
    });
  });

  const checkUpdatesBtn = document.getElementById('check-updates-btn');
  if (checkUpdatesBtn) checkUpdatesBtn.addEventListener('click', checkForUpdates);

  const applyUpdateBtn = document.getElementById('apply-update-btn');
  if (applyUpdateBtn) applyUpdateBtn.addEventListener('click', applyUpdate);
}

// ── Core Data Loading ────────────────────────────────────────────
async function loadDashboardStats() {
  const bridge = getIsecBridge();
  if (!bridge) return;

  try {
    const [status, retention, integrity, confidence, timeline] = await Promise.all([
      bridge.invoke('get-backend-status').catch(() => null),
      bridge.invoke('get-retention-status').catch(() => null),
      bridge.invoke('get-system-integrity').catch(() => null),
      bridge.invoke('get-evidence-confidence').catch(() => null),
      bridge.invoke('get-evidence-timeline').catch(() => null),
    ]);

    _cachedTimeline = (timeline && Array.isArray(timeline.items)) ? timeline.items : [];

    updateStatCards(status, retention, integrity);
    updateLicensePanel(status && status.license);
    updatePermissionUI(status);
    renderDonutChart(status, _cachedTimeline);
    renderLineChart(_cachedTimeline);
    renderGaugeChart(confidence);
    renderEvidenceTypeBars(status, _cachedTimeline);
    renderSparkline(_cachedTimeline);
    updateHealthStatusRow(integrity, status);
  } catch (err) {
    console.error('Dashboard load error:', err);
  }
}

// ── Stat Cards ───────────────────────────────────────────────────
function updateStatCards(status, retention, integrity) {
  const evidenceCount = (status && typeof status.evidenceItemsCount === 'number')
    ? status.evidenceItemsCount
    : ((retention && typeof retention.total_evidence === 'number') ? retention.total_evidence : 0);

  const totalEl = document.getElementById('total-evidence');
  if (totalEl) {
    const prev = parseInt(totalEl.textContent.replace(/,/g, ''), 10) || 0;
    if (prev !== evidenceCount && typeof ISECCharts !== 'undefined') {
      ISECCharts.animateValue(totalEl, prev, evidenceCount, 800);
    } else if (totalEl) {
      totalEl.textContent = evidenceCount.toLocaleString();
    }
  }

  // Integrity card
  const integrityEl = document.getElementById('integrity-status');
  const integrityCard = document.getElementById('integrity-card');
  const integrityIndicator = document.getElementById('integrity-status-card');
  const compromised = (integrity && integrity.status === 'compromised') || (status && status.tamperingDetected);
  if (integrityEl) {
    integrityEl.textContent = compromised ? 'COMPROMISED' : 'VERIFIED';
  }
  if (integrityIndicator) {
    integrityIndicator.className = 'integrity-indicator ' + (compromised ? 'integrity-compromised' : 'integrity-valid');
  }
  if (integrityCard) {
    integrityCard.style.borderColor = compromised ? 'rgba(255,23,68,0.3)' : 'rgba(0,230,118,0.2)';
  }

  // Last collect
  const lastEl = document.getElementById('last-collect');
  if (lastEl && _cachedTimeline.length > 0) {
    const newest = _cachedTimeline[0];
    if (newest && newest.timestamp) {
      const d = new Date(newest.timestamp);
      lastEl.textContent = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
  }
}

// ── License Panel ────────────────────────────────────────────────
function updateLicensePanel(license) {
  const safe = (id, val) => {
    const el = document.getElementById(id);
    if (el) el.textContent = val || '—';
  };

  if (!license) {
    safe('license-status', 'Unlicensed');
    safe('license-plan', 'No valid license');
    return;
  }

  const statusEl = document.getElementById('license-status');
  if (statusEl) {
    statusEl.textContent = license.valid ? 'LICENSED' : 'UNLICENSED';
    statusEl.style.color = license.valid ? 'var(--success)' : 'var(--danger)';
  }

  safe('license-plan', license.plan || license.message || '—');
  safe('license-id', license.license_id);
  safe('license-customer', license.customer);
  safe('license-plan-detail', license.plan);
  safe('license-expiration', license.expires_at ? new Date(license.expires_at).toLocaleDateString() : 'None');
  safe('license-features', Array.isArray(license.features) && license.features.length ? license.features.join(', ') : 'None');
  safe('license-fingerprint', license.system_fingerprint);
}

// ── Permission UI ─────────────────────────────────────────────────
function updatePermissionUI(status) {
  const collectBtn = document.getElementById('collect-btn');
  if (!status || !collectBtn) return;

  const perms = Array.isArray(status.permissions) ? status.permissions : [];
  const canCollect = perms.includes('collect');
  const tampered = !!status.tamperingDetected;
  const licensed = status.license ? !!status.license.valid : false;
  const blocked = !canCollect || tampered || !licensed;

  collectBtn.disabled = blocked;
  document.querySelectorAll('.quick-collect-btn').forEach(btn => {
    btn.disabled = blocked;
    btn.style.opacity = blocked ? '0.4' : '1';
    btn.style.cursor = blocked ? 'not-allowed' : 'pointer';
  });

  if (!blocked) {
    collectBtn.title = '';
  } else if (!licensed) {
    collectBtn.title = (status.license && status.license.message) || 'Valid license required';
  } else if (tampered) {
    collectBtn.title = 'Locked: Tampering detected';
  } else {
    collectBtn.title = 'Collector role required';
  }
}

// ── Charts ────────────────────────────────────────────────────────
function renderDonutChart(status, timeline) {
  if (typeof ISECCharts === 'undefined') return;
  const canvas = document.getElementById('donut-chart');
  if (!canvas) return;

  const typeCounts = (status && status.evidenceTypeCounts) ? status.evidenceTypeCounts : {};
  let data = [];

  if (Object.keys(typeCounts).length > 0) {
    data = Object.entries(typeCounts).map(([type, count]) => ({
      label: ISECCharts.EVIDENCE_LABELS[type] || type,
      value: count,
      color: ISECCharts.EVIDENCE_COLORS[type] || ISECCharts.COLORS.primary,
    }));
  } else if (timeline.length > 0) {
    const counts = {};
    timeline.forEach(item => { counts[item.type] = (counts[item.type] || 0) + 1; });
    data = Object.entries(counts).map(([type, count]) => ({
      label: ISECCharts.EVIDENCE_LABELS[type] || type,
      value: count,
      color: ISECCharts.EVIDENCE_COLORS[type] || ISECCharts.COLORS.primary,
    }));
  }

  const total = data.reduce((s, d) => s + d.value, 0);

  if (_charts.donut) { _charts.donut.update(data); }
  else {
    _charts.donut = new ISECCharts.DonutChart(canvas, data, {
      centerLabel: 'ITEMS',
      centerValue: total,
    });
  }
  if (_charts.donut && total !== undefined) {
    _charts.donut.opts.centerValue = total;
    _charts.donut.opts.centerLabel = 'ITEMS';
  }

  // Legend
  const legend = document.getElementById('donut-legend');
  if (legend) {
    legend.innerHTML = data.map(d => `
      <div style="display:flex; align-items:center; justify-content:space-between; gap:8px;">
        <div style="display:flex; align-items:center; gap:6px;">
          <div style="width:8px;height:8px;border-radius:2px;background:${d.color};box-shadow:0 0 6px ${d.color}66;flex-shrink:0;"></div>
          <span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-muted);text-transform:uppercase;">${d.label}</span>
        </div>
        <span style="font-family:var(--font-mono);font-size:0.7rem;font-weight:600;color:var(--text-secondary);">${d.value}</span>
      </div>
    `).join('');
  }
}

function buildChartData(timeline, rangeDays) {
  const now = Date.now();
  const msPerDay = 86400000;
  const days = [];
  const labels = [];
  for (let i = rangeDays - 1; i >= 0; i--) {
    const d = new Date(now - i * msPerDay);
    days.push(d.toDateString());
    labels.push(i === 0 ? 'Today' : (i === 1 ? 'Yday' : d.toLocaleDateString([], { month: 'short', day: 'numeric' })));
  }
  const countsByDay = {};
  days.forEach(d => { countsByDay[d] = 0; });
  timeline.forEach(item => {
    if (!item.timestamp) return;
    const d = new Date(item.timestamp).toDateString();
    if (countsByDay.hasOwnProperty(d)) countsByDay[d]++;
  });
  return { data: days.map(d => countsByDay[d]), labels };
}

function renderLineChart(timeline) {
  if (typeof ISECCharts === 'undefined') return;
  const canvas = document.getElementById('line-chart');
  if (!canvas) return;

  const { data, labels } = buildChartData(timeline, _chartRange);
  const dataset = [{ label: 'Evidence', data, color: ISECCharts.COLORS.primary, fill: true }];

  if (_charts.line) { _charts.line.update(dataset, labels); }
  else {
    _charts.line = new ISECCharts.LineChart(canvas, dataset, {
      labels,
      animMs: 900,
      showDots: data.length <= 14,
      dotRadius: 3,
      fillAlpha: 0.15,
      paddingX: 36,
    });
  }
}

function setChartRange(days, btn) {
  _chartRange = days;
  document.querySelectorAll('#chart-timeframe .btn').forEach(b => {
    b.className = b === btn ? 'btn btn-primary' : 'btn btn-secondary';
    b.style.padding = '4px 10px';
    b.style.fontSize = '0.65rem';
  });
  if (_charts.line) {
    const { data, labels } = buildChartData(_cachedTimeline, days);
    _charts.line.update([{ label: 'Evidence', data, color: ISECCharts.COLORS.primary, fill: true }], labels);
  }
}

function renderGaugeChart(confidence) {
  if (typeof ISECCharts === 'undefined') return;
  const canvas = document.getElementById('gauge-chart');
  if (!canvas) return;

  const score = (confidence && typeof confidence.score === 'number') ? confidence.score : 0;

  if (_charts.gauge) { _charts.gauge.update(score); }
  else {
    _charts.gauge = new ISECCharts.GaugeChart(canvas, score, {
      label: 'CONFIDENCE',
      animMs: 1200,
    });
  }
}

function renderSparkline(timeline) {
  if (typeof ISECCharts === 'undefined') return;
  const canvas = document.getElementById('sparkline-evidence');
  if (!canvas) return;

  const { data } = buildChartData(timeline, 14);
  if (_charts.sparkline) { _charts.sparkline.update(data); }
  else {
    _charts.sparkline = new ISECCharts.Sparkline(canvas, data, {
      color: ISECCharts.COLORS.primary,
      lineWidth: 1.5,
      fill: true,
      animMs: 800,
    });
  }
}

function renderEvidenceTypeBars(status, timeline) {
  const container = document.getElementById('evidence-type-bars');
  if (!container) return;

  const typeCounts = (status && status.evidenceTypeCounts) ? { ...status.evidenceTypeCounts } : {};
  if (Object.keys(typeCounts).length === 0 && timeline.length > 0) {
    timeline.forEach(item => { if (item.type) typeCounts[item.type] = (typeCounts[item.type] || 0) + 1; });
  }

  const total = Object.values(typeCounts).reduce((s, v) => s + v, 0) || 1;
  const types = ['system_logs', 'browser_history', 'network_connections', 'file_metadata'];
  const colors = ISECCharts.EVIDENCE_COLORS;
  const labels = ISECCharts.EVIDENCE_LABELS;

  container.innerHTML = types.map(type => {
    const count = typeCounts[type] || 0;
    const pct = Math.round((count / total) * 100);
    const color = colors[type] || '#888';
    return `
      <div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
          <span style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);text-transform:uppercase;">${labels[type] || type}</span>
          <span style="font-family:var(--font-mono);font-size:0.68rem;color:${color};font-weight:600;">${count}</span>
        </div>
        <div class="progress-bar-container">
          <div class="progress-bar" style="width:${pct}%;background:linear-gradient(90deg,${color}88,${color});box-shadow:0 0 6px ${color}66;transition:width 0.8s ease;"></div>
        </div>
      </div>
    `;
  }).join('');
}

function updateHealthStatusRow(integrity, status) {
  const container = document.getElementById('health-status-row');
  if (!container) return;

  const items = [
    {
      label: 'Chain',
      ok: !(status && status.tamperingDetected) && !(integrity && integrity.status === 'compromised'),
    },
    {
      label: 'DB',
      ok: !(status && status.tamperingDetected),
    },
    {
      label: 'Keys',
      ok: status && status.license ? !!status.license.valid : true,
    },
  ];

  container.innerHTML = items.map(it => `
    <div style="text-align:center;">
      <div class="status-dot" style="width:6px;height:6px;border-radius:50%;background:${it.ok ? 'var(--success)' : 'var(--danger)'};box-shadow:0 0 6px ${it.ok ? 'var(--success)' : 'var(--danger)'};margin:0 auto 3px;${it.ok ? 'animation:pulse-success 2s ease-in-out infinite' : 'animation:pulse-danger 1s ease-in-out infinite'};"></div>
      <div style="font-family:var(--font-mono);font-size:0.58rem;color:var(--text-muted);text-transform:uppercase;">${it.label}</div>
    </div>
  `).join('');
}

// ── Browser Consent Modal ─────────────────────────────────────────
function openBrowserConsentModal() {
  return new Promise((resolve) => {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-content">
        <div class="modal-header">
          <h3>Browser Data Consent</h3>
          <button class="close" type="button" aria-label="Close">×</button>
        </div>
        <div class="modal-body">
          <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:14px;line-height:1.6;">
            Browser history collection requires explicit consent. The following data will be collected and stored locally for forensic purposes only.
          </p>
          <div class="modal-field">
            <label>Time Range</label>
            <select id="consent-time-range">
              <option value="last_24h">Last 24 hours</option>
              <option value="last_7d" selected>Last 7 days</option>
              <option value="last_30d">Last 30 days</option>
              <option value="all_time">All time</option>
            </select>
          </div>
          <div class="modal-field">
            <label>Specific Browsers (optional)</label>
            <input id="consent-browsers" type="text" placeholder="e.g. Chrome, Firefox" />
            <small class="modal-note">Leave blank to include all detected browsers.</small>
          </div>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" type="button" data-action="cancel">Skip</button>
          <button class="btn btn-success" type="button" data-action="confirm">Grant Consent</button>
        </div>
      </div>
    `;

    const closeModal = (result) => {
      modal.classList.remove('show');
      setTimeout(() => modal.remove(), 250);
      resolve(result);
    };

    modal.addEventListener('click', (e) => { if (e.target === modal) closeModal(null); });
    modal.querySelector('.close').addEventListener('click', () => closeModal(null));
    modal.querySelector('[data-action="cancel"]').addEventListener('click', () => closeModal(null));
    modal.querySelector('[data-action="confirm"]').addEventListener('click', () => {
      const tr = modal.querySelector('#consent-time-range');
      const br = modal.querySelector('#consent-browsers');
      const timeRange = tr ? tr.value : 'last_7d';
      const browsers = br ? br.value.split(',').map(b => b.trim()).filter(Boolean) : [];
      if (!timeRange) { ISECNotify && ISECNotify.warning('Please select a time range.'); return; }
      closeModal({ timeRange, browsers });
    });

    document.body.appendChild(modal);
    requestAnimationFrame(() => requestAnimationFrame(() => modal.classList.add('show')));
  });
}

// ── Evidence Collection ───────────────────────────────────────────
async function startEvidenceCollection(options = {}) {
  const bridge = getIsecBridge();
  if (!bridge) { ISECNotify && ISECNotify.error('IPC bridge not available.'); return; }

  const collectTypes = Array.isArray(options.types) && options.types.length > 0 ? options.types : null;

  try {
    const backendStatus = await bridge.invoke('get-backend-status');
    if (backendStatus && backendStatus.license && !backendStatus.license.valid) {
      ISECNotify && ISECNotify.error(backendStatus.license.message || 'Valid license required.');
      return;
    }

    const consent = backendStatus && backendStatus.browserConsent;
    const needsBrowserConsent = !collectTypes || collectTypes.includes('browser_history');
    if (needsBrowserConsent && consent && (consent.status === 'PENDING' || consent.status === 'EXPIRED')) {
      const consentInput = await openBrowserConsentModal();
      if (consentInput && consentInput.timeRange) {
        const consentRes = await bridge.invoke('set-browser-consent', {
          timeRange: consentInput.timeRange,
          browsers: consentInput.browsers || [],
        });
        if (!consentRes || !consentRes.success) {
          ISECNotify && ISECNotify.warning((consentRes && consentRes.message) || 'Consent update failed.');
        }
      }
    }

    showLoading();
    const notify = ISECNotify && ISECNotify.loading('Collecting evidence...');
    const result = await bridge.invoke('start-evidence-collection', { types: collectTypes || [] });
    notify && notify.dismiss();

    if (result.success) {
      ISECNotify && ISECNotify.success(`Collection complete — ${result.evidenceCount || 0} items secured.`);

      const totalEl = document.getElementById('total-evidence');
      if (totalEl && result.evidenceCount !== undefined && typeof ISECCharts !== 'undefined') {
        const prev = parseInt(totalEl.textContent.replace(/,/g, ''), 10) || 0;
        ISECCharts.animateValue(totalEl, prev, result.evidenceCount, 600);
      }

      const lastEl = document.getElementById('last-collect');
      if (lastEl) lastEl.textContent = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      await loadDashboardStats();
    } else {
      ISECNotify && ISECNotify.error(result.message || 'Collection failed.');
    }
  } catch (err) {
    console.error('Collection error:', err);
    ISECNotify && ISECNotify.error('Collection error: ' + err.message);
  } finally {
    hideLoading();
  }
}

function performQuickAction(action) {
  const typeMap = {
    'system-logs': 'system_logs',
    'browser-history': 'browser_history',
    'network-connections': 'network_connections',
    'file-metadata': 'file_metadata',
  };
  const labels = { 'system-logs': 'System Logs', 'browser-history': 'Browser History', 'network-connections': 'Network', 'file-metadata': 'Files' };
  const type = typeMap[action];
  if (!type) return;
  ISECNotify && ISECNotify.info(`Starting ${labels[action] || action} collection…`);
  startEvidenceCollection({ types: [type] });
}

// ── Update Check ──────────────────────────────────────────────────
async function checkForUpdates() {
  const bridge = getIsecBridge();
  if (!bridge) return;
  try {
    const status = await bridge.invoke('check-for-updates');
    const statusEl = document.getElementById('update-status');
    const applyBtn = document.getElementById('apply-update-btn');
    if (!statusEl || !applyBtn) return;

    if (status && status.available) {
      statusEl.textContent = `Update v${status.availableVersion} available (current v${status.currentVersion}).`;
      statusEl.style.color = 'var(--warning)';
      applyBtn.disabled = false;
      ISECNotify && ISECNotify.info(`Update available: v${status.availableVersion}`);
    } else {
      const reason = status && status.reason ? status.reason.replace(/_/g, ' ') : 'up to date';
      statusEl.textContent = `System is ${reason}.`;
      statusEl.style.color = '';
      applyBtn.disabled = true;
    }
  } catch (err) {
    console.error('Update check error:', err);
  }
}

async function applyUpdate() {
  const bridge = getIsecBridge();
  if (!bridge) return;
  try {
    const result = await bridge.invoke('apply-update');
    if (result && result.success) {
      ISECNotify && ISECNotify.success(result.message || 'Update applied.');
    } else {
      ISECNotify && ISECNotify.warning(result && result.message ? result.message : 'Update could not be started.');
    }
  } catch (err) {
    ISECNotify && ISECNotify.error('Update failed: ' + err.message);
  }
}

// ── Public Exports ────────────────────────────────────────────────
// (updateLicenseUI kept for role-manager.js compatibility)
function updateLicenseUI(license) { updateLicensePanel(license); }
