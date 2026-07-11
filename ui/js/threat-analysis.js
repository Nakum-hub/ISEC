// ISEC Threat Analysis Engine — Risk Scoring, Anomaly Detection, Pattern Recognition

(function () {
  'use strict';

  let _threatBarChart = null;

  async function initThreatAnalysis() {
    const btn = document.getElementById('threat-refresh-btn');
    if (btn) btn.addEventListener('click', runThreatAnalysis);

    const sevFilter = document.getElementById('anomaly-filter-sev');
    if (sevFilter) sevFilter.addEventListener('change', () => refilterAnomalies());

    await runThreatAnalysis();
  }

  // ── Main Analysis ─────────────────────────────────────────────
  async function runThreatAnalysis() {
    const bridge = window.isec;
    if (!bridge) return;

    try {
      const [status, timeline, integrity, confidence] = await Promise.all([
        bridge.invoke('get-backend-status').catch(() => null),
        bridge.invoke('get-evidence-timeline').catch(() => null),
        bridge.invoke('get-system-integrity').catch(() => null),
        bridge.invoke('get-evidence-confidence').catch(() => null),
      ]);

      const items = (timeline && Array.isArray(timeline.items)) ? timeline.items : [];
      const analysis = computeAnalysis(status, items, integrity, confidence);

      renderRiskBanner(analysis);
      renderAnomalies(analysis.anomalies);
      renderPatterns(analysis.patterns);
      renderThreatBarChart(analysis.severityCounts);
      renderNetworkActivity(items);
      renderRecommendations(analysis);

    } catch (err) {
      console.error('Threat analysis error:', err);
      ISECNotify && ISECNotify.error('Threat analysis failed: ' + err.message);
    }
  }

  // ── Core Computation ──────────────────────────────────────────
  function computeAnalysis(status, items, integrity, confidence) {
    let riskScore = 0;

    // Factor 1: Tampering
    const tampered = status && status.tamperingDetected;
    if (tampered) riskScore += 40;

    // Factor 2: Chain integrity
    const chainBroken = integrity && integrity.status === 'compromised';
    if (chainBroken) riskScore += 35;

    // Factor 3: Evidence severity distribution
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    items.forEach(it => {
      const s = (it.severity || 'info').toLowerCase();
      if (sevCounts.hasOwnProperty(s)) sevCounts[s]++;
    });
    riskScore += Math.min(sevCounts.critical * 8, 30);
    riskScore += Math.min(sevCounts.high * 3, 15);

    // Factor 4: Low confidence
    if (confidence && typeof confidence.score === 'number' && confidence.score < 50) riskScore += 10;

    riskScore = Math.min(100, riskScore);

    // Anomalies: any critical or high severity events
    const anomalies = items
      .filter(it => ['critical','high','medium'].includes((it.severity||'').toLowerCase()))
      .sort((a,b) => {
        const ord = { critical:3, high:2, medium:1 };
        return (ord[(b.severity||'').toLowerCase()]||0) - (ord[(a.severity||'').toLowerCase()]||0);
      });

    // Patterns
    const patterns = detectPatterns(items, status, integrity);

    return { riskScore, tampered, chainBroken, severityCounts: sevCounts, anomalies, patterns, items };
  }

  function detectPatterns(items, status, integrity) {
    const patterns = [];
    if (!items.length) return patterns;

    // Pattern: High network activity
    const networkItems = items.filter(it => it.type === 'network_connections');
    if (networkItems.length > 20) {
      patterns.push({ icon: '🌐', title: 'High Network Activity', detail: `${networkItems.length} network connections recorded — possible exfiltration or scanning`, severity: networkItems.length > 50 ? 'high' : 'medium' });
    }

    // Pattern: Off-hours activity
    const offHours = items.filter(it => {
      if (!it.timestamp) return false;
      const h = new Date(it.timestamp).getHours();
      return h < 6 || h > 22;
    });
    if (offHours.length > 0) {
      patterns.push({ icon: '🌙', title: 'Off-Hours Activity', detail: `${offHours.length} events detected outside business hours (22:00 – 06:00)`, severity: offHours.length > 5 ? 'high' : 'medium' });
    }

    // Pattern: Rapid sequential events
    const sorted = [...items].sort((a,b) => new Date(a.timestamp)-new Date(b.timestamp));
    let burstCount = 0;
    for (let i = 1; i < sorted.length; i++) {
      const delta = new Date(sorted[i].timestamp) - new Date(sorted[i-1].timestamp);
      if (delta < 2000) burstCount++;
    }
    if (burstCount > 10) {
      patterns.push({ icon: '⚡', title: 'Rapid Event Burst', detail: `${burstCount} events within 2-second windows — possible automated collection or attack`, severity: 'high' });
    }

    // Pattern: Tampering
    if (status && status.tamperingDetected) {
      patterns.push({ icon: '🚨', title: 'Tampering Detected', detail: 'Evidence database or hash chain has been modified — forensic integrity compromised', severity: 'critical' });
    }

    // Pattern: Chain break
    if (integrity && integrity.status === 'compromised') {
      patterns.push({ icon: '⛓', title: 'Chain of Custody Broken', detail: 'Hash chain verification failed — evidence may have been deleted or altered', severity: 'critical' });
    }

    // Pattern: Large browser history
    const browserItems = items.filter(it => it.type === 'browser_history');
    if (browserItems.length > 100) {
      patterns.push({ icon: '🌍', title: 'Extensive Browser History', detail: `${browserItems.length} browser history entries — review for policy violations`, severity: 'medium' });
    }

    // No issues
    if (patterns.length === 0) {
      patterns.push({ icon: '✅', title: 'No Significant Patterns', detail: 'Evidence analysis found no concerning activity patterns at this time', severity: 'low' });
    }

    return patterns;
  }

  // ── Render Functions ──────────────────────────────────────────
  function renderRiskBanner(analysis) {
    const { riskScore, items, anomalies, severityCounts, chainBroken, tampered } = analysis;
    const level = riskScore >= 75 ? 'CRITICAL' : riskScore >= 50 ? 'HIGH' : riskScore >= 25 ? 'MEDIUM' : 'MINIMAL';
    const color = riskScore >= 75 ? 'var(--danger)' : riskScore >= 50 ? 'var(--orange)' : riskScore >= 25 ? 'var(--warning)' : 'var(--success)';

    const scoreEl = document.getElementById('risk-score-label');
    const levelEl = document.getElementById('risk-level-label');
    const barEl   = document.getElementById('risk-bar');

    if (scoreEl) { scoreEl.textContent = riskScore; scoreEl.style.color = color; }
    if (levelEl) { levelEl.textContent = level;     levelEl.style.color = color; }
    if (barEl)   { barEl.style.width = riskScore + '%'; barEl.style.background = color; barEl.style.boxShadow = `0 0 10px ${color}`; }

    setText('risk-anomalies', anomalies.length);
    setText('risk-critical',  severityCounts.critical || 0);
    setText('risk-chain',     (chainBroken || tampered) ? '⚠ BROKEN' : '✓ INTACT');
    const el = document.getElementById('risk-chain');
    if (el) el.style.color = (chainBroken || tampered) ? 'var(--danger)' : 'var(--success)';
    setText('risk-analysed', items.length + ' items');
  }

  function renderAnomalies(anomalies) {
    window._threatAnomalies = anomalies;
    refilterAnomalies();
  }

  function refilterAnomalies() {
    const anomalies = window._threatAnomalies || [];
    const sev = (document.getElementById('anomaly-filter-sev') || {}).value || 'all';
    const filtered = sev === 'all' ? anomalies : anomalies.filter(a => (a.severity||'').toLowerCase() === sev);

    const container = document.getElementById('anomaly-list');
    if (!container) return;

    if (!filtered.length) {
      container.innerHTML = '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);text-align:center;padding:20px;">No anomalies detected in this range.</div>';
      return;
    }

    const sevColor = { critical:'var(--danger)', high:'var(--orange)', medium:'var(--warning)', low:'var(--success)', info:'var(--cyan-bright)' };

    container.innerHTML = filtered.slice(0,50).map(item => {
      const s = (item.severity||'info').toLowerCase();
      const color = sevColor[s] || 'var(--text-muted)';
      const ts = item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Unknown';
      return `
        <div class="anomaly-item" data-evidence-id="${item.id}" style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-left:3px solid ${color};border-radius:6px;padding:10px 12px;cursor:pointer;transition:background 0.15s;">
          <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
            <div style="font-family:var(--font-ui);font-size:0.78rem;color:var(--text-secondary);flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${escHtml(item.description||'')}">
              ${escHtml(item.description||'(no description)')}
            </div>
            <span class="badge" style="background:${color}15;color:${color};border:1px solid ${color}33;font-size:0.58rem;white-space:nowrap;">${s}</span>
          </div>
          <div style="font-family:var(--font-mono);font-size:0.6rem;color:var(--text-muted);margin-top:4px;">${ts}</div>
        </div>
      `;
    }).join('');

    // Bind anomaly click-through (CSP forbids inline onclick)
    container.querySelectorAll('.anomaly-item').forEach(el => {
      el.addEventListener('click', () => {
        const id = parseInt(el.getAttribute('data-evidence-id'), 10);
        if (Number.isFinite(id) && typeof viewEvidenceDetail === 'function') viewEvidenceDetail(id);
      });
    });
  }

  function renderPatterns(patterns) {
    const container = document.getElementById('pattern-list');
    if (!container) return;

    const sevColor = { critical:'var(--danger)', high:'var(--orange)', medium:'var(--warning)', low:'var(--success)', info:'var(--cyan-bright)' };

    container.innerHTML = patterns.map(p => {
      const color = sevColor[(p.severity||'info').toLowerCase()] || 'var(--text-muted)';
      return `
        <div style="display:flex;gap:12px;align-items:flex-start;padding:10px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;">
          <div style="font-size:20px;flex-shrink:0;line-height:1;margin-top:1px;">${p.icon}</div>
          <div style="flex:1;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:3px;">
              <div style="font-family:var(--font-ui);font-size:0.78rem;font-weight:600;color:var(--text-primary);">${escHtml(p.title)}</div>
              <span class="badge" style="background:${color}15;color:${color};border:1px solid ${color}33;font-size:0.58rem;">${p.severity||'info'}</span>
            </div>
            <div style="font-family:var(--font-ui);font-size:0.72rem;color:var(--text-muted);line-height:1.4;">${escHtml(p.detail)}</div>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderThreatBarChart(sevCounts) {
    if (typeof ISECCharts === 'undefined') return;
    const canvas = document.getElementById('threat-bar-chart');
    if (!canvas) return;

    const data = [
      { label: 'Critical', value: sevCounts.critical || 0, color: '#ff1744' },
      { label: 'High',     value: sevCounts.high     || 0, color: '#ff6d00' },
      { label: 'Medium',   value: sevCounts.medium   || 0, color: '#ffd600' },
      { label: 'Low',      value: sevCounts.low      || 0, color: '#00e676' },
      { label: 'Info',     value: sevCounts.info     || 0, color: '#00c8ff' },
    ];

    if (_threatBarChart) { _threatBarChart.update(data); }
    else { _threatBarChart = new ISECCharts.BarChart(canvas, data, { paddingX: 30, paddingY: 10, barGap: 0.35 }); }
  }

  function renderNetworkActivity(items) {
    const container = document.getElementById('network-activity-list');
    if (!container) return;

    const netItems = items
      .filter(it => it.type === 'network_connections' && it.data && (it.data.remote_address || it.data.remote_host))
      .slice(0, 12);

    if (!netItems.length) {
      container.innerHTML = '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);">No network evidence collected.</div>';
      return;
    }

    const ipCounts = {};
    netItems.forEach(it => {
      const addr = it.data.remote_address || it.data.remote_host || 'unknown';
      ipCounts[addr] = (ipCounts[addr] || 0) + 1;
    });

    container.innerHTML = Object.entries(ipCounts)
      .sort(([,a],[,b]) => b-a)
      .slice(0,8)
      .map(([ip, count]) => `
        <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
          <div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--ffd740, var(--warning));">${escHtml(ip)}</div>
          <div style="font-family:var(--font-mono);font-size:0.68rem;font-weight:700;color:var(--text-secondary);">${count}×</div>
        </div>
      `).join('');
  }

  function renderRecommendations(analysis) {
    const container = document.getElementById('recommendations-list');
    if (!container) return;

    const recs = [];

    if (analysis.tampered || analysis.chainBroken) {
      recs.push({ icon:'🔒', title:'Preserve Evidence', detail:'Immediately export and hash all evidence to an offline archive before further analysis.', severity:'critical' });
      recs.push({ icon:'⚖️', title:'Engage Legal Counsel', detail:'Chain of custody breach may require legal review before evidence can be used in proceedings.', severity:'critical' });
    }

    if (analysis.riskScore > 50) {
      recs.push({ icon:'🔍', title:'Deep Investigation', detail:'High risk score warrants manual review of all critical and high severity events.', severity:'high' });
    }

    if (analysis.severityCounts.critical > 0) {
      recs.push({ icon:'🚨', title:'Escalate Critical Events', detail:`${analysis.severityCounts.critical} critical severity events require immediate escalation to security team.`, severity:'critical' });
    }

    recs.push({ icon:'📋', title:'Generate Forensic Report', detail:'Export a full forensic PDF report to document findings for investigation records.', severity:'info' });
    recs.push({ icon:'🔄', title:'Enable Auto-Collection', detail:'Schedule regular automated evidence collection to maintain continuous forensic coverage.', severity:'low' });
    recs.push({ icon:'🗃️', title:'Review Retention Policy', detail:'Ensure evidence retention policy aligns with legal and compliance requirements.', severity:'low' });

    const sevColor = { critical:'var(--danger)', high:'var(--orange)', medium:'var(--warning)', low:'var(--success)', info:'var(--cyan-bright)' };

    container.innerHTML = recs.slice(0,6).map(r => {
      const color = sevColor[r.severity] || 'var(--text-muted)';
      return `
        <div style="display:flex;gap:10px;align-items:flex-start;padding:12px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;">
          <div style="font-size:18px;flex-shrink:0;">${r.icon}</div>
          <div>
            <div style="font-family:var(--font-ui);font-size:0.78rem;font-weight:600;color:var(--text-primary);margin-bottom:3px;">${escHtml(r.title)}</div>
            <div style="font-family:var(--font-ui);font-size:0.7rem;color:var(--text-muted);line-height:1.4;">${escHtml(r.detail)}</div>
          </div>
        </div>
      `;
    }).join('');
  }

  function setText(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
  function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

  window.initThreatAnalysis = initThreatAnalysis;
})();
