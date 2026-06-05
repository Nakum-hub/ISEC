// ISEC Evidence Detail View — Chain of Custody, Integrity Verification, Evidence Analysis

(function () {
  'use strict';

  let _currentDetail = null;
  let _rawVisible    = false;

  // ── Lifecycle ────────────────────────────────────────────────
  function initDetailView() {
    const backBtn    = document.getElementById('detail-back-btn');
    const copyBtn    = document.getElementById('detail-copy-btn');
    const exportBtn  = document.getElementById('detail-export-btn');
    const toggleRaw  = document.getElementById('toggle-raw-btn');

    if (backBtn)   backBtn.addEventListener('click', closeDetailPanel);
    if (copyBtn)   copyBtn.addEventListener('click', copyDetailJson);
    if (exportBtn) exportBtn.addEventListener('click', exportDetailReport);
    if (toggleRaw) toggleRaw.addEventListener('click', toggleRawData);
  }

  // ── Open / Close Panel ────────────────────────────────────────
  async function viewEvidenceDetail(id) {
    if (!id) return;
    const panel = document.getElementById('detail-panel');
    if (!panel) return;

    setSubtitle('Loading evidence #' + id + '…');
    panel.classList.remove('hidden');
    panel.style.display = 'flex';

    const bridge = window.isec;
    if (!bridge) { setSubtitle('Error: IPC bridge not available'); return; }

    try {
      const [rawDetail, confidence] = await Promise.all([
        bridge.invoke('get-evidence-detail', { id }),
        bridge.invoke('get-evidence-confidence').catch(() => null),
      ]);

      // Handler returns { item: {...}, success } or a flat object
      const detail = (rawDetail && rawDetail.item) ? rawDetail.item : rawDetail;

      if (!detail || detail.error || rawDetail === null) {
        setSubtitle('Evidence not found or access denied.');
        return;
      }

      _currentDetail = detail;
      _rawVisible    = false;

      renderDetailHeader(detail);
      renderDetailFields(detail);
      renderRawData(detail);
      renderCustodyChain(detail);
      renderCryptoIntegrity(detail);
      renderConfidence(confidence);
      renderAdditionalFields(detail);

    } catch (err) {
      console.error('Detail load error:', err);
      setSubtitle('Error loading detail: ' + err.message);
      ISECNotify && ISECNotify.error('Failed to load evidence detail.');
    }
  }

  function closeDetailPanel() {
    const panel = document.getElementById('detail-panel');
    if (panel) { panel.classList.add('hidden'); panel.style.display = 'none'; }
    _currentDetail = null;
  }

  // ── Render Sections ───────────────────────────────────────────
  function renderDetailHeader(detail) {
    const sev = (detail.severity || 'info').toLowerCase();
    setSubtitle(`Record #${detail.id || '?'} — ${formatType(detail.type)} — ${sev.toUpperCase()}`);

    const intBadge = document.getElementById('detail-integrity-badge');
    const ok = detail.integrityOk !== false && detail.chainVerificationResult !== 'CHAIN_BROKEN';
    if (intBadge) {
      intBadge.className = 'integrity-indicator ' + (ok ? 'integrity-valid' : 'integrity-compromised');
      intBadge.querySelector('span').textContent = ok ? 'VERIFIED' : 'COMPROMISED';
    }
  }

  function renderDetailFields(detail) {
    const ts = detail.timestamp ? new Date(detail.timestamp) : null;
    const tsStr = ts ? ts.toLocaleDateString([], { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric' }) + ' ' + ts.toLocaleTimeString() : '—';

    setElText('detail-description', detail.description || '(no description)');
    setElText('detail-type', formatType(detail.type));
    setElText('detail-timestamp', tsStr);
    setElText('detail-actor', detail.actor || '—');
    setElText('detail-workstation', detail.workstationId || '—');
    setElText('detail-ip', detail.ipAddress || '—');
    setElText('detail-size', detail.sizeBytes !== undefined ? formatBytes(detail.sizeBytes) : '—');
    setElText('detail-retention', formatRetentionStatus(detail.retentionStatus));
    setElText('detail-id', detail.id || '—');

    const sevBadgeEl = document.getElementById('detail-severity-badge');
    if (sevBadgeEl) sevBadgeEl.innerHTML = buildSeverityBadge((detail.severity || 'info').toLowerCase());
  }

  function renderRawData(detail) {
    const data = detail.data || {};
    const formatted = document.getElementById('evidence-data-formatted');
    const raw = document.getElementById('evidence-data-raw');

    if (formatted) {
      const fields = Object.entries(data);
      if (fields.length === 0) {
        formatted.innerHTML = '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);">No evidence data fields.</div>';
      } else {
        formatted.innerHTML = `<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;">
          ${fields.map(([k, v]) => `
            <div>
              <div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">${escHtml(k.replace(/_/g,' '))}</div>
              <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--teal);word-break:break-all;">${escHtml(String(v ?? '—'))}</div>
            </div>`).join('')}
        </div>`;
      }
    }

    if (raw) {
      raw.textContent = JSON.stringify(data, null, 2);
      raw.style.display = 'none';
    }
  }

  function toggleRawData() {
    const formatted = document.getElementById('evidence-data-formatted');
    const raw       = document.getElementById('evidence-data-raw');
    const btn       = document.getElementById('toggle-raw-btn');
    _rawVisible = !_rawVisible;
    if (formatted) formatted.style.display = _rawVisible ? 'none' : 'block';
    if (raw)       raw.style.display       = _rawVisible ? 'block' : 'none';
    if (btn)       btn.textContent         = _rawVisible ? 'Show Formatted' : 'Show Raw';
  }

  // ── Chain of Custody ─────────────────────────────────────────
  function renderCustodyChain(detail) {
    const container = document.getElementById('custody-chain');
    if (!container) return;

    const steps = buildCustodySteps(detail);
    container.innerHTML = steps.map((step, i) => `
      <div style="display:flex;gap:0;position:relative;">
        <!-- Timeline line -->
        ${i < steps.length - 1 ? `<div style="position:absolute;left:15px;top:32px;bottom:-4px;width:2px;background:${step.ok ? 'rgba(0,230,118,0.2)' : 'rgba(255,23,68,0.2)'};"></div>` : ''}
        <!-- Step dot -->
        <div style="display:flex;flex-direction:column;align-items:center;gap:0;flex-shrink:0;width:32px;">
          <div style="width:10px;height:10px;border-radius:50%;background:${step.ok ? 'var(--success)' : 'var(--danger)'};box-shadow:0 0 8px ${step.ok ? 'var(--success)' : 'var(--danger)'};margin-top:10px;flex-shrink:0;${step.ok ? 'animation:pulse-success 2s ease-in-out infinite' : ''};"></div>
        </div>
        <!-- Step content -->
        <div style="flex:1;padding:8px 0 16px 12px;">
          <div style="font-family:var(--font-mono);font-size:0.68rem;font-weight:600;color:${step.ok ? 'var(--text-primary)' : 'var(--danger)'};text-transform:uppercase;letter-spacing:0.06em;">${step.label}</div>
          <div style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);margin-top:2px;">${step.detail}</div>
          ${step.timestamp ? `<div style="font-family:var(--font-mono);font-size:0.58rem;color:var(--text-muted);margin-top:2px;opacity:0.7;">${step.timestamp}</div>` : ''}
        </div>
      </div>
    `).join('');
  }

  function buildCustodySteps(detail) {
    const ts = detail.timestamp ? new Date(detail.timestamp).toLocaleString() : 'Unknown time';
    const chainOk = detail.chainVerificationResult !== 'CHAIN_BROKEN';
    const hmacOk  = !!detail.hmacSignature;
    const intOk   = detail.integrityOk !== false;

    return [
      {
        label: 'Evidence Captured',
        detail: `By ${detail.actor || 'system'} on ${detail.workstationId || 'unknown workstation'}`,
        timestamp: ts,
        ok: true,
      },
      {
        label: 'HMAC Signed',
        detail: hmacOk ? `Signature: ${detail.hmacSignature ? detail.hmacSignature.slice(0,16) + '…' : '—'}` : 'Signature missing',
        timestamp: ts,
        ok: hmacOk,
      },
      {
        label: 'Hash Chain Linked',
        detail: chainOk
          ? `Prev: ${detail.prevRecordHash ? detail.prevRecordHash.slice(0,12) + '…' : 'Genesis'}`
          : 'Chain break detected — potential tampering',
        timestamp: ts,
        ok: chainOk,
      },
      {
        label: 'Integrity Verified',
        detail: intOk ? 'All cryptographic checks passed' : 'Integrity check failed',
        timestamp: ts,
        ok: intOk,
      },
      {
        label: 'Stored in Encrypted DB',
        detail: `Record size: ${detail.sizeBytes !== undefined ? formatBytes(detail.sizeBytes) : '—'}`,
        timestamp: ts,
        ok: true,
      },
    ];
  }

  // ── Crypto Integrity Panel ────────────────────────────────────
  function renderCryptoIntegrity(detail) {
    setElText('detail-hmac', detail.hmacSignature || '— not available —');
    setElText('detail-hash-current', detail.currentRecordHash || '— not available —');
    setElText('detail-hash-prev', detail.prevRecordHash || '— GENESIS (first record) —');

    const verifyEl    = document.getElementById('detail-verify-result');
    const verifyTitle = document.getElementById('verify-title');
    const verifyDet   = document.getElementById('verify-detail');

    const compromised = detail.chainVerificationResult === 'CHAIN_BROKEN' || detail.integrityOk === false;
    if (verifyEl) {
      verifyEl.style.background = compromised ? 'rgba(255,23,68,0.07)' : 'rgba(0,230,118,0.07)';
      verifyEl.style.borderColor = compromised ? 'rgba(255,23,68,0.2)' : 'rgba(0,230,118,0.2)';
      const dot = verifyEl.querySelector('div');
      if (dot) {
        dot.style.background = compromised ? 'var(--danger)' : 'var(--success)';
        dot.style.boxShadow  = compromised ? '0 0 8px var(--danger)' : '0 0 8px var(--success)';
        dot.style.animation  = compromised ? 'pulse-danger 1s ease-in-out infinite' : 'pulse-success 2s ease-in-out infinite';
      }
    }
    if (verifyTitle) {
      verifyTitle.textContent = compromised ? '⚠ CHAIN BROKEN' : '✓ CHAIN INTACT';
      verifyTitle.style.color = compromised ? 'var(--danger)' : 'var(--success)';
    }
    if (verifyDet) {
      verifyDet.textContent = compromised
        ? `Verification failed: ${detail.chainVerificationResult || 'integrity check failure'}`
        : 'All cryptographic checks passed — evidence is unmodified';
    }
  }

  // ── Confidence ───────────────────────────────────────────────
  function renderConfidence(confidence) {
    const container = document.getElementById('confidence-content');
    if (!container) return;

    if (!confidence) {
      container.innerHTML = '<div style="font-family:var(--font-mono);font-size:0.7rem;color:var(--text-muted);">Confidence data unavailable.</div>';
      return;
    }

    const score   = typeof confidence.score === 'number' ? confidence.score : 0;
    const level   = confidence.confidenceLevel || 'UNKNOWN';
    const factors = Array.isArray(confidence.factors) ? confidence.factors : [];
    const levelColor = score >= 80 ? 'var(--success)' : score >= 50 ? 'var(--warning)' : 'var(--danger)';

    container.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;">
        <div style="font-family:var(--font-mono);font-size:2rem;font-weight:700;color:${levelColor};">${score}</div>
        <div>
          <div style="font-family:var(--font-mono);font-size:0.7rem;font-weight:700;color:${levelColor};text-transform:uppercase;">${level}</div>
          <div style="font-size:0.65rem;color:var(--text-muted);margin-top:2px;">Confidence Score</div>
        </div>
      </div>
      <div class="progress-bar-container" style="margin-bottom:12px;">
        <div class="progress-bar" style="width:${score}%;background:${levelColor};box-shadow:0 0 8px ${levelColor}66;"></div>
      </div>
      ${factors.length > 0 ? `
        <div style="font-family:var(--font-mono);font-size:0.6rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:8px;">Contributing Factors</div>
        <div style="display:flex;flex-direction:column;gap:6px;">
          ${factors.map(f => `
            <div style="display:flex;align-items:center;gap:8px;">
              <div style="width:5px;height:5px;border-radius:50%;background:${levelColor};flex-shrink:0;"></div>
              <div style="font-family:var(--font-mono);font-size:0.68rem;color:var(--text-secondary);">${escHtml(String(f))}</div>
            </div>`).join('')}
        </div>` : ''}
    `;
  }

  // ── Additional Fields ─────────────────────────────────────────
  function renderAdditionalFields(detail) {
    const card    = document.getElementById('additional-fields-card');
    const content = document.getElementById('additional-fields-content');
    if (!card || !content) return;

    const fields = detail.additionalFields || {};
    const entries = Object.entries(fields).filter(([, v]) => v !== null && v !== undefined && v !== '');
    if (entries.length === 0) { card.style.display = 'none'; return; }

    card.style.display = 'block';
    content.innerHTML = entries.map(([k, v]) => `
      <div>
        <div style="font-family:var(--font-mono);font-size:0.58rem;text-transform:uppercase;color:var(--text-muted);margin-bottom:2px;">${escHtml(k)}</div>
        <div style="font-family:var(--font-mono);font-size:0.72rem;color:var(--text-secondary);word-break:break-all;">${escHtml(String(v))}</div>
      </div>
    `).join('');
  }

  // ── Actions ───────────────────────────────────────────────────
  async function copyDetailJson() {
    if (!_currentDetail) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(_currentDetail, null, 2));
      ISECNotify && ISECNotify.success('Evidence JSON copied to clipboard');
    } catch (e) {
      ISECNotify && ISECNotify.error('Copy failed: ' + e.message);
    }
  }

  function exportDetailReport() {
    if (!_currentDetail) return;
    if (typeof navigateTo === 'function') {
      navigateTo('report');
      ISECNotify && ISECNotify.info('Opened report generator — select evidence type and format.');
    }
  }

  // ── Utilities ─────────────────────────────────────────────────
  function setSubtitle(text) {
    const el = document.getElementById('detail-subtitle');
    if (el) el.textContent = text;
  }

  function setElText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  function buildSeverityBadge(sev) {
    const cls = { critical:'severity-critical', high:'severity-high', medium:'severity-medium', low:'severity-low', info:'severity-info' }[sev] || 'badge-muted';
    return `<span class="${cls}">${sev}</span>`;
  }

  function formatType(type) {
    const labels = { system_logs:'System Logs', browser_history:'Browser History', network_connections:'Network Connections', file_metadata:'File Metadata' };
    return labels[type] || (type ? type.replace(/_/g,' ') : '—');
  }

  function formatRetentionStatus(s) {
    if (!s) return '—';
    return s === 'ACTIVE' ? '✓ Active' : s === 'EXPIRED' ? '⚠ Expired' : s;
  }

  function formatBytes(bytes) {
    if (!bytes || bytes < 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  }

  function escHtml(str) {
    return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Public ────────────────────────────────────────────────────
  window.viewEvidenceDetail = viewEvidenceDetail;
  window.closeDetailPanel   = closeDetailPanel;
  window.initDetailView     = initDetailView;

})();
