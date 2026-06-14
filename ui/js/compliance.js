// ISEC Compliance Dashboard — NIST CSF 2.0 / ISO 27001 / GDPR Coverage Mapping
(function () {
  'use strict';

  const FRAMEWORK = [
    {
      id:'GV', label:'Govern', color:'#7c4dff',
      desc:'Organizational context, risk strategy, supply chain, policy',
      controls:[
        { id:'GV.OC', label:'Org Context',   types:['system_logs','file_metadata'] },
        { id:'GV.RM', label:'Risk Mgmt',     types:['system_logs','network_connections'] },
        { id:'GV.RR', label:'Roles & Resp',  types:['system_logs'] },
        { id:'GV.PO', label:'Policy',        types:['system_logs','file_metadata'] },
      ]
    },
    {
      id:'ID', label:'Identify', color:'#00c8ff',
      desc:'Asset management, risk assessment, improvement planning',
      controls:[
        { id:'ID.AM', label:'Asset Mgmt',    types:['file_metadata','system_logs'] },
        { id:'ID.RA', label:'Risk Assess',   types:['network_connections','system_logs'] },
        { id:'ID.IM', label:'Improvement',   types:['system_logs'] },
      ]
    },
    {
      id:'PR', label:'Protect', color:'#1de9b6',
      desc:'Identity, access, awareness, data security, platform security',
      controls:[
        { id:'PR.AA', label:'Auth & Access', types:['system_logs','browser_history'] },
        { id:'PR.DS', label:'Data Security', types:['file_metadata','system_logs'] },
        { id:'PR.PS', label:'Platform Sec',  types:['system_logs','network_connections'] },
        { id:'PR.IR', label:'Infra Resil',   types:['network_connections','system_logs'] },
      ]
    },
    {
      id:'DE', label:'Detect', color:'#ffd600',
      desc:'Continuous monitoring and adverse event analysis',
      controls:[
        { id:'DE.CM', label:'Monitoring',    types:['network_connections','system_logs','browser_history'] },
        { id:'DE.AE', label:'Adverse Events',types:['system_logs','network_connections','file_metadata'] },
      ]
    },
    {
      id:'RS', label:'Respond', color:'#ff6d00',
      desc:'Incident management, analysis, mitigation, reporting',
      controls:[
        { id:'RS.MA', label:'Incident Mgmt', types:['system_logs'] },
        { id:'RS.AN', label:'Analysis',      types:['system_logs','network_connections','file_metadata','browser_history'] },
        { id:'RS.MI', label:'Mitigation',    types:['system_logs','network_connections'] },
        { id:'RS.CO', label:'Reporting',     types:['system_logs','file_metadata'] },
      ]
    },
    {
      id:'RC', label:'Recover', color:'#00e676',
      desc:'Recovery planning, communications, improvements',
      controls:[
        { id:'RC.RP', label:'Recovery Plan', types:['system_logs','file_metadata'] },
        { id:'RC.CO', label:'Comms',         types:['system_logs'] },
      ]
    },
  ];

  let _typeCounts = {};
  let _barChart = null;

  async function initCompliance() {
    document.getElementById('compliance-refresh-btn') && document.getElementById('compliance-refresh-btn').addEventListener('click', loadCompliance);
    document.getElementById('compliance-export-btn') && document.getElementById('compliance-export-btn').addEventListener('click', exportMatrix);
    const tvBtn = document.getElementById('transparency-verify-btn');
    if (tvBtn) tvBtn.addEventListener('click', verifyTransparencyLog);
    const ceBtn = document.getElementById('case-export-btn');
    if (ceBtn) ceBtn.addEventListener('click', exportCaseBundle);
    await loadCompliance();
  }

  async function loadCompliance() {
    const bridge = window.isec;
    if (bridge) {
      try {
        const status = await bridge.invoke('get-backend-status').catch(()=>null);
        _typeCounts = (status && status.evidenceTypeCounts) || {};
        const tl = await bridge.invoke('get-evidence-timeline').catch(()=>null);
        if (tl && Array.isArray(tl.items)) {
          tl.items.forEach(it => {
            if (it.type) _typeCounts[it.type] = (_typeCounts[it.type]||0) + 1;
          });
        }
      } catch(_) {}
    }
    renderCompliance();
  }

  function coverageForControl(ctrl) {
    const covered = ctrl.types.filter(t => (_typeCounts[t]||0) > 0);
    return Math.round((covered.length / ctrl.types.length) * 100);
  }

  function functionCoverage(fn) {
    const scores = fn.controls.map(c => coverageForControl(c));
    return Math.round(scores.reduce((a,b)=>a+b,0) / scores.length);
  }

  function overallCoverage() {
    const scores = FRAMEWORK.map(fn => functionCoverage(fn));
    return Math.round(scores.reduce((a,b)=>a+b,0) / scores.length);
  }

  function renderCompliance() {
    const overall = overallCoverage();
    const pctEl  = document.getElementById('compliance-pct');
    const barEl  = document.getElementById('compliance-bar');
    const statEl = document.getElementById('compliance-status');

    if (pctEl) {
      pctEl.textContent = overall + '%';
      pctEl.style.color = overall >= 70 ? 'var(--success)' : overall >= 40 ? 'var(--warning)' : 'var(--danger)';
    }
    if (barEl) {
      barEl.style.width = overall + '%';
      barEl.style.background = overall >= 70 ? 'var(--success)' : overall >= 40 ? 'var(--warning)' : 'var(--danger)';
      barEl.style.boxShadow = `0 0 10px ${overall >= 70 ? 'var(--success)' : overall >= 40 ? 'var(--warning)' : 'var(--danger)'}`;
    }
    if (statEl) statEl.textContent = overall >= 70 ? 'Good Coverage' : overall >= 40 ? 'Partial Coverage' : 'Insufficient Evidence';

    // Framework pills
    const pillsEl = document.getElementById('compliance-framework-pills');
    if (pillsEl) {
      pillsEl.innerHTML = FRAMEWORK.map(fn => {
        const pct = functionCoverage(fn);
        return `<div style="display:flex;align-items:center;gap:6px;background:${fn.color}12;border:1px solid ${fn.color}30;border-radius:20px;padding:4px 12px;">
          <div style="width:6px;height:6px;border-radius:50%;background:${fn.color};box-shadow:0 0 5px ${fn.color};"></div>
          <span style="font-family:var(--font-mono);font-size:0.62rem;color:${fn.color};text-transform:uppercase;">${fn.id}</span>
          <span style="font-family:var(--font-mono);font-size:0.62rem;color:var(--text-muted);">${pct}%</span>
        </div>`;
      }).join('');
    }

    // Framework cards
    const grid = document.getElementById('compliance-grid');
    if (!grid) return;

    grid.innerHTML = FRAMEWORK.map(fn => {
      const pct = functionCoverage(fn);
      const color = fn.color;
      return `
        <div class="glassmorphism" style="padding:18px;border-left:3px solid ${color};">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <div style="width:34px;height:34px;border-radius:8px;background:${color}18;border:1px solid ${color}30;display:flex;align-items:center;justify-content:center;font-family:var(--font-mono);font-size:0.72rem;font-weight:700;color:${color};">${fn.id}</div>
              <div>
                <div style="font-size:0.88rem;font-weight:600;color:var(--text-primary);">${fn.label}</div>
                <div style="font-size:0.68rem;color:var(--text-muted);">${fn.desc}</div>
              </div>
            </div>
            <div style="text-align:right;flex-shrink:0;">
              <div style="font-family:var(--font-mono);font-size:1.2rem;font-weight:700;color:${color};">${pct}%</div>
              <div style="font-size:0.6rem;color:var(--text-muted);text-transform:uppercase;">Coverage</div>
            </div>
          </div>
          <div style="height:4px;background:rgba(255,255,255,0.06);border-radius:2px;overflow:hidden;margin-bottom:14px;">
            <div style="height:100%;width:${pct}%;background:${color};border-radius:2px;transition:width 0.8s ease;box-shadow:0 0 6px ${color}66;"></div>
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;">
            ${fn.controls.map(ctrl => {
              const ctrlPct = coverageForControl(ctrl);
              const ctrlColor = ctrlPct===100?'var(--success)':ctrlPct>0?'var(--warning)':'var(--text-muted)';
              const evidenceList = ctrl.types.map(t=>{
                const n = _typeCounts[t]||0;
                const tLabel = {system_logs:'Sys Logs',browser_history:'Browser',network_connections:'Network',file_metadata:'Files'}[t]||t;
                return `<span style="font-size:0.58rem;color:${n>0?color:'#4d6080'};">${tLabel}${n>0?' ('+n+')':''}</span>`;
              }).join(' · ');
              return `
                <div style="background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:7px;padding:9px 10px;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
                    <span style="font-family:var(--font-mono);font-size:0.65rem;font-weight:600;color:${ctrlColor};">${ctrl.id}</span>
                    <span style="font-family:var(--font-mono);font-size:0.6rem;color:${ctrlColor};">${ctrlPct}%</span>
                  </div>
                  <div style="font-size:0.68rem;color:var(--text-secondary);margin-bottom:5px;">${ctrl.label}</div>
                  <div style="height:2px;background:rgba(255,255,255,0.05);border-radius:1px;overflow:hidden;margin-bottom:5px;">
                    <div style="height:100%;width:${ctrlPct}%;background:${ctrlColor};border-radius:1px;"></div>
                  </div>
                  <div style="line-height:1.5;">${evidenceList}</div>
                </div>`;
            }).join('')}
          </div>
        </div>`;
    }).join('');
  }

  function exportMatrix() {
    const rows = [['Function','Control','Label','Coverage%','Evidence Types']];
    FRAMEWORK.forEach(fn => {
      fn.controls.forEach(ctrl => {
        const pct = coverageForControl(ctrl);
        rows.push([fn.label, ctrl.id, ctrl.label, pct + '%', ctrl.types.join('; ')]);
      });
    });
    const csv = rows.map(r=>r.map(v=>`"${v}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type:'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href=url; a.download=`isec-compliance-matrix-${Date.now()}.csv`;
    a.click(); URL.revokeObjectURL(url);
    ISECNotify && ISECNotify.success('Compliance matrix exported');
  }

  // ── Evidence integrity & interoperability helpers ───────────────────────────
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]));
  }

  async function verifyTransparencyLog() {
    const bridge = window.isec;
    const out = document.getElementById('transparency-result');
    const btn = document.getElementById('transparency-verify-btn');
    if (!bridge) { if (out) out.textContent = 'Secure bridge unavailable.'; return; }
    if (btn) { btn.disabled = true; btn.textContent = 'Verifying…'; }
    if (out) out.innerHTML = '<span style="color:var(--text-muted);">Verifying transparency log…</span>';
    try {
      const res = await bridge.invoke('get-transparency-status');
      if (!res || res.success === false) {
        const msg = (res && res.message) ? res.message : 'Verification failed.';
        if (out) out.innerHTML = `<span style="color:var(--danger);">\u2717 ${esc(msg)}</span>`;
        ISECNotify && ISECNotify.error(msg);
        return;
      }
      const t = res.transparency || {};
      if (!t.present) {
        if (out) out.innerHTML = '<span style="color:var(--warning);">No transparency log present yet.</span>';
        ISECNotify && ISECNotify.info('No transparency log present.');
        return;
      }
      const ok = !!t.valid;
      const color = ok ? 'var(--success)' : 'var(--danger)';
      const icon = ok ? '\u2713' : '\u2717';
      const issues = Array.isArray(t.issues) ? t.issues : [];
      let html = `<div style="color:${color};font-weight:600;margin-bottom:4px;">${icon} ${ok ? 'Log verified' : 'Verification failed'}</div>`;
      html += `<div>Entries: ${esc(t.entries != null ? t.entries : 0)} \u00b7 Schema: ${esc(t.schema || '\u2014')}</div>`;
      html += `<div>Signature: ${t.signatureVerification ? '<span style="color:var(--success);">verified</span>' : '<span style="color:var(--text-muted);">not verified</span>'}</div>`;
      if (issues.length) {
        html += '<div style="margin-top:5px;color:var(--warning);">Issues:</div>';
        html += issues.map(i => `<div style="color:var(--warning);">\u2022 ${esc(i)}</div>`).join('');
      }
      if (out) out.innerHTML = html;
      ISECNotify && (ok ? ISECNotify.success('Transparency log verified') : ISECNotify.warning('Transparency log verification failed'));
    } catch (err) {
      if (out) out.innerHTML = `<span style="color:var(--danger);">\u2717 ${esc(err.message || 'Verification error')}</span>`;
      ISECNotify && ISECNotify.error(err.message || 'Verification error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Verify Log'; }
    }
  }

  async function exportCaseBundle() {
    const bridge = window.isec;
    const out = document.getElementById('case-export-result');
    const btn = document.getElementById('case-export-btn');
    if (!bridge) { if (out) out.textContent = 'Secure bridge unavailable.'; return; }
    const opts = {
      includePayload: !!(document.getElementById('case-include-payload') && document.getElementById('case-include-payload').checked),
      includeExpired: !!(document.getElementById('case-include-expired') && document.getElementById('case-include-expired').checked),
      includeDeleted: !!(document.getElementById('case-include-deleted') && document.getElementById('case-include-deleted').checked),
    };
    if (btn) { btn.disabled = true; btn.textContent = 'Exporting…'; }
    if (out) out.innerHTML = '<span style="color:var(--text-muted);">Exporting CASE/UCO bundle…</span>';
    try {
      const res = await bridge.invoke('export-case', opts);
      if (res && res.success) {
        if (out) out.innerHTML = `<span style="color:var(--success);">\u2713 Exported</span><div style="color:var(--text-muted);margin-top:3px;word-break:break-all;">${esc(res.filePath || '')}</div>`;
        ISECNotify && ISECNotify.success(res.message || 'CASE/UCO bundle exported');
      } else {
        const msg = (res && res.message) ? res.message : 'Export failed.';
        if (out) out.innerHTML = `<span style="color:var(--danger);">\u2717 ${esc(msg)}</span>`;
        ISECNotify && ISECNotify.error(msg);
      }
    } catch (err) {
      if (out) out.innerHTML = `<span style="color:var(--danger);">\u2717 ${esc(err.message || 'Export error')}</span>`;
      ISECNotify && ISECNotify.error(err.message || 'Export error');
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Export Bundle'; }
    }
  }

  window.initCompliance = initCompliance;
})();
