/**
 * ISEC Charts Engine v2.0
 * Canvas-based charting library — zero external dependencies
 * Supports: Donut, Line/Area, Bar, Gauge, Sparkline charts
 */
const ISECCharts = (function () {
  'use strict';

  // ── Design Tokens ──────────────────────────────────────────────
  const COLORS = {
    primary: '#00c8ff',
    accent: '#007acc',
    success: '#00e676',
    warning: '#ffd600',
    danger: '#ff1744',
    purple: '#7c4dff',
    teal: '#1de9b6',
    orange: '#ff6d00',
    pink: '#f50057',
    text: '#e0e7ff',
    textMuted: '#6b7faa',
    bg: 'rgba(15, 22, 40, 0.0)',
    grid: 'rgba(0, 200, 255, 0.07)',
    gridBright: 'rgba(0, 200, 255, 0.15)',
  };

  const EVIDENCE_COLORS = {
    system_logs: '#64b5f6',
    browser_history: '#69f0ae',
    network_connections: '#ffd740',
    file_metadata: '#ce93d8',
  };

  const EVIDENCE_LABELS = {
    system_logs: 'System Logs',
    browser_history: 'Browser History',
    network_connections: 'Network',
    file_metadata: 'File Metadata',
  };

  // ── Utilities ──────────────────────────────────────────────────
  function dpr() { return window.devicePixelRatio || 1; }

  function setupCanvas(canvas) {
    const r = canvas.getBoundingClientRect();
    const d = dpr();
    canvas.width = r.width * d;
    canvas.height = r.height * d;
    const ctx = canvas.getContext('2d');
    ctx.scale(d, d);
    return { ctx, w: r.width, h: r.height };
  }

  function ease(t) {
    return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
  }

  function hexToRgba(hex, alpha) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r},${g},${b},${alpha})`;
  }

  function roundedRect(ctx, x, y, w, h, r) {
    ctx.beginPath();
    ctx.moveTo(x + r, y);
    ctx.lineTo(x + w - r, y);
    ctx.arcTo(x + w, y, x + w, y + r, r);
    ctx.lineTo(x + w, y + h - r);
    ctx.arcTo(x + w, y + h, x + w - r, y + h, r);
    ctx.lineTo(x + r, y + h);
    ctx.arcTo(x, y + h, x, y + h - r, r);
    ctx.lineTo(x, y + r);
    ctx.arcTo(x, y, x + r, y, r);
    ctx.closePath();
  }

  // ── Donut Chart ────────────────────────────────────────────────
  class DonutChart {
    constructor(canvas, data, opts = {}) {
      this.canvas = canvas;
      this.data = data; // [{label, value, color}]
      this.opts = {
        innerRatio: 0.62,
        gap: 0.015,
        animMs: 900,
        centerLabel: null,
        centerValue: null,
        ...opts
      };
      this._frame = null;
      this._start = null;
      this.render();
    }

    render() {
      if (this._frame) cancelAnimationFrame(this._frame);
      this._start = null;
      const step = (ts) => {
        if (!this._start) this._start = ts;
        const p = Math.min((ts - this._start) / this.opts.animMs, 1);
        this._draw(ease(p));
        if (p < 1) this._frame = requestAnimationFrame(step);
      };
      this._frame = requestAnimationFrame(step);
    }

    update(data) {
      this.data = data;
      this.render();
    }

    destroy() {
      if (this._frame) cancelAnimationFrame(this._frame);
    }

    _draw(progress) {
      const { canvas, data, opts } = this;
      const { ctx, w, h } = setupCanvas(canvas);
      ctx.clearRect(0, 0, w, h);

      if (!data || data.length === 0) {
        this._drawEmpty(ctx, w, h);
        return;
      }

      const total = data.reduce((s, d) => s + (d.value || 0), 0);
      if (total === 0) { this._drawEmpty(ctx, w, h); return; }

      const cx = w / 2, cy = h / 2;
      const outerR = Math.min(w, h) / 2 * 0.85;
      const innerR = outerR * opts.innerRatio;

      let angle = -Math.PI / 2;
      const fullTurn = Math.PI * 2 * progress;

      data.forEach((seg) => {
        const segAngle = (seg.value / total) * fullTurn;
        const endAngle = angle + segAngle - opts.gap;

        ctx.beginPath();
        ctx.arc(cx, cy, outerR, angle, endAngle);
        ctx.arc(cx, cy, innerR, endAngle, angle, true);
        ctx.closePath();

        const grd = ctx.createRadialGradient(cx, cy, innerR, cx, cy, outerR);
        grd.addColorStop(0, hexToRgba(seg.color || COLORS.primary, 0.6));
        grd.addColorStop(1, hexToRgba(seg.color || COLORS.primary, 1.0));
        ctx.fillStyle = grd;
        ctx.fill();

        // Glow
        ctx.shadowColor = seg.color || COLORS.primary;
        ctx.shadowBlur = 8;
        ctx.fill();
        ctx.shadowBlur = 0;

        angle += segAngle;
      });

      // Center text
      if (opts.centerLabel !== null) {
        ctx.fillStyle = COLORS.text;
        ctx.font = `600 ${Math.floor(outerR * 0.28)}px 'JetBrains Mono', 'Courier New', monospace`;
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(String(opts.centerValue || ''), cx, cy - outerR * 0.08);

        ctx.fillStyle = COLORS.textMuted;
        ctx.font = `400 ${Math.floor(outerR * 0.14)}px 'Rajdhani', sans-serif`;
        ctx.fillText(opts.centerLabel, cx, cy + outerR * 0.16);
      }
    }

    _drawEmpty(ctx, w, h) {
      const cx = w / 2, cy = h / 2;
      const r = Math.min(w, h) / 2 * 0.85;
      const innerR = r * this.opts.innerRatio;

      ctx.beginPath();
      ctx.arc(cx, cy, r, 0, Math.PI * 2);
      ctx.arc(cx, cy, innerR, 0, Math.PI * 2, true);
      ctx.closePath();
      ctx.fillStyle = 'rgba(255,255,255,0.05)';
      ctx.fill();

      ctx.fillStyle = COLORS.textMuted;
      ctx.font = `400 12px 'Rajdhani', sans-serif`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('No Data', cx, cy);
    }
  }

  // ── Line / Area Chart ──────────────────────────────────────────
  class LineChart {
    constructor(canvas, datasets, opts = {}) {
      this.canvas = canvas;
      this.datasets = datasets; // [{label, data: [y...], color, fill?}]
      this.labels = opts.labels || [];
      this.opts = {
        animMs: 1000,
        paddingX: 40,
        paddingY: 20,
        showGrid: true,
        showDots: true,
        dotRadius: 3,
        lineWidth: 2,
        fillAlpha: 0.12,
        yMin: null,
        yMax: null,
        ...opts
      };
      this._frame = null;
      this._start = null;
      this.render();
    }

    render() {
      if (this._frame) cancelAnimationFrame(this._frame);
      this._start = null;
      const step = (ts) => {
        if (!this._start) this._start = ts;
        const p = Math.min((ts - this._start) / this.opts.animMs, 1);
        this._draw(ease(p));
        if (p < 1) this._frame = requestAnimationFrame(step);
      };
      this._frame = requestAnimationFrame(step);
    }

    update(datasets, labels) {
      this.datasets = datasets;
      if (labels) this.labels = labels;
      this.render();
    }

    destroy() {
      if (this._frame) cancelAnimationFrame(this._frame);
    }

    _draw(progress) {
      const { canvas, datasets, labels, opts } = this;
      const { ctx, w, h } = setupCanvas(canvas);
      ctx.clearRect(0, 0, w, h);

      if (!datasets || datasets.length === 0) return;

      const px = opts.paddingX, py = opts.paddingY;
      const chartW = w - px * 2;
      const chartH = h - py * 2 - 20;

      // Compute range
      const allVals = datasets.flatMap(d => d.data || []);
      if (allVals.length === 0) return;
      const yMin = opts.yMin !== null ? opts.yMin : Math.min(0, ...allVals);
      const yMax = opts.yMax !== null ? opts.yMax : Math.max(...allVals) * 1.1 || 1;
      const yRange = yMax - yMin || 1;
      const xStep = datasets[0].data.length > 1 ? chartW / (datasets[0].data.length - 1) : chartW;

      const toX = (i) => px + i * xStep;
      const toY = (v) => py + chartH - ((v - yMin) / yRange) * chartH;

      // Grid
      if (opts.showGrid) {
        const gridLines = 4;
        ctx.strokeStyle = COLORS.grid;
        ctx.lineWidth = 1;
        for (let i = 0; i <= gridLines; i++) {
          const y = py + (chartH / gridLines) * i;
          ctx.beginPath();
          ctx.moveTo(px, y);
          ctx.lineTo(px + chartW, y);
          ctx.stroke();
        }

        // Y axis labels
        ctx.fillStyle = COLORS.textMuted;
        ctx.font = `10px 'JetBrains Mono', monospace`;
        ctx.textAlign = 'right';
        for (let i = 0; i <= gridLines; i++) {
          const v = yMax - (yRange / gridLines) * i;
          const y = py + (chartH / gridLines) * i;
          ctx.fillText(Math.round(v), px - 4, y + 4);
        }
      }

      // X axis labels
      if (labels.length > 0) {
        ctx.fillStyle = COLORS.textMuted;
        ctx.font = `10px 'JetBrains Mono', monospace`;
        ctx.textAlign = 'center';
        const step = Math.max(1, Math.floor(labels.length / 6));
        labels.forEach((lbl, i) => {
          if (i % step === 0) {
            ctx.fillText(lbl, toX(i), py + chartH + 14);
          }
        });
      }

      datasets.forEach((ds) => {
        const data = ds.data || [];
        if (data.length === 0) return;
        const color = ds.color || COLORS.primary;
        const pointCount = Math.floor(data.length * progress) + 1;
        const pts = data.slice(0, Math.min(pointCount, data.length));

        // Fill
        if (ds.fill !== false) {
          ctx.beginPath();
          ctx.moveTo(toX(0), toY(yMin));
          pts.forEach((v, i) => ctx.lineTo(toX(i), toY(v)));
          ctx.lineTo(toX(pts.length - 1), toY(yMin));
          ctx.closePath();
          const grad = ctx.createLinearGradient(0, py, 0, py + chartH);
          grad.addColorStop(0, hexToRgba(color, opts.fillAlpha * 2.5));
          grad.addColorStop(1, hexToRgba(color, 0));
          ctx.fillStyle = grad;
          ctx.fill();
        }

        // Line
        ctx.beginPath();
        ctx.strokeStyle = color;
        ctx.lineWidth = opts.lineWidth;
        ctx.lineJoin = 'round';
        ctx.shadowColor = color;
        ctx.shadowBlur = 6;
        pts.forEach((v, i) => {
          if (i === 0) ctx.moveTo(toX(i), toY(v));
          else ctx.lineTo(toX(i), toY(v));
        });
        ctx.stroke();
        ctx.shadowBlur = 0;

        // Dots
        if (opts.showDots) {
          pts.forEach((v, i) => {
            ctx.beginPath();
            ctx.arc(toX(i), toY(v), opts.dotRadius, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.shadowColor = color;
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
          });
        }
      });
    }
  }

  // ── Gauge Chart ────────────────────────────────────────────────
  class GaugeChart {
    constructor(canvas, value, opts = {}) {
      this.canvas = canvas;
      this.value = Math.max(0, Math.min(100, value));
      this.opts = {
        animMs: 1000,
        label: 'SCORE',
        min: 0,
        max: 100,
        thresholds: [
          { at: 0, color: '#00e676' },
          { at: 40, color: '#ffd600' },
          { at: 70, color: '#ff6d00' },
          { at: 85, color: '#ff1744' },
        ],
        ...opts
      };
      this._frame = null;
      this._start = null;
      this.render();
    }

    render() {
      if (this._frame) cancelAnimationFrame(this._frame);
      this._start = null;
      const step = (ts) => {
        if (!this._start) this._start = ts;
        const p = Math.min((ts - this._start) / this.opts.animMs, 1);
        this._draw(ease(p));
        if (p < 1) this._frame = requestAnimationFrame(step);
      };
      this._frame = requestAnimationFrame(step);
    }

    update(value) {
      this.value = Math.max(0, Math.min(100, value));
      this.render();
    }

    destroy() {
      if (this._frame) cancelAnimationFrame(this._frame);
    }

    _getColor(val) {
      const { thresholds } = this.opts;
      let color = thresholds[0].color;
      for (const t of thresholds) {
        if (val >= t.at) color = t.color;
      }
      return color;
    }

    _draw(progress) {
      const { canvas, value, opts } = this;
      const { ctx, w, h } = setupCanvas(canvas);
      ctx.clearRect(0, 0, w, h);

      const cx = w / 2;
      const cy = h * 0.6;
      const radius = Math.min(w, h) * 0.38;
      const startAngle = Math.PI * 0.75;
      const fullSweep = Math.PI * 1.5;
      const currentVal = value * progress;
      const normalised = (currentVal - opts.min) / (opts.max - opts.min);
      const endAngle = startAngle + fullSweep * normalised;
      const color = this._getColor(currentVal);

      // Track (background arc)
      ctx.beginPath();
      ctx.arc(cx, cy, radius, startAngle, startAngle + fullSweep);
      ctx.strokeStyle = 'rgba(255,255,255,0.07)';
      ctx.lineWidth = radius * 0.14;
      ctx.lineCap = 'round';
      ctx.stroke();

      // Value arc
      if (normalised > 0) {
        ctx.beginPath();
        ctx.arc(cx, cy, radius, startAngle, endAngle);
        ctx.strokeStyle = color;
        ctx.lineWidth = radius * 0.14;
        ctx.lineCap = 'round';
        ctx.shadowColor = color;
        ctx.shadowBlur = 16;
        ctx.stroke();
        ctx.shadowBlur = 0;
      }

      // Value text
      ctx.fillStyle = color;
      ctx.font = `700 ${Math.floor(radius * 0.5)}px 'JetBrains Mono', monospace`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(Math.round(currentVal), cx, cy - radius * 0.05);

      ctx.fillStyle = COLORS.textMuted;
      ctx.font = `500 ${Math.floor(radius * 0.17)}px 'Rajdhani', sans-serif`;
      ctx.fillText(opts.label, cx, cy + radius * 0.28);
    }
  }

  // ── Bar Chart ─────────────────────────────────────────────────
  class BarChart {
    constructor(canvas, data, opts = {}) {
      this.canvas = canvas;
      this.data = data; // [{label, value, color?}]
      this.opts = {
        animMs: 700,
        barGap: 0.3,
        paddingX: 40,
        paddingY: 20,
        horizontal: false,
        showValues: true,
        ...opts
      };
      this._frame = null;
      this._start = null;
      this.render();
    }

    render() {
      if (this._frame) cancelAnimationFrame(this._frame);
      this._start = null;
      const step = (ts) => {
        if (!this._start) this._start = ts;
        const p = Math.min((ts - this._start) / this.opts.animMs, 1);
        this._draw(ease(p));
        if (p < 1) this._frame = requestAnimationFrame(step);
      };
      this._frame = requestAnimationFrame(step);
    }

    update(data) {
      this.data = data;
      this.render();
    }

    destroy() {
      if (this._frame) cancelAnimationFrame(this._frame);
    }

    _draw(progress) {
      const { canvas, data, opts } = this;
      const { ctx, w, h } = setupCanvas(canvas);
      ctx.clearRect(0, 0, w, h);

      if (!data || data.length === 0) return;

      const px = opts.paddingX, py = opts.paddingY;
      const chartW = w - px * 2;
      const chartH = h - py * 2 - 20;
      const maxVal = Math.max(...data.map(d => d.value || 0)) || 1;
      const barW = (chartW / data.length) * (1 - opts.barGap);
      const barSpacing = chartW / data.length;

      data.forEach((item, i) => {
        const barH = ((item.value || 0) / maxVal) * chartH * progress;
        const x = px + i * barSpacing + (barSpacing - barW) / 2;
        const y = py + chartH - barH;
        const color = item.color || COLORS.primary;

        const grad = ctx.createLinearGradient(0, y, 0, y + barH);
        grad.addColorStop(0, hexToRgba(color, 0.9));
        grad.addColorStop(1, hexToRgba(color, 0.3));
        ctx.fillStyle = grad;

        roundedRect(ctx, x, y, barW, barH, 3);
        ctx.fill();

        ctx.shadowColor = color;
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Label
        ctx.fillStyle = COLORS.textMuted;
        ctx.font = `10px 'JetBrains Mono', monospace`;
        ctx.textAlign = 'center';
        ctx.fillText(item.label || '', x + barW / 2, py + chartH + 14);

        // Value on bar
        if (opts.showValues && barH > 16) {
          ctx.fillStyle = COLORS.text;
          ctx.font = `bold 11px 'JetBrains Mono', monospace`;
          ctx.fillText(Math.round(item.value * progress), x + barW / 2, y - 4);
        }
      });
    }
  }

  // ── Sparkline ──────────────────────────────────────────────────
  class Sparkline {
    constructor(canvas, data, opts = {}) {
      this.canvas = canvas;
      this.data = data;
      this.opts = {
        color: COLORS.primary,
        lineWidth: 1.5,
        fill: true,
        animMs: 600,
        ...opts
      };
      this._frame = null;
      this._start = null;
      this.render();
    }

    render() {
      if (this._frame) cancelAnimationFrame(this._frame);
      this._start = null;
      const step = (ts) => {
        if (!this._start) this._start = ts;
        const p = Math.min((ts - this._start) / this.opts.animMs, 1);
        this._draw(ease(p));
        if (p < 1) this._frame = requestAnimationFrame(step);
      };
      this._frame = requestAnimationFrame(step);
    }

    update(data) { this.data = data; this.render(); }
    destroy() { if (this._frame) cancelAnimationFrame(this._frame); }

    _draw(progress) {
      const { canvas, data, opts } = this;
      const { ctx, w, h } = setupCanvas(canvas);
      ctx.clearRect(0, 0, w, h);

      if (!data || data.length < 2) return;
      const min = Math.min(...data), max = Math.max(...data);
      const range = max - min || 1;
      const points = data.slice(0, Math.round(data.length * progress));
      const xStep = w / (data.length - 1);

      const toX = i => i * xStep;
      const toY = v => h - ((v - min) / range) * (h * 0.8) - h * 0.1;

      if (opts.fill) {
        ctx.beginPath();
        ctx.moveTo(toX(0), h);
        points.forEach((v, i) => ctx.lineTo(toX(i), toY(v)));
        ctx.lineTo(toX(points.length - 1), h);
        ctx.closePath();
        const g = ctx.createLinearGradient(0, 0, 0, h);
        g.addColorStop(0, hexToRgba(opts.color, 0.3));
        g.addColorStop(1, hexToRgba(opts.color, 0));
        ctx.fillStyle = g;
        ctx.fill();
      }

      ctx.beginPath();
      ctx.strokeStyle = opts.color;
      ctx.lineWidth = opts.lineWidth;
      ctx.lineJoin = 'round';
      ctx.shadowColor = opts.color;
      ctx.shadowBlur = 4;
      points.forEach((v, i) => {
        if (i === 0) ctx.moveTo(toX(i), toY(v));
        else ctx.lineTo(toX(i), toY(v));
      });
      ctx.stroke();
      ctx.shadowBlur = 0;
    }
  }

  // ── Animate Number ─────────────────────────────────────────────
  function animateValue(el, from, to, ms, format) {
    const start = performance.now();
    const fmt = format || (v => Math.round(v).toLocaleString());
    function tick(now) {
      const p = Math.min((now - start) / ms, 1);
      el.textContent = fmt(from + (to - from) * ease(p));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  // Public API
  return {
    DonutChart, LineChart, GaugeChart, BarChart, Sparkline,
    animateValue, COLORS, EVIDENCE_COLORS, EVIDENCE_LABELS,
  };
})();
