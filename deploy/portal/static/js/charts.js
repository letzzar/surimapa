/* Línea temporal: barras apiladas por severidad (Chart.js, sin adaptador de fechas).
   Tema SOC: sev. 1 abajo, sin redondeo, 1 px de separación entre segmentos (ayuda con
   daltonismo), leyenda HTML en la cabecera y marcas ▼ sobre los intervalos con sev. 1. */
"use strict";

const Charts = (() => {
  const TZ = Intl.DateTimeFormat().resolvedOptions().timeZone;   // zona horaria del navegador
  const fmtHour = new Intl.DateTimeFormat("es-ES", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });
  const fmtDay = new Intl.DateTimeFormat("es-ES", { timeZone: TZ, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  let chart;
  let lastData;

  function dataset(sev) {
    return {
      label: `Sev. ${sev} · ${Dom.SEV_LABEL[sev]}`,
      data: [],
      backgroundColor: Dom.cssVar(`--sev${sev}`),
      borderColor: Dom.cssVar("--surface"),
      borderWidth: { top: 1, right: 0, bottom: 0, left: 0 },   // separa los segmentos apilados
      borderRadius: 0,
      barPercentage: 0.9,
      categoryPercentage: 1,
      stack: "sev",
    };
  }

  // Marcas ▼ (color --sev1) encima de cada barra con sev1 > 0. Plugin propio, no una librería.
  const sev1Marks = {
    id: "sev1Marks",
    afterDatasetsDraw(c) {
      const pts = lastData?.points;
      if (!pts) return;
      const metas = [0, 1, 2].map((i) => c.getDatasetMeta(i)).filter((m) => !m.hidden);
      if (!metas.length) return;
      const ctx = c.ctx;
      ctx.save();
      ctx.fillStyle = Dom.cssVar("--sev1");
      pts.forEach((p, i) => {
        if (!p.sev1) return;
        const bars = metas.map((m) => m.data[i]).filter(Boolean);
        if (!bars.length) return;
        const top = Math.min(...bars.map((b) => b.y));
        const x = bars[0].x, y = top - 5, s = 4;
        ctx.beginPath();
        ctx.moveTo(x - s, y - s * 1.6);
        ctx.lineTo(x + s, y - s * 1.6);
        ctx.lineTo(x, y);
        ctx.closePath();
        ctx.fill();
      });
      ctx.restore();
    },
  };

  function themeOptions() {
    const muted = Dom.cssVar("--ink-muted");
    const grid = Dom.cssVar("--grid");
    const axis = Dom.cssVar("--axis");
    const mono = { family: Dom.cssVar("--mono"), size: 10 };
    return {
      responsive: true,
      maintainAspectRatio: false,
      animation: false,
      layout: { padding: { top: 12 } },          // hueco para las marcas ▼
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { display: false },              // leyenda HTML en la cabecera (index.html)
        tooltip: {
          backgroundColor: Dom.cssVar("--topbar"),
          borderColor: Dom.cssVar("--border-2"),
          borderWidth: 1,
          padding: 10,
          titleColor: Dom.cssVar("--ink"),
          bodyColor: Dom.cssVar("--ink-2"),
          footerColor: Dom.cssVar("--ink-muted"),
          bodyFont: { family: Dom.cssVar("--mono"), size: 11 },
          boxWidth: 8, boxHeight: 8,
          callbacks: {
            title: (items) => Dom.timeLong(lastData?.points?.[items[0].dataIndex]?.ts_ms),
            footer: (items) => `Total: ${Dom.num(items.reduce((s, i) => s + i.parsed.y, 0))}`,
          },
        },
      },
      scales: {
        x: { stacked: true, grid: { display: false }, border: { color: axis }, ticks: { color: muted, font: mono, maxRotation: 0, autoSkipPadding: 24 } },
        y: { stacked: true, beginAtZero: true, grace: "6%", grid: { color: grid }, border: { display: false }, ticks: { color: muted, font: mono, precision: 0 } },
      },
    };
  }

  function init(canvasId) {
    chart = new Chart(document.getElementById(canvasId), {
      type: "bar",
      data: { labels: [], datasets: [dataset(1), dataset(2), dataset(3)] },
      options: themeOptions(),
      plugins: [sev1Marks],
    });
    window.addEventListener("themechange", restyle);    // conmutador de tema (app.js)
  }

  function restyle() {
    if (!chart) return;
    chart.options = themeOptions();
    chart.data.datasets.forEach((ds, i) => {
      ds.backgroundColor = Dom.cssVar(`--sev${i + 1}`);
      ds.borderColor = Dom.cssVar("--surface");
    });
    chart.update();
  }

  // data = respuesta de GET /api/timeline
  function update(data) {
    lastData = data;
    const pts = data.points || [];
    const fmt = data.bucket_ms >= 3600000 ? fmtDay : fmtHour;
    chart.data.labels = pts.map((p) => fmt.format(new Date(p.ts_ms)));
    chart.data.datasets[0].data = pts.map((p) => p.sev1 || 0);
    chart.data.datasets[1].data = pts.map((p) => p.sev2 || 0);
    chart.data.datasets[2].data = pts.map((p) => p.sev3 || 0);
    chart.update();
    return data;
  }

  // «15 min», «1 h»… para el subtítulo de la tarjeta.
  function bucketLabel(ms) {
    if (!ms) return "";
    return ms < 3600000 ? `${Math.round(ms / 60000)} min` : `${Math.round(ms / 3600000)} h`;
  }

  return { init, update, bucketLabel };
})();
