/* Orquestación: estado de filtros (en la URL), carga de datos, tiempo real y salud. */
"use strict";

(() => {
  const RANGES = ["1h", "24h", "7d", "30d", "90d"];
  const TOP_DIMS = ["signature", "remote_ip", "country", "asn", "dest_port"];
  const TOP_LIMIT = 10;
  const PAGE_SIZE = 25;
  const REFRESH_MS = 60000;   // KPI, mapa y gráficos en modo vivo
  const HEALTH_MS = 30000;

  const $ = (id) => document.getElementById(id);

  // ---------- Estado ----------
  const qs = new URLSearchParams(location.search);
  // Solo se aceptan de la URL las interfaces que ofrece el selector de index.html.
  const IFACES = [...document.querySelectorAll("#f-iface option")].map((o) => o.value).filter(Boolean);
  const state = {
    range: RANGES.includes(qs.get("range")) ? qs.get("range") : "24h",
    sev: ["1", "2", "3"].includes(qs.get("sev")) ? qs.get("sev") : "",
    dir: ["in", "out", "local"].includes(qs.get("dir")) ? qs.get("dir") : "",
    iface: IFACES.includes(qs.get("iface")) ? qs.get("iface") : "",
    live: qs.get("live") !== "0",
    fw: qs.get("fw") === "1",   // capa de bloqueos del firewall en el mapa
    page: 1,
    q: "",
    origin: null,          // { country, label } o { lat, lon, label }: filtra solo la lista de eventos
    totalEvents: 0,
  };

  function syncUrl() {
    const p = new URLSearchParams();
    p.set("range", state.range);
    if (state.sev) p.set("sev", state.sev);
    if (state.dir) p.set("dir", state.dir);
    if (state.iface) p.set("iface", state.iface);
    if (!state.live) p.set("live", "0");
    if (state.fw) p.set("fw", "1");
    history.replaceState(null, "", `?${p}`);
  }

  function syncControls() {
    for (const b of $("f-range").querySelectorAll("button")) b.setAttribute("aria-checked", String(b.dataset.range === state.range));
    $("f-sev").value = state.sev;
    $("f-dir").value = state.dir;
    $("f-iface").value = state.iface;
    $("f-live").setAttribute("aria-pressed", String(state.live));
    $("fw-toggle").setAttribute("aria-pressed", String(state.fw));
    setLiveText();
    updateFilterCount();
  }

  // Contador de filtros activos en el botón «Filtros» (móvil).
  function updateFilterCount() {
    const active = [state.sev, state.dir, state.iface].filter(Boolean).length;
    $("f-count").hidden = !active;
    $("f-count").textContent = String(active);
  }

  // Texto de la pastilla: EN VIVO / EN PAUSA / SIN CONEXIÓN (data-state="error").
  function setLiveText() {
    const btn = $("f-live");
    $("live-text").textContent = btn.dataset.state === "error" ? "SIN CONEXIÓN" : state.live ? "EN VIVO" : "EN PAUSA";
  }

  // ---------- KPI ----------
  const RANGE_LABEL = { "1h": "1 h", "24h": "24 h", "7d": "7 días", "30d": "30 días", "90d": "90 días" };
  const RANGE_PHRASE = { "1h": "última hora", "24h": "últimas 24 h", "7d": "últimos 7 días", "30d": "últimos 30 días", "90d": "últimos 90 días" };
  const MINUS = "\u2212";

  // Variación frente al periodo anterior. `absolute`: diferencia en unidades (para cifras pequeñas).
  function setKpi(id, value, prev, { noPrev = false, absolute = false } = {}) {
    const box = $(id);
    box.querySelector(".kpi-value").textContent = Dom.num(value);
    const delta = box.querySelector(".kpi-delta");
    delete delta.dataset.trend;
    const suffix = Dom.el("span", null, ` vs. ${RANGE_LABEL[state.range]} anteriores`);
    if (noPrev || prev === undefined || prev === null) {
      delta.replaceChildren("sin datos del periodo anterior");
      return;
    }
    const diff = value - prev;
    let text;
    if (absolute || prev === 0) {
      text = `${Dom.num(Math.abs(diff))} (antes ${Dom.num(prev)})`;
    } else {
      const pct = (diff / prev) * 100;
      text = Math.abs(pct) < 0.05 ? "" : `${Dom.dec1(Math.abs(pct))} %`;
    }
    if (diff === 0 || text === "") {
      delta.replaceChildren(Dom.el("b", null, "· sin cambios"), suffix);
      return;
    }
    delta.dataset.trend = diff > 0 ? "up" : "down";
    delta.replaceChildren(Dom.el("b", null, `${diff > 0 ? "▲ +" : `▼ ${MINUS}`}${text}`), suffix);
  }

  function renderSummary(s) {
    const prev = s.previous || {};
    const noPrev = !prev.total;                    // periodo anterior sin datos (p. ej., instalación reciente)
    const sev1 = s.by_severity?.["1"] ?? 0;
    setKpi("kpi-total", s.total, prev.total, { noPrev });
    setKpi("kpi-ips", s.unique_ips, prev.unique_ips, { noPrev });
    setKpi("kpi-countries", s.unique_countries, prev.unique_countries, { noPrev });
    setKpi("kpi-sev1", sev1, prev.by_severity?.["1"] ?? 0, { noPrev, absolute: true });
    $("kpi-sev1").dataset.hot = String(sev1 > 0);
  }

  // ---------- Salud del colector ----------
  async function refreshHealth() {
    const box = $("kpi-health");
    const value = box.querySelector(".kpi-value");
    try {
      const h = await Api.health();
      const age = h.collector_heartbeat_age_s;
      box.dataset.state = age === null || age === undefined || age > 120 ? "down" : age > 60 ? "stale" : "ok";
      value.textContent = { ok: "En marcha", stale: "Con retraso", down: "Parado" }[box.dataset.state];
      $("h-beat").textContent = Dom.ago(age);
      $("h-queue").textContent = Dom.num(h.redis_queue_len);
      $("h-db").textContent = Dom.bytes(h.db_size_bytes);
    } catch {
      box.dataset.state = "down";
      value.textContent = "Sin API";
      for (const id of ["h-beat", "h-queue", "h-db"]) $(id).textContent = "—";
    }
  }

  // ---------- Carga de datos ----------
  let loadSeq = 0;

  // ---------- Tarjeta de severidad (#sev-dist): de summary y timeline, ya cargados ----------
  let lastSummary = null;
  let lastTimeline = null;

  function renderSevDist() {
    const s = lastSummary;
    if (s) {
      const counts = [1, 2, 3].map((k) => s.by_severity?.[String(k)] ?? 0);
      const total = counts.reduce((a, b) => a + b, 0);
      const pcts = counts.map((c) => (total ? (c / total) * 100 : 0));
      // Ancho mínimo 0,8 % para que una sev. 1 escasa siga viéndose en la barra.
      const widths = counts.map((c, i) => (c ? Math.max(pcts[i], 0.8) : 0));
      const sum = widths.reduce((a, b) => a + b, 0) || 1;
      $("sev-bar").replaceChildren(...widths.map((w, i) => {
        const seg = Dom.el("span", { dataset: { sev: i + 1 } });
        seg.style.width = `${(w / sum) * 100}%`;
        return seg;
      }));
      $("sev-rows").replaceChildren(...counts.map((c, i) => Dom.el("li", null,
        Dom.sevBadge(i + 1),
        Dom.el("span", { class: "sr-count mono" }, Dom.num(c)),
        Dom.el("span", { class: "sr-pct mono" }, total ? `${Dom.dec1(pcts[i])} %` : "—"))));
      const minutes = Math.max(1, (s.range.to_ms - s.range.from_ms) / 60000);
      $("sev-rate").textContent = `${Dom.dec1(total / minutes)}/min`;
      $("sev-rate-sub").textContent = RANGE_PHRASE[state.range];
    }
    const pts = lastTimeline?.points || [];
    let peak = null;
    for (const p of pts) {
      const n = (p.sev1 || 0) + (p.sev2 || 0) + (p.sev3 || 0);
      if (n > 0 && (!peak || n > peak.n)) peak = { n, ts: p.ts_ms };
    }
    $("sev-peak").textContent = peak ? Dom.num(peak.n) : "—";
    $("sev-peak-sub").textContent = peak ? `${Dom.hm(peak.ts)} · ${Charts.bucketLabel(lastTimeline.bucket_ms)}` : "";
  }

  // ---------- Estados por panel: carga (skeleton), error con «Reintentar» ----------
  const section = (id) => $(id)?.closest("section, .kpi") || null;

  function errorBox(retry) {
    return Dom.el("div", { class: "card-error", role: "alert" },
      Dom.el("p", null, "No se pudo cargar"),
      Dom.el("button", { type: "button", class: "btn-ghost", onclick: retry }, "Reintentar"));
  }

  function clearError(els) {
    for (const e of els) {
      if (!e) continue;
      if (e.dataset.state === "error") delete e.dataset.state;
      e.querySelector(":scope > .card-error")?.remove();
    }
  }

  // Carga un panel. errEls: donde se muestra el error; loadEls: donde va el skeleton.
  async function runPanel({ errEls, loadEls = errEls, load, render, skeleton }) {
    const seq = loadSeq;
    clearError(errEls);
    if (skeleton) loadEls.forEach((e) => e?.classList.add("is-loading"));
    try {
      const d = await load();
      if (seq === loadSeq) render(d);
    } catch (err) {
      if (seq === loadSeq) {
        for (const e of errEls) {
          if (!e) continue;
          e.dataset.state = "error";
          if (!e.querySelector(":scope > .card-error")) {
            e.append(errorBox(() => runPanel({ errEls, loadEls, load, render, skeleton: true })));
          }
        }
      }
      throw err;
    } finally {
      if (seq === loadSeq) loadEls.forEach((e) => e?.classList.remove("is-loading"));
    }
  }

  // ---------- Mini-gráficas de los KPI (de timeline.points, ya cargados) ----------
  function spark(values, tone) {
    if (values.length < 2) return null;
    const W = 100, H = 28, max = Math.max(1, ...values);
    const pts = values.map((v, i) => [(i / (values.length - 1)) * W, H - 2 - (v / max) * (H - 5)]);
    const line = `M${pts.map(([x, y]) => `${x.toFixed(2)},${y.toFixed(2)}`).join("L")}`;
    return Dom.svg("svg", { class: "kpi-spark", viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", "aria-hidden": "true", "data-tone": tone },
      Dom.svg("path", { class: "sp-area", d: `${line}L${W},${H}L0,${H}Z` }),
      Dom.svg("path", { class: "sp-line", d: line, "vector-effect": "non-scaling-stroke" }));
  }

  function renderSparks(tl) {
    const pts = tl?.points || [];
    const totals = pts.map((p) => (p.sev1 || 0) + (p.sev2 || 0) + (p.sev3 || 0));
    const sev1 = pts.map((p) => p.sev1 || 0);
    // IPs y países no tienen serie propia: se muestra la de alertas en gris.
    for (const [id, values, tone] of [["kpi-total", totals, "accent"], ["kpi-ips", totals, "muted"],
      ["kpi-countries", totals, "muted"], ["kpi-sev1", sev1, "sev1"]]) {
      const box = $(id);
      box.querySelector(".kpi-spark")?.remove();
      const svg = spark(values, tone);
      if (svg) box.append(svg);
    }
  }

  // ---------- Bloqueos del firewall ----------
  const FW_TOP_DIMS = ["remote_ip", "dest_port"];

  function renderFw([summary, ...tops]) {
    $("fw-total").textContent = Dom.num(summary.total);
    $("fw-ips").textContent = Dom.num(summary.unique_ips);
    $("fw-countries").textContent = Dom.num(summary.unique_countries);
    $("fw-sub").textContent = `WAN · ${RANGE_PHRASE[state.range]}`;
    FW_TOP_DIMS.forEach((dim, i) => Tables.renderTop($(`fw-top-${dim}`), tops[i]));
  }

  // Capa del mapa: solo se pide si está activada.
  function loadFwMap() {
    if (!state.fw) { WorldMap.setFirewall(null); return Promise.resolve(); }
    const f = { range: state.range };
    return runPanel({ errEls: [], load: () => Api.fwMap(f), render: (d) => WorldMap.setFirewall(d) });
  }

  async function loadDashboard(skeleton = false) {
    const seq = ++loadSeq;  // descarta respuestas de filtros ya cambiados
    const f = { range: state.range, sev: state.sev, dir: state.dir, iface: state.iface };
    const kpis = ["kpi-total", "kpi-ips", "kpi-countries", "kpi-sev1"].map($);
    const jobs = [
      runPanel({
        errEls: [document.querySelector(".kpis"), section("sev-dist")], loadEls: [...kpis, section("sev-dist")], skeleton,
        load: () => Api.summary(f),
        render: (d) => { lastSummary = d; renderSummary(d); renderSevDist(); },
      }),
      runPanel({
        errEls: [section("timeline")], skeleton,
        load: () => Api.timeline(f),
        render: (d) => {
          lastTimeline = Charts.update(d);
          $("timeline-sub").textContent = `intervalos de ${Charts.bucketLabel(d.bucket_ms)}`;
          renderSevDist();
          renderSparks(lastTimeline);
        },
      }),
      runPanel({
        errEls: [section("map")], loadEls: [], skeleton,     // el mapa base se ve siempre: sin skeleton
        load: () => Api.map(f),
        render: (d) => {
          const n = WorldMap.update(d);
          $("map-sub").textContent = `${Dom.num(n.countries)} países · ${Dom.num(n.points)} ubicaciones · ${RANGE_PHRASE[state.range]}`;
        },
      }),
      runPanel({
        errEls: [section("fw-total")], skeleton,
        load: () => Promise.all([Api.fwSummary(f), ...FW_TOP_DIMS.map((dim) => Api.fwTop(dim, f, TOP_LIMIT))]),
        render: renderFw,
      }),
      loadFwMap(),
      ...TOP_DIMS.map((dim) => runPanel({
        errEls: [section(`top-${dim}`)], skeleton,
        load: () => Api.top(dim, f, TOP_LIMIT),
        render: (d) => Tables.renderTop($(`top-${dim}`), d),
      })),
    ];
    const results = await Promise.allSettled(jobs);
    const failed = results.filter((r) => r.status === "rejected");
    if (failed.length && seq === loadSeq) {
      console.error("[Surimapa]", ...failed.map((r) => r.reason));
      Dom.toast(`No se pudieron cargar ${failed.length} paneles`);
    }
  }

  async function loadEvents(skeleton = false) {
    const f = { range: state.range, sev: state.sev, dir: state.dir, iface: state.iface };
    $("export-csv").href = Api.eventsCsvUrl(f, state.q, state.origin);     // el CSV exporta esta misma vista
    try {
      await runPanel({
        errEls: [section("events-body")], loadEls: [document.querySelector(".table-wrap")], skeleton,
        load: () => Api.events(f, state.page, PAGE_SIZE, state.q, state.origin),
        render: (d) => renderEventsPage(d),
      });
    } catch (err) {
      console.error("[Surimapa]", err);
      Dom.toast("No se pudieron cargar los eventos");
    }
  }

  function renderEventsPage(d) {
    state.totalEvents = d.total || 0;
    Tables.renderEvents($("events-body"), d);
    $("events-total").textContent = `${Dom.num(state.totalEvents)} ${state.totalEvents === 1 ? "resultado" : "resultados"}`;
    $("pg-help").hidden = !(state.q || state.origin);
    // Siembra la actividad en vivo con lo ya cargado (sin petición propia).
    if (!feedSeeded && state.page === 1 && !state.q && !state.origin) {
      feedPush(d.items.slice(0, FEED_MAX), false);
      feedSeeded = true;
    }
    const pages = Math.max(1, Math.ceil(state.totalEvents / PAGE_SIZE));
    const first = state.totalEvents ? (state.page - 1) * PAGE_SIZE + 1 : 0;
    const last = Math.min(state.page * PAGE_SIZE, state.totalEvents);
    $("pg-info").textContent = `${Dom.num(first)}–${Dom.num(last)} de ${Dom.num(state.totalEvents)} · pág. ${Dom.num(state.page)}/${Dom.num(pages)}`;
    $("pg-prev").disabled = state.page <= 1;
    $("pg-next").disabled = state.page >= pages;
  }

  function reloadAll() {
    state.page = 1;
    updateFilterCount();
    feedReset();
    syncUrl();
    loadDashboard(true);
    loadEvents(true);
    connectStream();
  }

  // ---------- Actividad en vivo (#live-feed): mismo SSE que los misiles ----------
  const FEED_MAX = 8;
  const RATE_WINDOW_MS = 60000;
  const arrivals = [];          // instante de llegada de cada evento SSE (para el ritmo)
  let streamStart = Date.now();
  let feedSeeded = false;

  function feedItem(ev, isNew) {
    const sev = [1, 2, 3].includes(ev.severity) ? ev.severity : 3;
    const li = Dom.el("li", { tabindex: 0, class: isNew ? "is-new" : null, title: ev.signature || "" },
      Dom.el("div", { class: "fi-top" },
        Dom.el("span", { class: "fi-time mono" }, Dom.clock(ev.ts_ms)),
        Dom.el("span", { class: "fi-sev", dataset: { sev } }, `S${sev}`),
        Dom.iso(ev.country_iso),
        Dom.el("span", { class: "fi-ip mono" }, ev.remote_ip || ev.src_ip || "—")),
      Dom.el("div", { class: "fi-sig" }, ev.signature || "—"));
    const open = () => Tables.showEvent(ev.id);
    li.addEventListener("click", open);
    li.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    if (isNew) setTimeout(() => li.classList.remove("is-new"), 4000);
    return li;
  }

  function feedPush(events, isNew) {
    const list = $("live-feed");
    for (const ev of [...events].sort((a, b) => a.ts_ms - b.ts_ms)) list.prepend(feedItem(ev, isNew));
    while (list.children.length > FEED_MAX) list.lastElementChild.remove();
  }

  function feedReset() {
    $("live-feed").replaceChildren();
    arrivals.length = 0;
    streamStart = Date.now();
    feedSeeded = false;
    renderRate();
  }

  // Ritmo = eventos recibidos en los últimos 60 s (escalado si la conexión es más reciente).
  function renderRate() {
    $("feed-panel").classList.toggle("is-paused", !state.live);
    if (!state.live) { $("feed-rate").textContent = "En pausa"; return; }
    const now = Date.now();
    while (arrivals.length && now - arrivals[0] > RATE_WINDOW_MS) arrivals.shift();
    if (!arrivals.length) { $("feed-rate").textContent = "—"; return; }
    const span = Math.min(RATE_WINDOW_MS, Math.max(20000, now - streamStart));
    $("feed-rate").textContent = `${Dom.dec1(arrivals.length / (span / 60000))}/min`;
  }
  setInterval(renderRate, 5000);

  // ---------- Tiempo real (SSE) ----------
  let stream = null;
  let refreshTimer = null;

  function connectStream() {
    if (stream) { stream.close(); stream = null; }
    clearInterval(refreshTimer);
    const btn = $("f-live");
    delete btn.dataset.state;
    setLiveText();
    arrivals.length = 0;          // el ritmo se mide solo sobre la conexión actual
    streamStart = Date.now();
    renderRate();
    if (!state.live) return;

    stream = new EventSource(Api.streamUrl({ range: state.range, sev: state.sev, dir: state.dir, iface: state.iface }));
    stream.addEventListener("open", () => { delete btn.dataset.state; setLiveText(); });
    stream.addEventListener("error", () => { btn.dataset.state = "error"; setLiveText(); }); // EventSource reintenta solo
    stream.addEventListener("events", (msg) => {
      let events;
      try { events = JSON.parse(msg.data); } catch { return; }
      if (!Array.isArray(events) || !events.length) return;
      WorldMap.fire(events);
      const now = Date.now();
      for (let k = 0; k < events.length; k++) arrivals.push(now);
      feedPush(events, true);
      renderRate();
      // Solo se insertan en vivo si se está viendo la primera página sin búsqueda.
      if (state.page === 1 && !state.q && !state.origin) {
        Tables.prependEvents($("events-body"), events, PAGE_SIZE);
      }
    });
    refreshTimer = setInterval(() => loadDashboard(false), REFRESH_MS);   // recarga silenciosa: sin skeletons
  }

  // ---------- Filtro de la lista por origen ----------
  function setOrigin(origin) {
    state.origin = origin;
    state.page = 1;
    WorldMap.setSelection(origin);
    const chip = $("origin-chip");
    chip.hidden = !origin;
    $("origin-label").textContent = origin ? origin.label : "";
    loadEvents();
    if (origin) $("h-events").scrollIntoView({ behavior: "smooth" });
  }

  // Pulsar de nuevo el origen ya seleccionado (país o círculo del mapa, Top países) lo quita.
  function sameOrigin(a, b) {
    if (!a || !b) return false;
    if (a.country || b.country) return a.country === b.country;
    return a.lat === b.lat && a.lon === b.lon;
  }

  function toggleOrigin(origin) {
    setOrigin(sameOrigin(origin, state.origin) ? null : origin);
  }

  // ---------- Eventos de la interfaz ----------
  function bindUi() {
    $("f-range").addEventListener("click", (e) => {
      const b = e.target.closest("button[data-range]");
      if (!b || b.dataset.range === state.range) return;
      state.range = b.dataset.range;
      syncControls();
      reloadAll();
    });
    $("f-sev").addEventListener("change", (e) => { state.sev = e.target.value; reloadAll(); });
    $("f-dir").addEventListener("change", (e) => { state.dir = e.target.value; reloadAll(); });
    $("f-iface").addEventListener("change", (e) => { state.iface = e.target.value; reloadAll(); });
    $("f-live").addEventListener("click", () => {
      state.live = !state.live;
      syncControls();
      syncUrl();
      connectStream();
    });
    $("fw-toggle").addEventListener("click", () => {
      state.fw = !state.fw;
      syncControls();
      syncUrl();
      loadFwMap().catch((err) => { console.error("[Surimapa]", err); Dom.toast("No se pudo cargar la capa del firewall"); });
    });
    $("filters").addEventListener("submit", (e) => e.preventDefault());

    let searchTimer;
    const runSearch = () => { state.q = $("q").value.trim(); state.page = 1; loadEvents(); };
    $("q").addEventListener("input", () => { clearTimeout(searchTimer); searchTimer = setTimeout(runSearch, 350); });
    $("search").addEventListener("submit", (e) => { e.preventDefault(); clearTimeout(searchTimer); runSearch(); });

    $("origin-clear").addEventListener("click", () => setOrigin(null));
    $("f-more").addEventListener("click", () => {
      const open = $("filter-extra").classList.toggle("open");
      $("f-more").setAttribute("aria-expanded", String(open));
    });
    $("f-theme").addEventListener("click", () => {
      const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
      document.documentElement.dataset.theme = next;
      try { localStorage.setItem("surimapa-theme", next); } catch { /* sin almacenamiento: solo esta sesión */ }
      window.dispatchEvent(new Event("themechange"));   // mapa y gráfica releen los tokens
    });
    $("pg-prev").addEventListener("click", () => { if (state.page > 1) { state.page--; loadEvents(); } });
    $("pg-next").addEventListener("click", () => { state.page++; loadEvents(); });

    $("drawer-close").addEventListener("click", Tables.closeDrawer);
    // Esc: cierra el panel lateral si está abierto; si no, quita el filtro de origen.
    document.addEventListener("keydown", (e) => {
      if (e.key !== "Escape") return;
      if (!$("drawer").hidden) Tables.closeDrawer();
      else if (state.origin) setOrigin(null);
    });
    // Atajo "/": enfoca la búsqueda salvo que ya se esté escribiendo en un campo.
    document.addEventListener("keydown", (e) => {
      if (e.key !== "/" || e.ctrlKey || e.metaKey || e.altKey) return;
      const t = e.target;
      if (t instanceof HTMLInputElement || t instanceof HTMLTextAreaElement || t instanceof HTMLSelectElement || t.isContentEditable) return;
      e.preventDefault();
      $("q").focus();
    });
  }

  // ---------- Arranque ----------
  async function start() {
    Tables.configure({
      onIpClick: (ip) => Tables.showIp(ip),
      onSearch: (q) => { $("q").value = q; state.q = q; state.page = 1; loadEvents(); $("h-events").scrollIntoView({ behavior: "smooth" }); },
      onOrigin: toggleOrigin,
      getRange: () => state.range,
    });
    WorldMap.setOriginHandler(toggleOrigin);
    syncControls();
    syncUrl();
    bindUi();
    Charts.init("timeline");
    try {
      await WorldMap.init("map");
    } catch (err) {
      console.error("[Surimapa]", err);
      Dom.toast("No se pudo cargar el mapa base");
    }
    refreshHealth();
    setInterval(refreshHealth, HEALTH_MS);
    loadDashboard(true);
    loadEvents(true);
    connectStream();
  }

  start();
})();
