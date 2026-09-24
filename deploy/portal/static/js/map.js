/* Mapa mundial sin teselas (tema SOC): países desde GeoJSON local, círculos por ciudad,
   selección de origen, casa ("RED PROPIA") y misiles en vivo.
   Los tooltips y marcadores se construyen como nodos DOM: Leaflet trata los strings como HTML. */
"use strict";

const WorldMap = (() => {
  // Encuadre sin Antártida ni Ártico: el mundo llena el ancho.
  const WORLD = [[-48, -180], [75, 180]];
  const STEPS = 6;              // --seq-1 … --seq-6 (el --seq-0 es "sin alertas")
  const LOG_MAX = 3;            // escala log. absoluta: 1 → --seq-1 … ≥ 1.000 (10³) → --seq-6
  const MAX_MISSILES = 25;      // simultáneos; el resto se descarta
  const LAUNCH_GAP_MS = 120;    // escalonado dentro de un lote SSE
  const FLIGHT_MS = 1600;
  const IMPACT_MS = 700;
  const ARC_POINTS = 64;
  const TAIL_POINTS = 18;
  let map, countryLayer, pointLayer, fwLayer, gratLayer, selectionRing = null;
  let fwOn = false;             // capa de bloqueos del firewall visible (app.js decide)
  let home = null;
  let onOrigin = () => {};      // clic en un país o círculo → filtrar la lista (app.js)
  let selected = null;          // { country } o { lat, lon } (celda de la rejilla)
  let inFlight = 0;
  const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
  let countsByIso = new Map();
  let lastPoints = [];          // puntos de la última actualización (para el anillo de selección)

  // ---------- Estilos ----------
  function seqColor(count) {
    if (!count) return Dom.cssVar("--seq-0");
    const t = Math.min(1, Math.log10(count) / LOG_MAX);
    return Dom.cssVar(`--seq-${1 + Math.round(t * (STEPS - 1))}`);
  }

  const isSelectedCountry = (iso) => !!(selected?.country && iso && selected.country === iso);

  function countryStyle(feature) {
    const iso = feature.properties.iso;
    const style = {
      fillColor: seqColor(countsByIso.get(iso)),
      fillOpacity: 1,
      color: Dom.cssVar("--map-line"),
      weight: 0.6,
      dashArray: null,
    };
    if (isSelectedCountry(iso)) Object.assign(style, { color: "#ffffff", weight: 1.6, dashArray: "4 3" });
    return style;
  }

  function dotStyle() {
    const dot = Dom.cssVar("--dot");
    return { fillColor: dot, fillOpacity: 0.35, color: dot, opacity: 0.8, weight: 0.8 };
  }

  const radiusFor = (count) => 2.2 + Math.sqrt(count) * 0.2;

  // Bloqueos del firewall: volumen muy superior al de alertas → tamaño logarítmico.
  function fwStyle() {
    const fw = Dom.cssVar("--fw");
    return { fillColor: fw, fillOpacity: 0.3, color: fw, opacity: 0.9, weight: 1.2 };
  }
  const fwRadiusFor = (count) => 3 + Math.log10(count + 1) * 3.2;

  // ---------- Tooltips (nodos DOM) ----------
  function tip(title, count, filtering, unit = "alertas") {
    return Dom.el("div", null,
      Dom.el("div", { class: "tip-title" }, title),
      Dom.el("div", { class: "tip-value" }, `${Dom.num(count)} ${unit}`),
      filtering ? Dom.el("div", { class: "tip-note" }, "Filtrando la tabla por este origen · clic para quitar") : null);
  }

  function countryTip(layer) {
    const p = layer.feature.properties;
    return tip(p.name, countsByIso.get(p.iso) || 0, isSelectedCountry(p.iso));
  }

  const pointLabel = (p) => `${p.city || "(sin ciudad)"}, ${p.country || "?"}`;
  const isSelectedPoint = (p) => !!(selected && selected.lat === p.lat && selected.lon === p.lon);

  // ---------- Inicialización ----------
  async function init(containerId) {
    const container = document.getElementById(containerId);
    map = L.map(container, {
      zoomSnap: 0.25,
      maxZoom: 6,
      worldCopyJump: false,
      maxBounds: WORLD,
      maxBoundsViscosity: 1,
      attributionControl: false,
      zoomControl: false,
    });
    fitWorld();
    map.on("resize", fitWorld);
    L.control.zoom({ position: "topright", zoomInTitle: "Acercar", zoomOutTitle: "Alejar" }).addTo(map);
    worldViewControl().addTo(map);

    // Retícula tenue del mar, bajo los países.
    map.createPane("graticule");
    map.getPane("graticule").style.zIndex = 350;
    map.getPane("graticule").style.pointerEvents = "none";
    const grat = { pane: "graticule", color: Dom.cssVar("--map-grat"), weight: 1, interactive: false };
    gratLayer = L.layerGroup().addTo(map);
    for (let lat = -40; lat <= 60; lat += 20) L.polyline([[lat, -180], [lat, 180]], grat).addTo(gratLayer);
    for (let lon = -150; lon <= 180; lon += 30) L.polyline([[-60, lon], [85, lon]], grat).addTo(gratLayer);

    const res = await fetch("vendor/world-110m.geojson");
    if (!res.ok) throw new Error("No se pudo cargar el mapa base");
    const geo = await res.json();

    countryLayer = L.geoJSON(geo, { style: countryStyle, className: "country" }).addTo(map);
    countryLayer.eachLayer((l) => {
      l.bindTooltip(countryTip, { sticky: true, className: "map-tip" });
      l.on("click", () => {
        const p = l.feature.properties;
        if (p.iso && countsByIso.get(p.iso)) onOrigin({ country: p.iso, label: p.name });
      });
      // Hover solo en países con alertas.
      l.on("mouseover", () => {
        if (countsByIso.get(l.feature.properties.iso) && !isSelectedCountry(l.feature.properties.iso)) {
          l.setStyle({ color: Dom.cssVar("--accent"), weight: 1.4 });
          l.bringToFront();
        }
      });
      l.on("mouseout", () => countryLayer.resetStyle(l));
    });
    // Círculos de ciudad y anillo de selección en su propio pane, SIEMPRE por encima de los
    // países: el hover de un país usa bringToFront() y, si compartieran capa, lo taparía.
    map.createPane("points");
    map.getPane("points").style.zIndex = 420;
    pointLayer = L.layerGroup().addTo(map);
    // Bloqueos del firewall: por encima de los países y por debajo de los círculos de alertas.
    map.createPane("fw");
    map.getPane("fw").style.zIndex = 410;
    fwLayer = L.layerGroup().addTo(map);

    // Capa de misiles por encima de países y círculos; no captura el ratón.
    map.createPane("missiles");
    map.getPane("missiles").style.zIndex = 450;
    map.getPane("missiles").style.pointerEvents = "none";

    home = readHome(container);
    if (home) {
      L.marker(home, { icon: homeIcon(), interactive: false, keyboard: false, zIndexOffset: 1000 }).addTo(map);
    }
    renderLegend();
  }

  function fitWorld() {
    map.fitBounds(WORLD, { animate: false });
    map.setMinZoom(map.getZoom());
  }

  // Botón "vista mundial" junto al zoom (icono casa).
  function worldViewControl() {
    const Ctl = L.Control.extend({
      options: { position: "topright" },
      onAdd() {
        const bar = Dom.el("div", { class: "leaflet-bar leaflet-control map-world" });
        const btn = Dom.el("a", { href: "#", role: "button", title: "Vista mundial", "aria-label": "Vista mundial" },
          Dom.icon(["M3 10.5 12 3l9 7.5", "M5 9.5V21h14V9.5"], 15));
        L.DomEvent.on(btn, "click", (e) => { L.DomEvent.preventDefault(e); fitWorld(); });
        L.DomEvent.disableClickPropagation(bar);
        bar.append(btn);
        return bar;
      },
    });
    return new Ctl();
  }

  // Casa: punto + dos anillos que se expanden + etiqueta "RED PROPIA" (divIcon con nodo DOM).
  function homeIcon() {
    const node = Dom.el("div", { class: "home-marker" },
      Dom.el("span", { class: "home-ring" }),
      Dom.el("span", { class: "home-ring home-ring-2" }),
      Dom.el("span", { class: "home-dot" }),
      Dom.el("span", { class: "home-label" }, "RED PROPIA"));
    return L.divIcon({ html: node, className: "home-icon", iconSize: [0, 0] });
  }

  function restyle() {
    if (!countryLayer) return;
    countryLayer.setStyle(countryStyle);
    pointLayer.eachLayer((l) => l.setStyle(dotStyle()));
    fwLayer.eachLayer((l) => l.setStyle(fwStyle()));
    gratLayer.eachLayer((l) => l.setStyle({ color: Dom.cssVar("--map-grat") }));
    renderLegend();
  }

  // ---------- Leyenda flotante ----------
  function renderLegend() {
    const legend = document.getElementById("map-legend");
    const ramp = Dom.el("div", { class: "lg-ramp" });
    for (let i = 1; i <= STEPS; i++) {
      const s = Dom.el("span");
      s.style.background = Dom.cssVar(`--seq-${i}`);
      ramp.append(s);
    }
    const dots = Dom.el("span", { class: "lg-dots", "aria-hidden": "true" },
      ...[3, 5, 7].map((r) => {
        const d = Dom.el("i");
        d.style.width = d.style.height = `${r * 2}px`;
        return d;
      }));
    const missile = (sev) => Dom.el("span", { class: "lg-missile", dataset: { sev } }, String(sev));
    legend.replaceChildren(
      Dom.el("div", { class: "lg-title" }, Dom.el("b", null, "Alertas por país"), " · escala log."),
      ramp,
      Dom.el("div", { class: "lg-ticks mono" }, ...["1", "10", "100", "1k+"].map((t) => Dom.el("span", null, t))),
      Dom.el("div", { class: "lg-row" }, dots, Dom.el("span", null, "Tamaño del círculo = alertas por ubicación")),
      Dom.el("div", { class: "lg-row lg-missiles" }, "Misiles:", missile(1), missile(2), missile(3)),
      fwOn ? Dom.el("div", { class: "lg-row lg-fw" }, Dom.el("i"), Dom.el("span", null, "Bloqueos del firewall (tamaño log.)")) : null);
  }

  // ---------- Datos (GET /api/map) ----------
  function update(data) {
    countsByIso = new Map((data.countries || []).map((c) => [c.country_iso, c.count]));
    countryLayer.setStyle(countryStyle);
    countryLayer.eachLayer((l) => {
      const el = l.getElement();
      if (el) el.classList.toggle("has-alerts", !!countsByIso.get(l.feature.properties.iso));
    });

    pointLayer.clearLayers();
    const points = (data.points || []).filter((p) => typeof p.lat === "number" && typeof p.lon === "number");
    lastPoints = points;
    // Primero los grandes, para que los pequeños queden encima y sean clicables.
    for (const p of [...points].sort((a, b) => b.count - a.count)) {
      L.circleMarker([p.lat, p.lon], { pane: "points", radius: radiusFor(p.count), ...dotStyle() })
        .bindTooltip(() => tip(pointLabel(p), p.count, isSelectedPoint(p)), { className: "map-tip" })
        .on("click", () => onOrigin({ lat: p.lat, lon: p.lon, label: pointLabel(p) }))
        .addTo(pointLayer);
    }
    drawSelectionRing();
    return { countries: countsByIso.size, points: points.length };
  }

  // ---------- Bloqueos del firewall (GET /api/fw/map); null = ocultar la capa ----------
  function setFirewall(data) {
    if (!fwLayer) return;
    fwLayer.clearLayers();
    fwOn = !!data;
    const points = (data?.points || []).filter((p) => typeof p.lat === "number" && typeof p.lon === "number");
    for (const p of [...points].sort((a, b) => b.count - a.count)) {
      L.circleMarker([p.lat, p.lon], { pane: "fw", radius: fwRadiusFor(p.count), ...fwStyle() })
        .bindTooltip(() => tip(pointLabel(p), p.count, false, "bloqueos del firewall"), { className: "map-tip" })
        .addTo(fwLayer);
    }
    renderLegend();
  }

  // ---------- Selección de origen (§6.2) ----------
  function setSelection(origin) {
    selected = origin ? (origin.country ? { country: origin.country } : { lat: origin.lat, lon: origin.lon }) : null;
    if (!countryLayer) return;
    countryLayer.setStyle(countryStyle);
    drawSelectionRing();
  }

  // Anillo blanco a r + 5 alrededor del círculo seleccionado.
  function drawSelectionRing() {
    if (selectionRing) { selectionRing.remove(); selectionRing = null; }
    if (!selected || selected.country) return;
    const match = lastPoints.find(isSelectedPoint);
    selectionRing = L.circleMarker([selected.lat, selected.lon], {
      pane: "points", radius: (match ? radiusFor(match.count) : 4) + 5, color: "#ffffff", weight: 1.5, fill: false, interactive: false,
    }).addTo(map);
  }

  // ---------- Misiles (eventos en vivo) ----------
  function readHome(container) {
    const lat = Number(container.dataset.homeLat);
    const lon = Number(container.dataset.homeLon);
    if (!Number.isFinite(lat) || !Number.isFinite(lon) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
    return L.latLng(lat, lon);
  }

  const isCoord = (lat, lon) => typeof lat === "number" && typeof lon === "number" && Math.abs(lat) <= 90 && Math.abs(lon) <= 180;

  // Curva Bézier cuadrática en espacio proyectado (zoom fijo), combada hacia el norte.
  function arc(from, to) {
    const Z = 3;
    const a = map.project(from, Z);
    const b = map.project(to, Z);
    const mid = a.add(b).divideBy(2);
    const d = b.subtract(a);
    const len = Math.hypot(d.x, d.y);
    let n = L.point(-d.y / (len || 1), d.x / (len || 1));
    if (n.y > 0) n = n.multiplyBy(-1);           // y crece hacia el sur: bulto hacia arriba
    const ctrl = mid.add(n.multiplyBy(len * 0.25));
    const pts = [];
    for (let i = 0; i <= ARC_POINTS; i++) {
      const t = i / ARC_POINTS, u = 1 - t;
      pts.push(map.unproject(L.point(
        u * u * a.x + 2 * u * t * ctrl.x + t * t * b.x,
        u * u * a.y + 2 * u * t * ctrl.y + t * t * b.y), Z));
    }
    return pts;
  }

  // Anillo que crece y se desvanece (origen al disparar, destino al impactar).
  function pulse(latlng, color, maxRadius, weight = 2, startOpacity = 1) {
    const ring = L.circleMarker(latlng, { pane: "missiles", radius: 3, color, weight, fill: false, opacity: startOpacity }).addTo(map);
    const t0 = performance.now();
    (function step(now) {
      const t = Math.min(1, (now - t0) / IMPACT_MS);
      ring.setRadius(3 + t * (maxRadius - 3));
      ring.setStyle({ opacity: startOpacity * (1 - t) });
      if (t < 1) requestAnimationFrame(step); else ring.remove();
    })(t0);
  }

  function setInFlight(delta) {
    inFlight += delta;
    const el = document.getElementById("map-inflight");
    if (el) el.textContent = inFlight > 0 ? `${inFlight} ${inFlight === 1 ? "misil" : "misiles"} en vuelo` : "";
  }

  function launch(ev) {
    if (!map || !home || inFlight >= MAX_MISSILES) return;
    if (ev.direction === "local" || !isCoord(ev.lat, ev.lon)) return;
    const remote = L.latLng(ev.lat, ev.lon);
    const [from, to] = ev.direction === "out" ? [home, remote] : [remote, home];
    const color = Dom.cssVar(`--sev${[1, 2, 3].includes(ev.severity) ? ev.severity : 3}`);
    const pts = arc(from, to);
    setInFlight(+1);

    if (reducedMotion.matches) {
      const line = L.polyline(pts, { pane: "missiles", color, weight: 2, opacity: 0.8, interactive: false }).addTo(map);
      setTimeout(() => { line.remove(); setInFlight(-1); }, 2500);
      return;
    }

    const common = { pane: "missiles", color, lineCap: "round", interactive: false };
    const ghost = L.polyline(pts, { ...common, weight: 1, opacity: 0.14 }).addTo(map);   // arco fantasma
    const halo = L.polyline([], { ...common, weight: 7, opacity: 0.35 }).addTo(map);     // halo bajo la estela
    const trail = L.polyline([], { ...common, weight: 2, opacity: 0.95 }).addTo(map);
    const head = L.circleMarker(from, { pane: "missiles", radius: 3, color, fillColor: color, fillOpacity: 1, weight: 0, interactive: false }).addTo(map);
    pulse(from, color, 10, 3, 0.8);                                                       // anillo de salida
    const t0 = performance.now();
    (function step(now) {
      const t = Math.min(1, (now - t0) / FLIGHT_MS);
      const e = t < 0.5 ? 2 * t * t : 1 - (-2 * t + 2) ** 2 / 2;   // ease-in-out
      const i = Math.round(e * ARC_POINTS);
      const seg = pts.slice(Math.max(0, i - TAIL_POINTS), i + 1);
      trail.setLatLngs(seg);
      halo.setLatLngs(seg);
      head.setLatLng(pts[i]);
      if (t < 1) { requestAnimationFrame(step); return; }
      for (const l of [ghost, halo, trail, head]) l.remove();
      pulse(to, color, 18);
      setInFlight(-1);
    })(t0);
  }

  // events = lote recibido por SSE; se lanzan en orden cronológico.
  function fire(events) {
    if (document.hidden) return;   // rAF se congela en segundo plano: no acumular
    [...events].sort((a, b) => a.ts_ms - b.ts_ms)
      .forEach((ev, k) => setTimeout(() => launch(ev), k * LAUNCH_GAP_MS));
  }

  function setOriginHandler(fn) { onOrigin = fn; }

  // Repintar al cambiar de tema (conmutador en app.js).
  window.addEventListener("themechange", restyle);

  return { init, update, fire, setOriginHandler, setSelection, setFirewall, restyle };
})();
