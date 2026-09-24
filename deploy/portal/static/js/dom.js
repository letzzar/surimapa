/* Utilidades de DOM y formato.
   REGLA: los datos de la API se insertan SOLO como nodos de texto (el() / textContent).
   No usar innerHTML, outerHTML, insertAdjacentHTML ni document.write en ningún fichero. */
"use strict";

const Dom = (() => {
  const TZ = Intl.DateTimeFormat().resolvedOptions().timeZone;   // zona horaria del navegador
  // useGrouping "always": es-ES no agrupa por defecto los números de 4 cifras (4011 → 4.011).
  const nf = new Intl.NumberFormat("es-ES", { useGrouping: "always" });
  const dtShort = new Intl.DateTimeFormat("es-ES", { timeZone: TZ, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const dtLong = new Intl.DateTimeFormat("es-ES", { timeZone: TZ, dateStyle: "medium", timeStyle: "medium" });

  // el("td", { class: "x", dataset: { id: 1 }, onclick: fn }, "texto", nodo, ...)
  function el(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "dataset") Object.assign(node.dataset, v);
      else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, String(v));
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  function setText(node, value) { node.textContent = value ?? ""; }

  // Elementos SVG (iconos) con createElementNS. svg("path", { d: "…" }). Solo atributos constantes.
  const SVG_NS = "http://www.w3.org/2000/svg";
  function svg(tag, attrs, ...children) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v !== null && v !== undefined && v !== false) node.setAttribute(k, String(v));
    }
    for (const c of children.flat()) if (c) node.append(c);
    return node;
  }

  // Icono de trazo 24×24 a partir de uno o varios `d`.
  function icon(paths, size = 16) {
    return svg("svg", { viewBox: "0 0 24 24", width: size, height: size, fill: "none", stroke: "currentColor",
      "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
    ...[].concat(paths).map((d) => svg("path", { d })));
  }

  const num = (n) => (n === null || n === undefined ? "—" : nf.format(n));
  const nf1 = new Intl.NumberFormat("es-ES", { minimumFractionDigits: 1, maximumFractionDigits: 1, useGrouping: "always" });
  const dec1 = (n) => nf1.format(n);

  // «hace 7 s», «hace 3 min», «hace 2 h», «hace 4 d»
  function ago(seconds) {
    if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
    const s = Math.max(0, Math.round(seconds));
    if (s < 60) return `hace ${s} s`;
    if (s < 3600) return `hace ${Math.floor(s / 60)} min`;
    if (s < 86400) return `hace ${Math.floor(s / 3600)} h`;
    return `hace ${Math.floor(s / 86400)} d`;
  }

  // 1.234.567 → «1,2 MB»
  function bytes(n) {
    if (n === null || n === undefined || !Number.isFinite(n)) return "—";
    const units = ["B", "KB", "MB", "GB", "TB"];
    let v = n, i = 0;
    while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
    return `${i === 0 ? num(v) : dec1(v)} ${units[i]}`;
  }
  const time = (ms) => (ms ? dtShort.format(new Date(ms)) : "—");
  const dtClock = new Intl.DateTimeFormat("es-ES", { timeZone: TZ, hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const dtHm = new Intl.DateTimeFormat("es-ES", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });
  const clock = (ms) => (ms ? dtClock.format(new Date(ms)) : "—");     // 12:41:08
  const hm = (ms) => (ms ? dtHm.format(new Date(ms)) : "—");           // 12:41
  const timeLong = (ms) => (ms ? dtLong.format(new Date(ms)) : "—");

  // Bandera emoji a partir de un ISO-3166 alfa-2 validado (nunca de texto libre).
  function flag(iso) {
    if (typeof iso !== "string" || !/^[A-Z]{2}$/.test(iso)) return "";
    return String.fromCodePoint(...[...iso].map((c) => 0x1f1a5 + c.charCodeAt(0)));
  }

  // Chip ISO monoespaciado (sustituye a la bandera emoji: se ve igual en todos los sistemas).
  // Solo códigos validados; si no, null (el llamador decide qué mostrar).
  function iso(code) {
    if (typeof code !== "string" || !/^[A-Z]{2}$/.test(code)) return null;
    return el("span", { class: "iso", title: code }, code);
  }

  const SEV_LABEL = { 1: "alta", 2: "media", 3: "baja" };
  function sevBadge(sev) {
    const s = Number(sev);
    return el("span", { class: "sev", dataset: { sev: s } }, SEV_LABEL[s] ? `${s} · ${SEV_LABEL[s]}` : "—");
  }

  function empty(text) { return el("li", { class: "empty" }, text); }

  let toastTimer;
  function toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg;
    t.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.hidden = true; }, 4000);
  }

  // Lee un token CSS (para Chart.js y Leaflet, que no entienden var()).
  const cssVar = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

  return { el, svg, icon, setText, num, dec1, ago, bytes, time, clock, hm, timeLong, flag, iso, sevBadge, empty, toast, cssVar, SEV_LABEL };
})();
