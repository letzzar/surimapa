/* Cliente de la API de Surimapa (referencia: docs/en/API.md, docs/es/API.md). */
"use strict";

const Api = (() => {
  const TIMEOUT_MS = 10000;

  // Traduce el estado de filtros de la página a parámetros de la API.
  function filterParams(f) {
    const p = new URLSearchParams();
    p.set("range", f.range);
    if (f.sev) p.set("severity", f.sev);
    if (f.dir) p.set("direction", f.dir);
    if (f.iface) p.set("iface", f.iface);
    return p;
  }

  // Parámetros de la tabla de eventos: filtros + búsqueda + origen ({ country } o { lat, lon }).
  function listParams(f, q, origin) {
    const p = filterParams(f);
    if (q) p.set("q", q);
    if (origin?.country) p.set("country", origin.country);
    else if (origin && Number.isFinite(origin.lat) && Number.isFinite(origin.lon)) {
      p.set("lat", String(origin.lat));
      p.set("lon", String(origin.lon));
    }
    return p;
  }

  // Bloqueos del firewall: solo el periodo (no tienen severidad, sentido ni interfaz).
  const rangeParams = (f) => new URLSearchParams({ range: f.range });

  async function get(path, params) {
    const url = params && [...params].length ? `${path}?${params}` : path;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
    try {
      const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: "application/json" } });
      if (res.status === 401) location.assign("/login");             // sesión caducada o cerrada
      if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      if (err.name === "AbortError") throw new Error(`${path}: tiempo de espera agotado`);
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    config:   ()           => get("/api/config"),
    health:   ()           => get("/api/health"),
    summary:  (f)          => get("/api/summary", filterParams(f)),
    timeline: (f)          => { const p = filterParams(f); p.set("bucket", "auto"); return get("/api/timeline", p); },
    top:      (dim, f, n)  => { const p = filterParams(f); p.set("limit", String(n)); return get(`/api/top/${encodeURIComponent(dim)}`, p); },
    map:      (f)          => get("/api/map", filterParams(f)),
    events:   (f, page, size, q, origin) => {
      const p = listParams(f, q, origin);
      p.set("page", String(page));
      p.set("size", String(size));
      return get("/api/events", p);
    },
    eventsCsvUrl: (f, q, origin) => `/api/events.csv?${listParams(f, q, origin)}`,
    event:    (id)         => get(`/api/events/${encodeURIComponent(id)}`),
    ip:       (ip)         => get(`/api/ip/${encodeURIComponent(ip)}`),
    fwSummary:(f)          => get("/api/fw/summary", rangeParams(f)),
    fwTop:    (dim, f, n)  => { const p = rangeParams(f); p.set("limit", String(n)); return get(`/api/fw/top/${encodeURIComponent(dim)}`, p); },
    fwMap:    (f)          => get("/api/fw/map", rangeParams(f)),
    streamUrl:(f)          => { const p = filterParams(f); p.delete("range"); return `/api/stream?${p}`; },
  };
})();
