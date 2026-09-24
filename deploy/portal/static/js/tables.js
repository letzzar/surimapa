/* Rankings, tabla de eventos y panel lateral (ficha de IP / detalle de evento). Tema SOC.
   Todo se construye con Dom.el()/textContent: ningún dato de la API se interpreta como HTML. */
"use strict";

const Tables = (() => {
  const { el } = Dom;
  let onIpClick = () => {};
  let onSearch = () => {};
  let onOrigin = () => {};
  let getRange = () => "24h";
  let lastFocus = null;

  function configure(handlers) {
    onIpClick = handlers.onIpClick;
    onSearch = handlers.onSearch;
    onOrigin = handlers.onOrigin;
    getRange = handlers.getRange || getRange;
  }

  // Interfaces: etiqueta visible desde el selector de index.html (pppoe0 → WAN, bridge0 → LAN).
  const IFACE_LABEL = Object.fromEntries([...document.querySelectorAll("#f-iface option")]
    .filter((o) => o.value).map((o) => [o.value, o.textContent.trim()]));
  const ifaceLabel = (iface) => IFACE_LABEL[iface] || iface || "—";

  // Nombres de servicio para Top puertos (mapa fijo, solo presentación).
  const SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 123: "ntp",
    143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2323: "telnet-alt", 3306: "mysql",
    3389: "rdp", 5060: "sip", 5432: "postgres", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elastic", 27017: "mongodb",
  };

  const DIR_TEXT = { in: "entrante", out: "saliente", local: "local" };
  function dirIcon(direction) {
    if (direction === "in") return Dom.icon(["M17 7 7 17", "M16 17H7V8"], 13);
    if (direction === "out") return Dom.icon(["M7 17 17 7", "M8 7h9v9"], 13);
    return null;
  }

  const isoOrDash = (code) => Dom.iso(code) || el("span", { class: "iso iso-empty" }, "—");

  // ---------- Rankings (GET /api/top/{dim}) ----------
  function labelFor(dim, it) {
    switch (dim) {
      case "remote_ip":
        return [isoOrDash(it.country_iso), el("span", { class: "mono r-main" }, it.label),
          it.as_org ? el("span", { class: "r-sub" }, it.as_org) : null];
      case "country":
        return [isoOrDash(it.key), el("span", { class: "r-main" }, it.label || it.key || "Desconocido")];
      case "asn":
        return [el("span", { class: "mono r-pre" }, it.key ? `AS${it.key}` : "—"), el("span", { class: "r-main" }, it.label || "—")];
      case "signature":
        return [el("span", { class: "mono r-pre" }, it.key ? String(it.key) : "—"),
          it.severity === 1 ? Dom.sevBadge(1) : null,
          el("span", { class: "r-main" }, it.label || "—")];
      case "dest_port":
        return [el("span", { class: "mono r-main" }, it.label ?? String(it.key)),
          SERVICES[it.key] ? el("span", { class: "r-sub" }, SERVICES[it.key]) : null];
      default:
        return [el("span", { class: "r-main" }, it.label ?? String(it.key))];
    }
  }

  function clickFor(dim, it) {
    if (dim === "remote_ip" && it.key) return () => onIpClick(it.key);
    if (dim === "signature" && it.key) return () => onSearch(String(it.key));
    if (dim === "country" && it.key) return () => onOrigin({ country: it.key, label: it.label || it.key });
    return null;
  }

  function rankItem(pos, labelNodes, count, max, action, title) {
    const bar = el("span");
    bar.style.width = `${max ? (count / max) * 100 : 0}%`;
    const li = el("li", { class: action ? "clickable" : null, tabindex: action ? 0 : null, title: title ?? null },
      el("span", { class: "r-pos mono" }, String(pos)),
      el("span", { class: "r-label" }, ...labelNodes),
      el("span", { class: "r-count mono" }, Dom.num(count)),
      el("span", { class: "r-bar", "aria-hidden": "true" }, bar));
    if (action) {
      li.addEventListener("click", action);
      li.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); action(); } });
    }
    return li;
  }

  function renderTop(listEl, data) {
    const dim = listEl.dataset.dim;
    const fw = listEl.dataset.source === "fw";        // bloqueos del firewall: sin ficha ni filtros de Suricata
    const items = data.items || [];
    if (!items.length) { listEl.replaceChildren(Dom.empty(fw ? "Sin bloqueos en este periodo" : "Sin alertas en este periodo")); return; }
    const max = Math.max(...items.map((i) => i.count));
    listEl.replaceChildren(...items.map((it, i) =>
      rankItem(i + 1, labelFor(dim, it), it.count, max, fw ? null : clickFor(dim, it), it.label ?? null)));
  }

  // ---------- Tabla de eventos (GET /api/events, SSE) ----------
  const LONG_RANGES = new Set(["7d", "30d", "90d"]);
  const dtDayHm = new Intl.DateTimeFormat("es-ES", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  const rowTime = (ms) => (LONG_RANGES.has(getRange()) ? dtDayHm.format(new Date(ms)).replace(",", "") : Dom.clock(ms));

  function eventRow(ev, isNew) {
    const dir = dirIcon(ev.direction);
    const remote = ev.remote_ip
      ? el("span", { class: "ip-cell" },
        dir ? el("span", { class: "dir", title: DIR_TEXT[ev.direction] || "" }, dir) : null,
        el("button", { type: "button", class: "ip-link", onclick: (e) => { e.stopPropagation(); onIpClick(ev.remote_ip); } }, ev.remote_ip))
      : el("span", { class: "muted", title: "local" }, "—");
    const country = ev.country_iso
      ? el("span", { class: "country-cell" }, Dom.iso(ev.country_iso), el("span", null, ev.country || ev.country_iso))
      : el("span", { class: "muted" }, "—");
    const dest = `${ev.dest_ip}${ev.dest_port != null ? ":" + ev.dest_port : ""}`;
    const tr = el("tr", { tabindex: 0, class: [isNew ? "is-new" : "", ev.severity === 1 ? "is-sev1" : ""].join(" ").trim() || null },
      el("td", { class: "mono c-time", title: Dom.timeLong(ev.ts_ms) }, rowTime(ev.ts_ms)),
      el("td", { class: "c-sev" }, Dom.sevBadge(ev.severity)),
      el("td", { class: "c-if" }, el("span", { class: "if-pill mono", title: ev.iface || "" }, ifaceLabel(ev.iface))),
      el("td", { class: "c-ip" }, remote),
      el("td", { class: "c-country" }, country),
      el("td", { class: "mono c-dest", title: dest }, dest),
      el("td", { class: "sig", title: ev.signature || "" },
        isNew ? el("span", { class: "new-pill" }, "NUEVO") : null, ev.signature || "—"));
    if (isNew) setTimeout(() => { tr.querySelector(".new-pill")?.remove(); tr.classList.remove("is-new"); }, 6000);
    const open = () => showEvent(ev.id);
    tr.addEventListener("click", open);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter") open(); });
    return tr;
  }

  function renderEvents(tbody, data) {
    const items = data.items || [];
    if (!items.length) {
      tbody.replaceChildren(el("tr", null, el("td", { colspan: 7, class: "empty" }, "Sin alertas para estos filtros")));
      return;
    }
    tbody.replaceChildren(...items.map((ev) => eventRow(ev, false)));
  }

  // Inserta eventos nuevos (SSE) arriba y recorta al tamaño de página.
  function prependEvents(tbody, events, pageSize) {
    if (tbody.querySelector("td.empty")) tbody.replaceChildren();
    for (const ev of events) tbody.prepend(eventRow(ev, true));
    while (tbody.rows.length > pageSize) tbody.deleteRow(-1);
  }

  // ---------- Copiar (Clipboard API solo en contexto seguro; si no, respaldo) ----------
  async function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      try { await navigator.clipboard.writeText(text); return true; } catch { /* respaldo */ }
    }
    // HTTP en la LAN: la Clipboard API no existe → textarea temporal + execCommand (obsoleto pero funcional).
    const ta = el("textarea", { readonly: "", "aria-hidden": "true", class: "copy-buffer" });
    ta.value = text;
    document.body.append(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { ok = false; }
    ta.remove();
    return ok;
  }

  function copyButton(getText, label = "Copiar") {
    const text = el("span", null, label);
    const btn = el("button", { type: "button", class: "btn-ghost btn-copy", title: "Copiar al portapapeles" },
      Dom.icon(["M9 9h10v10H9z", "M5 15V5h10"], 13), text);
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const ok = await copyText(getText());
      text.textContent = ok ? "Copiado" : "No se pudo copiar";
      setTimeout(() => { text.textContent = label; }, 1500);
    });
    return btn;
  }

  // ---------- JSON resaltado (nodos + textContent; nunca HTML) ----------
  function jsonNodes(value, indent = 0) {
    const pad = "  ".repeat(indent);
    const pad1 = "  ".repeat(indent + 1);
    const punct = (t) => el("span", { class: "j-punct" }, t);
    if (value === null || typeof value === "number" || typeof value === "boolean") {
      return [el("span", { class: "j-num" }, JSON.stringify(value))];
    }
    if (typeof value === "string") return [el("span", { class: "j-str" }, JSON.stringify(value))];
    if (Array.isArray(value)) {
      if (!value.length) return [punct("[]")];
      const out = [punct("["), "\n"];
      value.forEach((v, i) => {
        out.push(pad1, ...jsonNodes(v, indent + 1));
        if (i < value.length - 1) out.push(punct(","));
        out.push("\n");
      });
      out.push(pad, punct("]"));
      return out;
    }
    const keys = Object.keys(value);
    if (!keys.length) return [punct("{}")];
    const out = [punct("{"), "\n"];
    keys.forEach((k, i) => {
      out.push(pad1, el("span", { class: "j-key" }, JSON.stringify(k)), punct(": "), ...jsonNodes(value[k], indent + 1));
      if (i < keys.length - 1) out.push(punct(","));
      out.push("\n");
    });
    out.push(pad, punct("}"));
    return out;
  }

  function rawBlock(raw) {
    let parsed;
    try { parsed = JSON.parse(raw); } catch { parsed = undefined; }
    return el("pre", { class: "raw" }, ...(parsed === undefined ? [String(raw ?? "")] : jsonNodes(parsed)));
  }

  // ---------- Panel lateral ----------
  const drawer = () => document.getElementById("drawer");

  function openDrawer(kicker, titleNodes, ...nodes) {
    if (drawer().hidden) lastFocus = document.activeElement;
    document.getElementById("drawer-kicker").textContent = kicker;
    document.getElementById("drawer-title").replaceChildren(...[].concat(titleNodes));
    document.getElementById("drawer-body").replaceChildren(...nodes);
    drawer().hidden = false;
    document.getElementById("drawer-close").focus();
  }

  function closeDrawer() {
    drawer().hidden = true;
    if (lastFocus && lastFocus.isConnected) lastFocus.focus();
  }

  // Focus trap: Tab no sale del panel mientras está abierto.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Tab" || drawer().hidden) return;
    const focusable = [...drawer().querySelectorAll('button, [href], input, [tabindex]:not([tabindex="-1"])')]
      .filter((n) => !n.disabled && n.offsetParent !== null);
    if (!focusable.length) return;
    const first = focusable[0], last = focusable[focusable.length - 1];
    if (e.shiftKey && (document.activeElement === first || !drawer().contains(document.activeElement))) {
      e.preventDefault(); last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || !drawer().contains(document.activeElement))) {
      e.preventDefault(); first.focus();
    }
  });

  function kv(pairs) {
    return el("dl", { class: "kv" }, ...pairs.filter(Boolean).flatMap(([k, v]) => [el("dt", null, k), el("dd", null, v ?? "—")]));
  }

  function section(title, ...content) {
    return el("section", { class: "d-section" }, el("h3", null, title), ...content);
  }

  function stat(label, value, sub) {
    return el("div", { class: "d-stat" },
      el("span", { class: "ms-label" }, label),
      el("span", { class: "ms-value mono" }, value),
      sub ? el("span", { class: "ms-sub" }, sub) : null);
  }

  const agoMs = (ms) => (ms ? Dom.ago((Date.now() - ms) / 1000) : "");
  const dtDay = new Intl.DateTimeFormat("es-ES", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
  const dtFull = new Intl.DateTimeFormat("es-ES", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });

  function location(d) {
    const place = [d.country, d.city].filter(Boolean).join(" · ");
    return el("p", { class: "d-location" },
      Dom.iso(d.country_iso), el("span", null, place || "Ubicación desconocida"),
      d.asn ? el("span", { class: "d-sep", "aria-hidden": "true" }, "|") : null,
      d.asn ? el("span", { class: "mono muted" }, `AS${d.asn}`) : null,
      d.asn ? el("span", null, d.as_org || "") : null);
  }

  function loading(kicker, title) { openDrawer(kicker, title, el("p", { class: "note" }, "Cargando…")); }

  async function showIp(ip) {
    loading("Ficha de IP", ip);
    try {
      const d = await Api.ip(ip);
      const sigMax = Math.max(1, ...(d.signatures || []).map((s) => s.count));
      const sigs = (d.signatures || []).map((s, i) => rankItem(i + 1,
        [el("span", { class: "mono r-pre" }, String(s.sid)), s.severity === 1 ? Dom.sevBadge(1) : null,
          el("span", { class: "r-main" }, s.signature || "—")],
        s.count, sigMax, null, s.signature || null));
      const ports = (d.dest_ports || []).map((p) => el("li", { class: "port-chip mono" },
        String(p.dest_port), el("span", null, ` ×${Dom.num(p.count)}`)));
      openDrawer("Ficha de IP",
        [el("span", { class: "mono" }, d.ip), copyButton(() => d.ip, "")],
        location(d),
        el("div", { class: "d-stats" },
          stat("Alertas", Dom.num(d.total), "en total"),
          stat("Firmas distintas", Dom.num(d.signatures_total ?? (d.signatures || []).length)),
          stat("Primera vez", d.first_seen_ms ? dtDay.format(new Date(d.first_seen_ms)).replace(",", "") : "—", agoMs(d.first_seen_ms)),
          stat("Última vez", Dom.clock(d.last_seen_ms), agoMs(d.last_seen_ms))),
        section("Firmas", el("ol", { class: "rank" }, sigs.length ? sigs : Dom.empty("—"))),
        section("Puertos destino", el("ul", { class: "port-chips" }, ports.length ? ports : Dom.empty("—"))),
        el("button", { type: "button", class: "btn-primary", onclick: () => { closeDrawer(); onSearch(d.ip); } },
          Dom.icon(["M20 20l-4.2-4.2", "M11 17.5a6.5 6.5 0 1 0 0-13 6.5 6.5 0 0 0 0 13Z"], 14), "Ver sus eventos en la tabla"),
        el("p", { class: "note" }, "Los datos de la IP proceden del tráfico y de GeoLite: la ubicación es aproximada y puede ser un centroide de país."));
    } catch (err) {
      openDrawer("Ficha de IP", ip, el("p", { class: "note" }, `No se pudo cargar la ficha: ${err.message}`));
    }
  }

  function endpoint(ip, port, clickable) {
    const ipNode = clickable
      ? el("button", { type: "button", class: "ip-link", onclick: () => showIp(ip) }, ip)
      : el("span", { class: "mono" }, ip);
    return el("span", { class: "mono" }, ipNode, port != null ? el("span", { class: "muted" }, `:${port}`) : null);
  }

  async function showEvent(id) {
    loading("Detalle de evento", `Evento #${id}`);
    try {
      const d = await Api.event(id);
      const dir = dirIcon(d.direction);
      openDrawer("Detalle de evento",
        [el("span", { class: "mono" }, `Evento #${d.id}`), Dom.sevBadge(d.severity)],
        section("Resumen", kv([
          ["Hora", el("span", { class: "mono" }, dtFull.format(new Date(d.ts_ms)).replace(",", ""))],
          ["Severidad", Dom.sevBadge(d.severity)],
          ["Dirección", el("span", { class: "dir-text" }, dir, `${DIR_TEXT[d.direction] || d.direction} · ${ifaceLabel(d.iface)}${d.iface ? ` (${d.iface})` : ""}`)],
          ["Origen", endpoint(d.src_ip, d.src_port, d.src_ip === d.remote_ip)],
          ["Destino", el("span", null, endpoint(d.dest_ip, d.dest_port, d.dest_ip === d.remote_ip),
            [d.proto, d.app_proto].filter(Boolean).length ? el("span", { class: "muted" }, ` · ${[d.proto, d.app_proto].filter(Boolean).join(" / ")}`) : null)],
          ["País", d.country_iso ? el("span", { class: "country-cell" }, Dom.iso(d.country_iso),
            el("span", null, [d.country, d.city].filter(Boolean).join(" · "))) : null],
          ["ASN", d.asn ? el("span", null, el("span", { class: "mono muted" }, `AS${d.asn} `), d.as_org || "") : null],
          ["Firma", d.signature],
          ["SID", d.sid != null ? el("span", { class: "mono" }, String(d.sid)) : null],
          ["Categoría", d.category],
          ["Flow ID", d.flow_id != null ? el("span", { class: "mono" }, String(d.flow_id)) : null],
        ])),
        el("section", { class: "d-section" },
          el("div", { class: "d-section-head" }, el("h3", null, "JSON EVE (crudo)"), copyButton(() => d.raw || "")),
          d.raw_truncated ? el("p", { class: "note" }, "El JSON se truncó al guardarlo (> 4 KB): se muestra tal cual.") : null,
          rawBlock(d.raw)),
        el("p", { class: "note" }, "El campo action no se interpreta: en modo Legacy de pfSense siempre llega «allowed» aunque la IP acabe bloqueada."));
    } catch (err) {
      openDrawer("Detalle de evento", `Evento #${id}`, el("p", { class: "note" }, `No se pudo cargar el evento: ${err.message}`));
    }
  }

  return { configure, renderTop, renderEvents, prependEvents, showIp, showEvent, closeDrawer };
})();
