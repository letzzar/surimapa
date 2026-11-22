#!/usr/bin/env python3
"""API simulada de Surimapa para previsualizar el panel sin NAS ni credenciales.

Uso (desde la raíz del proyecto; solo biblioteca estándar):
    python3 scripts/mock_api.py                 # http://127.0.0.1:8099
    python3 scripts/mock_api.py --port 9000 --events 3000

Sirve deploy/portal/static y los endpoints /api/* con el MISMO contrato que la
API real, respetando filtros, paginación, rejilla del mapa y SSE.
Datos ficticios y deterministas (IP de documentación), con casos límite a propósito:
firmas con <script>/<img onerror>, IPv6, eventos de LAN (bridge0) y locales,
ciudades sin nombre. NO usar como servidor real: no tiene autenticación.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import math
import random
import re
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

STATIC = Path(__file__).resolve().parent.parent / "deploy" / "portal" / "static"
H, D = 3_600_000, 86_400_000
RANGES = {"1h": H, "24h": D, "7d": 7 * D, "30d": 30 * D, "90d": 90 * D}
WAN_IP = "192.0.2.10"
CITIES = [  # iso, país, ciudad, lat, lon, asn, organización
    ("US", "Estados Unidos", "Ashburn", 39.0438, -77.4874, 14618, "Amazon.com, Inc."),
    ("US", "Estados Unidos", None, 37.751, -97.822, 398324, "Censys, Inc."),
    ("FR", "Francia", "París", 48.8566, 2.3522, 16276, "OVH SAS"),
    ("NL", "Países Bajos", "Ámsterdam", 52.3740, 4.8897, 209334, "Modat B.V."),
    ("CN", "China", "Pekín", 39.9042, 116.4074, 4134, "Chinanet"),
    ("RU", "Rusia", "Moscú", 55.7558, 37.6173, 12389, "Rostelecom"),
    ("BG", "Bulgaria", "Sofía", 42.6977, 23.3219, 204957, "GreenFloid LLC"),
    ("BR", "Brasil", "São Paulo", -23.5505, -46.6333, 28573, "Claro NXT"),
    ("IN", "India", "Bombay", 19.0760, 72.8777, 9829, "BSNL"),
    ("KR", "Corea del Sur", "Seúl", 37.5665, 126.9780, 4766, "Korea Telecom"),
    ("VN", "Vietnam", "Hanói", 21.0278, 105.8342, 45899, "VNPT Corp"),
    ("DE", "Alemania", "Fráncfort", 50.1109, 8.6821, 24940, "Hetzner Online GmbH"),
]
SIGNATURES = [  # sid, firma, categoría, severidad
    (2402000, "ET DROP Dshield Block Listed Source group 1", "Misc Attack", 2),
    (2403445, "ET CINS Active Threat Intelligence Poor Reputation IP group 146", "Misc Attack", 2),
    (2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
    (2024792, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2),
    (2019284, "ET WEB_SERVER Possible XSS <script>alert(1)</script> Attempt", "Web Application Attack", 1),
    (2027865, "ET INFO Observed DNS Query to .cloud TLD", "Potentially Bad Traffic", 3),
    (2999999, "PRUEBA XSS <img src=x onerror=alert('xss')> \"comillas\" & ampersand", "Not Suspicious Traffic", 3),
]
PORTS = [22, 23, 80, 443, 445, 1433, 3389, 5060, 8080, 8443]


def grid(v: float) -> float:
    """Misma rejilla que la API real (queries.grid): 0,1°, mitad hacia arriba."""
    return round(math.floor(v / 0.1 + 0.5) * 0.1, 1)


def build(n: int, seed: int = 7) -> list[dict]:
    rng = random.Random(seed)
    now = int(time.time() * 1000)
    ips = [f"{rng.choice(['198.51.100', '203.0.113'])}.{rng.randint(1, 254)}" for _ in range(n // 3)]
    ips += [f"2001:db8::{rng.randint(1, 0xffff):x}" for _ in range(n // 40)]
    out = []
    for i in range(n):
        ts = now - int((i / n) ** 1.6 * 90 * D)          # más densidad en lo reciente
        sid, sig, cat, sev = rng.choice(SIGNATURES)
        iso, country, city, lat, lon, asn, org = rng.choice(CITIES)
        kind = rng.choices(["wan-in", "wan-out", "lan-out", "lan-local"], weights=[88, 5, 5, 2])[0]
        ip = rng.choice(ips)
        e = {"id": n - i, "ts_ms": ts, "severity": sev, "sid": sid, "signature": sig, "category": cat,
             "src_port": rng.randint(1024, 65535), "dest_port": rng.choice(PORTS), "proto": "TCP",
             "iface": "pppoe0", "direction": "in", "src_ip": ip, "dest_ip": WAN_IP, "remote_ip": ip,
             "country_iso": iso, "country": country, "city": city, "lat": lat, "lon": lon, "asn": asn, "as_org": org}
        if kind == "wan-out":
            e.update(direction="out", src_ip=WAN_IP, dest_ip=ip)
        elif kind == "lan-out":
            e.update(iface="bridge0", direction="out", src_ip=f"192.168.1.{rng.randint(20, 60)}", dest_ip=ip)
        elif kind == "lan-local":
            e.update(iface="bridge0", direction="local", src_ip="192.168.1.20", dest_ip="192.168.1.10", remote_ip=None,
                     country_iso=None, country=None, city=None, lat=None, lon=None, asn=None, as_org=None,
                     sid=2210045, signature="SURICATA STREAM TIMEWAIT ACK with wrong seq",
                     category="Generic Protocol Command Decode", severity=3)
        out.append(e)
    out.sort(key=lambda e: e["id"])
    return out


FW_EXTRA_CITIES = [  # solo en los bloqueos del firewall: círculos donde no hay alertas
    ("TW", "Taiwán", "Taipéi", 25.0330, 121.5654, 3462, "Chunghwa Telecom"),
    ("IR", "Irán", "Teherán", 35.6892, 51.3890, 58224, "TCI"),
    ("ZA", "Sudáfrica", "Johannesburgo", -26.2041, 28.0473, 37457, "Telkom SA"),
]
FW_PORTS = [23, 22, 445, 3389, 80, 8080, 5555, 2323, 1433, 37215, None]   # None = ICMP


def build_fw(n: int, seed: int = 11) -> list[dict]:
    """Bloqueos del firewall (WAN entrantes), mismo esquema que firewall_events."""
    rng = random.Random(seed)
    now = int(time.time() * 1000)
    ips = [f"{rng.choice(['198.51.100', '203.0.113'])}.{rng.randint(1, 254)}" for _ in range(n // 20)]
    out = []
    for i in range(n):
        iso, country, city, lat, lon, asn, org = rng.choice(CITIES + FW_EXTRA_CITIES * 2)
        port = rng.choices(FW_PORTS, weights=[30, 20, 12, 10, 8, 6, 4, 4, 3, 2, 1])[0]
        out.append({"ts_ms": now - int((i / n) ** 1.6 * 30 * D), "remote_ip": rng.choice(ips),
                    "proto": "ICMP" if port is None else rng.choice(["TCP", "TCP", "UDP"]), "dest_port": port,
                    "country_iso": iso, "country": country, "city": city, "lat": lat, "lon": lon,
                    "asn": asn, "as_org": org})
    return out


LIST_KEYS = ("id", "ts_ms", "severity", "direction", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
             "remote_ip", "sid", "signature", "category", "country_iso", "country", "city", "asn", "as_org", "iface")
# Exportación CSV: mismas columnas y cabecera que el portal (app/api.py, queries.CSV_COLUMNS).
CSV_KEYS = ("severity", "iface", "direction", "remote_ip", "country_iso", "country", "city", "asn", "as_org",
            "src_ip", "src_port", "dest_ip", "dest_port", "proto", "sid", "signature", "category")
CSV_HEADER = ("fecha_utc", "severidad", "interfaz", "direccion", "ip_remota", "pais_iso", "pais", "ciudad", "asn",
              "organizacion", "ip_origen", "puerto_origen", "ip_destino", "puerto_destino", "protocolo", "sid",
              "firma", "categoria")


class Api(SimpleHTTPRequestHandler):
    events: list[dict] = []
    fw_events: list[dict] = []

    def log_message(self, fmt, *args):             # silencio: solo errores
        pass

    def end_headers(self):
        if not self.path.startswith("/api/"):       # estáticos: revalidar siempre (como el portal)
            self.send_header("Cache-Control", "no-cache")
        super().end_headers()

    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def filtered(self, q: dict) -> list[dict] | None:
        rng = q.get("range", ["24h"])[0]
        if rng not in RANGES:
            return None
        frm = int(time.time() * 1000) - RANGES[rng]
        sev, dirn, iface = q.get("severity", [None])[0], q.get("direction", [None])[0], q.get("iface", [None])[0]
        return [e for e in self.events if e["ts_ms"] >= frm
                and (sev is None or str(e["severity"]) == sev)
                and (dirn is None or e["direction"] == dirn)
                and (iface is None or e["iface"] == iface)]

    def do_GET(self):
        u = urlparse(self.path)
        if not u.path.startswith("/api/"):
            return super().do_GET()
        q = parse_qs(u.query)
        p = u.path
        if p == "/api/config":
            return self.send_json({"bledeagle_url": "https://bledeagle.lan.example", "version": "1.1.0"})
        if p == "/api/health":
            return self.send_json({"status": "ok", "last_event_ms": self.events[-1]["ts_ms"],
                                   "collector_heartbeat_age_s": 7, "redis_queue_len": 0,
                                   "db_size_bytes": 1_234_567})
        if p == "/api/stream":
            return self.stream(q)
        m = re.fullmatch(r"/api/events/(\d+)", p)
        if m:
            e = next((x for x in self.events if x["id"] == int(m.group(1))), None)
            if not e:
                return self.send_json({"detail": "Evento no encontrado"}, 404)
            raw = {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime(e["ts_ms"] / 1000)),
                   "event_type": "alert", "in_iface": e["iface"], "src_ip": e["src_ip"], "dest_ip": e["dest_ip"],
                   "proto": e["proto"], "alert": {"signature_id": e["sid"], "signature": e["signature"],
                                                  "category": e["category"], "severity": e["severity"]}}
            return self.send_json({**{k: e[k] for k in LIST_KEYS}, "app_proto": None,
                                   "action": "allowed", "flow_id": e["id"],
                                   "raw": json.dumps(raw, ensure_ascii=False), "raw_truncated": 0})
        m = re.fullmatch(r"/api/ip/(.+)", p)
        if m:
            xs = [e for e in self.events if e["remote_ip"] == m.group(1)]
            if not xs:
                return self.send_json({"detail": "Sin eventos para esta IP"}, 404)
            last = xs[-1]
            return self.send_json({
                "ip": m.group(1), "first_seen_ms": xs[0]["ts_ms"], "last_seen_ms": last["ts_ms"], "total": len(xs),
                **{k: last[k] for k in ("country_iso", "country", "city", "asn", "as_org")},
                "signatures_total": len({e["sid"] for e in xs}),
                "signatures": [{"sid": s, "signature": next(e["signature"] for e in xs if e["sid"] == s),
                                "severity": next(e["severity"] for e in xs if e["sid"] == s),
                                "count": n} for s, n in self.count(xs, "sid")[:20]],
                "dest_ports": [{"dest_port": k, "count": n} for k, n in self.count(xs, "dest_port")[:20]]})

        if p.startswith("/api/fw/"):
            return self.firewall(p, q)
        ev = self.filtered(q)
        if ev is None:
            return self.send_json({"detail": "range no válido"}, 422)
        if p == "/api/summary":
            return self.send_json(self.summary(ev, q))
        if p == "/api/timeline":
            span = RANGES[q.get("range", ["24h"])[0]]
            b = 60_000 if span <= H else 900_000 if span <= D else H if span <= 7 * D else 6 * H
            now = int(time.time() * 1000)
            buckets = {t: {"ts_ms": t, "sev1": 0, "sev2": 0, "sev3": 0}
                       for t in range((now - span) // b * b, now + 1, b)}
            for e in ev:
                if (t := e["ts_ms"] // b * b) in buckets:
                    buckets[t][f"sev{e['severity']}"] += 1
            return self.send_json({"bucket_ms": b, "points": list(buckets.values())})
        m = re.fullmatch(r"/api/top/(\w+)", p)
        if m:
            return self.top(ev, m.group(1), int(q.get("limit", ["10"])[0]))
        if p == "/api/map":
            cells, countries = {}, {}
            for e in ev:
                if e["lat"] is None:
                    continue
                k = (grid(e["lat"]), grid(e["lon"]))
                c = cells.setdefault(k, {"lat": k[0], "lon": k[1], "count": 0, "country_iso": e["country_iso"],
                                         "country": e["country"], "city": e["city"]})
                c["count"] += 1
                countries.setdefault(e["country_iso"], {"country_iso": e["country_iso"], "country": e["country"],
                                                        "count": 0})["count"] += 1
            return self.send_json({"points": sorted(cells.values(), key=lambda c: -c["count"]),
                                   "countries": sorted(countries.values(), key=lambda c: -c["count"])})
        if p == "/api/events":
            return self.list_events(ev, q)
        if p == "/api/events.csv":
            return self.events_csv(ev, q)
        return self.send_json({"detail": "Not Found"}, 404)

    @staticmethod
    def count(rows, key):
        c = {}
        for r in rows:
            if r[key] is not None:
                c[r[key]] = c.get(r[key], 0) + 1
        return sorted(c.items(), key=lambda kv: (-kv[1], str(kv[0])))

    def summary(self, ev, q):
        def agg(rows):
            return {"total": len(rows), "unique_ips": len({e["remote_ip"] for e in rows if e["remote_ip"]}),
                    "unique_countries": len({e["country_iso"] for e in rows if e["country_iso"]}),
                    "by_severity": {s: sum(e["severity"] == int(s) for e in rows) for s in ("1", "2", "3")}}
        span = RANGES[q.get("range", ["24h"])[0]]
        now = int(time.time() * 1000)
        prev = [e for e in self.events if now - 2 * span <= e["ts_ms"] < now - span]
        return {**agg(ev), "previous": agg(prev), "range": {"from_ms": now - span, "to_ms": now}}

    def top(self, ev, dim, limit):
        key = {"remote_ip": "remote_ip", "signature": "sid", "country": "country_iso", "asn": "asn",
               "dest_port": "dest_port", "category": "category"}.get(dim)
        if key is None:
            return self.send_json({"detail": "dim no válida"}, 422)
        label = {"sid": "signature", "country_iso": "country", "asn": "as_org"}.get(key)
        items = []
        for k, n in self.count(ev, key)[:limit]:
            first = next(e for e in ev if e[key] == k)
            item = {"key": k, "label": first[label] if label else str(k), "count": n}
            if dim == "remote_ip":
                item.update(country_iso=first["country_iso"], as_org=first["as_org"])
            elif dim == "signature":
                item["severity"] = first["severity"]
            items.append(item)
        return self.send_json({"dim": dim, "items": items})

    def table_view(self, ev, q):
        text = (q.get("q", [""])[0] or "").strip().casefold()
        if text:
            ev = [e for e in ev if text in (e["remote_ip"] or "", e["src_ip"], e["dest_ip"], str(e["sid"]))
                  or text in e["signature"].casefold()]
        if "country" in q:
            ev = [e for e in ev if e["country_iso"] == q["country"][0]]
        if "lat" in q and "lon" in q:
            cell = (grid(float(q["lat"][0])), grid(float(q["lon"][0])))
            ev = [e for e in ev if e["lat"] is not None and (grid(e["lat"]), grid(e["lon"])) == cell]
        return sorted(ev, key=lambda e: -e["id"])

    def list_events(self, ev, q):
        ev = self.table_view(ev, q)
        page, size = int(q.get("page", ["1"])[0]), min(100, int(q.get("size", ["25"])[0]))
        rows = ev[(page - 1) * size: page * size]
        return self.send_json({"page": page, "size": size, "total": len(ev),
                               "items": [{k: e[k] for k in LIST_KEYS} for e in rows]})

    def firewall(self, p, q):
        rng = q.get("range", ["24h"])[0]
        if rng not in RANGES:
            return self.send_json({"detail": "range no válido"}, 422)
        now = int(time.time() * 1000)
        ev = [e for e in self.fw_events if e["ts_ms"] >= now - RANGES[rng]]
        if p == "/api/fw/summary":
            return self.send_json({"total": len(ev), "unique_ips": len({e["remote_ip"] for e in ev}),
                                   "unique_countries": len({e["country_iso"] for e in ev}),
                                   "range": {"from_ms": now - RANGES[rng], "to_ms": now}})
        m = re.fullmatch(r"/api/fw/top/(\w+)", p)
        if m:
            dim = m.group(1)
            key = {"remote_ip": "remote_ip", "dest_port": "dest_port", "country": "country_iso"}.get(dim)
            if key is None:
                return self.send_json({"detail": "dim no válida"}, 422)
            items = []
            for k, n in self.count(ev, key)[:int(q.get("limit", ["10"])[0])]:
                first = next(e for e in ev if e[key] == k)
                item = {"key": k, "label": first["country"] if key == "country_iso" else str(k), "count": n}
                if dim == "remote_ip":
                    item.update(country_iso=first["country_iso"], as_org=first["as_org"])
                items.append(item)
            return self.send_json({"dim": dim, "items": items})
        if p == "/api/fw/map":
            cells, countries = {}, {}
            for e in ev:
                k = (grid(e["lat"]), grid(e["lon"]))
                c = cells.setdefault(k, {"lat": k[0], "lon": k[1], "count": 0, "country_iso": e["country_iso"],
                                         "country": e["country"], "city": e["city"]})
                c["count"] += 1
                countries.setdefault(e["country_iso"], {"country_iso": e["country_iso"], "country": e["country"],
                                                        "count": 0})["count"] += 1
            return self.send_json({"points": sorted(cells.values(), key=lambda c: -c["count"]),
                                   "countries": sorted(countries.values(), key=lambda c: -c["count"])})
        return self.send_json({"detail": "Not Found"}, 404)

    def events_csv(self, ev, q):
        """Mismo formato que el portal (';', BOM, fórmulas neutralizadas); sin streaming."""
        buf = io.StringIO()
        w = csv.writer(buf, delimiter=";", lineterminator="\r\n")
        w.writerow(CSV_HEADER)
        for e in self.table_view(ev, q)[:50_000]:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(e["ts_ms"] // 1000)) + f".{e['ts_ms'] % 1000:03d}Z"
            w.writerow([ts, *("" if e[k] is None else ("'" + str(e[k]) if str(e[k])[:1] in "=+-@\t\r" else e[k])
                              for k in CSV_KEYS)])
        body = ("\ufeff" + buf.getvalue()).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="surimapa-alertas-mock.csv"')
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def stream(self, q):
        """Cada 2-4 s, 1-3 eventos nuevos (con lat/lon para los misiles)."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        rng = random.Random()
        try:
            self.wfile.write(b"retry: 5000\n\n")
            while True:
                time.sleep(rng.uniform(2, 4))
                batch = []
                for _ in range(rng.randint(1, 3)):
                    e = dict(rng.choice(self.events[-500:]))
                    e.update(id=self.events[-1]["id"] + 1, ts_ms=int(time.time() * 1000),
                             severity=rng.choice([1, 2, 2, 3]))
                    self.events.append(e)
                    batch.append({**{k: e[k] for k in LIST_KEYS}, "lat": e["lat"], "lon": e["lon"]})
                sev, dirn = q.get("severity", [None])[0], q.get("direction", [None])[0]
                batch = [b for b in batch if (sev is None or str(b["severity"]) == sev)
                         and (dirn is None or b["direction"] == dirn)]
                if batch:
                    self.wfile.write(f"event: events\ndata: {json.dumps(batch, ensure_ascii=False)}\n\n".encode())
                    self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            return


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--events", type=int, default=2000)
    args = ap.parse_args()
    Api.events = build(args.events)
    Api.fw_events = build_fw(args.events * 20)
    server = ThreadingHTTPServer((args.host, args.port), partial(Api, directory=str(STATIC)))
    print(f"Surimapa (simulado) en http://{args.host}:{args.port}  ·  {args.events} eventos  ·  Ctrl+C para salir")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
