"""SQL del portal. Todas las consultas son parametrizadas.

Los únicos fragmentos de SQL que se componen son constantes de este módulo
(listas blancas); ningún valor recibido de la API se concatena en el SQL.
"""
from __future__ import annotations

import ipaddress
import math
import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class Filters:
    from_ms: int
    to_ms: int                      # exclusivo
    severity: int | None = None
    direction: str | None = None
    iface: str | None = None
    range_name: str | None = None    # "24h", "90d"… (None si es un intervalo from/to)

    def where(self, prefix: str = "") -> tuple[str, list]:
        clauses = [f"{prefix}ts_ms >= ?", f"{prefix}ts_ms < ?"]
        params: list = [self.from_ms, self.to_ms]
        if self.severity is not None:
            clauses.append(f"{prefix}severity = ?")
            params.append(self.severity)
        if self.direction is not None:
            clauses.append(f"{prefix}direction = ?")
            params.append(self.direction)
        if self.iface is not None:
            clauses.append(f"{prefix}iface = ?")
            params.append(self.iface)
        return " AND ".join(clauses), params

    def shifted(self, delta_ms: int) -> "Filters":
        return Filters(self.from_ms - delta_ms, self.to_ms - delta_ms, self.severity, self.direction, self.iface)


# Columnas de un evento en listados (sin raw).
LIST_COLUMNS = (
    "id", "ts_ms", "severity", "direction", "src_ip", "src_port", "dest_ip", "dest_port",
    "proto", "remote_ip", "sid", "signature", "category", "country_iso", "country", "city",
    "asn", "as_org", "iface",
)
DETAIL_COLUMNS = LIST_COLUMNS + ("app_proto", "action", "flow_id", "raw", "raw_truncated")
STREAM_COLUMNS = LIST_COLUMNS + ("lat", "lon")
# Exportación CSV (misma vista que la tabla; ts_ms primero, se formatea en la API).
CSV_COLUMNS = (
    "ts_ms", "severity", "iface", "direction", "remote_ip", "country_iso", "country", "city", "asn",
    "as_org", "src_ip", "src_port", "dest_ip", "dest_port", "proto", "sid", "signature", "category",
)

# dim → columna clave. Lista blanca: la API valida `dim` contra estas claves.
# Se agrega SOLO por la clave (resoluble en índices cubrientes) y después se buscan
# las etiquetas de los N ganadores con consultas indexadas (medido: ×10–40 más rápido).
TOP_DIMS = {
    "remote_ip": "remote_ip",
    "signature": "sid",
    "country": "country_iso",
    "asn": "asn",
    "dest_port": "dest_port",
    "category": "category",
}
# columna clave → SQL indexado que devuelve su etiqueta más reciente
_LABELS = {
    "sid": "SELECT signature FROM events WHERE sid = ? ORDER BY ts_ms DESC LIMIT 1",
    "country_iso": "SELECT country FROM events WHERE country_iso = ? ORDER BY ts_ms DESC LIMIT 1",
    "asn": "SELECT as_org FROM events WHERE asn = ? LIMIT 1",
}
_IP_INFO = "SELECT country_iso, as_org FROM events WHERE remote_ip = ? ORDER BY ts_ms DESC LIMIT 1"
_SID_INFO = "SELECT signature, severity FROM events WHERE sid = ? ORDER BY ts_ms DESC LIMIT 1"

# Bloqueos del firewall (tabla firewall_events): solo periodo, sin severidad/sentido/interfaz.
FW_TOP_DIMS = {"remote_ip": "remote_ip", "dest_port": "dest_port", "country": "country_iso"}
_FW_LABELS = {
    "country_iso": "SELECT country FROM firewall_events WHERE country_iso = ? ORDER BY ts_ms DESC LIMIT 1",
}
_FW_IP_INFO = "SELECT country_iso, as_org FROM firewall_events WHERE remote_ip = ? ORDER BY ts_ms DESC LIMIT 1"

MAP_MAX_POINTS = 2000
MAP_STEP = 0.1                      # rejilla de los puntos del mapa (grados)


def grid(value: float) -> float:
    """Celda de la rejilla del mapa (redondeo a 0,1° «mitad hacia arriba»).

    El mapa agrupa con esta función y el filtro por origen usa el intervalo
    [celda - 0,05, celda + 0,05): así la lista coincide con lo que cuenta el círculo.
    """
    return round(math.floor(value / MAP_STEP + 0.5) * MAP_STEP, 1)


def _rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


# ---------- Resumen ----------
def summary(conn: sqlite3.Connection, f: Filters) -> dict:
    def one(flt: Filters) -> dict:
        where, params = flt.where()
        row = conn.execute(
            f"SELECT COUNT(*) AS total, COUNT(DISTINCT remote_ip) AS unique_ips, "
            f"COUNT(DISTINCT country_iso) AS unique_countries, "
            f"SUM(severity = 1) AS s1, SUM(severity = 2) AS s2, SUM(severity = 3) AS s3 "
            f"FROM events WHERE {where}", params).fetchone()
        return {
            "total": row["total"],
            "unique_ips": row["unique_ips"],
            "unique_countries": row["unique_countries"],
            "by_severity": {"1": row["s1"] or 0, "2": row["s2"] or 0, "3": row["s3"] or 0},
        }

    current = one(f)
    current["previous"] = one(f.shifted(f.to_ms - f.from_ms))
    current["range"] = {"from_ms": f.from_ms, "to_ms": f.to_ms}
    return current


# ---------- Línea temporal ----------
def timeline(conn: sqlite3.Connection, f: Filters, bucket_ms: int) -> dict:
    where, params = f.where()
    cur = conn.execute(
        f"SELECT (ts_ms / ?) * ? AS b, SUM(severity = 1) AS sev1, SUM(severity = 2) AS sev2, "
        f"SUM(severity = 3) AS sev3 FROM events WHERE {where} GROUP BY b",
        [bucket_ms, bucket_ms, *params])
    found = {r["b"]: r for r in cur.fetchall()}
    points = []
    start = (f.from_ms // bucket_ms) * bucket_ms
    for b in range(start, f.to_ms, bucket_ms):          # rellenar huecos con ceros
        r = found.get(b)
        points.append({"ts_ms": b, "sev1": r["sev1"] if r else 0,
                       "sev2": r["sev2"] if r else 0, "sev3": r["sev3"] if r else 0})
    return {"bucket_ms": bucket_ms, "points": points}


# ---------- Rankings ----------
def label_for(conn: sqlite3.Connection, column: str, key, labels: dict = _LABELS):
    sql = labels.get(column)
    if sql is None:
        return str(key)
    row = conn.execute(sql, [key]).fetchone()
    return row[0] if row else None


def top(conn: sqlite3.Connection, f: Filters, dim: str, limit: int) -> dict:
    column = TOP_DIMS[dim]                            # KeyError imposible: la API valida dim
    where, params = f.where()
    cur = conn.execute(
        f"SELECT {column} AS key, COUNT(*) AS count FROM events "
        f"WHERE {where} AND {column} IS NOT NULL GROUP BY {column} ORDER BY count DESC, key LIMIT ?",
        [*params, limit])
    items = []
    for key, count in cur.fetchall():
        if dim == "remote_ip":                        # + país y organización del AS (misma consulta)
            iso, org = conn.execute(_IP_INFO, [key]).fetchone()
            item = {"key": key, "label": key, "count": count, "country_iso": iso, "as_org": org}
        elif dim == "signature":                      # + severidad (misma consulta que la etiqueta)
            sig, sev = conn.execute(_SID_INFO, [key]).fetchone()
            item = {"key": key, "label": sig, "count": count, "severity": sev}
        else:
            item = {"key": key, "label": label_for(conn, column, key), "count": count}
        items.append(item)
    return {"dim": dim, "items": items}


# ---------- Mapa ----------
def map_data(conn: sqlite3.Connection, f: Filters, firewall: bool = False) -> dict:
    """Países y círculos del mapa: alertas de Suricata o, con firewall=True, bloqueos del firewall."""
    table, labels = ("firewall_events", _FW_LABELS) if firewall else ("events", _LABELS)
    where, params = f.where()
    countries = [
        {"country_iso": iso, "country": label_for(conn, "country_iso", iso, labels), "count": n}
        for iso, n in conn.execute(
            f"SELECT country_iso, COUNT(*) AS n FROM {table} WHERE {where} AND country_iso IS NOT NULL "
            f"GROUP BY country_iso ORDER BY n DESC", params)
    ]
    names = {c["country_iso"]: c["country"] for c in countries}
    # Agrupar por coordenadas exactas (centroides de GeoLite: pocas distintas) dentro del índice
    # cubriente y redondear a 0,1° aquí; el GROUP BY ROUND() en SQL era el cuello de botella.
    merged: dict[tuple, dict] = {}
    for lat, lon, n, iso, city in conn.execute(
            f"SELECT lat, lon, COUNT(*), MAX(country_iso), MAX(city) FROM {table} "
            f"WHERE {where} AND lat IS NOT NULL AND lon IS NOT NULL GROUP BY lat, lon", params):
        k = (grid(lat), grid(lon))
        p = merged.get(k)
        if p is None:
            merged[k] = {"lat": k[0], "lon": k[1], "count": n, "country_iso": iso, "city": city, "_best": n}
        else:
            p["count"] += n
            if n > p["_best"]:                        # etiqueta del grupo más numeroso
                p.update(country_iso=iso, city=city, _best=n)
    points = sorted(merged.values(), key=lambda p: p["count"], reverse=True)[:MAP_MAX_POINTS]
    for p in points:
        del p["_best"]
        p["country"] = names.get(p["country_iso"])
    return {"points": points, "countries": countries}


# ---------- Bloqueos del firewall ----------
def fw_summary(conn: sqlite3.Connection, f: Filters) -> dict:
    where, params = f.where()
    total, ips, countries = conn.execute(
        f"SELECT COUNT(*), COUNT(DISTINCT remote_ip), COUNT(DISTINCT country_iso) FROM firewall_events "
        f"WHERE {where}", params).fetchone()
    return {"total": total, "unique_ips": ips, "unique_countries": countries,
            "range": {"from_ms": f.from_ms, "to_ms": f.to_ms}}


def fw_top(conn: sqlite3.Connection, f: Filters, dim: str, limit: int) -> dict:
    column = FW_TOP_DIMS[dim]                         # KeyError imposible: la API valida dim
    where, params = f.where()
    cur = conn.execute(
        f"SELECT {column} AS key, COUNT(*) AS count FROM firewall_events "
        f"WHERE {where} AND {column} IS NOT NULL GROUP BY {column} ORDER BY count DESC, key LIMIT ?",
        [*params, limit])
    items = []
    for key, count in cur.fetchall():
        if dim == "remote_ip":
            iso, org = conn.execute(_FW_IP_INFO, [key]).fetchone()
            items.append({"key": key, "label": key, "count": count, "country_iso": iso, "as_org": org})
        else:
            items.append({"key": key, "label": label_for(conn, column, key, _FW_LABELS), "count": count})
    return {"dim": dim, "items": items}


# ---------- Eventos ----------
def _search(conn: sqlite3.Connection, q: str) -> tuple[str, list]:
    """q = IP exacta, SID (número) o texto de firma."""
    try:
        ip = ipaddress.ip_address(q)
    except ValueError:
        ip = None
    if ip is not None:
        if ip.is_global:                              # IP de Internet: siempre es la remota (indexada)
            return "remote_ip = ?", [ip.compressed]
        return "(src_ip = ? OR dest_ip = ?)", [ip.compressed, ip.compressed]
    if q.isdigit() and len(q) <= 18:
        return "sid = ?", [int(q)]
    # Texto: se resuelve contra las firmas distintas (pocas, vía índice por SID) en lugar de
    # hacer LIKE sobre todas las filas. Mismo criterio que LIKE: subcadena sin distinguir mayúsculas.
    needle = q.casefold()
    sids = [sid for (sid,) in conn.execute("SELECT DISTINCT sid FROM events WHERE sid IS NOT NULL")
            if needle in (label_for(conn, "sid", sid) or "").casefold()]
    if not sids:
        return "0", []
    return f"sid IN ({', '.join('?' for _ in sids)})", sids


def _origin(country: str | None, cell: tuple[float, float] | None) -> tuple[str, list]:
    """Origen del ataque: país (ISO alfa-2) o celda del mapa (lat, lon de `grid`)."""
    if country is not None:
        return "country_iso = ?", [country]
    lat, lon = cell
    half = MAP_STEP / 2
    return "lat >= ? AND lat < ? AND lon >= ? AND lon < ?", [lat - half, lat + half, lon - half, lon + half]


def _list_where(conn: sqlite3.Connection, f: Filters, q: str | None,
                country: str | None, cell: tuple[float, float] | None) -> tuple[str, list]:
    """WHERE de la tabla de eventos: filtros + búsqueda + origen (lo comparten lista y CSV)."""
    where, params = f.where()
    if q:
        clause, extra = _search(conn, q)
        where, params = f"{where} AND {clause}", [*params, *extra]
    if country is not None or cell is not None:
        clause, extra = _origin(country, cell)
        where, params = f"{where} AND {clause}", [*params, *extra]
    return where, params


def events(conn: sqlite3.Connection, f: Filters, page: int, size: int, q: str | None,
           country: str | None = None, cell: tuple[float, float] | None = None) -> dict:
    where, params = _list_where(conn, f, q, country, cell)
    total = conn.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()[0]
    cur = conn.execute(
        f"SELECT {', '.join(LIST_COLUMNS)} FROM events WHERE {where} ORDER BY id DESC LIMIT ? OFFSET ?",
        [*params, size, (page - 1) * size])
    return {"page": page, "size": size, "total": total, "items": _rows(cur)}


def events_export(conn: sqlite3.Connection, f: Filters, q: str | None, country: str | None,
                  cell: tuple[float, float] | None, limit: int) -> sqlite3.Cursor:
    """Cursor (tuplas en el orden de CSV_COLUMNS) con la vista de la tabla, del más reciente al más antiguo."""
    where, params = _list_where(conn, f, q, country, cell)
    return conn.execute(
        f"SELECT {', '.join(CSV_COLUMNS)} FROM events WHERE {where} ORDER BY id DESC LIMIT ?", [*params, limit])


def event(conn: sqlite3.Connection, event_id: int) -> dict | None:
    row = conn.execute(f"SELECT {', '.join(DETAIL_COLUMNS)} FROM events WHERE id = ?", [event_id]).fetchone()
    return dict(row) if row else None


# ---------- Ficha de IP (toda la retención) ----------
def ip_detail(conn: sqlite3.Connection, ip: str) -> dict | None:
    head = conn.execute(
        "SELECT COUNT(*) AS total, MIN(ts_ms) AS first_seen_ms, MAX(ts_ms) AS last_seen_ms "
        "FROM events WHERE remote_ip = ?", [ip]).fetchone()
    if not head["total"]:
        return None
    geo = conn.execute(
        "SELECT country_iso, country, city, asn, as_org FROM events "
        "WHERE remote_ip = ? ORDER BY ts_ms DESC LIMIT 1", [ip]).fetchone()
    sigs = []
    for sid, n in conn.execute(
            "SELECT sid, COUNT(*) AS n FROM events WHERE remote_ip = ? AND sid IS NOT NULL "
            "GROUP BY sid ORDER BY n DESC LIMIT 20", [ip]).fetchall():
        sig, sev = conn.execute(_SID_INFO, [sid]).fetchone()      # texto + severidad (misma consulta)
        sigs.append({"sid": sid, "signature": sig, "severity": sev, "count": n})
    ports = conn.execute(
        "SELECT dest_port, COUNT(*) AS count FROM events WHERE remote_ip = ? AND dest_port IS NOT NULL "
        "GROUP BY dest_port ORDER BY count DESC LIMIT 20", [ip])
    total_sigs = conn.execute(
        "SELECT COUNT(DISTINCT sid) FROM events WHERE remote_ip = ?", [ip]).fetchone()[0]
    return {"ip": ip, **dict(head), **dict(geo), "signatures_total": total_sigs,
            "signatures": sigs, "dest_ports": _rows(ports)}


# ---------- Tiempo real y salud ----------
def max_id(conn: sqlite3.Connection) -> int:
    return conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]


def events_after(conn: sqlite3.Connection, last_id: int, upto_id: int, severity: int | None,
                 direction: str | None, iface: str | None, limit: int) -> list[dict]:
    clauses, params = ["id > ?", "id <= ?"], [last_id, upto_id]
    for col, val in (("severity", severity), ("direction", direction), ("iface", iface)):
        if val is not None:
            clauses.append(f"{col} = ?")
            params.append(val)
    cur = conn.execute(
        f"SELECT {', '.join(STREAM_COLUMNS)} FROM events WHERE {' AND '.join(clauses)} ORDER BY id LIMIT ?",
        [*params, limit])
    return _rows(cur)


def last_event_ms(conn: sqlite3.Connection) -> int | None:
    return conn.execute("SELECT MAX(ts_ms) FROM events").fetchone()[0]
