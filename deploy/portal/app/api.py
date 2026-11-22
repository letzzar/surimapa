"""Endpoints /api/* (referencia: docs/en/API.md, docs/es/API.md)."""
from __future__ import annotations

import asyncio
import csv
import io
import ipaddress
import json
import logging
import os
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from typing import Annotated, Literal
from urllib.parse import urlsplit

import redis
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from . import __version__, db, queries
from .cache import TTLCache
from .queries import Filters

log = logging.getLogger("surimapa.portal")
router = APIRouter(prefix="/api")

H, D = 3_600_000, 86_400_000
RANGES = {"1h": H, "24h": D, "7d": 7 * D, "30d": 30 * D, "90d": 90 * D}
MAX_SPAN_MS = 90 * D
HEARTBEAT_STALE_S = 120
STREAM_EVERY_S = 2
STREAM_BATCH = 50
STREAM_PING_S = 15

# Periodos largos: se sirven desde caché (precalculada cada CACHE_TTL_S, ver warm_long_ranges).
LONG_RANGES = ("30d", "90d")
CACHE_TTL_S = 300
PANEL_TOP_DIMS = ("signature", "remote_ip", "country", "asn", "dest_port")   # los que pide el panel
PANEL_TOP_LIMIT = 10
PANEL_PAGE_SIZE = 25
PANEL_FW_TOP_DIMS = ("remote_ip", "dest_port")                  # tarjeta «Bloqueos del firewall»
cache = TTLCache()


def sibling_url(raw: str) -> str | None:
    """URL del portal hermano (Bledeagle) para la barra superior: solo https:// con host; si no, sin enlace."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
        parts.port                                    # ValueError si el puerto no es válido
        ok = parts.scheme == "https" and bool(parts.hostname) and parts.username is None
    except ValueError:
        ok = False
    if not ok:
        log.warning("BLEDEAGLE_URL no es una URL https:// válida: se omite el enlace")
        return None
    return raw


BLEDEAGLE_URL = sibling_url(os.environ.get("BLEDEAGLE_URL", ""))

Range = Literal["1h", "24h", "7d", "30d", "90d"]
Direction = Literal["in", "out", "local"]
TopDim = Literal["remote_ip", "signature", "country", "asn", "dest_port", "category"]
FwTopDim = Literal["remote_ip", "dest_port", "country"]
Severity = Annotated[int | None, Query(ge=1, le=3)]
Iface = Annotated[str | None, Query(min_length=1, max_length=32, pattern=r"^[A-Za-z0-9_.:-]+$")]


def bucket_for(span_ms: int) -> int:
    """Tamaño de bucket automático: 1h→1 min, 24h→15 min, 7d→1 h, más→6 h."""
    if span_ms <= H:
        return 60_000
    if span_ms <= D:
        return 15 * 60_000
    if span_ms <= 7 * D:
        return H
    return 6 * H


def _ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def filters(
    range_: Annotated[Range, Query(alias="range")] = "24h",
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: Annotated[datetime | None, Query()] = None,
    severity: Severity = None,
    direction: Direction | None = None,
    iface: Iface = None,
) -> Filters:
    if from_ is not None or to is not None:
        if from_ is None or to is None:
            raise HTTPException(422, "Hay que indicar 'from' y 'to' a la vez")
        from_ms, to_ms = _ms(from_), _ms(to)
        if not 0 < to_ms - from_ms <= MAX_SPAN_MS:
            raise HTTPException(422, "El intervalo debe ser positivo y de 90 días como máximo")
    else:
        to_ms = int(time.time() * 1000) + 1
        from_ms = to_ms - RANGES[range_]
        return Filters(from_ms, to_ms, severity, direction, iface, range_name=range_)
    return Filters(from_ms, to_ms, severity, direction, iface)


Flt = Annotated[Filters, Depends(filters)]


def fw_filters(
    range_: Annotated[Range, Query(alias="range")] = "24h",
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: Annotated[datetime | None, Query()] = None,
) -> Filters:
    """Bloqueos del firewall: solo periodo (no tienen severidad, sentido ni interfaz que filtrar)."""
    return filters(range_, from_, to)


FwFlt = Annotated[Filters, Depends(fw_filters)]


def _with_db(fn, *args):
    try:
        with db.connect() as conn:
            return fn(conn, *args)
    except db.DatabaseUnavailable:
        raise HTTPException(503, "Base de datos no disponible todavía") from None


def _key(name: str, f: Filters, *extra) -> tuple:
    return (name, f.range_name, f.severity, f.direction, f.iface, *extra)


def _cached(name: str, f: Filters, extra: tuple, fn, *args):
    """Periodos largos: desde caché (o se calcula y se guarda). El resto, siempre en vivo."""
    if f.range_name not in LONG_RANGES:
        return _with_db(fn, f, *args)
    key = _key(name, f, *extra)
    value = cache.get(key)
    if value is None:
        value = _with_db(fn, f, *args)
        cache.set(key, value, CACHE_TTL_S)
    return value


def warm_long_ranges() -> int:
    """Precalcula lo que pide el panel para 30d/90d sin filtros. Devuelve cuántas entradas."""
    count = 0
    with db.connect() as conn:
        for name in LONG_RANGES:
            to_ms = int(time.time() * 1000) + 1
            f = Filters(to_ms - RANGES[name], to_ms, range_name=name)
            bucket = bucket_for(f.to_ms - f.from_ms)
            jobs = [("summary", (), queries.summary, ()), ("timeline", (bucket,), queries.timeline, (bucket,)),
                    ("map", (), queries.map_data, ()),
                    ("events", (1, PANEL_PAGE_SIZE), queries.events, (1, PANEL_PAGE_SIZE, None))]
            jobs += [("top", (dim, PANEL_TOP_LIMIT), queries.top, (dim, PANEL_TOP_LIMIT)) for dim in PANEL_TOP_DIMS]
            jobs += [("fw_summary", (), queries.fw_summary, ()), ("fw_map", (), queries.map_data, (True,))]
            jobs += [("fw_top", (dim, PANEL_TOP_LIMIT), queries.fw_top, (dim, PANEL_TOP_LIMIT))
                     for dim in PANEL_FW_TOP_DIMS]
            for key_name, extra, fn, args in jobs:
                # TTL algo mayor que el periodo de refresco: la vista por defecto nunca queda fría.
                cache.set(_key(key_name, f, *extra), fn(conn, f, *args), CACHE_TTL_S + 60)
                count += 1
    return count


async def warm_loop() -> None:
    while True:
        t0 = time.monotonic()
        try:
            n = await run_in_threadpool(warm_long_ranges)
            log.info("Caché 30d/90d precalculada: %d respuestas en %.1f s", n, time.monotonic() - t0)
        except db.DatabaseUnavailable:
            log.info("Caché 30d/90d: la BD aún no existe; reintento en %d s", CACHE_TTL_S)
        except Exception:                                   # no tumbar el portal por un fallo puntual
            log.exception("Error precalculando la caché 30d/90d")
        await asyncio.sleep(CACHE_TTL_S)


# ---------- Endpoints ----------
@router.get("/config")
def config() -> dict:
    return {"bledeagle_url": BLEDEAGLE_URL, "version": __version__}


@router.get("/health")
def health() -> dict:
    out = {"status": "ok", "last_event_ms": None, "collector_heartbeat_age_s": None,
           "redis_queue_len": None, "db_size_bytes": db.db_size_bytes()}
    try:
        with db.connect() as conn:
            out["last_event_ms"] = queries.last_event_ms(conn)
    except db.DatabaseUnavailable:
        out["status"] = "degraded"
    try:
        r = db.redis_client()
        beat = r.get("surimapa:collector:heartbeat")
        out["redis_queue_len"] = r.llen(db.redis_key())
        if beat is not None:
            out["collector_heartbeat_age_s"] = max(0, int(time.time()) - int(beat))
    except (redis.RedisError, ValueError):
        pass
    age = out["collector_heartbeat_age_s"]
    if age is None or age > HEARTBEAT_STALE_S:
        out["status"] = "degraded"
    return out


@router.get("/summary")
def summary(f: Flt) -> dict:
    return _cached("summary", f, (), queries.summary)


@router.get("/timeline")
def timeline(f: Flt, bucket: Literal["auto"] = "auto") -> dict:
    size = bucket_for(f.to_ms - f.from_ms)
    return _cached("timeline", f, (size,), queries.timeline, size)


@router.get("/top/{dim}")
def top(dim: Annotated[TopDim, Path()], f: Flt, limit: Annotated[int, Query(ge=1, le=50)] = 10) -> dict:
    return _cached("top", f, (dim, limit), queries.top, dim, limit)


@router.get("/map")
def map_(f: Flt) -> dict:
    return _cached("map", f, (), queries.map_data)


# ---------- Bloqueos del firewall (tabla firewall_events) ----------
@router.get("/fw/summary")
def fw_summary(f: FwFlt) -> dict:
    return _cached("fw_summary", f, (), queries.fw_summary)


@router.get("/fw/map")
def fw_map(f: FwFlt) -> dict:
    return _cached("fw_map", f, (), queries.map_data, True)


@router.get("/fw/top/{dim}")
def fw_top(dim: Annotated[FwTopDim, Path()], f: FwFlt, limit: Annotated[int, Query(ge=1, le=50)] = 10) -> dict:
    return _cached("fw_top", f, (dim, limit), queries.fw_top, dim, limit)


Q = Annotated[str | None, Query(max_length=200)]
Country = Annotated[str | None, Query(pattern=r"^[A-Z]{2}$")]
Lat = Annotated[float | None, Query(ge=-90, le=90)]
Lon = Annotated[float | None, Query(ge=-180, le=180)]


def _origin_args(q: str | None, country: str | None, lat: float | None, lon: float | None):
    """Normaliza búsqueda y origen (clic en el mapa): `country` o `lat`+`lon` (celda de 0,1°)."""
    q = (q.strip() if q else None) or None
    if (lat is None) != (lon is None):
        raise HTTPException(422, "Hay que indicar 'lat' y 'lon' a la vez")
    if country is not None and lat is not None:
        raise HTTPException(422, "Origen: 'country' o 'lat'/'lon', no ambos")
    cell = (queries.grid(lat), queries.grid(lon)) if lat is not None else None
    return q, cell


@router.get("/events")
def events(
    f: Flt,
    page: Annotated[int, Query(ge=1, le=100_000)] = 1,
    size: Annotated[int, Query(ge=1, le=100)] = 25,
    q: Q = None,
    country: Country = None,
    lat: Lat = None,
    lon: Lon = None,
) -> dict:
    """Lista paginada. Origen opcional (clic en el mapa): `country` o `lat`+`lon` (celda de 0,1°)."""
    q, cell = _origin_args(q, country, lat, lon)
    if q is None and country is None and cell is None:      # búsquedas y orígenes siempre en vivo
        return _cached("events", f, (page, size), queries.events, page, size, None)
    return _with_db(queries.events, f, page, size, q, country, cell)


# ---------- Exportación CSV de la vista de la tabla ----------
CSV_MAX_ROWS = 50_000
CSV_CHUNK = 1_000
CSV_HEADER = (
    "fecha_utc", "severidad", "interfaz", "direccion", "ip_remota", "pais_iso", "pais", "ciudad", "asn",
    "organizacion", "ip_origen", "puerto_origen", "ip_destino", "puerto_destino", "protocolo", "sid",
    "firma", "categoria",
)
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value) -> str:
    """Celda segura: los datos vienen de Suricata (no confiables). Un valor que empiece como
    fórmula se prefija con ' para que Excel/LibreOffice no lo ejecuten (inyección CSV)."""
    if value is None:
        return ""
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def _iso_utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _csv_chunks(stack: ExitStack, cur):
    """Genera el CSV por bloques (memoria acotada) y cierra la conexión al terminar o si se corta."""
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";", lineterminator="\r\n")    # ';' + BOM: Excel en español
    try:
        buf.write("\ufeff")
        writer.writerow(CSV_HEADER)
        while rows := cur.fetchmany(CSV_CHUNK):
            for row in rows:
                writer.writerow([_iso_utc(row[0]), *(csv_cell(v) for v in row[1:])])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate()
        if buf.tell():                                   # sin filas: solo cabecera
            yield buf.getvalue()
    finally:
        stack.close()


@router.get("/events.csv")
def events_csv(f: Flt, q: Q = None, country: Country = None, lat: Lat = None, lon: Lon = None):
    """La vista actual de la tabla (filtros + búsqueda + origen) en CSV, hasta CSV_MAX_ROWS filas."""
    q, cell = _origin_args(q, country, lat, lon)
    stack = ExitStack()
    try:
        conn = stack.enter_context(db.connect())
        cur = queries.events_export(conn, f, q, country, cell, CSV_MAX_ROWS)
    except db.DatabaseUnavailable:
        stack.close()
        raise HTTPException(503, "Base de datos no disponible todavía") from None
    except BaseException:
        stack.close()
        raise
    name = f"surimapa-alertas-{datetime.now(timezone.utc):%Y%m%d-%H%M}.csv"
    return StreamingResponse(_csv_chunks(stack, cur), media_type="text/csv; charset=utf-8",
                             headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/events/{event_id}")
def event(event_id: Annotated[int, Path(ge=1, le=2**63 - 1)]) -> dict:
    row = _with_db(queries.event, event_id)
    if row is None:
        raise HTTPException(404, "Evento no encontrado")
    return row


@router.get("/ip/{ip}")
def ip_detail(ip: Annotated[str, Path(max_length=45)]) -> dict:
    try:
        ip = ipaddress.ip_address(ip).compressed
    except ValueError:
        raise HTTPException(422, "IP no válida") from None
    row = _with_db(queries.ip_detail, ip)
    if row is None:
        raise HTTPException(404, "Sin eventos para esta IP")
    return row


@router.get("/stream")
async def stream(request: Request, severity: Severity = None, direction: Direction | None = None,
                 iface: Iface = None) -> StreamingResponse:
    def read(fn, *args):
        try:
            with db.connect() as conn:
                return fn(conn, *args)
        except db.DatabaseUnavailable:
            return None

    async def gen():
        last = await run_in_threadpool(read, queries.max_id) or 0
        idle = 0.0
        yield "retry: 5000\n\n"
        while not await request.is_disconnected():
            await asyncio.sleep(STREAM_EVERY_S)
            upto = await run_in_threadpool(read, queries.max_id)
            rows = []
            if upto and upto > last:
                rows = await run_in_threadpool(read, queries.events_after, last, upto, severity,
                                               direction, iface, STREAM_BATCH) or []
                # Si hay más de STREAM_BATCH, el resto se envía en las siguientes vueltas.
                last = rows[-1]["id"] if len(rows) == STREAM_BATCH else upto
            if rows:
                idle = 0.0
                yield f"event: events\ndata: {json.dumps(rows, ensure_ascii=False)}\n\n"
            else:
                idle += STREAM_EVERY_S
                if idle >= STREAM_PING_S:
                    idle = 0.0
                    yield ": ping\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
