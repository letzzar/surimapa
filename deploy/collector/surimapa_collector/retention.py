"""Retención: borrado por antigüedad y mantenimiento de SQLite.

Una vez al día (03:30 hora local): DELETE de las filas con más de RETENTION_DAYS,
en bloques para no retener el bloqueo de escritura, y después incremental_vacuum,
optimize y checkpoint TRUNCATE del WAL.
"""
from __future__ import annotations

import logging
import sqlite3
import time
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

log = logging.getLogger("surimapa.retention")

RUN_AT = (3, 30)            # hora local
CHUNK = 5000
DAY_MS = 86_400_000


def next_run(now: datetime, tz: ZoneInfo) -> datetime:
    """Próxima ejecución (03:30 en `tz`) estrictamente posterior a `now`."""
    local = now.astimezone(tz)
    target = local.replace(hour=RUN_AT[0], minute=RUN_AT[1], second=0, microsecond=0)
    if target <= local:
        target = (local + timedelta(days=1)).replace(hour=RUN_AT[0], minute=RUN_AT[1], second=0, microsecond=0)
    return target


_DELETE = {                 # tablas con retención (constantes: nada de la configuración va al SQL)
    table: f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE ts_ms < ? LIMIT ?)"
    for table in ("events", "firewall_events")
}


def _delete_older(conn: sqlite3.Connection, table: str, cutoff: int) -> int:
    deleted = 0
    while True:
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(_DELETE[table], (cutoff, CHUNK))
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        deleted += cur.rowcount
        if cur.rowcount < CHUNK:
            return deleted


def run(conn: sqlite3.Connection, days: int, now_ms: int | None = None, fw_days: int | None = None) -> int:
    """Borra lo anterior a `days` días (y los bloqueos del firewall anteriores a `fw_days`)
    y hace mantenimiento. Devuelve filas borradas en total."""
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    t0 = time.monotonic()
    deleted = _delete_older(conn, "events", now_ms - days * DAY_MS)
    fw_deleted = _delete_older(conn, "firewall_events", now_ms - fw_days * DAY_MS) if fw_days else 0
    conn.execute("PRAGMA incremental_vacuum").fetchall()      # puede requerir varios pasos
    conn.execute("PRAGMA optimize")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    log.info("Retención (%d días): %d filas borradas; firewall (%s días): %d; en %.1f s",
             days, deleted, fw_days or "-", fw_deleted, time.monotonic() - t0)
    return deleted + fw_deleted
