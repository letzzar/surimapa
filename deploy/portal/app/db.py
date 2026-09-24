"""Acceso de SOLO LECTURA a la BD SQLite del colector y a Redis.

El volumen se monta en lectura-escritura porque WAL necesita el fichero -shm,
pero la conexión se abre con mode=ro y PRAGMA query_only=ON: ninguna escritura
es posible desde el portal.
"""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

import redis

DB_PATH = os.environ.get("DB_PATH", "/data/surimapa.db")


class DatabaseUnavailable(RuntimeError):
    """La BD aún no existe (el colector no ha arrancado) o no se puede abrir."""


@contextmanager
def connect(path: str | None = None):
    path = path or DB_PATH
    if not Path(path).exists():
        raise DatabaseUnavailable(path)
    try:
        uri = Path(path).resolve().as_uri() + "?mode=ro"      # as_uri() escapa espacios, '?', '#'…
        conn = sqlite3.connect(uri, uri=True, timeout=5, check_same_thread=False)
    except sqlite3.OperationalError as exc:
        raise DatabaseUnavailable(path) from exc
    try:
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.row_factory = sqlite3.Row
        yield conn
    finally:
        conn.close()


def db_size_bytes(path: str | None = None) -> int | None:
    path = path or DB_PATH
    total, found = 0, False
    for suffix in ("", "-wal", "-shm"):
        try:
            total += os.stat(path + suffix).st_size
            found = True
        except FileNotFoundError:
            pass
    return total if found else None


@lru_cache(maxsize=1)
def redis_client() -> redis.Redis:
    return redis.Redis.from_url(
        os.environ.get("REDIS_URL", "redis://redis:6379/0"),
        username=os.environ.get("REDIS_USER") or None,
        password=os.environ.get("REDIS_PASSWORD") or None,
        socket_timeout=2,
        socket_connect_timeout=2,
    )


def redis_key() -> str:
    return os.environ.get("REDIS_KEY", "suricata")
