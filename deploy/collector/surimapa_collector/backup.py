"""Copia de seguridad diaria de la BD (tras la retención de las 03:30).

API de backup de SQLite (copia consistente aunque haya WAL) → fichero .tmp →
PRAGMA quick_check → renombrado atómico a surimapa-AAAA-MM-DD.db. Se conservan
las `keep` copias más recientes.
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import time
from datetime import date
from pathlib import Path

log = logging.getLogger("surimapa.backup")

NAME = re.compile(r"^surimapa-\d{4}-\d{2}-\d{2}\.db$")


def run(conn: sqlite3.Connection, directory: str, today: date, keep: int) -> Path:
    """Crea la copia del día y rota las antiguas. Devuelve la ruta de la copia."""
    folder = Path(directory)
    final = folder / f"surimapa-{today.isoformat()}.db"
    tmp = final.with_suffix(".db.tmp")
    tmp.unlink(missing_ok=True)
    t0 = time.monotonic()
    dst = sqlite3.connect(tmp)
    try:
        conn.backup(dst)
        result = dst.execute("PRAGMA quick_check").fetchone()[0]
        if result != "ok":
            raise sqlite3.DatabaseError(f"quick_check de la copia: {result}")
    except BaseException:
        dst.close()
        tmp.unlink(missing_ok=True)
        raise
    dst.close()
    os.replace(tmp, final)                                    # atómico: nunca queda una copia a medias
    size_mb = final.stat().st_size / 1e6
    removed = rotate(folder, keep)
    log.info("Copia %s (%.0f MB) en %.1f s; %d antiguas borradas", final.name, size_mb,
             time.monotonic() - t0, removed)
    return final


def rotate(folder: Path, keep: int) -> int:
    """Deja las `keep` copias más recientes y borra .tmp huérfanos."""
    removed = 0
    for stale in folder.glob("surimapa-*.db.tmp"):
        stale.unlink(missing_ok=True)
    copies = sorted(p for p in folder.iterdir() if NAME.match(p.name))    # el nombre ordena por fecha
    for old in copies[:-keep]:                                # keep ≥ 1 (lo valida config)
        old.unlink(missing_ok=True)
        removed += 1
    return removed
