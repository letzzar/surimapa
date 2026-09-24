"""SQLite: apertura, migraciones del esquema e inserción por lotes.

El colector es el ÚNICO escritor de la base de datos.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS events (
    id            INTEGER PRIMARY KEY,
    ts_ms         INTEGER NOT NULL,
    iface         TEXT,
    direction     TEXT NOT NULL CHECK (direction IN ('in','out','local')),
    src_ip        TEXT NOT NULL,
    src_port      INTEGER,
    dest_ip       TEXT NOT NULL,
    dest_port     INTEGER,
    proto         TEXT,
    app_proto     TEXT,
    remote_ip     TEXT,
    sid           INTEGER,
    signature     TEXT,
    category      TEXT,
    severity      INTEGER,
    action        TEXT,
    flow_id       INTEGER,
    country_iso   TEXT,
    country       TEXT,
    city          TEXT,
    lat           REAL,
    lon           REAL,
    asn           INTEGER,
    as_org        TEXT,
    raw           TEXT,
    raw_truncated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_events_ts        ON events(ts_ms);
CREATE INDEX IF NOT EXISTS ix_events_remote_ts ON events(remote_ip, ts_ms);
CREATE INDEX IF NOT EXISTS ix_events_sid_ts    ON events(sid, ts_ms);
CREATE INDEX IF NOT EXISTS ix_events_country   ON events(country_iso, ts_ms);
"""

# v2 (Fase 3, rendimiento de la API): índice cubriente para agregar por periodo sin leer
# la tabla (cuyas filas incluyen `raw`, ~900 B), e índice por ASN para resolver etiquetas.
# ix_events_ts queda cubierto por el nuevo (misma primera columna).
SCHEMA_V2 = """
CREATE INDEX IF NOT EXISTS ix_events_ts_cover ON events(
    ts_ms, severity, direction, iface, remote_ip, country_iso, sid, asn, dest_port, lat, lon, city);
CREATE INDEX IF NOT EXISTS ix_events_asn ON events(asn);
CREATE INDEX IF NOT EXISTS ix_events_remote_cover ON events(remote_ip, ts_ms, sid, dest_port);
DROP INDEX IF EXISTS ix_events_ts;
DROP INDEX IF EXISTS ix_events_remote_ts;
"""

# v3: bloqueos del firewall de pfSense (filterlog por syslog), tabla aparte y sin `raw`.
# Solo WAN entrantes con origen público: remote_ip es siempre el origen.
SCHEMA_V3 = """
CREATE TABLE IF NOT EXISTS firewall_events (
    id          INTEGER PRIMARY KEY,
    ts_ms       INTEGER NOT NULL,
    remote_ip   TEXT NOT NULL,
    proto       TEXT,
    dest_port   INTEGER,
    country_iso TEXT,
    country     TEXT,
    city        TEXT,
    lat         REAL,
    lon         REAL,
    asn         INTEGER,
    as_org      TEXT
);
CREATE INDEX IF NOT EXISTS ix_fw_ts_cover ON firewall_events(ts_ms, remote_ip, country_iso, dest_port, lat, lon, city);
CREATE INDEX IF NOT EXISTS ix_fw_remote ON firewall_events(remote_ip, ts_ms);
CREATE INDEX IF NOT EXISTS ix_fw_country ON firewall_events(country_iso, ts_ms)
"""

# Migraciones en orden: índice = versión resultante - 1.
MIGRATIONS = [SCHEMA_V1, SCHEMA_V2, SCHEMA_V3]

COLUMNS = (
    "ts_ms", "iface", "direction", "src_ip", "src_port", "dest_ip", "dest_port",
    "proto", "app_proto", "remote_ip", "sid", "signature", "category", "severity",
    "action", "flow_id", "country_iso", "country", "city", "lat", "lon", "asn",
    "as_org", "raw", "raw_truncated",
)
_INSERT = (
    f"INSERT INTO events ({', '.join(COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in COLUMNS)})"
)


FW_COLUMNS = (
    "ts_ms", "remote_ip", "proto", "dest_port", "country_iso", "country", "city", "lat", "lon", "asn", "as_org",
)
_INSERT_FW = (
    f"INSERT INTO firewall_events ({', '.join(FW_COLUMNS)}) "
    f"VALUES ({', '.join('?' for _ in FW_COLUMNS)})"
)


def connect(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=5, isolation_level=None)  # transacciones explícitas
    # auto_vacuum solo tiene efecto antes de crear la primera tabla.
    conn.execute("PRAGMA auto_vacuum=INCREMENTAL")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def schema_version(conn: sqlite3.Connection) -> int:
    conn.execute("CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = conn.execute("SELECT value FROM meta WHERE key = 'schema_version'").fetchone()
    return int(row[0]) if row else 0


def migrate(conn: sqlite3.Connection) -> int:
    """Aplica las migraciones pendientes. Devuelve la versión final."""
    current = schema_version(conn)
    if current > len(MIGRATIONS):
        raise RuntimeError(f"La BD tiene schema_version={current}, más nueva que este colector")
    for version in range(current + 1, len(MIGRATIONS) + 1):
        conn.execute("BEGIN IMMEDIATE")
        try:
            for statement in MIGRATIONS[version - 1].split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.execute(
                "INSERT INTO meta (key, value) VALUES ('schema_version', ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (str(version),),
            )
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return len(MIGRATIONS)


def insert_batch(conn: sqlite3.Connection, rows: list[dict], firewall: bool = False) -> int:
    """Inserta todas las filas en una sola transacción (en `events` o, con firewall=True,
    en `firewall_events`). Devuelve cuántas."""
    if not rows:
        return 0
    columns, sql = (FW_COLUMNS, _INSERT_FW) if firewall else (COLUMNS, _INSERT)
    params = [tuple(row.get(col) for col in columns) for row in rows]
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.executemany(sql, params)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return len(params)
