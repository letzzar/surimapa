import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import pytest

from surimapa_collector import config, retention, store
from surimapa_collector.main import Collector
from surimapa_collector.parser import normalize

MADRID = ZoneInfo("Europe/Madrid")
DAY = retention.DAY_MS
NOW = 1_790_150_400_000                                       # 2026-09-23T08:00Z


@pytest.mark.parametrize("now_utc,expected_local", [
    ("2026-09-24T00:00:00+00:00", "2026-09-24T03:30:00+02:00"),    # 02:00 local → hoy 03:30
    ("2026-09-24T01:30:00+00:00", "2026-09-25T03:30:00+02:00"),    # justo a las 03:30 → mañana
    ("2026-09-24T12:00:00+00:00", "2026-09-25T03:30:00+02:00"),
    ("2026-10-24T12:00:00+00:00", "2026-10-25T03:30:00+01:00"),    # cambio de hora de octubre
])
def test_next_run(now_utc, expected_local):
    got = retention.next_run(datetime.fromisoformat(now_utc), MADRID)
    assert got.isoformat() == expected_local


def _db_con(tmp_path, real_alert, ages_days):
    conn = store.connect(str(tmp_path / "r.db"))
    store.migrate(conn)
    rows = []
    for age in ages_days:
        row = normalize(json.dumps(real_alert))
        row["ts_ms"] = NOW - int(age * DAY)
        rows.append(row)
    store.insert_batch(conn, rows)
    return conn


def test_borra_solo_lo_antiguo_por_bloques(tmp_path, real_alert, monkeypatch):
    monkeypatch.setattr(retention, "CHUNK", 3)                # varias vueltas del bucle
    conn = _db_con(tmp_path, real_alert, [0, 1, 89.9] + [90.1] * 7 + [400])
    assert retention.run(conn, 90, now_ms=NOW) == 8
    ages = sorted((NOW - ts) / DAY for (ts,) in conn.execute("SELECT ts_ms FROM events"))
    assert ages == pytest.approx([0, 1, 89.9])


def test_sin_filas_antiguas(tmp_path, real_alert):
    conn = _db_con(tmp_path, real_alert, [0, 5])
    assert retention.run(conn, 90, now_ms=NOW) == 0
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2


def test_el_colector_la_ejecuta_cuando_toca(tmp_path, real_alert):
    cfg = config.load({"DB_PATH": str(tmp_path / "c.db"), "RETENTION_DAYS": "30", "GEOIP_DIR": str(tmp_path),
                       "BACKUP_DIR": str(tmp_path)})
    c = Collector(cfg)
    old = normalize(json.dumps(real_alert))
    old["ts_ms"] = 0                                          # 1970
    store.insert_batch(c.db, [old, normalize(json.dumps(real_alert))])
    c.maybe_retention()                                       # aún no es la hora
    assert c.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 2
    c.next_retention = datetime(2000, 1, 1, tzinfo=timezone.utc)
    c.maybe_retention()
    assert c.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert c.stats["retention_deleted"] == 1
    assert c.next_retention > datetime.now(timezone.utc)


@pytest.mark.parametrize("env", [{"RETENTION_DAYS": "0"}, {"RETENTION_DAYS": "x"}, {"TZ": "Marte/Olimpo"}])
def test_config_invalida(env):
    with pytest.raises(config.ConfigError):
        config.load(env)
