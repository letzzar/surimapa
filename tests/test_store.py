import json

import pytest

from surimapa_collector import config, store
from surimapa_collector.main import Collector
from surimapa_collector.parser import normalize


@pytest.fixture
def db(tmp_path):
    conn = store.connect(str(tmp_path / "t.db"))
    store.migrate(conn)
    yield conn
    conn.close()


def test_pragmas(tmp_path):
    conn = store.connect(str(tmp_path / "p.db"))
    store.migrate(conn)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert conn.execute("PRAGMA auto_vacuum").fetchone()[0] == 2        # INCREMENTAL
    assert conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1


def test_migracion_idempotente(tmp_path):
    path = str(tmp_path / "m.db")
    conn = store.connect(path)
    assert store.migrate(conn) == 3
    conn.close()
    conn = store.connect(path)
    assert store.migrate(conn) == 3
    assert store.schema_version(conn) == 3
    idx = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'ix_%'")}
    assert idx == {"ix_events_ts_cover", "ix_events_remote_cover", "ix_events_sid_ts",
                   "ix_events_country", "ix_events_asn", "ix_fw_ts_cover", "ix_fw_remote", "ix_fw_country"}


def test_migracion_v1_a_v2_conserva_datos(tmp_path, real_alert):
    path = str(tmp_path / "v1.db")
    conn = store.connect(path)
    store.MIGRATIONS, saved = store.MIGRATIONS[:1], store.MIGRATIONS     # simular un colector v1
    try:
        assert store.migrate(conn) == 1
        store.insert_batch(conn, [normalize(json.dumps(real_alert))])
    finally:
        store.MIGRATIONS = saved
    assert store.migrate(conn) == 3
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM firewall_events").fetchone()[0] == 0


def test_bd_mas_nueva_que_el_colector(db):
    db.execute("UPDATE meta SET value='99' WHERE key='schema_version'")
    with pytest.raises(RuntimeError):
        store.migrate(db)


def test_insert_batch(db, real_alert):
    rows = [normalize(json.dumps(real_alert), frozenset({"192.0.2.10"})) for _ in range(3)]
    assert store.insert_batch(db, rows) == 3
    got = db.execute("SELECT direction, remote_ip, iface, sid, country_iso FROM events").fetchall()
    assert got == [("in", "198.51.100.23", "pppoe0", 2403445, None)] * 3


def test_insert_batch_vacio(db):
    assert store.insert_batch(db, []) == 0


def test_lote_invalido_hace_rollback(db, real_alert):
    good = normalize(json.dumps(real_alert))
    bad = dict(good, direction="arriba")          # viola el CHECK
    with pytest.raises(Exception):
        store.insert_batch(db, [good, bad])
    assert db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0


def test_sql_injection_en_texto_se_guarda_literal(db, real_alert):
    real_alert["alert"]["signature"] = "x'); DROP TABLE events;--"
    store.insert_batch(db, [normalize(json.dumps(real_alert))])
    assert db.execute("SELECT signature FROM events").fetchone()[0] == "x'); DROP TABLE events;--"


def test_process_cuenta_descartes(tmp_path, real_alert):
    cfg = config.load({"DB_PATH": str(tmp_path / "c.db"), "WAN_IPS": "192.0.2.10"})
    c = Collector(cfg)
    n = c.process([json.dumps(real_alert).encode(), b"{roto", json.dumps({"event_type": "dns"}).encode()])
    assert n == 1
    assert c.stats == {"processed": 1, "discarded_invalid_json": 1, "discarded_not_alert": 1}
    assert c.db.execute("SELECT direction FROM events").fetchone()[0] == "in"


def test_config_valida_wan_ips():
    assert config.load({"WAN_IPS": " 192.0.2.10 , 2001:DB8::1 "}).wan_ips == {"192.0.2.10", "2001:db8::1"}
    with pytest.raises(config.ConfigError):
        config.load({"WAN_IPS": "no-es-ip"})
    with pytest.raises(config.ConfigError):
        config.load({"REDIS_KEY": "sur-icata"})
