import json
import sqlite3
from datetime import date, datetime, timezone

import pytest

from surimapa_collector import backup, config, store
from surimapa_collector.main import Collector
from surimapa_collector.parser import normalize


@pytest.fixture
def db(tmp_path, real_alert):
    conn = store.connect(str(tmp_path / "live.db"))
    store.migrate(conn)
    store.insert_batch(conn, [normalize(json.dumps(real_alert)) for _ in range(5)])
    yield conn
    conn.close()


def test_copia_consistente_y_legible(db, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    path = backup.run(db, str(out), date(2026, 9, 24), keep=7)
    assert path.name == "surimapa-2026-09-24.db"
    copy = sqlite3.connect(path)
    assert copy.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 5
    assert copy.execute("SELECT value FROM meta WHERE key='schema_version'").fetchone()[0] == str(len(store.MIGRATIONS))
    assert not list(out.glob("*.tmp"))


def test_rotacion_conserva_las_mas_recientes(db, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    for d in range(1, 6):
        (out / f"surimapa-2026-09-0{d}.db").write_bytes(b"x")
    (out / "surimapa-2026-09-09.db.tmp").write_bytes(b"a medias")
    (out / "otro-fichero.txt").write_text("no tocar")
    backup.run(db, str(out), date(2026, 9, 10), keep=3)
    assert sorted(p.name for p in out.iterdir()) == [
        "otro-fichero.txt", "surimapa-2026-09-04.db", "surimapa-2026-09-05.db", "surimapa-2026-09-10.db"]


def test_misma_fecha_se_sobrescribe(db, tmp_path):
    out = tmp_path / "bk"
    out.mkdir()
    backup.run(db, str(out), date(2026, 9, 24), keep=7)
    store.insert_batch(db, [dict(normalize(json.dumps({"event_type": "alert", "timestamp": "2026-09-24T10:00:00.000000+0200",
        "src_ip": "198.51.100.1", "dest_ip": "192.0.2.10", "alert": {"signature_id": 1}})))])
    path = backup.run(db, str(out), date(2026, 9, 24), keep=7)
    assert sqlite3.connect(path).execute("SELECT COUNT(*) FROM events").fetchone()[0] == 6
    assert len(list(out.glob("surimapa-*.db"))) == 1


def test_directorio_inexistente_lanza_oserror(db, tmp_path):
    with pytest.raises((OSError, sqlite3.Error)):
        backup.run(db, str(tmp_path / "no-existe"), date(2026, 9, 24), keep=7)


def test_el_colector_copia_tras_la_retencion(tmp_path, real_alert):
    out = tmp_path / "bk"
    out.mkdir()
    cfg = config.load({"DB_PATH": str(tmp_path / "c.db"), "GEOIP_DIR": str(tmp_path), "BACKUP_DIR": str(out),
                       "BACKUP_KEEP": "2"})
    c = Collector(cfg)
    store.insert_batch(c.db, [normalize(json.dumps(real_alert))])
    c.next_retention = datetime(2000, 1, 1, tzinfo=timezone.utc)
    c.maybe_retention()
    assert c.stats["backups"] == 1 and len(list(out.glob("surimapa-*.db"))) == 1


def test_fallo_de_copia_no_tumba_el_colector(tmp_path, real_alert):
    cfg = config.load({"DB_PATH": str(tmp_path / "c.db"), "GEOIP_DIR": str(tmp_path),
                       "BACKUP_DIR": str(tmp_path / "no-existe")})
    c = Collector(cfg)
    c.next_retention = datetime(2000, 1, 1, tzinfo=timezone.utc)
    c.maybe_retention()
    assert c.stats["backup_errors"] == 1 and c.next_retention > datetime.now(timezone.utc)


@pytest.mark.parametrize("value", ["0", "366", "x"])
def test_backup_keep_invalido(value):
    with pytest.raises(config.ConfigError):
        config.load({"BACKUP_KEEP": value})
