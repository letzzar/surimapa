"""GeoIP con las bases de PRUEBA de MaxMind (tests/fixtures/geoip, datos ficticios)."""
import json
import os
import shutil

import pytest

from surimapa_collector import config, geoip
from surimapa_collector.main import Collector

from conftest import FIXTURES

TEST_DB = FIXTURES / "geoip"


@pytest.fixture
def geo_dir(tmp_path):
    shutil.copy(TEST_DB / "GeoLite2-City-Test.mmdb", tmp_path / geoip.CITY_FILE)
    shutil.copy(TEST_DB / "GeoLite2-ASN-Test.mmdb", tmp_path / geoip.ASN_FILE)
    return tmp_path


def test_ciudad_con_nombre_en_espanol(geo_dir):
    r = geoip.GeoIP(str(geo_dir)).lookup("81.2.69.142")
    assert (r["country_iso"], r["country"], r["city"]) == ("GB", "Reino Unido", "Londres")
    assert r["lat"] == pytest.approx(51.5142) and r["lon"] == pytest.approx(-0.0931)


def test_respaldo_en_ingles_si_no_hay_es(geo_dir):
    assert geoip.GeoIP(str(geo_dir)).lookup("2.125.160.216")["city"] == "Boxford"


def test_sin_ciudad_e_ipv6(geo_dir):
    r = geoip.GeoIP(str(geo_dir)).lookup("2001:218::1")
    assert (r["country_iso"], r["country"], r["city"]) == ("JP", "Japón", None)


def test_asn(geo_dir):
    r = geoip.GeoIP(str(geo_dir)).lookup("1.128.0.1")
    assert (r["asn"], r["as_org"]) == (1221, "Telstra Pty Ltd")


@pytest.mark.parametrize("ip", ["8.8.8.8", None, "", "no-es-ip"])
def test_ip_sin_datos_o_invalida(geo_dir, ip):
    assert geoip.GeoIP(str(geo_dir)).lookup(ip) == geoip.EMPTY


def test_sin_bases_no_falla(tmp_path, caplog):
    g = geoip.GeoIP(str(tmp_path / "vacio"))
    assert g.lookup("81.2.69.142") == geoip.EMPTY
    assert "No existe" in caplog.text
    caplog.clear()
    g.maybe_reload(force=True)                      # segundo intento en la misma hora: sin aviso
    assert "No existe" not in caplog.text


def test_base_corrupta_no_rompe(geo_dir):
    (geo_dir / geoip.ASN_FILE).write_bytes(b"esto no es un mmdb")
    r = geoip.GeoIP(str(geo_dir)).lookup("81.2.69.142")
    assert r["country_iso"] == "GB" and r["asn"] is None


def test_recarga_si_cambia_el_mtime(tmp_path):
    g = geoip.GeoIP(str(tmp_path))                  # arranca sin bases
    assert g.lookup("81.2.69.142")["country_iso"] is None
    shutil.copy(TEST_DB / "GeoLite2-City-Test.mmdb", tmp_path / geoip.CITY_FILE)
    g.maybe_reload()                                # aún no toca revisar
    assert g.lookup("81.2.69.142")["country_iso"] is None
    g.maybe_reload(force=True)
    assert g.lookup("81.2.69.142")["country_iso"] == "GB"
    # geoipupdate sustituye el fichero: nuevo mtime → se reabre
    os.utime(tmp_path / geoip.CITY_FILE, (1, 1))
    g.maybe_reload(force=True)
    assert g.city.mtime == 1


def test_colector_enriquece_solo_la_ip_remota(geo_dir, tmp_path, real_alert):
    cfg = config.load({"DB_PATH": str(tmp_path / "g.db"), "GEOIP_DIR": str(geo_dir),
                       "WAN_IPS": "192.0.2.10"})
    c = Collector(cfg)
    entrante = dict(real_alert, src_ip="81.2.69.142")                        # remota = Londres
    local = dict(real_alert, src_ip="192.168.1.20", dest_ip="192.168.1.10")      # sin remota
    c.process([json.dumps(entrante).encode(), json.dumps(local).encode()])
    rows = c.db.execute("SELECT direction, remote_ip, country_iso, city, asn FROM events ORDER BY id").fetchall()
    assert rows == [("in", "81.2.69.142", "GB", "Londres", None), ("local", None, None, None, None)]
