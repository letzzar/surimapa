"""API del portal contra una BD de fixtures (esquema real del colector)."""
import time

import pytest
from fastapi.testclient import TestClient

from app import db as pdb
from app.main import app
from surimapa_collector import store

NOW = int(time.time() * 1000)
MIN = 60_000


def row(**over) -> dict:
    base = {
        "ts_ms": NOW - 5 * MIN, "iface": "pppoe0", "direction": "in",
        "src_ip": "198.51.100.23", "src_port": 40000, "dest_ip": "192.0.2.10", "dest_port": 22,
        "proto": "TCP", "app_proto": None, "remote_ip": "198.51.100.23",
        "sid": 2001219, "signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak",
        "severity": 2, "action": "allowed", "flow_id": 1,
        "country_iso": "FR", "country": "Francia", "city": "París", "lat": 48.8566, "lon": 2.3522,
        "asn": 16276, "as_org": "OVH SAS", "raw": '{"event_type":"alert"}', "raw_truncated": 0,
    }
    base.update(over)
    return base


ROWS = [
    row(),
    row(ts_ms=NOW - 10 * MIN, severity=1, sid=2019284, signature="ET WEB <script>alert(1)</script> 100%_off"),
    row(ts_ms=NOW - 20 * MIN, src_ip="203.0.113.9", remote_ip="203.0.113.9", country_iso="US",
        country="Estados Unidos", city=None, lat=37.751, lon=-97.822, asn=398324, as_org="Censys, Inc.",
        dest_port=443),
    row(ts_ms=NOW - 30 * MIN, direction="out", src_ip="192.0.2.10", dest_ip="203.0.113.9",
        remote_ip="203.0.113.9", country_iso="US", country="Estados Unidos", city=None, lat=37.751,
        lon=-97.822, severity=3, sid=2027865, signature="ET INFO DNS .cloud"),
    row(ts_ms=NOW - 40 * MIN, direction="local", src_ip="192.168.1.20", dest_ip="192.168.1.10", remote_ip=None,
        country_iso=None, country=None, city=None, lat=None, lon=None, asn=None, as_org=None, iface="bridge0"),
    row(ts_ms=NOW - 2 * 86_400_000, remote_ip="198.51.100.77", src_ip="198.51.100.77"),        # hace 2 días
    row(ts_ms=NOW - 26 * 3_600_000, remote_ip="198.51.100.88", src_ip="198.51.100.88"),        # periodo anterior
    row(ts_ms=NOW - 3 * MIN, src_ip="2001:db8::1", remote_ip="2001:db8::1", dest_ip="2001:db8:ffff::10"),
]


def fw(**over) -> dict:
    base = {"ts_ms": NOW - 5 * MIN, "remote_ip": "198.51.100.23", "proto": "TCP", "dest_port": 22,
            "country_iso": "FR", "country": "Francia", "city": "París", "lat": 48.8566, "lon": 2.3522,
            "asn": 16276, "as_org": "OVH SAS"}
    base.update(over)
    return base


FW_ROWS = [
    fw(), fw(ts_ms=NOW - 6 * MIN, dest_port=3389),
    fw(ts_ms=NOW - 7 * MIN, remote_ip="203.0.113.9", country_iso="US", country="Estados Unidos", city=None,
       lat=37.751, lon=-97.822, asn=398324, as_org="Censys, Inc.", dest_port=3389),
    fw(ts_ms=NOW - 8 * MIN, remote_ip="203.0.113.50", proto="ICMP", dest_port=None, country_iso=None, country=None,
       city=None, lat=None, lon=None, asn=None, as_org=None),
    fw(ts_ms=NOW - 3 * 86_400_000, remote_ip="198.51.100.77"),                               # hace 3 días
]


class FakeRedis:
    def __init__(self, beat_age=5, queue=3):
        self.beat_age, self.queue = beat_age, queue

    def get(self, key):
        return None if self.beat_age is None else str(int(time.time()) - self.beat_age).encode()

    def llen(self, key):
        return self.queue


@pytest.fixture(autouse=True)
def _cache_vacia():
    from app import api
    api.cache.clear()
    yield
    api.cache.clear()


@pytest.fixture
def client(tmp_path, monkeypatch):
    path = str(tmp_path / "api.db")
    conn = store.connect(path)
    store.migrate(conn)
    store.insert_batch(conn, ROWS)
    store.insert_batch(conn, FW_ROWS, firewall=True)
    conn.close()
    monkeypatch.setattr(pdb, "DB_PATH", path)
    monkeypatch.setattr(pdb, "redis_client", lambda: FakeRedis())
    c = TestClient(app)
    c.auth = ("tester", "clave-de-prueba")
    return c


# ---------- Salud y cabeceras ----------
def test_health_ok(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["redis_queue_len"] == 3
    assert h["collector_heartbeat_age_s"] <= 6 and h["last_event_ms"] == NOW - 3 * MIN
    assert h["db_size_bytes"] > 0


def test_health_colector_parado(client, monkeypatch):
    monkeypatch.setattr(pdb, "redis_client", lambda: FakeRedis(beat_age=None))
    assert client.get("/api/health").json()["status"] == "degraded"


def test_sin_bd_devuelve_503(client, monkeypatch, tmp_path):
    monkeypatch.setattr(pdb, "DB_PATH", str(tmp_path / "no-existe.db"))
    assert client.get("/api/summary").status_code == 503
    assert client.get("/api/health").json()["status"] == "degraded"


def test_cabeceras_de_seguridad_y_sin_docs(client):
    r = client.get("/api/health")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["cache-control"] == "no-store"
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_sirve_el_panel(client):
    r = client.get("/")
    assert r.status_code == 200 and "SURIMAPA" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


# ---------- Resumen y línea temporal ----------
def test_summary_24h(client):
    s = client.get("/api/summary?range=24h").json()
    assert s["total"] == 6                               # fuera: hace 2 días y hace 26 h
    assert s["unique_ips"] == 3 and s["unique_countries"] == 2
    assert s["by_severity"] == {"1": 1, "2": 4, "3": 1}
    assert s["previous"]["total"] == 1                   # la de hace 26 h
    assert s["range"]["to_ms"] - s["range"]["from_ms"] == 86_400_000


def test_summary_filtros(client):
    assert client.get("/api/summary?range=24h&severity=1").json()["total"] == 1
    assert client.get("/api/summary?range=24h&direction=out").json()["total"] == 1
    assert client.get("/api/summary?range=24h&iface=bridge0").json()["total"] == 1
    assert client.get("/api/summary?range=7d").json()["total"] == 8


def test_timeline_rellena_huecos(client):
    t = client.get("/api/timeline?range=1h").json()
    assert t["bucket_ms"] == 60_000
    assert 60 <= len(t["points"]) <= 61
    assert sum(p["sev1"] + p["sev2"] + p["sev3"] for p in t["points"]) == 6
    assert all(b["ts_ms"] - a["ts_ms"] == 60_000 for a, b in zip(t["points"], t["points"][1:]))


@pytest.mark.parametrize("rng,bucket", [("24h", 900_000), ("7d", 3_600_000), ("30d", 21_600_000), ("90d", 21_600_000)])
def test_timeline_bucket_automatico(client, rng, bucket):
    assert client.get(f"/api/timeline?range={rng}").json()["bucket_ms"] == bucket


def test_rango_personalizado(client):
    frm = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW / 1000 - 3600))
    to = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(NOW / 1000 + 60))
    assert client.get(f"/api/summary?from={frm}&to={to}").json()["total"] == 6


# ---------- Rankings y mapa ----------
def test_top_remote_ip(client):
    items = client.get("/api/top/remote_ip?range=24h").json()["items"]
    assert items[0] == {"key": "198.51.100.23", "label": "198.51.100.23", "count": 2, "country_iso": "FR",
                        "as_org": "OVH SAS"}
    assert all(i["key"] for i in items)                  # sin NULL (el evento local)


def test_top_signature_y_puertos(client):
    sig = client.get("/api/top/signature?range=24h").json()["items"]
    assert {"key": 2019284, "label": "ET WEB <script>alert(1)</script> 100%_off", "count": 1, "severity": 1} in sig
    ports = client.get("/api/top/dest_port?range=24h&limit=1").json()["items"]
    assert ports == [{"key": 22, "label": "22", "count": 5}]


def test_top_country_y_asn(client):
    c = client.get("/api/top/country?range=24h").json()["items"]
    assert c[0]["key"] in ("FR", "US") and {i["key"] for i in c} == {"FR", "US"}
    a = client.get("/api/top/asn?range=24h").json()["items"]
    assert {"key": 398324, "label": "Censys, Inc.", "count": 1} in a


def test_map(client):
    m = client.get("/api/map?range=24h").json()
    assert {"country_iso": "FR", "country": "Francia", "count": 3} in m["countries"]
    paris = next(p for p in m["points"] if p["country_iso"] == "FR")
    assert (paris["lat"], paris["lon"], paris["count"]) == (48.9, 2.4, 3)


# ---------- Eventos ----------
def test_events_paginado(client):
    e = client.get("/api/events?range=24h&page=1&size=2").json()
    assert e["total"] == 6 and len(e["items"]) == 2
    assert e["items"][0]["ts_ms"] == NOW - 3 * MIN        # más reciente primero
    assert "raw" not in e["items"][0]
    assert client.get("/api/events?range=24h&page=4&size=2").json()["items"] == []


@pytest.mark.parametrize("q,expected", [
    ("203.0.113.9", 2), ("2001:DB8::1", 1), ("2019284", 1), ("ssh scan", 4),
    ("100%_off", 1), ("%", 1), ("_", 1),        # escapados: sin escape coincidirían las 6 filas
    ("' OR 1=1 --", 0), ("\\", 0),
])
def test_busqueda(client, q, expected):
    from urllib.parse import quote
    assert client.get(f"/api/events?range=24h&q={quote(q)}").json()["total"] == expected


def test_evento_detalle_y_404(client):
    first = client.get("/api/events?range=7d&size=100").json()["items"][-1]
    d = client.get(f"/api/events/{first['id']}").json()
    assert d["raw"] == '{"event_type":"alert"}' and d["raw_truncated"] == 0 and "iface" in d
    assert client.get("/api/events/999999").status_code == 404


# ---------- Bloqueos del firewall ----------
def test_fw_summary(client):
    s = client.get("/api/fw/summary?range=24h").json()
    assert (s["total"], s["unique_ips"], s["unique_countries"]) == (4, 3, 2)
    assert client.get("/api/fw/summary?range=7d").json()["total"] == 5
    # los filtros de Suricata no aplican (ni rompen) al firewall
    assert client.get("/api/fw/summary?range=24h&severity=1&iface=bridge0").json()["total"] == 4


def test_fw_top(client):
    ips = client.get("/api/fw/top/remote_ip?range=24h").json()["items"]
    assert ips[0] == {"key": "198.51.100.23", "label": "198.51.100.23", "count": 2,
                      "country_iso": "FR", "as_org": "OVH SAS"}
    ports = client.get("/api/fw/top/dest_port?range=24h").json()["items"]
    assert [(p["key"], p["count"]) for p in ports] == [(3389, 2), (22, 1)]
    countries = client.get("/api/fw/top/country?range=24h").json()["items"]
    assert countries[0] == {"key": "FR", "label": "Francia", "count": 2}
    assert client.get("/api/fw/top/signature?range=24h").status_code == 422
    assert client.get("/api/fw/top/remote_ip?range=24h&limit=0").status_code == 422


def test_fw_map(client):
    d = client.get("/api/fw/map?range=24h").json()
    assert {c["country_iso"]: c["count"] for c in d["countries"]} == {"FR": 2, "US": 1}
    assert [(p["lat"], p["lon"], p["count"], p["city"]) for p in d["points"]] == [
        (48.9, 2.4, 2, "París"), (37.8, -97.8, 1, None)]
    assert client.get("/api/fw/map", auth=None).status_code == 401


# ---------- Exportación CSV ----------
def _csv(resp):
    import csv
    import io
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.headers["content-disposition"].startswith('attachment; filename="surimapa-alertas-')
    assert resp.text.startswith("\ufeff")
    return list(csv.reader(io.StringIO(resp.text[1:]), delimiter=";"))


def test_events_csv_vista_de_la_tabla(client):
    rows = _csv(client.get("/api/events.csv?range=24h"))
    assert rows[0][:5] == ["fecha_utc", "severidad", "interfaz", "direccion", "ip_remota"]
    assert len(rows) - 1 == client.get("/api/events?range=24h").json()["total"]
    assert rows[1][0].endswith("Z") and rows[1][4] == "2001:db8::1"          # más reciente primero
    # mismos filtros que la tabla: severidad, búsqueda y origen
    assert [r[16] for r in _csv(client.get("/api/events.csv?range=24h&severity=1"))[1:]] == [
        "ET WEB <script>alert(1)</script> 100%_off"]
    assert {r[4] for r in _csv(client.get("/api/events.csv?range=24h&q=203.0.113.9"))[1:]} == {"203.0.113.9"}
    assert {r[5] for r in _csv(client.get("/api/events.csv?range=24h&country=US"))[1:]} == {"US"}
    assert len(_csv(client.get("/api/events.csv?range=24h&q=nada-coincide"))) == 1       # solo cabecera


def test_events_csv_tope_y_bloques(client, monkeypatch):
    from app import api
    monkeypatch.setattr(api, "CSV_CHUNK", 2)
    monkeypatch.setattr(api, "CSV_MAX_ROWS", 5)
    assert len(_csv(client.get("/api/events.csv?range=24h"))) - 1 == 5


def test_events_csv_validacion(client):
    assert client.get("/api/events.csv?lat=10").status_code == 422
    assert client.get("/api/events.csv?country=us").status_code == 422
    assert client.get("/api/events.csv", auth=None).status_code == 401


def test_csv_cell_neutraliza_formulas():
    from app.api import csv_cell
    assert csv_cell('=HYPERLINK("http://x")') == '\'=HYPERLINK("http://x")'
    assert [csv_cell(v) for v in ("+1", "-1", "@SUM(A1)", "\tx", "\rx")] == ["'+1", "'-1", "'@SUM(A1)", "'\tx", "'\rx"]
    assert csv_cell(None) == "" and csv_cell(443) == "443" and csv_cell("ET SCAN") == "ET SCAN"


def test_ip_detalle(client):
    d = client.get("/api/ip/203.0.113.9").json()
    assert d["signatures_total"] == 2
    assert d["total"] == 2 and d["country_iso"] == "US" and d["asn"] == 398324
    assert {s["sid"] for s in d["signatures"]} == {2001219, 2027865}
    assert {s["sid"]: s["severity"] for s in d["signatures"]} == {2001219: 2, 2027865: 3}
    assert client.get("/api/ip/2001:0db8::0001").json()["ip"] == "2001:db8::1"
    assert client.get("/api/ip/8.8.8.8").status_code == 404


# ---------- Validación de parámetros ----------
@pytest.mark.parametrize("url", [
    "/api/summary?range=1y", "/api/summary?severity=4", "/api/summary?severity=0",
    "/api/summary?direction=up", "/api/summary?iface=a%20b", "/api/summary?iface=" + "x" * 33,
    "/api/top/raw?range=24h", "/api/top/remote_ip?limit=51", "/api/top/remote_ip?limit=0",
    "/api/events?size=101", "/api/events?page=0", "/api/events?q=" + "a" * 201,
    "/api/events/0", "/api/events/abc", "/api/ip/no-es-ip", "/api/ip/1.2.3.4.5",
    "/api/summary?from=2026-01-01T00:00:00Z", "/api/summary?from=2026-01-01T00:00:00Z&to=2026-06-01T00:00:00Z",
    "/api/summary?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z",
])
def test_parametros_invalidos(client, url):
    assert client.get(url).status_code == 422


def test_bd_en_solo_lectura(client):
    with pdb.connect() as conn:
        with pytest.raises(Exception):
            conn.execute("DELETE FROM events")


# ---------- Tiempo real ----------
def test_stream_emite_eventos_nuevos(client, monkeypatch):
    from app import api, queries
    monkeypatch.setattr(api, "STREAM_EVERY_S", 0)
    rows = []
    with pdb.connect() as conn:
        last = queries.max_id(conn)
        rows = queries.events_after(conn, 0, last, None, "in", None, 50)
    assert rows and all(r["direction"] == "in" for r in rows)
    assert {"lat", "lon"} <= set(rows[0])                # para los misiles
    with pdb.connect() as conn:
        assert queries.events_after(conn, last, last, None, None, None, 50) == []


# ---------- Caché de periodos largos (30d/90d) ----------
def _insertar(extra_rows):
    conn = store.connect(pdb.DB_PATH)
    store.insert_batch(conn, extra_rows)
    conn.close()


def test_90d_se_sirve_de_cache_y_24h_en_vivo(client):
    assert client.get("/api/summary?range=90d").json()["total"] == 8
    assert client.get("/api/summary?range=24h").json()["total"] == 6
    _insertar([row(ts_ms=NOW - MIN)])
    assert client.get("/api/summary?range=90d").json()["total"] == 8         # caché
    assert client.get("/api/summary?range=24h").json()["total"] == 7         # en vivo
    assert client.get("/api/summary?range=90d&severity=2").json()["total"] == 7   # otra clave: calculada


def test_busquedas_y_rango_personalizado_no_se_cachean(client):
    assert client.get("/api/events?range=90d&q=ssh").json()["total"] == 6
    _insertar([row(ts_ms=NOW - MIN)])
    assert client.get("/api/events?range=90d&q=ssh").json()["total"] == 7


def test_precalculo_llena_la_cache_del_panel(client, monkeypatch, tmp_path):
    from app import api
    assert api.warm_long_ranges() == 2 * (4 + len(api.PANEL_TOP_DIMS) + 2 + len(api.PANEL_FW_TOP_DIMS))
    monkeypatch.setattr(pdb, "DB_PATH", str(tmp_path / "no-existe.db"))    # sin BD: 30d/90d desde caché
    for url in ("/api/summary?range=90d", "/api/timeline?range=30d", "/api/map?range=90d",
                "/api/top/signature?range=90d&limit=10", "/api/events?range=30d&page=1&size=25"):
        assert client.get(url).status_code == 200, url
    assert client.get("/api/summary?range=24h").status_code == 503


def test_ttlcache_caduca_y_limita_entradas(monkeypatch):
    from app.cache import TTLCache
    t = [1000.0]
    monkeypatch.setattr("app.cache.time.monotonic", lambda: t[0])
    c = TTLCache(max_entries=2)
    c.set("a", 1, 10)
    c.set("b", 2, 10)
    c.set("c", 3, 10)                     # expulsa "a" (la más antigua)
    assert (c.get("a"), c.get("b"), c.get("c")) == (None, 2, 3)
    t[0] += 11
    assert c.get("b") is None and len(c) == 1


# ---------- Autenticación (HTTP Basic) ----------
@pytest.fixture
def anon(client, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "AUTH_FAIL_DELAY_S", 0)
    c = TestClient(app)
    return c


@pytest.mark.parametrize("path", ["/", "/index.html", "/js/app.js", "/api/health", "/api/summary", "/api/stream",
                                  "/api/events/1", "/vendor/world-110m.geojson"])
def test_todo_requiere_credenciales(anon, path):
    r = anon.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith('Basic realm="Surimapa"')
    assert "default-src 'self'" in r.headers["content-security-policy"]


@pytest.mark.parametrize("auth", [("tester", "mala"), ("otro", "clave-de-prueba"), ("tester", ""),
                                  ("", ""), ("tester", "clave-de-prueba "), ("TESTER", "clave-de-prueba")])
def test_credenciales_incorrectas(anon, auth):
    assert anon.get("/api/health", auth=auth).status_code == 401


@pytest.mark.parametrize("header", ["Basic", "Basic !!!", "Bearer abc", "Basic dGVzdGVy",    # sin ':'
                                    "Basic " + "//79"])
def test_cabecera_malformada(anon, header):
    assert anon.get("/api/health", headers={"Authorization": header}).status_code == 401


def test_credenciales_correctas(anon):
    assert anon.get("/api/health", auth=("tester", "clave-de-prueba")).status_code == 200
    lower = {"Authorization": "basic dGVzdGVyOmNsYXZlLWRlLXBydWViYQ=="}    # esquema en minúsculas
    assert anon.get("/api/health", headers=lower).status_code == 200


def test_contrasena_con_dos_puntos_y_unicode(anon, monkeypatch):
    from app import main
    monkeypatch.setattr(main, "PORTAL_PASSWORD", "a:b:ñ€")
    assert anon.get("/api/health", auth=("tester", "a:b:ñ€")).status_code == 200


def test_intento_fallido_espera(anon, monkeypatch):
    import time
    from app import main
    monkeypatch.setattr(main, "AUTH_FAIL_DELAY_S", 0.3)
    t0 = time.perf_counter()
    anon.get("/api/health", auth=("tester", "mala"))
    assert time.perf_counter() - t0 >= 0.3
    t0 = time.perf_counter()
    anon.get("/api/health")                         # sin cabecera (1.ª visita): sin espera
    assert time.perf_counter() - t0 < 0.3


# ---------- Filtro de la lista por origen (clic en el mapa) ----------
def test_origen_por_pais(client):
    e = client.get("/api/events?range=24h&country=US").json()
    assert e["total"] == 2 and {i["country_iso"] for i in e["items"]} == {"US"}


def test_origen_por_celda_coincide_con_cada_circulo(client):
    points = client.get("/api/map?range=24h").json()["points"]
    assert points
    for p in points:
        total = client.get(f"/api/events?range=24h&lat={p['lat']}&lon={p['lon']}").json()["total"]
        assert total == p["count"], p


def test_origen_por_celda_acepta_coordenadas_sin_redondear(client):
    # 48.8566/2.3522 (París) cae en la celda 48.9/2.4
    assert client.get("/api/events?range=24h&lat=48.8566&lon=2.3522").json()["total"] == 3


def test_origen_se_combina_con_busqueda_y_filtros(client):
    assert client.get("/api/events?range=24h&country=US&q=ssh").json()["total"] == 1
    assert client.get("/api/events?range=24h&country=US&direction=out").json()["total"] == 1


def test_origen_no_se_cachea(client):
    assert client.get("/api/events?range=90d&country=FR").json()["total"] == 5
    _insertar([row(ts_ms=NOW - MIN)])
    assert client.get("/api/events?range=90d&country=FR").json()["total"] == 6


@pytest.mark.parametrize("qs", ["lat=48.9", "lon=2.4", "country=fr", "country=FRA", "country=F1",
                                "country=FR&lat=48.9&lon=2.4", "lat=91&lon=0", "lat=0&lon=181", "lat=x&lon=1"])
def test_origen_parametros_invalidos(client, qs):
    assert client.get(f"/api/events?range=24h&{qs}").status_code == 422


@pytest.mark.parametrize("value,cell", [(48.8566, 48.9), (2.3522, 2.4), (-0.0931, -0.1), (0.05, 0.1),
                                        (-0.05, 0.0), (37.751, 37.8), (-97.822, -97.8), (-33.45, -33.4)])
def test_rejilla_mitad_hacia_arriba(value, cell):
    from app.queries import grid
    assert grid(value) == cell


# ---------- Campos añadidos para el rediseño (2026-09-24) ----------
def test_listado_y_stream_incluyen_iface(client):
    items = client.get("/api/events?range=24h&size=100").json()["items"]
    assert {i["iface"] for i in items} == {"pppoe0", "bridge0"}
    from app import queries
    with pdb.connect() as conn:
        rows = queries.events_after(conn, 0, queries.max_id(conn), None, None, None, 50)
    assert "iface" in rows[0] and {"lat", "lon"} <= set(rows[0])


def test_detalle_sin_columnas_duplicadas(client):
    from app import queries
    assert len(queries.DETAIL_COLUMNS) == len(set(queries.DETAIL_COLUMNS))
    d = client.get("/api/events/1").json()
    assert d["iface"] == "pppoe0" and "raw" in d


def test_signatures_total_no_se_limita_a_20(client):
    _insertar([row(ts_ms=NOW - MIN, sid=5_000_000 + k, signature=f"FIRMA {k}") for k in range(30)])
    d = client.get("/api/ip/198.51.100.23").json()
    assert len(d["signatures"]) == 20 and d["signatures_total"] == 32       # 30 nuevas + 2 previas


def test_estaticos_se_revalidan_siempre(client):
    for path in ("/", "/js/app.js", "/css/app.css"):
        assert client.get(path).headers["cache-control"] == "no-cache", path
    assert client.get("/api/health").headers["cache-control"] == "no-store"
