import json

import pytest

from surimapa_collector import parser
from surimapa_collector.parser import Discard, normalize

WAN = frozenset({"192.0.2.10"})


def msg(event: dict) -> bytes:
    return json.dumps(event).encode()


def base(**over) -> dict:
    ev = {
        "timestamp": "2026-09-23T10:47:37.161496+0200",
        "event_type": "alert",
        "in_iface": "pppoe0",
        "src_ip": "198.51.100.23", "src_port": 57948,
        "dest_ip": "192.0.2.10", "dest_port": 8443,
        "proto": "TCP",
        "flow_id": 1234567890123,
        "alert": {"signature_id": 2403445, "signature": "ET CINS Test", "category": "Misc Attack",
                  "severity": 2, "action": "allowed"},
    }
    ev.update(over)
    return ev


# ---------- Descartes ----------
@pytest.mark.parametrize("raw", [b"", b"{no es json", b"[1,2,3]", b'"texto"', b"\xff\xfe\x00"])
def test_json_invalido(raw):
    with pytest.raises(Discard) as e:
        normalize(raw)
    assert e.value.reason == "invalid_json"


def test_evento_no_alert():
    with pytest.raises(Discard) as e:
        normalize(msg(base(event_type="tls")))
    assert e.value.reason == "not_alert"


@pytest.mark.parametrize("alert", [None, "texto", 3])
def test_falta_alert(alert):
    ev = base()
    ev["alert"] = alert
    with pytest.raises(Discard) as e:
        normalize(msg(ev))
    assert e.value.reason == "missing_alert"


@pytest.mark.parametrize("field,value", [("src_ip", "999.1.1.1"), ("dest_ip", None), ("src_ip", 12345)])
def test_ip_invalida(field, value):
    with pytest.raises(Discard) as e:
        normalize(msg(base(**{field: value})))
    assert e.value.reason == "bad_ip"


@pytest.mark.parametrize("ts", ["ayer", None, "2026-09-23T10:47:37"])
def test_timestamp_invalido_o_sin_zona(ts):
    with pytest.raises(Discard) as e:
        normalize(msg(base(timestamp=ts)))
    assert e.value.reason == "bad_timestamp"


# ---------- Fixture real ----------
def test_alerta_real_anonimizada(real_alert):
    row = normalize(msg(real_alert), WAN)
    assert row["direction"] == "in"
    assert row["remote_ip"] == "198.51.100.23"
    assert row["iface"] == "pppoe0"
    assert row["sid"] == 2403445
    assert row["severity"] == 2
    assert row["dest_port"] == 8443
    raw = json.loads(row["raw"])
    assert "packet" not in raw and row["raw_truncated"] == 0


# ---------- Timestamp ----------
def test_timestamp_con_zona_a_utc():
    row = normalize(msg(base(timestamp="2026-09-23T10:00:00.500000+0200")))
    assert row["ts_ms"] == 1790150400500           # 2026-09-23T08:00:00.5Z


def test_timestamp_iso_con_dos_puntos():
    a = normalize(msg(base(timestamp="2026-09-23T10:00:00+02:00")))["ts_ms"]
    b = normalize(msg(base(timestamp="2026-09-23T08:00:00.000000+0000")))["ts_ms"]
    assert a == b


# ---------- Dirección y IP remota ----------
@pytest.mark.parametrize("src,dest,wan,remote,direction", [
    ("198.51.100.23", "192.168.1.10", frozenset(), "198.51.100.23", "in"),    # pública → privada
    ("192.168.1.20", "203.0.113.9", frozenset(), "203.0.113.9", "out"),        # privada → pública
    ("198.51.100.23", "192.0.2.10", WAN, "198.51.100.23", "in"),             # → IP WAN propia
    ("192.0.2.10", "203.0.113.9", WAN, "203.0.113.9", "out"),                # IP WAN propia → fuera
    ("198.51.100.23", "203.0.113.9", frozenset(), "198.51.100.23", "in"),    # ambas externas
    ("192.168.1.20", "192.168.1.10", frozenset(), None, "local"),               # ambas privadas
    ("100.101.102.103", "192.168.1.10", frozenset(), None, "local"),          # Tailscale (CGNAT)
    ("192.168.1.20", "239.255.255.250", frozenset(), None, "local"),           # multicast
])
def test_direccion(src, dest, wan, remote, direction):
    row = normalize(msg(base(src_ip=src, dest_ip=dest)), wan)
    assert (row["remote_ip"], row["direction"]) == (remote, direction)


def test_rangos_documentacion_son_remotos():
    # is_global los trata como no globales; aquí deben contar como remotos (ver LOCAL_NETS).
    import ipaddress
    for ip in ("192.0.2.1", "198.51.100.1", "203.0.113.1", "2001:db8::1"):
        assert not parser.is_local(ipaddress.ip_address(ip))


def test_ipv6_se_normaliza_y_clasifica():
    row = normalize(msg(base(src_ip="2001:0DB8:0000::0001", dest_ip="fd00::20")))
    assert row["src_ip"] == "2001:db8::1"
    assert (row["remote_ip"], row["direction"]) == ("2001:db8::1", "in")


# ---------- Datos no confiables ----------
def test_html_y_control_en_firma():
    sig = "<img src=x onerror=alert(1)>\x00\x1b[31m hola\x7f\u0085"
    row = normalize(msg(base(alert={"signature_id": 1, "signature": sig, "severity": 1})))
    assert row["signature"] == "<img src=x onerror=alert(1)>[31m hola"   # HTML intacto (el frontend usa textContent), sin controles
    assert not any(ord(c) < 32 or 0x7f <= ord(c) <= 0x9f for c in row["signature"])


def test_truncado_de_textos():
    row = normalize(msg(base(alert={"signature_id": 1, "signature": "A" * 1000, "category": "B" * 1000,
                                    "severity": 1}, proto="X" * 100)))
    assert len(row["signature"]) == parser.MAX_SIGNATURE
    assert len(row["category"]) == parser.MAX_CATEGORY
    assert len(row["proto"]) == parser.MAX_SHORT


@pytest.mark.parametrize("value", [-1, 70000, "22", True, 1.5, None])
def test_puertos_invalidos_quedan_a_null(value):
    assert normalize(msg(base(src_port=value)))["src_port"] is None


def test_severidad_y_sid_invalidos():
    row = normalize(msg(base(alert={"signature_id": "x", "severity": 0})))
    assert row["sid"] is None and row["severity"] is None


def test_flow_id_fuera_de_int64():
    assert normalize(msg(base(flow_id=2**64 - 1)))["flow_id"] is None


def test_raw_sin_payload_ni_packet_ni_http():
    ev = base(payload="AAAA", payload_printable="GET /", packet="AAAA", http={"url": "/admin"})
    raw = json.loads(normalize(msg(ev))["raw"])
    for key in ("payload", "payload_printable", "packet", "http"):
        assert key not in raw
    assert raw["alert"]["signature"] == "ET CINS Test"


def test_raw_grande_se_trunca_y_marca():
    ev = base(extra="é" * 5000)                    # multibyte: el corte no debe romper UTF-8
    row = normalize(msg(ev))
    assert row["raw_truncated"] == 1
    assert len(row["raw"].encode("utf-8")) <= parser.MAX_RAW_BYTES


def test_json_muy_anidado_no_rompe():
    deep = '{"a":' * 100000 + "1" + "}" * 100000
    with pytest.raises(Discard):
        normalize(deep.encode())
