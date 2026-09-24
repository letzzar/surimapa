"""Bloqueos del firewall: parser de filterlog, hilo UDP, tabla firewall_events y retención."""
import socket
import time

import pytest

from surimapa_collector import config, filterlog, retention, store
from surimapa_collector.main import Collector
from surimapa_collector.parser import Discard

from test_geoip import geo_dir  # noqa: F401  (fixture: bases GeoIP de prueba)

HDR = b"<134>Sep 24 18:23:00 filterlog[12345]: "
TCP4 = b"5,,,1000000103,pppoe0,match,block,in,4,0x0,,242,54321,0,none,6,tcp,40,198.51.100.23,192.0.2.10,40000,22,0,S,1234567890,,1024,,"
UDP4 = b"5,,,1000000103,pppoe0,match,block,in,4,0x0,,50,1234,0,none,17,udp,56,203.0.113.9,192.0.2.10,5353,1900,36"
ICMP4 = b"5,,,1000000103,pppoe0,match,block,in,4,0x0,,50,1234,0,none,1,icmp,84,203.0.113.9,192.0.2.10,request,1234,1"
TCP6 = b"5,,,1000000103,pppoe0,match,block,in,6,0x00,0x00000,57,tcp,6,40,2001:db8::1,2001:db8:ffff::10,40000,23,0,S,1,,1024,,"


def test_parse_tcp_udp_icmp_ipv6():
    assert filterlog.parse(HDR + TCP4, "pppoe0", now_ms=7) == {
        "ts_ms": 7, "remote_ip": "198.51.100.23", "proto": "TCP", "dest_port": 22}
    assert filterlog.parse(HDR + UDP4, "pppoe0")["dest_port"] == 1900
    icmp = filterlog.parse(HDR + ICMP4, "pppoe0")
    assert icmp["proto"] == "ICMP" and icmp["dest_port"] is None
    v6 = filterlog.parse(HDR + TCP6, "pppoe0")
    assert (v6["remote_ip"], v6["dest_port"]) == ("2001:db8::1", 23)


def test_parse_con_hostname_y_reject():
    line = b"<134>Sep 24 18:23:00 pfsense filterlog: " + TCP4.replace(b",block,", b",reject,")
    assert filterlog.parse(line, "pppoe0")["remote_ip"] == "198.51.100.23"


@pytest.mark.parametrize("line,reason", [
    (HDR + TCP4.replace(b",block,", b",pass,"), "action"),
    (HDR + TCP4.replace(b",in,4,", b",out,4,"), "direction"),
    (HDR + TCP4.replace(b"pppoe0", b"bridge0"), "iface"),
    (HDR + TCP4.replace(b"198.51.100.23", b"192.168.1.20"), "local_src"),
    (HDR + TCP4.replace(b"198.51.100.23", b"no-es-ip"), "malformed"),
    (HDR + b"5,,,1,pppoe0,match,block,in,4,0x0", "malformed"),
    (HDR + b"1,2,3", "malformed"),
    (b"<13>Sep 24 18:23:00 sshd[1]: Accepted", "not_filterlog"),
    (HDR + b"\xff\xfe", "not_filterlog"),                       # no ASCII
    (HDR + TCP4 + b"," * 3000, "too_long"),
])
def test_parse_descarta(line, reason):
    with pytest.raises(Discard) as exc:
        filterlog.parse(line, "pppoe0")
    assert exc.value.reason == reason


def test_parse_valores_hostiles():
    evil = TCP4.replace(b",tcp,", b",<script>,").replace(b",22,0,S", b",99999,0,S")
    row = filterlog.parse(HDR + evil, "pppoe0")
    assert row["proto"] == "OTHER" and row["dest_port"] is None


def _send(port, *datagrams):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for d in datagrams:
        s.sendto(d, ("127.0.0.1", port))
    s.close()


def _wait(pred, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_listener_solo_acepta_el_origen_permitido():
    ok = filterlog.Listener(0, frozenset({"127.0.0.1"}), "pppoe0", host="127.0.0.1")
    ok.start()
    try:
        _send(ok.port, HDR + TCP4, HDR + TCP4.replace(b",block,", b",pass,"))
        assert _wait(lambda: len(ok.queue) == 2)
        assert [k for k, _ in ok.queue] == ["row", "discard"]
    finally:
        ok.stop()
        ok.join(3)
    other = filterlog.Listener(0, frozenset({"192.168.1.1"}), "pppoe0", host="127.0.0.1")
    other.start()
    try:
        _send(other.port, HDR + TCP4)
        assert _wait(lambda: len(other.queue) == 1)
        assert other.queue[0] == ("discard", "source")
    finally:
        other.stop()
        other.join(3)


def test_listener_cola_llena(monkeypatch):
    monkeypatch.setattr(filterlog, "QUEUE_MAX", 1)
    li = filterlog.Listener(0, frozenset({"127.0.0.1"}), "pppoe0", host="127.0.0.1")
    li.start()
    try:
        _send(li.port, HDR + TCP4, HDR + TCP4, HDR + TCP4)
        assert _wait(lambda: li.dropped == 2)
        assert len(li.queue) == 1
    finally:
        li.stop()
        li.join(3)


def test_colector_guarda_bloqueos_con_geoip(geo_dir, tmp_path):
    cfg = config.load({"DB_PATH": str(tmp_path / "fw.db"), "GEOIP_DIR": str(geo_dir)})
    c = Collector(cfg)
    c.fw = filterlog.Listener(0, frozenset({"127.0.0.1"}), "pppoe0", host="127.0.0.1")   # sin arrancar el hilo
    c.fw.queue.extend([
        ("row", filterlog.parse(HDR + TCP4.replace(b"198.51.100.23", b"81.2.69.142"), "pppoe0")),
        ("discard", "action"), ("discard", "action"), ("discard", "source"),
    ])
    assert c.process_firewall() == 1
    assert c.db.execute("SELECT remote_ip, proto, dest_port, country_iso, city FROM firewall_events").fetchall() == [
        ("81.2.69.142", "TCP", 22, "GB", "Londres")]
    assert c.stats == {"fw_stored": 1, "fw_discarded_action": 2, "fw_discarded_source": 1}
    assert c.db.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 0
    c.fw.sock.close()


def test_sin_puerto_no_hay_listener(tmp_path):
    c = Collector(config.load({"DB_PATH": str(tmp_path / "n.db"), "GEOIP_DIR": str(tmp_path)}))
    assert c.fw is None and c.process_firewall() == 0


@pytest.mark.parametrize("env", [
    {"FW_SYSLOG_PORT": "5140"},                                   # falta PFSENSE_IP
    {"FW_SYSLOG_PORT": "5140", "PFSENSE_IP": "pfsense"},
    {"FW_SYSLOG_PORT": "70000", "PFSENSE_IP": "192.168.1.1"},
    {"FW_IFACE": "pppoe0; DROP"},
    {"FW_RETENTION_DAYS": "0"},
    {"FW_BIND": "nas.local"},
])
def test_config_firewall_invalida(env):
    with pytest.raises(config.ConfigError):
        config.load(env)


def test_config_firewall():
    cfg = config.load({"FW_SYSLOG_PORT": "5140", "PFSENSE_IP": "192.168.1.1"})
    assert (cfg.fw_syslog_port, cfg.fw_sources, cfg.fw_iface, cfg.fw_retention_days, cfg.fw_bind) == (
        5140, frozenset({"192.168.1.1"}), "pppoe0", 30, "0.0.0.0")
    assert config.load({"FW_BIND": "192.168.1.10"}).fw_bind == "192.168.1.10"


def test_retencion_propia_del_firewall(tmp_path):
    conn = store.connect(str(tmp_path / "r.db"))
    store.migrate(conn)
    now = 1_790_150_400_000
    day = retention.DAY_MS
    store.insert_batch(conn, [{"ts_ms": now - d * day, "remote_ip": "198.51.100.23"} for d in (1, 29, 31, 60)],
                       firewall=True)
    assert retention.run(conn, 90, now_ms=now, fw_days=30) == 2
    assert [r[0] for r in conn.execute("SELECT ts_ms FROM firewall_events ORDER BY ts_ms DESC")] == [
        now - day, now - 29 * day]
