"""EVE JSON de Suricata → fila normalizada para la tabla `events`.

Todo lo que llega es dato NO confiable (puede estar controlado por un atacante):
se valida cada campo, se truncan los textos, se quitan caracteres de control y
no se guardan payloads ni volcados de paquetes.
"""
from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime

MAX_SIGNATURE = 256
MAX_CATEGORY = 128
MAX_SHORT = 32          # iface, proto, app_proto, action
MAX_RAW_BYTES = 4096
INT64_MAX = 2**63 - 1

# Campos que nunca se guardan en `raw`.
DROP_KEYS = ("payload", "payload_printable", "packet", "http")

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# Redes "propias o sin sentido geográfico". Lista explícita en lugar de `is_global`,
# que también excluye los rangos de documentación usados en los tests.
LOCAL_NETS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",   # RFC 1918
    "100.64.0.0/10",                                    # CGNAT / Tailscale
    "127.0.0.0/8", "169.254.0.0/16", "0.0.0.0/32",
    "224.0.0.0/4", "255.255.255.255/32",                # multicast / broadcast
    "::1/128", "::/128", "fc00::/7", "fe80::/10", "ff00::/8",
))


class Discard(Exception):
    """El mensaje no se guarda. `reason` sirve para las métricas."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _text(value, limit: int) -> str | None:
    if value is None:
        return None
    text = _CONTROL.sub("", str(value)).strip()
    return text[:limit] or None


def _int(value, lo: int, hi: int) -> int | None:
    # bool es subclase de int: no aceptarlo como número.
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value if lo <= value <= hi else None


def _ip(value):
    if not isinstance(value, str):
        raise Discard("bad_ip")
    try:
        return ipaddress.ip_address(value.strip())
    except ValueError:
        raise Discard("bad_ip") from None


def _ts_ms(value) -> int:
    # Suricata: 2026-09-23T10:47:37.161496+0200
    if not isinstance(value, str):
        raise Discard("bad_timestamp")
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            raise Discard("bad_timestamp") from None
    if dt.tzinfo is None:
        raise Discard("bad_timestamp")
    return int(dt.timestamp() * 1000)


def is_local(ip, wan_ips: frozenset[str] = frozenset()) -> bool:
    return ip.compressed in wan_ips or any(ip.version == n.version and ip in n for n in LOCAL_NETS)


def _direction(src, dest, wan_ips: frozenset[str]):
    """Devuelve (remote_ip, direction) según qué extremos son locales (LOCAL_NETS + WAN_IPS)."""
    src_local = is_local(src, wan_ips)
    dest_local = is_local(dest, wan_ips)
    if src_local and dest_local:
        return None, "local"
    if src_local:
        return dest.compressed, "out"
    return src.compressed, "in"     # dest local, o ambas externas


def _raw(event: dict) -> tuple[str, int]:
    reduced = {k: v for k, v in event.items() if k not in DROP_KEYS}
    text = json.dumps(reduced, ensure_ascii=False, separators=(",", ":"))
    data = text.encode("utf-8")
    if len(data) <= MAX_RAW_BYTES:
        return text, 0
    return data[:MAX_RAW_BYTES].decode("utf-8", "ignore"), 1


def normalize(message: bytes | str, wan_ips: frozenset[str] = frozenset()) -> dict:
    """Convierte un mensaje EVE en una fila. Lanza Discard si no se debe guardar."""
    if isinstance(message, bytes):
        message = message.decode("utf-8", "replace")
    try:
        event = json.loads(message)
    except (json.JSONDecodeError, RecursionError):
        raise Discard("invalid_json") from None
    if not isinstance(event, dict):
        raise Discard("invalid_json")
    if event.get("event_type") != "alert":
        raise Discard("not_alert")
    alert = event.get("alert")
    if not isinstance(alert, dict):
        raise Discard("missing_alert")

    src = _ip(event.get("src_ip"))
    dest = _ip(event.get("dest_ip"))
    remote_ip, direction = _direction(src, dest, wan_ips)
    raw, raw_truncated = _raw(event)

    return {
        "ts_ms": _ts_ms(event.get("timestamp")),
        "iface": _text(event.get("in_iface"), MAX_SHORT),
        "direction": direction,
        "src_ip": src.compressed,
        "src_port": _int(event.get("src_port"), 0, 65535),
        "dest_ip": dest.compressed,
        "dest_port": _int(event.get("dest_port"), 0, 65535),
        "proto": _text(event.get("proto"), MAX_SHORT),
        "app_proto": _text(event.get("app_proto"), MAX_SHORT),
        "remote_ip": remote_ip,
        "sid": _int(alert.get("signature_id"), 0, INT64_MAX),
        "signature": _text(alert.get("signature"), MAX_SIGNATURE),
        "category": _text(alert.get("category"), MAX_CATEGORY),
        "severity": _int(alert.get("severity"), 1, 255),
        "action": _text(alert.get("action"), MAX_SHORT),
        "flow_id": _int(event.get("flow_id"), 0, INT64_MAX),
        "raw": raw,
        "raw_truncated": raw_truncated,
    }
