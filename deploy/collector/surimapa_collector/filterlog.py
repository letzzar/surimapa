"""Bloqueos del firewall de pfSense: `filterlog` por syslog UDP (RFC 3164) → fila de `firewall_events`.

Solo se guardan los paquetes bloqueados o rechazados que ENTRAN por la interfaz WAN
(FW_IFACE) desde una IP pública: lo que tiene sentido en el mapa. El resto se descarta.

Todo lo que llega es dato NO confiable: el syslog por UDP se puede falsificar desde la LAN,
así que solo se aceptan datagramas cuyo origen sea pfSense (PFSENSE_IP), y cada campo se
valida antes de usarlo. No se guarda el mensaje original.

Formato de `filterlog` (CSV tras "filterlog[pid]: "), campos comunes:
  0 regla, 1 subregla, 2 ancla, 3 tracker, 4 interfaz, 5 motivo, 6 acción, 7 sentido, 8 versión IP
IPv4: 16 protocolo (texto), 18 origen, 19 destino, 20 puerto origen, 21 puerto destino (tcp/udp)
IPv6: 12 protocolo (texto), 15 origen, 16 destino, 17 puerto origen, 18 puerto destino (tcp/udp)
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import threading
import time
from collections import deque

from .parser import Discard, is_local

log = logging.getLogger("surimapa.filterlog")

MAX_DATAGRAM = 2048             # una línea de filterlog ronda los 200 B
QUEUE_MAX = 20_000              # colchón entre el hilo UDP y el bucle principal
ACTIONS = ("block", "reject")
_MSG = re.compile(rb"\bfilterlog(?:\[\d{1,10}\])?: ([\x20-\x7e]+)")
_PROTO = re.compile(r"[a-z0-9-]{1,16}")


def _port(raw: str) -> int | None:
    if raw.isdigit() and len(raw) <= 5 and int(raw) <= 65535:
        return int(raw)
    return None


def parse(datagram: bytes, iface: str, now_ms: int | None = None) -> dict:
    """Datagrama syslog → fila (sin GeoIP). Lanza Discard(motivo) si no se guarda."""
    if len(datagram) > MAX_DATAGRAM:
        raise Discard("too_long")
    m = _MSG.search(datagram)
    if m is None:
        raise Discard("not_filterlog")
    f = m.group(1).decode("ascii").rstrip().split(",")
    if len(f) < 9:
        raise Discard("malformed")
    if f[4] != iface:
        raise Discard("iface")
    if f[6] not in ACTIONS:
        raise Discard("action")
    if f[7] != "in":
        raise Discard("direction")
    if f[8] == "4" and len(f) >= 20:
        proto, src, rest = f[16], f[18], f[20:]
    elif f[8] == "6" and len(f) >= 17:
        proto, src, rest = f[12], f[15], f[17:]
    else:
        raise Discard("malformed")
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        raise Discard("malformed") from None
    if is_local(ip):
        raise Discard("local_src")
    proto = proto.lower()
    dest_port = _port(rest[1]) if proto in ("tcp", "udp") and len(rest) >= 2 else None
    return {
        "ts_ms": int(time.time() * 1000) if now_ms is None else now_ms,   # RFC 3164 no trae año ni zona
        "remote_ip": ip.compressed,
        "proto": proto.upper() if _PROTO.fullmatch(proto) else "OTHER",
        "dest_port": dest_port,
    }


class Listener(threading.Thread):
    """Hilo que recibe el syslog UDP, lo filtra y deja en `queue` tuplas:
    ("row", fila) o ("discard", motivo). El bucle principal las vacía (único escritor de SQLite)."""

    def __init__(self, port: int, allowed_sources: frozenset[str], iface: str, host: str = "0.0.0.0"):
        super().__init__(name="filterlog", daemon=True)
        self.allowed, self.iface = allowed_sources, iface
        self.queue: deque = deque()
        self.dropped = 0            # descartados por cola llena (solo lo escribe este hilo)
        self.stopping = threading.Event()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((host, port))
        self.sock.settimeout(1)

    @property
    def port(self) -> int:
        return self.sock.getsockname()[1]

    def run(self) -> None:
        log.info("Escuchando syslog UDP en el puerto %d (origen permitido: %s, interfaz %s)",
                 self.port, ", ".join(sorted(self.allowed)), self.iface)
        while not self.stopping.is_set():
            try:
                data, (addr, _port) = self.sock.recvfrom(MAX_DATAGRAM + 1)
            except TimeoutError:
                continue
            except OSError:
                if self.stopping.is_set():
                    break
                log.exception("Error recibiendo syslog")
                continue
            if len(self.queue) >= QUEUE_MAX:
                self.dropped += 1
                continue
            if addr not in self.allowed:
                self.queue.append(("discard", "source"))
                continue
            try:
                self.queue.append(("row", parse(data, self.iface)))
            except Discard as d:
                self.queue.append(("discard", d.reason))
        self.sock.close()

    def stop(self) -> None:
        self.stopping.set()
