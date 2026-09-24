"""GeoIP (GeoLite2 City + ASN) con recarga automática de los .mmdb.

- Lectura con MODE_MMAP: la base no se carga en la RAM del proceso.
- Cada `check_s` segundos se compara el mtime y se reabre si geoipupdate la cambió.
- Si falta una base, se devuelven campos a None (aviso en log como mucho 1 vez/hora).
"""
from __future__ import annotations

import logging
import os
import re
import time

import maxminddb

log = logging.getLogger("surimapa.geoip")

CITY_FILE = "GeoLite2-City.mmdb"
ASN_FILE = "GeoLite2-ASN.mmdb"
FIELDS = ("country_iso", "country", "city", "lat", "lon", "asn", "as_org")
EMPTY = dict.fromkeys(FIELDS)

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ISO = re.compile(r"^[A-Z]{2}$")


def _name(record: dict | None, limit: int = 128) -> str | None:
    """Nombre en español con respaldo en inglés, sin controles y truncado."""
    names = (record or {}).get("names") or {}
    value = names.get("es") or names.get("en")
    if not isinstance(value, str):
        return None
    return _CONTROL.sub("", value).strip()[:limit] or None


def _coord(value, limit: float) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if -limit <= value <= limit else None


class _Db:
    """Un .mmdb que se reabre si cambia su mtime."""

    def __init__(self, path: str):
        self.path = path
        self.reader: maxminddb.Reader | None = None
        self.mtime: float | None = None
        self.last_warning = 0.0

    def refresh(self) -> None:
        try:
            mtime = os.stat(self.path).st_mtime
        except FileNotFoundError:
            self._close()
            if time.monotonic() - self.last_warning >= 3600 or not self.last_warning:
                log.warning("No existe %s: los campos de GeoIP quedarán vacíos", self.path)
                self.last_warning = time.monotonic()
            return
        if mtime == self.mtime and self.reader is not None:
            return
        try:
            reader = maxminddb.open_database(self.path, maxminddb.MODE_MMAP)
        except (OSError, maxminddb.InvalidDatabaseError) as exc:
            log.warning("No se pudo abrir %s (%s): se mantiene la versión anterior", self.path, exc)
            return
        self._close()
        self.reader, self.mtime = reader, mtime
        meta = reader.metadata()
        log.info("GeoIP cargada: %s (%s, build %s)", os.path.basename(self.path),
                 meta.database_type, time.strftime("%Y-%m-%d", time.gmtime(meta.build_epoch)))

    def get(self, ip: str) -> dict | None:
        if self.reader is None:
            return None
        try:
            record = self.reader.get(ip)
        except (ValueError, maxminddb.InvalidDatabaseError):
            return None
        return record if isinstance(record, dict) else None

    def _close(self) -> None:
        if self.reader is not None:
            self.reader.close()
        self.reader, self.mtime = None, None


class GeoIP:
    def __init__(self, directory: str, check_s: int = 3600):
        self.city = _Db(os.path.join(directory, CITY_FILE))
        self.asn = _Db(os.path.join(directory, ASN_FILE))
        self.check_s = check_s
        self.next_check = 0.0
        self.maybe_reload()

    def maybe_reload(self, force: bool = False) -> None:
        if not force and time.monotonic() < self.next_check:
            return
        self.city.refresh()
        self.asn.refresh()
        self.next_check = time.monotonic() + self.check_s

    def lookup(self, ip: str | None) -> dict:
        """Devuelve siempre los 7 campos (None si no hay dato)."""
        if not ip:
            return dict(EMPTY)
        out = dict(EMPTY)
        city = self.city.get(ip)
        if city:
            country = city.get("country") or city.get("registered_country") or {}
            iso = country.get("iso_code")
            out["country_iso"] = iso if isinstance(iso, str) and _ISO.match(iso) else None
            out["country"] = _name(country)
            out["city"] = _name(city.get("city"))
            loc = city.get("location") or {}
            out["lat"] = _coord(loc.get("latitude"), 90)
            out["lon"] = _coord(loc.get("longitude"), 180)
        asn = self.asn.get(ip)
        if asn:
            number = asn.get("autonomous_system_number")
            if isinstance(number, int) and not isinstance(number, bool) and 0 < number < 2**32:
                out["asn"] = number
            org = asn.get("autonomous_system_organization")
            if isinstance(org, str):
                out["as_org"] = _CONTROL.sub("", org).strip()[:128] or None
        return out
