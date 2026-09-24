"""Configuración del colector a partir de variables de entorno."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class ConfigError(ValueError):
    """Variable de entorno ausente o inválida."""


@dataclass(frozen=True)
class Config:
    redis_url: str
    redis_user: str | None
    redis_password: str | None
    redis_key: str
    db_path: str
    geoip_dir: str
    wan_ips: frozenset[str]      # IP públicas propias (normalizadas), tratadas como locales
    batch_max: int
    heartbeat_s: int
    retention_days: int
    backup_dir: str
    backup_keep: int
    tz: ZoneInfo
    heartbeat_file: str          # su mtime lo usa el HEALTHCHECK del contenedor
    log_level: str
    fw_syslog_port: int          # 0 = sin ingesta de bloqueos del firewall
    fw_sources: frozenset[str]   # IP desde las que se acepta el syslog (pfSense)
    fw_iface: str                # interfaz WAN en filterlog (pppoe0)
    fw_bind: str                 # IP local en la que escucha el syslog (en el NAS, la IP LAN)
    fw_retention_days: int


def _int(env: dict[str, str], name: str, default: int, lo: int, hi: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} debe ser un entero") from exc
    if not lo <= value <= hi:
        raise ConfigError(f"{name} debe estar entre {lo} y {hi}")
    return value


def _wan_ips(raw: str, name: str = "WAN_IPS") -> frozenset[str]:
    ips = set()
    for part in raw.replace(";", ",").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            ips.add(ipaddress.ip_address(part).compressed)
        except ValueError as exc:
            raise ConfigError(f"{name} contiene una IP inválida: {part!r}") from exc
    return frozenset(ips)


def _tz(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise ConfigError(f"TZ desconocida: {name!r}") from exc


def load(env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    key = env.get("REDIS_KEY", "suricata").strip() or "suricata"
    if not key.isalnum():
        raise ConfigError("REDIS_KEY debe ser alfanumérica (igual que en pfSense)")
    fw_port = _int(env, "FW_SYSLOG_PORT", 0, 0, 65535)
    fw_sources = _wan_ips(env.get("PFSENSE_IP", ""), "PFSENSE_IP")
    if fw_port and not fw_sources:
        raise ConfigError("FW_SYSLOG_PORT requiere PFSENSE_IP (origen permitido del syslog)")
    fw_bind = env.get("FW_BIND", "").strip() or "0.0.0.0"
    try:
        ipaddress.IPv4Address(fw_bind)
    except ValueError as exc:
        raise ConfigError(f"FW_BIND debe ser una IPv4: {fw_bind!r}") from exc
    fw_iface = env.get("FW_IFACE", "").strip() or "pppoe0"
    if not fw_iface.replace(".", "").replace("_", "").isalnum() or len(fw_iface) > 32:
        raise ConfigError("FW_IFACE no es un nombre de interfaz válido")
    return Config(
        redis_url=env.get("REDIS_URL", "redis://redis:6379/0").strip(),
        redis_user=env.get("REDIS_USER", "").strip() or None,
        redis_password=env.get("REDIS_PASSWORD") or None,
        redis_key=key,
        db_path=env.get("DB_PATH", "/data/surimapa.db").strip(),
        geoip_dir=env.get("GEOIP_DIR", "/geoip").strip(),
        wan_ips=_wan_ips(env.get("WAN_IPS", "")),
        batch_max=_int(env, "BATCH_MAX", 500, 1, 5000),
        heartbeat_s=_int(env, "HEARTBEAT_S", 30, 5, 3600),
        retention_days=_int(env, "RETENTION_DAYS", 90, 1, 3650),
        backup_dir=env.get("BACKUP_DIR", "/backups").strip(),
        backup_keep=_int(env, "BACKUP_KEEP", 7, 1, 365),
        tz=_tz(env.get("TZ", "").strip() or "UTC"),
        heartbeat_file=env.get("HEARTBEAT_FILE", "/tmp/surimapa-heartbeat").strip(),
        log_level=(env.get("LOG_LEVEL", "INFO").strip().upper() or "INFO"),
        fw_syslog_port=fw_port,
        fw_sources=fw_sources,
        fw_iface=fw_iface,
        fw_bind=fw_bind,
        fw_retention_days=_int(env, "FW_RETENTION_DAYS", 30, 1, 3650),
    )
