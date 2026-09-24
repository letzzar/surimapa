"""Bucle principal del colector: Redis (BRPOP) → parser → SQLite.

Pérdida asumida: si el proceso muere entre el POP y el
COMMIT se pierde ese lote (≤ BATCH_MAX eventos).
"""
from __future__ import annotations

import logging
import signal
import sqlite3
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import redis

from . import backup, config, filterlog, geoip, parser, retention, store

log = logging.getLogger("surimapa.collector")

HEARTBEAT_KEY = "surimapa:collector:heartbeat"
STATS_KEY = "surimapa:collector:stats"
BACKOFF_MAX_S = 30
FW_BATCH_MAX = filterlog.QUEUE_MAX


class Collector:
    def __init__(self, cfg: config.Config):
        self.cfg = cfg
        self.stop = False
        self.stats = Counter()          # processed, discarded_<motivo>, errors
        self.redis: redis.Redis | None = None
        self.db = store.connect(cfg.db_path)
        version = store.migrate(self.db)
        log.info("BD lista en %s (schema_version=%s)", cfg.db_path, version)
        self.geoip = geoip.GeoIP(cfg.geoip_dir)
        self.next_retention = retention.next_run(datetime.now(timezone.utc), cfg.tz)
        log.info("Retención: %d días; próxima ejecución %s", cfg.retention_days, self.next_retention.isoformat())
        self.fw: filterlog.Listener | None = None
        if cfg.fw_syslog_port:
            self.fw = filterlog.Listener(cfg.fw_syslog_port, cfg.fw_sources, cfg.fw_iface, host=cfg.fw_bind)
            self.fw.start()

    # ---------- Redis ----------
    def _redis(self) -> redis.Redis:
        if self.redis is None:
            self.redis = redis.Redis.from_url(
                self.cfg.redis_url,
                username=self.cfg.redis_user,
                password=self.cfg.redis_password,
                socket_timeout=10,
                socket_connect_timeout=5,
                health_check_interval=30,
            )
        return self.redis

    def _pop_batch(self) -> list[bytes]:
        r = self._redis()
        first = r.brpop([self.cfg.redis_key], timeout=1)
        if first is None:
            return []
        batch = [first[1]]
        if self.cfg.batch_max > 1:
            # Modo "List (LPUSH)" de pfSense: lo más antiguo está a la derecha → RPOP = FIFO.
            more = r.rpop(self.cfg.redis_key, self.cfg.batch_max - 1)
            if more:
                batch.extend(more)
        return batch

    # ---------- Procesado ----------
    def process(self, messages: list[bytes]) -> int:
        rows = []
        for message in messages:
            try:
                row = parser.normalize(message, self.cfg.wan_ips)
            except parser.Discard as d:
                self.stats[f"discarded_{d.reason}"] += 1
                continue
            row.update(self.geoip.lookup(row["remote_ip"]))
            rows.append(row)
        try:
            store.insert_batch(self.db, rows)
        except sqlite3.Error:
            self.stats["errors"] += 1
            log.exception("No se pudo guardar un lote de %d eventos (se pierde)", len(rows))
            return 0
        self.stats["processed"] += len(rows)
        return len(rows)

    def process_firewall(self) -> int:
        """Vacía la cola del hilo de syslog: GeoIP aquí (mismo hilo que maybe_reload) y un INSERT por lote."""
        if self.fw is None:
            return 0
        rows = []
        while self.fw.queue and len(rows) < FW_BATCH_MAX:
            kind, item = self.fw.queue.popleft()
            if kind == "discard":
                self.stats[f"fw_discarded_{item}"] += 1
                continue
            item.update(self.geoip.lookup(item["remote_ip"]))
            rows.append(item)
        if self.fw.dropped:
            self.stats["fw_dropped_queue_full"] = self.fw.dropped
        try:
            store.insert_batch(self.db, rows, firewall=True)
        except sqlite3.Error:
            self.stats["errors"] += 1
            log.exception("No se pudo guardar un lote de %d bloqueos del firewall (se pierde)", len(rows))
            return 0
        self.stats["fw_stored"] += len(rows)
        return len(rows)

    def heartbeat(self) -> None:
        now = int(time.time())
        pipe = self._redis().pipeline(transaction=False)
        pipe.set(HEARTBEAT_KEY, now, ex=120)
        pipe.hset(STATS_KEY, mapping={k: v for k, v in self.stats.items()} | {"updated": now})
        pipe.execute()
        # Solo tras hablar con Redis: si Redis cae, el fichero envejece y el contenedor pasa a unhealthy.
        Path(self.cfg.heartbeat_file).touch()
        log.info("heartbeat %s", dict(sorted(self.stats.items())))

    def maybe_retention(self) -> None:
        now = datetime.now(timezone.utc)
        if now < self.next_retention:
            return
        try:
            self.stats["retention_deleted"] += retention.run(
                self.db, self.cfg.retention_days, fw_days=self.cfg.fw_retention_days)
        except sqlite3.Error:
            self.stats["errors"] += 1
            log.exception("Fallo en la retención; se reintentará mañana")
        try:                                          # la copia se hace aunque falle la retención
            backup.run(self.db, self.cfg.backup_dir, now.astimezone(self.cfg.tz).date(), self.cfg.backup_keep)
            self.stats["backups"] += 1
        except (sqlite3.Error, OSError):
            self.stats["backup_errors"] += 1
            log.exception("Fallo en la copia de seguridad; se reintentará mañana")
        self.next_retention = retention.next_run(now, self.cfg.tz)

    # ---------- Bucle ----------
    def run(self) -> None:
        backoff = 1
        next_beat = 0.0
        while not self.stop:
            try:
                self.geoip.maybe_reload()
                self.process_firewall()                  # no depende de Redis: se vacía aunque Redis caiga
                self.maybe_retention()
                if time.monotonic() >= next_beat:
                    self.heartbeat()
                    next_beat = time.monotonic() + self.cfg.heartbeat_s
                batch = self._pop_batch()
                if batch:
                    self.process(batch)
                backoff = 1
            except redis.RedisError as exc:
                self.stats["redis_errors"] += 1
                log.warning("Redis no disponible (%s); reintento en %d s", exc.__class__.__name__, backoff)
                self.redis = None
                self._sleep(backoff)
                backoff = min(backoff * 2, BACKOFF_MAX_S)
        if self.fw is not None:
            self.fw.stop()
            self.fw.join(timeout=3)
            self.process_firewall()                          # lo que quedase en la cola
        log.info("Parada limpia. Totales: %s", dict(sorted(self.stats.items())))
        self.db.close()

    def _sleep(self, seconds: float) -> None:
        end = time.monotonic() + seconds
        while not self.stop and time.monotonic() < end:
            time.sleep(0.2)

    def request_stop(self, signum, _frame) -> None:
        log.info("Señal %s recibida: terminando el lote en curso", signal.Signals(signum).name)
        self.stop = True


def main() -> None:
    cfg = config.load()
    logging.basicConfig(level=cfg.log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    log.info("Arrancando: cola=%s, WAN_IPS=%d, lote=%d", cfg.redis_key, len(cfg.wan_ips), cfg.batch_max)
    collector = Collector(cfg)
    signal.signal(signal.SIGTERM, collector.request_stop)
    signal.signal(signal.SIGINT, collector.request_stop)
    collector.run()


if __name__ == "__main__":
    main()
