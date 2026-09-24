#!/usr/bin/env python3
"""Mide el tiempo de respuesta de la API con N filas sintéticas.

Uso (desde la raíz del proyecto, en el contenedor de pruebas):
    python scripts/bench_api.py --rows 200000
    python scripts/bench_api.py --rows 1000000 --db /tmp/bench.db

Genera una BD con el esquema real del colector repartiendo las filas en 90 días
(distribución sesgada de IP, firmas y países, como en el tráfico real), y mide
la mediana de cada endpoint en proceso (sin red).
"""
from __future__ import annotations

import argparse
import random
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "deploy" / "collector"), str(ROOT / "deploy" / "portal")]

from surimapa_collector import store  # noqa: E402

DAY = 86_400_000
COUNTRIES = [("US", "Estados Unidos", 38.0, -97.0), ("FR", "Francia", 48.9, 2.4), ("CA", "Canadá", 45.4, -75.7),
             ("NL", "Países Bajos", 52.4, 4.9), ("BG", "Bulgaria", 42.7, 23.3), ("DE", "Alemania", 50.1, 8.7),
             ("CN", "China", 39.9, 116.4), ("RU", "Rusia", 55.8, 37.6), ("BR", "Brasil", -23.5, -46.6),
             ("IN", "India", 19.1, 72.9)] + [(f"X{i}", f"País {i}", random.uniform(-50, 60), random.uniform(-170, 170))
                                            for i in range(50)]


def build(path: str, rows: int, seed: int = 1, raw_bytes: int = 800) -> None:
    rng = random.Random(seed)
    conn = store.connect(path)
    store.migrate(conn)
    now = int(time.time() * 1000)
    # Cardinalidades medidas en datos reales (2026-09-24): ~40 % de IP distintas, pocas coordenadas
    # (GeoLite devuelve centroides de ciudad) y unas 300 firmas.
    ips = [f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
           for _ in range(max(1000, rows * 2 // 5))]
    cities = [(round(lat + rng.uniform(-3, 3), 4), round(lon + rng.uniform(-3, 3), 4), f"Ciudad {k}")
              for k, (_, _, lat, lon) in enumerate(COUNTRIES * 35)]              # ~2.100 centroides
    batch = []
    for i in range(rows):
        ip = ips[min(int(rng.paretovariate(1.2)) - 1, len(ips) - 1)]
        ci = min(int(rng.paretovariate(1.5)) - 1, len(COUNTRIES) - 1)
        iso, name, _, _ = COUNTRIES[ci]
        lat, lon, city = cities[ci + len(COUNTRIES) * rng.randrange(35)]
        sid = 2400000 + min(int(rng.paretovariate(1.3)), 300)
        batch.append({
            "ts_ms": now - int(i * 90 * DAY / rows), "iface": "pppoe0",
            "direction": "in" if rng.random() < 0.97 else "out",
            "src_ip": ip, "src_port": rng.randint(1024, 65535), "dest_ip": "192.0.2.10",
            "dest_port": rng.choice([22, 23, 80, 443, 445, 3389, 8080, 5060, rng.randint(1, 65535)]),
            "proto": "TCP", "remote_ip": ip, "sid": sid, "signature": f"ET CINS Poor Reputation IP group {sid % 300}",
            "category": "Misc Attack", "severity": rng.choice([2, 2, 2, 2, 1, 3]), "action": "allowed",
            "flow_id": i, "country_iso": iso, "country": name, "city": city, "lat": lat, "lon": lon,
            "asn": 10000 + min(int(rng.paretovariate(1.2)), 5000), "as_org": "AS de prueba",
            "raw": '{"event_type":"alert","x":"' + "a" * raw_bytes + '"}', "raw_truncated": 0,
        })
        if len(batch) == 5000:
            store.insert_batch(conn, batch)
            batch = []
    store.insert_batch(conn, batch)
    conn.execute("PRAGMA optimize")
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


def bench(path: str, repeat: int) -> list[tuple[str, float]]:
    from fastapi.testclient import TestClient
    from app import api
    from app import db as pdb
    from app.main import app

    pdb.DB_PATH = path
    client = TestClient(app)
    ip = client.get("/api/top/remote_ip?range=90d&limit=1").json()["items"][0]["key"]
    urls = [f"/api/{u}" for u in (
        "summary?range=24h", "summary?range=90d", "timeline?range=24h", "timeline?range=90d",
        "top/remote_ip?range=24h", "top/remote_ip?range=90d", "top/signature?range=90d", "top/country?range=90d",
        "top/asn?range=90d", "top/dest_port?range=90d", "map?range=24h", "map?range=90d",
        "events?range=24h&page=1&size=25", "events?range=90d&page=1&size=25",
        "events?range=90d&q=Reputation%20IP%20group%2017", f"events?range=90d&q={ip}", "events/1", f"ip/{ip}",
    )]
    out = []
    for url in urls:
        times = []
        for _ in range(repeat):
            api.cache.clear()                               # medir siempre sin caché
            t0 = time.perf_counter()
            r = client.get(url)
            times.append((time.perf_counter() - t0) * 1000)
            assert r.status_code == 200, (url, r.status_code, r.text[:200])
        out.append((url.replace(ip, "<ip>"), statistics.median(times)))
    # Caché de 30d/90d: coste del precálculo (cada 5 min en el portal) y de servir desde ella.
    api.cache.clear()
    t0 = time.perf_counter()
    n = api.warm_long_ranges()
    warm_ms = (time.perf_counter() - t0) * 1000
    hits = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        client.get("/api/map?range=90d")
        hits.append((time.perf_counter() - t0) * 1000)
    print(f"Precálculo 30d/90d: {n} respuestas en {warm_ms:.0f} ms | /api/map?range=90d desde caché: "
          f"{statistics.median(hits):.1f} ms")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", type=int, default=200_000)
    ap.add_argument("--db", default="/tmp/surimapa-bench.db")
    ap.add_argument("--repeat", type=int, default=5)
    ap.add_argument("--limit-ms", type=float, default=200)
    ap.add_argument("--raw-bytes", type=int, default=800, help="tamaño del raw sintético (real ≈ 900 B)")
    args = ap.parse_args()
    for suffix in ("", "-wal", "-shm"):
        Path(args.db + suffix).unlink(missing_ok=True)
    t0 = time.perf_counter()
    build(args.db, args.rows, raw_bytes=args.raw_bytes)
    size = Path(args.db).stat().st_size / 1e6
    print(f"BD: {args.rows:,} filas, {size:.0f} MB, generada en {time.perf_counter() - t0:.0f} s")
    worst = 0.0
    for url, ms in bench(args.db, args.repeat):
        worst = max(worst, ms)
        print(f"{'OK ' if ms < args.limit_ms else 'LENTO'} {ms:8.1f} ms  {url}")
    print(f"Peor mediana: {worst:.1f} ms (límite {args.limit_ms:.0f} ms)")
    return 0 if worst < args.limit_ms else 1


if __name__ == "__main__":
    sys.exit(main())
