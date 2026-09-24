#!/usr/bin/env python3
"""Inyecta eventos EVE de ejemplo en Redis, igual que Suricata en modo "List (LPUSH)".

Uso (desarrollo):
    python3 scripts/send_test_events.py --count 200 --rate 20
    python3 scripts/send_test_events.py --redis-url redis://127.0.0.1:6379/0 --count 50

Usa el usuario Redis anónimo (el de Suricata: solo LPUSH/RPUSH/PING).
IP de documentación: remotas en 198.51.100.0/24, 203.0.113.0/24 y 2001:db8::/32; IP WAN propia
192.0.2.10 y 2001:db8:ffff::10 (añadir WAN_IPS=192.0.2.10,2001:db8:ffff::10 al .env de desarrollo
para que las salientes se clasifiquen bien).
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone

import redis

WAN_IP = "192.0.2.10"
LAN_IPS = ["192.168.1.20", "192.168.1.10", "fd00::20"]
SIGNATURES = [
    (2403445, "ET CINS Active Threat Intelligence Poor Reputation IP group 146", "Misc Attack", 2),
    (2402000, "ET DROP Dshield Block Listed Source group 1", "Misc Attack", 2),
    (2001219, "ET SCAN Potential SSH Scan", "Attempted Information Leak", 2),
    (2024792, "ET SCAN Suspicious inbound to MSSQL port 1433", "Potentially Bad Traffic", 2),
    (2019284, "ET WEB_SERVER Possible XSS <script>alert(1)</script>", "Web Application Attack", 1),
    (2027865, "ET INFO Observed DNS Query to .cloud TLD", "Potentially Bad Traffic", 3),
]
PORTS = [22, 23, 80, 443, 445, 1433, 3389, 8080, 8443]
TZ = timezone(timedelta(hours=2))


def remote_ip(rng: random.Random) -> str:
    if rng.random() < 0.1:
        return f"2001:db8::{rng.randint(1, 0xffff):x}"
    return f"{rng.choice(['198.51.100', '203.0.113'])}.{rng.randint(1, 254)}"


def alert(rng: random.Random, flow_id: int) -> dict:
    sid, sig, cat, sev = rng.choice(SIGNATURES)
    kind = rng.choices(["in", "out", "local"], weights=[85, 10, 5])[0]
    remote = remote_ip(rng)
    own = WAN_IP if ":" not in remote else "2001:db8:ffff::10"
    if kind == "in":
        src, dest = remote, own
    elif kind == "out":
        src, dest = own, remote
    else:
        src, dest = rng.sample(LAN_IPS[:2], 2)
    if rng.random() < 0.02:
        sig = "ET TEST <img src=x onerror=alert(1)>\x00\x1b[31m control\x7f"
    return {
        "timestamp": datetime.now(TZ).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
        "flow_id": flow_id,
        "in_iface": "pppoe0",
        "event_type": "alert",
        "src_ip": src, "src_port": rng.randint(1024, 65535),
        "dest_ip": dest, "dest_port": rng.choice(PORTS),
        "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                  "signature": sig, "category": cat, "severity": sev},
        "direction": "to_server",
        "packet": "AAAA",
        "host": "pfsense.local",
    }


def message(rng: random.Random, i: int) -> str:
    roll = rng.random()
    if roll < 0.02:
        return '{"event_type": "alert", roto'                  # JSON inválido
    if roll < 0.05:
        return json.dumps({"timestamp": datetime.now(TZ).isoformat(), "event_type": "tls",
                           "src_ip": "192.168.1.20", "dest_ip": "198.51.100.1"})
    return json.dumps(alert(rng, 1_000_000 + i), ensure_ascii=False)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--redis-url", default="redis://127.0.0.1:6379/0")
    ap.add_argument("--key", default="suricata")
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--rate", type=float, default=0, help="eventos por segundo (0 = todos de golpe)")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()
    if args.count < 1 or args.rate < 0:
        ap.error("--count debe ser ≥ 1 y --rate ≥ 0")

    rng = random.Random(args.seed)
    r = redis.Redis.from_url(args.redis_url, socket_timeout=5)
    try:
        r.ping()
    except redis.RedisError as exc:
        print(f"No se puede conectar a Redis ({args.redis_url}): {exc}", file=sys.stderr)
        return 1
    for i in range(args.count):
        r.lpush(args.key, message(rng, i))
        if args.rate:
            time.sleep(1 / args.rate)
    print(f"Enviados {args.count} mensajes a '{args.key}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
