# API reference

**English** · [Español](../es/API.md)

Read-only JSON API served by the `portal` container, under `/api`.

- **Authentication:** everything except `/login` and `/healthz` requires the session cookie `sur_session`, obtained by posting the login form. Without it, `/api/*` returns `401`. The cookie is `Secure`, so use the HTTPS address.
- **Caching:** responses carry `Cache-Control: no-store`.
- **Errors:** invalid parameters return `422`; a missing database returns `503`.

```bash
read -rs P                                    # portal password, not echoed
curl -s -c cookies.txt -d "username=surimapa" --data-urlencode "password=$P" https://surimapa.example.lan/login
curl -s -b cookies.txt "https://surimapa.example.lan/api/summary?range=24h"
```

| Endpoint | Notes |
|---|---|
| `POST /login` | Form fields `username`, `password`. `303` to `/` with the cookie, or `401` |
| `POST /logout` | Ends the session |
| `GET /healthz` | Public liveness check for the container: `{"status":"ok"}` |

## Common filters

Accepted by `summary`, `timeline`, `top`, `map`, `events` and `events.csv`:

| Parameter | Values |
|---|---|
| `range` | `1h`, `24h` (default), `7d`, `30d`, `90d`. `30d` and `90d` are served from a 5-minute cache |
| `from`, `to` | ISO 8601 datetimes, both together, span ≤ 90 days. Override `range` |
| `severity` | `1`, `2`, `3` |
| `direction` | `in`, `out`, `local` |
| `iface` | interface name as reported by Suricata (`in_iface`), e.g. `pppoe0` |

## Endpoints

| Endpoint | Returns |
|---|---|
| `GET /api/health` | `status` (`ok`/`degraded`), `last_event_ms`, `collector_heartbeat_age_s`, `redis_queue_len`, `db_size_bytes` |
| `GET /api/config` | `version` (Surimapa version) and `bledeagle_url` (sibling portal link, or `null`) |
| `GET /api/summary` | `total`, `unique_ips`, `unique_countries`, `by_severity`, and the same figures for the `previous` period |
| `GET /api/timeline?bucket=auto` | `bucket_ms` and `points[]` with `ts_ms`, `sev1`, `sev2`, `sev3` |
| `GET /api/top/{dim}?limit=10` | Ranking; `dim` ∈ `remote_ip`, `signature`, `country`, `asn`, `dest_port`, `category`; `limit` ≤ 50. Items: `key`, `label`, `count` (+ `country_iso`, `as_org` for IPs; + `severity` for signatures) |
| `GET /api/map` | `countries[]` (`country_iso`, `country`, `count`) and `points[]` on a 0.1° grid (`lat`, `lon`, `count`, `country_iso`, `country`, `city`) |
| `GET /api/events?page=1&size=25&q=` | Paged list (`size` ≤ 100). `q` = exact IP, SID or signature text. Optional origin: `country=XX` **or** `lat`+`lon` (a map cell) |
| `GET /api/events.csv` | The same view as `/api/events` (filters + `q` + origin) as a CSV download: up to 50,000 rows, `;` separator, UTF-8 with BOM, UTC timestamps, formula-injection safe |
| `GET /api/events/{id}` | One event with every field, including `raw` (reduced EVE JSON, without payload/packet) |
| `GET /api/ip/{ip}` | IP sheet: `total`, `first_seen_ms`, `last_seen_ms`, GeoIP/ASN, `signatures_total`, `signatures[]` (`sid`, `signature`, `severity`, `count`), `dest_ports[]` |
| `GET /api/stream` | Server-Sent Events. Every 2 s it emits `event: events` with the new alerts (≤ 50 per message, including `lat`/`lon`). Accepts `severity`, `direction`, `iface` |
| `GET /api/fw/summary` | Firewall blocks: `total`, `unique_ips`, `unique_countries`. **Only** `range` / `from` / `to` apply |
| `GET /api/fw/map` | Same shape as `/api/map`, for firewall blocks |
| `GET /api/fw/top/{dim}?limit=10` | `dim` ∈ `remote_ip`, `dest_port`, `country` |

Every field that comes from Suricata or the firewall is **untrusted data**. If you build your own client, render it as text, never as HTML.
