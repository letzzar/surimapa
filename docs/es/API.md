# Referencia de la API

[English](../en/API.md) · **Español**

API JSON de solo lectura, servida por el contenedor `portal` bajo `/api`.

- **Autenticación:** todo salvo `/login` y `/healthz` exige la cookie de sesión `sur_session`, que se obtiene enviando el formulario de acceso. Sin ella, `/api/*` devuelve `401`. La cookie es `Secure`: usa la dirección HTTPS.
- **Caché:** las respuestas llevan `Cache-Control: no-store`.
- **Errores:** un parámetro no válido devuelve `422`; si falta la base de datos, `503`.

```bash
read -rs P                                    # contraseña del portal, sin mostrarla
curl -s -c cookies.txt -d "username=surimapa" --data-urlencode "password=$P" https://surimapa.example.lan/login
curl -s -b cookies.txt "https://surimapa.example.lan/api/summary?range=24h"
```

| Endpoint | Notas |
|---|---|
| `POST /login` | Campos de formulario `username` y `password`. `303` a `/` con la cookie, o `401` |
| `POST /logout` | Cierra la sesión |
| `GET /healthz` | Comprobación pública de que el contenedor responde: `{"status":"ok"}` |

## Filtros comunes

Los aceptan `summary`, `timeline`, `top`, `map`, `events` y `events.csv`:

| Parámetro | Valores |
|---|---|
| `range` | `1h`, `24h` (por defecto), `7d`, `30d`, `90d`. `30d` y `90d` se sirven desde una caché de 5 minutos |
| `from`, `to` | Fechas ISO 8601, las dos a la vez, intervalo ≤ 90 días. Sustituyen a `range` |
| `severity` | `1`, `2`, `3` |
| `direction` | `in`, `out`, `local` |
| `iface` | interfaz tal como la envía Suricata (`in_iface`), p. ej. `pppoe0` |

## Endpoints

| Endpoint | Devuelve |
|---|---|
| `GET /api/health` | `status` (`ok`/`degraded`), `last_event_ms`, `collector_heartbeat_age_s`, `redis_queue_len`, `db_size_bytes` |
| `GET /api/config` | `version` (versión de Surimapa) y `bledeagle_url` (enlace al portal hermano, o `null`) |
| `GET /api/summary` | `total`, `unique_ips`, `unique_countries`, `by_severity`, y las mismas cifras del periodo anterior (`previous`) |
| `GET /api/timeline?bucket=auto` | `bucket_ms` y `points[]` con `ts_ms`, `sev1`, `sev2`, `sev3` |
| `GET /api/top/{dim}?limit=10` | Ranking; `dim` ∈ `remote_ip`, `signature`, `country`, `asn`, `dest_port`, `category`; `limit` ≤ 50. Elementos: `key`, `label`, `count` (+ `country_iso`, `as_org` en IPs; + `severity` en firmas) |
| `GET /api/map` | `countries[]` (`country_iso`, `country`, `count`) y `points[]` en una rejilla de 0,1° (`lat`, `lon`, `count`, `country_iso`, `country`, `city`) |
| `GET /api/events?page=1&size=25&q=` | Lista paginada (`size` ≤ 100). `q` = IP exacta, SID o texto de la firma. Origen opcional: `country=XX` **o** `lat`+`lon` (una celda del mapa) |
| `GET /api/events.csv` | La misma vista que `/api/events` (filtros + `q` + origen) como descarga CSV: hasta 50.000 filas, separador `;`, UTF-8 con BOM, fechas en UTC y protegido contra inyección de fórmulas |
| `GET /api/events/{id}` | Un evento con todos sus campos, incluido `raw` (JSON EVE reducido, sin payload ni packet) |
| `GET /api/ip/{ip}` | Ficha de IP: `total`, `first_seen_ms`, `last_seen_ms`, GeoIP/ASN, `signatures_total`, `signatures[]` (`sid`, `signature`, `severity`, `count`), `dest_ports[]` |
| `GET /api/stream` | Server-Sent Events. Cada 2 s emite `event: events` con las alertas nuevas (≤ 50 por mensaje, incluidos `lat`/`lon`). Acepta `severity`, `direction`, `iface` |
| `GET /api/fw/summary` | Bloqueos del firewall: `total`, `unique_ips`, `unique_countries`. **Solo** aplican `range` / `from` / `to` |
| `GET /api/fw/map` | Misma forma que `/api/map`, con los bloqueos del firewall |
| `GET /api/fw/top/{dim}?limit=10` | `dim` ∈ `remote_ip`, `dest_port`, `country` |

Cualquier campo que venga de Suricata o del firewall es un **dato no confiable**. Si haces tu propio cliente, muéstralo como texto, nunca como HTML.
