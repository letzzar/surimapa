# Deployment guide

**English** · [Español](../es/DESPLIEGUE.md)

Surimapa runs with Docker Compose: three long-running containers (`redis`, `collector`, `portal`) plus `geoipupdate`, which runs once a week to refresh GeoLite2. This guide covers a generic Linux host and includes notes for Synology NAS. Once it is running, follow the [data sources guide](SOURCES.md) to send it alerts.

All IP addresses below are **examples**. Replace them with your own:

| Example | Meaning |
|---|---|
| `192.168.1.10` | LAN IP of the Docker host (`NAS_LAN_IP`) |
| `192.168.1.1` | LAN IP of your firewall / router (`PFSENSE_IP`) |
| `/opt/surimapa/app` | where the compose project lives (code + `.env`) |
| `/srv/surimapa` | persistent data (`DATA_DIR`) |

---

## 1. Requirements

- Linux host with Docker Engine and the **Compose v2** plugin (`docker compose version`). x86-64 and ARM64 both work.
- A **fixed LAN IP** for the host.
- About 250 MB of free RAM. For disk, count roughly 1.5 KB per alert plus 200 B per firewall block, plus the daily backups.
- A free **MaxMind account** for GeoLite2 (<https://www.maxmind.com/en/geolite2/signup>). Create a license key under *Manage License Keys*.
- A Suricata sensor that can send EVE JSON to Redis (see [SOURCES.md](SOURCES.md)).

> The `collector` uses `network_mode: host` (see §8). On Docker Desktop for macOS/Windows, host networking does not behave like on Linux. Use a Linux host (or a NAS) for real deployments.

## 2. Get the code

Only the `deploy/` folder is needed at runtime:

```bash
git clone https://github.com/letzzar/surimapa.git
sudo mkdir -p /opt/surimapa
sudo cp -r surimapa/deploy /opt/surimapa/app
```

## 3. Data folders and permissions

```bash
sudo mkdir -p /srv/surimapa/{data,redis,geoip,backups}
# collector and portal run as UID 10001 (non-root): they must be able to write here
sudo chown 10001:10001 /srv/surimapa/data /srv/surimapa/backups
```

If `chown` is not possible on the host (for example on some NAS shares with ACLs), run it from a throwaway container:

```bash
sudo docker run --rm -v /srv/surimapa/data:/d -v /srv/surimapa/backups:/b alpine chown 10001:10001 /d /b
```

## 4. Configure `.env`

```bash
cd /opt/surimapa/app
sudo cp .env.example .env
sudo chmod 600 .env
sudo nano .env
```

| Variable | Example | Notes |
|---|---|---|
| `NAS_LAN_IP` | `192.168.1.10` | **Required.** Redis (6379/tcp) and the firewall syslog (5140/udp) listen **only** on this IP |
| `PORTAL_PORT` | `8095` | Portal port, published **only on `127.0.0.1`** for the HTTPS proxy (§7) |
| `PORTAL_USER` | `surimapa` | **Required.** User of the login page |
| `PORTAL_PASSWORD_HASH` | `scrypt:…` | **Required.** scrypt hash of the portal password (see below). The password itself is never stored |
| `BLEDEAGLE_URL` | `https://bledeagle.example.lan` | Optional. Adds a link to a sibling portal in the top bar. Only `https://` URLs are accepted; empty or invalid = no link |
| `REDIS_PASSWORD` | long random | **Required.** Password of the Redis user `surimapa` (collector and portal) |
| `REDIS_KEY` | `suricata` | Redis list the sensor writes to. Must match the sender |
| `WAN_IPS` | `203.0.113.7` | Your own public IP(s), comma separated. With them, outbound alerts from your WAN IP are classified correctly. If your WAN IP is dynamic, update it when it changes |
| `RETENTION_DAYS` | `90` | Days of alerts kept |
| `BACKUP_KEEP` | `7` | Daily database backups kept |
| `TZ` | `Europe/Berlin` | Time zone of the daily maintenance (03:30). The web UI always shows the viewer's browser time zone |
| `PFSENSE_IP` | `192.168.1.1` | **Required by the compose file.** Only source accepted for firewall syslog |
| `FW_SYSLOG_PORT` | `5140` | UDP port for firewall syslog. `0` disables it |
| `FW_IFACE` | `pppoe0` | WAN interface name as it appears in pfSense `filterlog` (e.g. `igb0`, `em0`, `pppoe0`) |
| `FW_RETENTION_DAYS` | `30` | Days of firewall blocks kept |
| `GEOIPUPDATE_ACCOUNT_ID` / `GEOIPUPDATE_LICENSE_KEY` | from MaxMind | Secrets |
| `GEOIPUPDATE_EDITION_IDS` | `GeoLite2-City GeoLite2-ASN` | |
| `DATA_DIR` | `/srv/surimapa` | Persistent data |

Generate passwords:

```bash
openssl rand -base64 32 | tr -d '/+=' | cut -c1-32
```

Generate the portal password hash (it asks for the password twice and prints the line to paste into `.env`):

```bash
cd /opt/surimapa/app
sudo docker run --rm -it -v "$PWD/portal/app/auth.py:/auth.py:ro" python:3.12-slim python /auth.py
```

`docker compose run` does not work for this: the compose file refuses to start while `PORTAL_PASSWORD_HASH` is empty. The hash contains no `$`, so it can be pasted as is.

Rules:

- **Never commit `.env`**, and keep its values out of logs and screenshots.
- Put comments on their own line if a value is not parsed well.
- Check the interpolation without printing secrets: `sudo docker compose config --services` must list `redis`, `collector` and `portal` (`geoipupdate` is in the `geoip` profile, §9).

### Personalise the map (optional)

These settings live in `deploy/portal/static/index.html`:

- **Home location**: the `data-home-lat` / `data-home-lon` attributes of `<div id="map">`. The missiles fly to this point. The default is an example (London); city precision is enough.
- **Interface filter**: the `<option>` values of `#f-iface`. The defaults are `pppoe0` = WAN and `bridge0` = LAN, as in pfSense. Use the `in_iface` names your sensor reports.

After changing them, rebuild the portal with `sudo docker compose up -d --build portal`.

## 5. Start

```bash
cd /opt/surimapa/app
sudo docker compose run --rm geoipupdate   # downloads GeoLite2 (about 80 MB) and exits
sudo docker compose up -d --build
sudo docker compose ps          # after ~1 minute, all "healthy"
```

Without the GeoLite2 databases, alerts are stored without GeoIP. Then schedule the weekly update (§9).

## 6. Verify

```bash
# collector: startup, DB schema, syslog listener, heartbeat counters every 30 s
sudo docker compose logs collector | tail -20
# portal liveness (public, no login): prints {"status":"ok"}
curl -s http://127.0.0.1:8095/healthz
```

Set up the HTTPS proxy (§7), open `https://surimapa.example.lan` in a browser and log in. The panel stays empty until a sensor sends data (see [SOURCES.md](SOURCES.md)). Its health strip and `GET /api/health` show `status` (`ok` / `degraded`), `last_event_ms`, `collector_heartbeat_age_s`, `redis_queue_len` and `db_size_bytes`.

Heartbeat counters in the collector log:

| Counter | Meaning |
|---|---|
| `processed` | Alerts stored |
| `discarded_not_alert`, `discarded_invalid_json`… | EVE records ignored, with the reason |
| `fw_stored` | Firewall blocks stored |
| `fw_discarded_source` | Syslog from a non-allowed IP (check `PFSENSE_IP`, §8) |
| `fw_discarded_iface` / `_action` / `_direction` / `_local_src` | Firewall lines ignored on purpose (other interfaces, `pass` rules, outbound traffic, private sources) |
| `retention_deleted`, `backups`, `errors`, `redis_errors` | Maintenance and errors |

## 7. Network protection

- **Redis (6379/tcp)** is published only on `NAS_LAN_IP`. Anonymous clients can only **append** alerts to the queue (`LPUSH`/`RPUSH`/`PING`); reading or deleting requires the `surimapa` password. The remaining risk is a LAN device injecting fake alerts. If you have other network segments (VLANs, VPN), block their access to port 6379 on your router.
- **Firewall syslog (5140/udp)**: only datagrams whose source is `PFSENSE_IP` are accepted. UDP can be spoofed inside the LAN; the worst case is fake blocks on the map.
- **Portal**: LAN or VPN only. **Never** forward it from the Internet. It has a login page (scrypt password hash, 1 s delay per failed attempt) and a session cookie marked `Secure`, `HttpOnly` and `SameSite=Strict`, valid for 12 h and kept in memory (restarting the portal logs everyone out). POST requests from another origin are rejected.
- **HTTPS is required.** Browsers drop `Secure` cookies on plain HTTP, so the login would loop. The portal listens only on `127.0.0.1:PORTAL_PORT`; put a reverse proxy with TLS on the same host. Minimal Caddy example (`/etc/caddy/Caddyfile`):

  ```
  surimapa.example.lan {
      tls internal
      reverse_proxy 127.0.0.1:8095
  }
  ```

  - `tls internal` uses Caddy's own CA, good for a LAN-only name: install its root certificate on your devices (`caddy trust`, or copy `root.crt` from Caddy's data folder), or browsers will warn. With a real domain you can use a Let's Encrypt certificate (DNS challenge) instead.
  - Any proxy works (nginx, Traefik…) as long as it passes the original `Host` header: the portal compares it with `Origin` on POST requests. Caddy does it by default; in nginx add `proxy_set_header Host $host;`.
  - If the proxy runs as a container, attach it to this project's network and point it at `portal:8000`; then you can remove the `ports` line of `portal`.
- On Synology, the DSM firewall does **not** reliably filter ports published by Docker (Docker inserts its own iptables rules). Rely on the binding to `NAS_LAN_IP`, the ACLs and your router rules.

## 8. Why the collector uses host networking

When a UDP packet enters a container through a **published port**, some Docker setups rewrite its source address to the Docker bridge gateway (for example `172.18.0.1`). Synology does this. The collector would then never see the real firewall IP, and the `PFSENSE_IP` filter would reject everything (`fw_discarded_source`).

That's why the `collector` service uses `network_mode: host`:

- it listens on `NAS_LAN_IP:5140/udp` directly (`FW_BIND`);
- it reaches Redis through the published port `NAS_LAN_IP:6379`;
- it publishes nothing else.

If you don't use the firewall feature, set `FW_SYSLOG_PORT=0`. `PFSENSE_IP` must still have any valid value, because the compose file requires it.

## 9. Operation

**Logs and status**

```bash
sudo docker compose ps
sudo docker compose logs -f collector
sudo docker stats --no-stream        # RAM: redis ≤ 64 MB, collector ≤ 128 MB, portal ≤ 192 MB
```

**Retention.** Every day at 03:30 (`TZ`), the collector:

- deletes alerts older than `RETENTION_DAYS` and blocks older than `FW_RETENTION_DAYS`;
- compacts the database;
- writes a hot backup to `DATA_DIR/backups/surimapa-YYYY-MM-DD.db`, verified with `quick_check`;
- keeps the last `BACKUP_KEEP` backups.

**GeoIP update.** `geoipupdate` is not left running: it is a one-shot job (`GEOIPUPDATE_FREQUENCY=0`, profile `geoip`, no `restart`). MaxMind limits daily downloads per account and every retry counts, so a container restarting in a loop after a failed download can exhaust the quota (`429 LIMIT_EXCEEDED`) and keep failing. Schedule it once a week instead, for example in root's crontab (MaxMind publishes on Tuesdays and Fridays):

```bash
0 4 * * 4  cd /opt/surimapa/app && docker compose run --rm geoipupdate
```

The collector reloads the `.mmdb` files on its own (it checks their date every hour). If one week fails, the previous databases keep working and the next run tries again.

**Restore a backup**

```bash
cd /opt/surimapa/app
sudo docker compose stop collector portal
sudo cp /srv/surimapa/backups/surimapa-2026-01-31.db /srv/surimapa/data/surimapa.db
sudo rm -f /srv/surimapa/data/surimapa.db-wal /srv/surimapa/data/surimapa.db-shm
sudo chown 10001:10001 /srv/surimapa/data/surimapa.db
sudo docker compose start collector portal
```

Do not open the live database over a network share (SMB/NFS) while the collector is running: SQLite over network file systems can corrupt it. Copy a backup instead.

**Update**

```bash
cd surimapa && git pull
sudo rsync -a --delete --exclude .env surimapa/deploy/ /opt/surimapa/app/   # or copy manually, keeping .env
cd /opt/surimapa/app && sudo docker compose up -d --build
```

Schema migrations are applied automatically by the collector on start. While it restarts, Redis buffers the incoming alerts.

**Uninstall**

```bash
cd /opt/surimapa/app && sudo docker compose down --rmi local
sudo rm -rf /opt/surimapa /srv/surimapa      # deletes all data
```

## 10. Synology NAS notes

- Install **Container Manager**. Enable SSH (*Control Panel → Terminal & SNMP*) and use `sudo docker compose …` from a shell. Alternatively, create a *Project* in Container Manager pointing to the `app` folder (it reads `docker-compose.yml` and `.env`).
- Typical paths: `/volume1/docker/surimapa/app` (code + `.env`) and `DATA_DIR=/volume1/docker/surimapa`.
- Shared folders use ACLs. Grant UID 10001 access with the throwaway-container `chown` from §3.
- If you edit files from macOS over SMB, exclude `._*`, `.DS_Store` and `.smbdelete*` when copying.
- Host networking (§8) is required on Synology for the firewall syslog.
- Weekly GeoIP update (§9): *Control Panel → Task Scheduler → Create → Scheduled Task → User-defined script*, user `root`, weekly, script `cd /volume1/docker/surimapa/app && docker compose run --rm geoipupdate`.

## 11. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker compose` fails with "Definir … en .env" | A required variable is empty (`NAS_LAN_IP`, `REDIS_PASSWORD`, `PORTAL_USER`, `PORTAL_PASSWORD_HASH`, `PFSENSE_IP`) |
| collector restarts, "unable to open database file" | `DATA_DIR/data` is not writable by UID 10001 (§3) |
| Panel empty, `redis_queue_len` stays 0 | The sensor is not sending. Check its Redis settings and that it reaches `NAS_LAN_IP:6379` |
| `redis_queue_len` keeps growing | The collector is down or failing: check `docker compose logs collector` |
| Alerts without country/city | GeoLite2 is not downloaded yet, or the MaxMind credentials are wrong: run `docker compose run --rm geoipupdate` and read its output |
| geoipupdate: `429 LIMIT_EXCEEDED` | MaxMind's daily download quota is used up. Wait 24 h without running it; if it started after a failed download, fix that cause first |
| Your own public IP appears as an attacker | Set `WAN_IPS` |
| Only `fw_discarded_source` grows | The syslog source is not `PFSENSE_IP`: check the firewall's source address, and that the collector uses host networking (§8) |
| Only `fw_discarded_iface` grows | `FW_IFACE` does not match the WAN name in `filterlog` |
| Login says "Usuario o contraseña incorrectos" | Wrong user, or `PORTAL_PASSWORD_HASH` does not match the password. Generate it again (§4) and run `docker compose up -d portal` |
| Login accepted but you land on the login page again | You are on plain HTTP: the `Secure` cookie is dropped. Use the HTTPS proxy (§7) |
| Login answers "Origen no permitido" (403) | The proxy does not pass the original `Host` header (§7) |
