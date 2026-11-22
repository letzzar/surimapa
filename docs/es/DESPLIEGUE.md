# Guía de despliegue

[English](../en/DEPLOYMENT.md) · **Español**

Surimapa se arranca con Docker Compose: tres contenedores permanentes (`redis`, `collector`, `portal`) más `geoipupdate`, que se ejecuta una vez por semana para actualizar GeoLite2. Esta guía cubre un host Linux genérico e incluye notas para NAS Synology. Cuando esté en marcha, sigue la [guía de fuentes de datos](FUENTES.md) para enviarle alertas.

Todas las direcciones IP son **ejemplos**. Sustitúyelas por las tuyas:

| Ejemplo | Significado |
|---|---|
| `192.168.1.10` | IP LAN del host Docker (`NAS_LAN_IP`) |
| `192.168.1.1` | IP LAN de tu firewall o router (`PFSENSE_IP`) |
| `/opt/surimapa/app` | carpeta del proyecto compose (código + `.env`) |
| `/srv/surimapa` | datos persistentes (`DATA_DIR`) |

---

## 1. Requisitos

- Un host Linux con Docker Engine y el plugin **Compose v2** (`docker compose version`). Sirve x86-64 o ARM64.
- **IP LAN fija** en el host.
- Unos 250 MB de RAM libres. En disco, cuenta con ~1,5 KB por alerta y ~200 B por bloqueo del firewall, más las copias diarias.
- Una **cuenta gratuita de MaxMind** para GeoLite2 (<https://www.maxmind.com/en/geolite2/signup>). Crea una clave en *Manage License Keys*.
- Un sensor Suricata capaz de enviar EVE JSON a Redis (ver [FUENTES.md](FUENTES.md)).

> El `collector` usa `network_mode: host` (ver §8). En Docker Desktop para macOS/Windows la red del host no se comporta como en Linux: para un despliegue real usa un host Linux o un NAS.

## 2. Obtener el código

En ejecución solo se necesita la carpeta `deploy/`:

```bash
git clone https://github.com/letzzar/surimapa.git
sudo mkdir -p /opt/surimapa
sudo cp -r surimapa/deploy /opt/surimapa/app
```

## 3. Carpetas de datos y permisos

```bash
sudo mkdir -p /srv/surimapa/{data,redis,geoip,backups}
# el colector y el portal corren con el UID 10001 (sin privilegios) y tienen que poder escribir aquí
sudo chown 10001:10001 /srv/surimapa/data /srv/surimapa/backups
```

Si no puedes hacer `chown` en el host (algunos recursos de NAS con ACL), hazlo desde un contenedor efímero:

```bash
sudo docker run --rm -v /srv/surimapa/data:/d -v /srv/surimapa/backups:/b alpine chown 10001:10001 /d /b
```

## 4. Configurar `.env`

```bash
cd /opt/surimapa/app
sudo cp .env.example .env
sudo chmod 600 .env
sudo nano .env
```

| Variable | Ejemplo | Notas |
|---|---|---|
| `NAS_LAN_IP` | `192.168.1.10` | **Obligatoria.** Redis (6379/tcp) y el syslog del firewall (5140/udp) escuchan **solo** en esta IP |
| `PORTAL_PORT` | `8095` | Puerto del portal web |
| `PORTAL_USER` / `PORTAL_PASSWORD` | `surimapa` / larga y aleatoria | **Obligatorias.** Credenciales HTTP Basic |
| `REDIS_PASSWORD` | larga y aleatoria | **Obligatoria.** Contraseña del usuario Redis `surimapa` (colector y portal) |
| `REDIS_KEY` | `suricata` | Lista de Redis en la que escribe el sensor. Debe coincidir con el emisor |
| `WAN_IPS` | `203.0.113.7` | Tus IP públicas, separadas por comas. Con ellas, las alertas salientes desde tu IP WAN se clasifican bien. Si tu IP es dinámica, actualízala cuando cambie |
| `RETENTION_DAYS` | `90` | Días de alertas que se conservan |
| `BACKUP_KEEP` | `7` | Copias diarias de la BD que se conservan |
| `TZ` | `Europe/Madrid` | Zona horaria del mantenimiento diario (03:30). La web siempre muestra la hora del navegador de quien la mira |
| `PFSENSE_IP` | `192.168.1.1` | **La exige el compose.** Único origen aceptado para el syslog del firewall |
| `FW_SYSLOG_PORT` | `5140` | Puerto UDP del syslog del firewall. `0` lo desactiva |
| `FW_IFACE` | `pppoe0` | Nombre de la WAN tal como aparece en `filterlog` de pfSense (p. ej. `igb0`, `em0`, `pppoe0`) |
| `FW_RETENTION_DAYS` | `30` | Días de bloqueos del firewall que se conservan |
| `GEOIPUPDATE_ACCOUNT_ID` / `GEOIPUPDATE_LICENSE_KEY` | de MaxMind | Secretos |
| `GEOIPUPDATE_EDITION_IDS` | `GeoLite2-City GeoLite2-ASN` | |
| `DATA_DIR` | `/srv/surimapa` | Datos persistentes |

Para generar contraseñas:

```bash
openssl rand -base64 32 | tr -d '/+=' | cut -c1-32
```

Reglas:

- **Nunca subas `.env` a git**, ni copies sus valores en logs o capturas.
- Si un valor no se interpreta bien por culpa de un comentario al final de la línea, pasa el comentario a su propia línea.
- Para comprobar la interpolación sin mostrar secretos: `sudo docker compose config --services` debe listar los 4 servicios.

### Personalizar el mapa (opcional)

Estos ajustes están en `deploy/portal/static/index.html`:

- **Ubicación de casa**: los atributos `data-home-lat` / `data-home-lon` de `<div id="map">`. Es el destino de los misiles. El valor por defecto es un ejemplo (Londres); basta con precisión de ciudad.
- **Filtro de interfaz**: los valores de las `<option>` de `#f-iface`. Por defecto son `pppoe0` = WAN y `bridge0` = LAN, como en pfSense. Pon los `in_iface` que envíe tu sensor.

Después de cambiarlos, reconstruye el portal con `sudo docker compose up -d --build portal`.

## 5. Arrancar

```bash
cd /opt/surimapa/app
sudo docker compose run --rm geoipupdate   # descarga GeoLite2 (unos 80 MB) y termina
sudo docker compose up -d --build
sudo docker compose ps          # en ~1 minuto, todos "healthy"
```

Sin las bases GeoLite2, las alertas se guardan sin GeoIP. Después, programa la actualización semanal (§9).

## 6. Verificar

```bash
# colector: arranque, esquema de la BD, escucha de syslog y contadores cada 30 s
sudo docker compose logs collector | tail -20
# salud de la API (pide la contraseña del portal)
curl -s -u surimapa http://192.168.1.10:8095/api/health
```

`/api/health` devuelve `status` (`ok` / `degraded`), `last_event_ms`, `collector_heartbeat_age_s`, `redis_queue_len` y `db_size_bytes`.

Abre `http://192.168.1.10:8095` en el navegador e inicia sesión. El panel estará vacío hasta que un sensor envíe datos (ver [FUENTES.md](FUENTES.md)).

Contadores del latido (heartbeat) en el log del colector:

| Contador | Significado |
|---|---|
| `processed` | Alertas guardadas |
| `discarded_not_alert`, `discarded_invalid_json`… | Registros EVE ignorados, con su motivo |
| `fw_stored` | Bloqueos del firewall guardados |
| `fw_discarded_source` | Syslog de una IP no permitida (revisar `PFSENSE_IP`, §8) |
| `fw_discarded_iface` / `_action` / `_direction` / `_local_src` | Líneas del firewall ignoradas a propósito (otras interfaces, reglas `pass`, tráfico saliente, orígenes privados) |
| `retention_deleted`, `backups`, `errors`, `redis_errors` | Mantenimiento y errores |

## 7. Protección de red

- **Redis (6379/tcp)** solo se publica en `NAS_LAN_IP`. Los clientes anónimos solo pueden **añadir** alertas a la cola (`LPUSH`/`RPUSH`/`PING`); leer o borrar exige la contraseña de `surimapa`. El riesgo que queda es que un equipo de la LAN inyecte alertas falsas. Si tienes otros segmentos (VLAN, VPN), bloquea en el router su acceso al puerto 6379.
- **Syslog del firewall (5140/udp)**: solo se aceptan datagramas con origen `PFSENSE_IP`. En la LAN, UDP se puede falsificar; lo peor sería pintar bloqueos falsos en el mapa.
- **Portal**: solo por LAN o VPN. **Nunca** lo abras a Internet. HTTP Basic sobre HTTP simple es aceptable en una LAN de confianza. Para cifrar:
  - usa una VPN que ya cifre (WireGuard, Tailscale); o
  - usa `tailscale serve --https=443 http://127.0.0.1:8095`; o
  - pon delante un proxy inverso con TLS (Caddy, nginx, Traefik).
- En Synology, el firewall de DSM **no** filtra de forma fiable los puertos que publica Docker (Docker añade sus propias reglas de iptables). Confía en el enlace a `NAS_LAN_IP`, en las ACL y en las reglas del router.

## 8. Por qué el colector usa la red del host

Cuando un paquete UDP entra en un contenedor por un **puerto publicado**, algunas configuraciones de Docker cambian su origen por la pasarela del bridge de Docker (por ejemplo `172.18.0.1`). Synology lo hace. Así el colector nunca vería la IP real del firewall, y el filtro `PFSENSE_IP` lo rechazaría todo (`fw_discarded_source`).

Por eso el servicio `collector` usa `network_mode: host`:

- escucha directamente en `NAS_LAN_IP:5140/udp` (`FW_BIND`);
- llega a Redis por el puerto publicado `NAS_LAN_IP:6379`;
- no publica nada más.

Si no usas la función del firewall, pon `FW_SYSLOG_PORT=0`. `PFSENSE_IP` tiene que seguir teniendo un valor válido, porque el compose lo exige.

## 9. Operación

**Logs y estado**

```bash
sudo docker compose ps
sudo docker compose logs -f collector
sudo docker stats --no-stream        # RAM: redis ≤ 64 MB, collector ≤ 128 MB, portal ≤ 192 MB
```

**Retención.** Cada día a las 03:30 (`TZ`), el colector:

- borra las alertas con más de `RETENTION_DAYS` y los bloqueos con más de `FW_RETENTION_DAYS`;
- compacta la BD;
- hace una copia en caliente en `DATA_DIR/backups/surimapa-AAAA-MM-DD.db`, verificada con `quick_check`;
- conserva las últimas `BACKUP_KEEP` copias.

**Actualización de GeoIP.** `geoipupdate` no queda en marcha: es una ejecución puntual (`GEOIPUPDATE_FREQUENCY=0`, perfil `geoip`, sin `restart`). MaxMind limita las descargas diarias por cuenta y cada reintento cuenta, así que un contenedor que se reinicia en bucle tras un fallo de descarga puede agotar el cupo (`429 LIMIT_EXCEEDED`) y seguir fallando. Prográmalo una vez por semana, por ejemplo en el crontab de root (MaxMind publica los martes y los viernes):

```bash
0 4 * * 4  cd /opt/surimapa/app && docker compose run --rm geoipupdate
```

El colector recarga los `.mmdb` solo (comprueba su fecha cada hora). Si una semana falla, se siguen usando las bases anteriores y se reintenta la siguiente.

**Restaurar una copia**

```bash
cd /opt/surimapa/app
sudo docker compose stop collector portal
sudo cp /srv/surimapa/backups/surimapa-2026-01-31.db /srv/surimapa/data/surimapa.db
sudo rm -f /srv/surimapa/data/surimapa.db-wal /srv/surimapa/data/surimapa.db-shm
sudo chown 10001:10001 /srv/surimapa/data/surimapa.db
sudo docker compose start collector portal
```

No abras la BD en uso a través de un recurso de red (SMB/NFS) con el colector en marcha: SQLite sobre un sistema de ficheros de red puede corromperse. Trabaja con una copia.

**Actualizar**

```bash
cd surimapa && git pull
sudo rsync -a --delete --exclude .env surimapa/deploy/ /opt/surimapa/app/   # o cópialo a mano conservando .env
cd /opt/surimapa/app && sudo docker compose up -d --build
```

El colector aplica solo las migraciones del esquema al arrancar. Mientras se reinicia, Redis guarda las alertas que llegan.

**Desinstalar**

```bash
cd /opt/surimapa/app && sudo docker compose down --rmi local
sudo rm -rf /opt/surimapa /srv/surimapa      # borra todos los datos
```

## 10. Notas para NAS Synology

- Instala **Container Manager**. Activa SSH (*Panel de control → Terminal y SNMP*) y usa `sudo docker compose …` desde una shell. También puedes crear un *Proyecto* en Container Manager que apunte a la carpeta `app` (lee `docker-compose.yml` y `.env`).
- Rutas habituales: `/volume1/docker/surimapa/app` (código + `.env`) y `DATA_DIR=/volume1/docker/surimapa`.
- Las carpetas compartidas usan ACL. Da acceso al UID 10001 con el `chown` desde un contenedor efímero del §3.
- Si editas desde macOS por SMB, excluye `._*`, `.DS_Store` y `.smbdelete*` al copiar.
- En Synology hace falta la red del host (§8) para el syslog del firewall.
- Actualización semanal de GeoIP (§9): *Panel de control → Programador de tareas → Crear → Tarea programada → Script definido por el usuario*, usuario `root`, semanal, script `cd /volume1/docker/surimapa/app && docker compose run --rm geoipupdate`.

## 11. Solución de problemas

| Síntoma | Causa / solución |
|---|---|
| `docker compose` falla con «Definir … en .env» | Falta una variable obligatoria (`NAS_LAN_IP`, `REDIS_PASSWORD`, `PORTAL_USER`, `PORTAL_PASSWORD`, `PFSENSE_IP`) |
| El colector se reinicia con «unable to open database file» | El UID 10001 no puede escribir en `DATA_DIR/data` (§3) |
| Panel vacío y `redis_queue_len` siempre a 0 | El sensor no envía. Revisa su configuración de Redis y que llegue a `NAS_LAN_IP:6379` |
| `redis_queue_len` no para de crecer | El colector está parado o falla: `docker compose logs collector` |
| Alertas sin país ni ciudad | GeoLite2 aún no se ha descargado, o las credenciales de MaxMind son incorrectas: lanza `docker compose run --rm geoipupdate` y lee su salida |
| geoipupdate: `429 LIMIT_EXCEEDED` | Cupo diario de descargas de MaxMind agotado. Espera 24 h sin lanzarlo; si empezó tras un fallo de descarga, corrige antes esa causa |
| Tu IP pública aparece como atacante | Rellena `WAN_IPS` |
| Solo sube `fw_discarded_source` | El origen del syslog no es `PFSENSE_IP`: revisa la dirección de origen en el firewall y que el colector use la red del host (§8) |
| Solo sube `fw_discarded_iface` | `FW_IFACE` no coincide con el nombre de la WAN en `filterlog` |
| El navegador pide la contraseña una y otra vez | `PORTAL_USER`/`PORTAL_PASSWORD` incorrectos. Tras editar `.env`: `docker compose up -d portal` |
