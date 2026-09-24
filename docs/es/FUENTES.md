# Guía de fuentes de datos

[English](../en/SOURCES.md) · **Español**

Surimapa acepta dos tipos de entrada:

| Entrada | Transporte | Para qué |
|---|---|---|
| **Alertas EVE JSON de Suricata** | Lista de Redis `REDIS_KEY` (por defecto `suricata`), un registro JSON por elemento, añadido con `LPUSH` | Mapa, indicadores, rankings, tabla de eventos |
| **Bloqueos del firewall de pfSense** (`filterlog`) | Syslog por UDP (RFC 3164) a `NAS_LAN_IP:5140` | Capa y tarjeta del firewall |

Sirve como fuente cualquier cosa capaz de **hacer `LPUSH` de una alerta EVE en Redis**: la salida Redis nativa de Suricata, un transportador de logs que lea `eve.json` o un script propio.

Estado de cada receta:

- ✅ **probada**: el autor la usa en producción.
- 🧪 **sin probar**: basada en la documentación oficial y en los formatos que espera Surimapa. Cuéntanos el resultado en una *issue*.

Todas las IP son **ejemplos**: `192.168.1.10` es el host Docker de Surimapa (`NAS_LAN_IP`) y `192.168.1.1` es el firewall (`PFSENSE_IP`).

---

## Qué espera Surimapa (alerta EVE)

Solo se guardan los registros con `"event_type": "alert"`; el resto se descarta, así que envía **solo alertas** para ahorrar tráfico. Campos mínimos:

```json
{"timestamp":"2026-01-31T12:00:00.000000+0000","event_type":"alert",
 "src_ip":"203.0.113.5","src_port":4444,"dest_ip":"192.0.2.10","dest_port":22,"proto":"TCP","in_iface":"eth0",
 "alert":{"signature_id":2001219,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}
```

Qué se hace con cada registro:

- **Campos opcionales:** `flow_id`, `app_proto` y `alert.action`.
- **Campos que se eliminan:** `payload`, `payload_printable`, `packet` y `http` se quitan antes de guardar. Desactívalos también en el origen, para no mover contenido de paquetes por la LAN.
- **Tamaño y limpieza:** los textos se truncan, se eliminan los caracteres de control y el JSON guardado tiene un máximo de 4 KB.

Puedes probar la cadena a mano desde cualquier equipo de la LAN. El usuario anónimo de Redis puede hacer `LPUSH`:

```bash
redis-cli -h 192.168.1.10 LPUSH suricata '{"timestamp":"2026-01-31T12:00:00.000000+0000","event_type":"alert","src_ip":"203.0.113.5","src_port":4444,"dest_ip":"192.0.2.10","dest_port":22,"proto":"TCP","in_iface":"eth0","alert":{"signature_id":2001219,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}'
```

En menos de un segundo aparece en la tabla de eventos. Usa una fecha real si quieres verla en la vista por defecto de 24 h.

---

## 1. pfSense + paquete Suricata ✅

Probado con pfSense CE 2.9 y el paquete Suricata 7.0.x (motor 8). Los textos de la interfaz pueden variar un poco entre versiones.

### 1.1 Alertas: EVE → Redis

*Services → Suricata → Interfaces*, edita la interfaz (normalmente **WAN**) → sección **Logging Settings / EVE Output Settings**:

1. ✔ **EVE JSON Log**.
2. **EVE Output Type**: `REDIS`.
3. **Redis Server**: `192.168.1.10` · **Port**: `6379`.
4. **Redis Mode**: `List (LPUSH)` · **Redis Key**: `suricata` (= `REDIS_KEY`).
   El paquete **no tiene campo de contraseña de Redis**. Por eso el Redis de Surimapa solo deja al usuario anónimo hacer `LPUSH`.
5. **EVE Logged Info / Traffic**: deja **solo Alerts**.
   - Desmarca HTTP, DNS, TLS, Files, SSH, SMTP, Flow, NetFlow, Stats, Drops, DHCP, MQTT, QUIC…
   - Desmarca el registro de **payload / packet** de las alertas.
6. **Save** y reinicia Suricata en esa interfaz.

Notas:

- En la WAN de una línea PPPoE, Suricata corre sobre `pppoe0` y ve el tráfico **después del NAT**. Pon tu IP pública en `WAN_IPS`.
- En modo de bloqueo **Legacy** quien bloquea es pfSense, no Suricata, así que EVE siempre dice `"action":"allowed"`. Surimapa no interpreta ese campo como «bloqueado / no bloqueado».
- También puedes activar EVE → Redis en una instancia de LAN: sus alertas llegan con ese `in_iface` (p. ej. `bridge0`) y el filtro de interfaz las separa.
- El tráfico que genera el propio pfSense no pasa por las reglas de interfaz, así que una regla que bloquee el 6379 desde otros segmentos (VPN, VLAN) no afecta a Suricata.

### 1.2 Bloqueos del firewall: `filterlog` → syslog

*Status → System Logs → Settings*:

1. **General Logging Options**:
   - **Log Message Format** = `BSD (RFC 3164, default)`.
   - ✔ **Log packets matched from the default block rules in the ruleset**.
2. **Remote Logging Options**:
   - ✔ **Enable Remote Logging**;
   - **Source Address**: tu interfaz **LAN**, para que el origen sea `192.168.1.1` = `PFSENSE_IP`;
   - **IP Protocol**: `IPv4`;
   - **Remote log servers**: `192.168.1.10:5140`;
   - **Remote Syslog Contents**: marca **solo** ✔ *Firewall Events*.
3. **Save**. No hace falta reiniciar.

Surimapa guarda una fila por cada paquete **bloqueado o rechazado, entrante, en `FW_IFACE` y con origen público**. Todo lo demás se cuenta y se descarta. Revisa el latido del colector (`fw_stored`, `fw_discarded_*`): ver [DESPLIEGUE.md §6](DESPLIEGUE.md#6-verificar).

---

## 2. Suricata independiente en Linux (salida Redis nativa) 🧪

Suricata puede escribir EVE directamente en Redis si se compiló con **hiredis**:

```bash
suricata --build-info | grep -i redis      # debe decir "hiredis support: yes"
```

En `suricata.yaml`, añade (o adapta) una salida `eve-log`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: redis
      redis:
        server: 192.168.1.10
        port: 6379
        mode: lpush            # "list" es un alias de lpush
        key: suricata          # = REDIS_KEY
      types:
        - alert:
            payload: no
            payload-printable: no
            packet: no
            metadata: yes
```

Reinicia Suricata (`systemctl restart suricata`). Puedes mantener también tu `eve-log` a fichero: las salidas son independientes.

Si el sensor ve tu IP pública (un sensor en la WAN del router, después del NAT), rellena `WAN_IPS`.

### 2.1 Suricata en Docker junto a Surimapa 🧪

Si tu router puede **replicar un puerto** (SPAN), o el host Docker ve el tráfico que quieres inspeccionar, puedes correr Suricata en un contenedor. Ejemplo con la imagen comunitaria `jasonish/suricata`:

```yaml
services:
  suricata:
    image: jasonish/suricata:latest
    network_mode: host
    cap_add: [NET_ADMIN, NET_RAW, SYS_NICE]
    command: -i eth1                    # interfaz que recibe el tráfico replicado
    volumes:
      - ./suricata/etc:/etc/suricata    # edita aquí suricata.yaml (§2) tras el primer arranque
      - ./suricata/log:/var/log/suricata
    restart: unless-stopped
```

Después, comprueba `--build-info` dentro del contenedor, activa el `eve-log` a Redis del §2 y actualiza las reglas (`docker compose exec suricata suricata-update`).

---

## 3. Cualquier Suricata que escriba `eve.json` → Vector → Redis 🧪

Si el sensor no puede escribir en Redis, envía su `eve.json` con [Vector](https://vector.dev), en el propio sensor o en un host que pueda leer el fichero:

```toml
# vector.toml
[sources.eve]
type = "file"
include = ["/var/log/suricata/eve.json"]

[transforms.alerts]
type = "filter"
inputs = ["eve"]
condition = 'contains(string!(.message), "\"event_type\":\"alert\"")'

[sinks.surimapa]
type = "redis"
inputs = ["alerts"]
endpoint = "redis://192.168.1.10:6379/0"     # usuario anónimo: solo LPUSH
key = "suricata"
data_type = "list"
list_option.method = "lpush"
encoding.codec = "text"                       # envía la línea JSON original
```

La misma idea vale con Fluent Bit, Filebeat o un script pequeño: una alerta por cada `LPUSH`.

---

## 4. OPNsense 🧪

OPNsense usa Suricata (*Services → Intrusion Detection*) pero **no ofrece salida a Redis** en su interfaz. Camino propuesto: **syslog → relé Vector → Redis**.

1. *Services → Intrusion Detection → Administration → Settings* (avanzado): activa **eve syslog output**. OPNsense envía entonces cada registro EVE al syslog.
2. *System → Settings → Logging / Targets*, añade un destino:
   - transporte `UDP(4)`;
   - aplicaciones: `suricata`;
   - host: el de Vector;
   - puerto `5514`;
   - **rfc5424** sin marcar.
3. Arranca Vector con una fuente syslog que se quede solo con las alertas y envíe la parte JSON a Redis:

```toml
[sources.opnsense]
type = "syslog"
address = "0.0.0.0:5514"
mode = "udp"

[transforms.eve]
type = "remap"
inputs = ["opnsense"]
source = '''
msg = string!(.message)
i = find(msg, "{")
if i < 0 || !contains(msg, "\"event_type\":\"alert\"") { abort }
.message = slice!(msg, i)
'''

[sinks.surimapa]
type = "redis"
inputs = ["eve"]
endpoint = "redis://192.168.1.10:6379/0"
key = "suricata"
data_type = "list"
list_option.method = "lpush"
encoding.codec = "text"
```

**Bloqueos del firewall de OPNsense.** OPNsense también registra con `filterlog`, con un CSV muy parecido. Puede funcionar si:

- envías la aplicación *filter* a `192.168.1.10:5140` (UDP, RFC 3164);
- pones en `PFSENSE_IP` la IP de OPNsense;
- pones en `FW_IFACE` su dispositivo WAN (p. ej. `igb0`, `vtnet0`, `pppoe0`).

No está probado. Revisa `fw_discarded_malformed` en el latido.

---

## 5. Pasarelas UniFi (Ubiquiti) 🧪

Las pasarelas UniFi (UDM, UDR, UCG, UXG…) usan Suricata en su **IDS/IPS** integrado, pero:

- **no** exponen EVE JSON ni una salida a Redis;
- su exportación syslog / SIEM (*Settings → Control Plane → Integrations* o *System Logs → SIEM Server*, según la versión) envía los eventos en un **formato de texto propio de UniFi o CEF**, que Surimapa **no** interpreta;
- los ficheros internos de la pasarela pueden cambiar con cada actualización de firmware, y Ubiquiti no admite software propio en ella.

Opciones recomendadas, de más a menos robusta:

1. **Monta tu propio sensor Suricata** (§2.1) en un puerto replicado de un switch UniFi (*port mirroring*) o en un host que vea el tráfico de la WAN, con la salida Redis nativa. Tendrás alertas EVE completas, y funciona con cualquier router.
2. **Reenvía y convierte** el syslog de UniFi con Vector (§4) a los campos EVE de [Qué espera Surimapa](#qué-espera-surimapa-alerta-eve): `timestamp`, `event_type: alert`, `src_ip`, `dest_ip`, `proto`, `alert.signature_id`, `alert.signature`, `alert.category`, `alert.severity`. La correspondencia depende del formato exacto de tu firmware; parte de un mensaje capturado.
3. *(Avanzado, sin soporte)* Si tu firmware guarda un `eve.json` propio de Suricata en la pasarela, léelo por SSH y envíalo con la receta del §3. Cuenta con que se rompa al actualizar.

Los bloqueos del firewall de UniFi no están soportados: su formato no es `filterlog`.

---

## 6. Otros routers y firewalls

| Equipo | Camino propuesto |
|---|---|
| **IPFire** | Suricata escribe `eve.json` → §3 (Vector) |
| **OpenWrt** | Paquete `suricata`, si tu hardware puede con él: salida Redis nativa (§2) si está compilado con hiredis; si no, §3 en otro host vía syslog |
| **MikroTik RouterOS** | No tiene Suricata. Replica el tráfico (port mirroring o **TZSP sniffer**) a un Linux con Suricata (§2.1) |
| **Firewalla, routers de operadora, otros** | Replica el tráfico hacia tu propio sensor Suricata (§2.1) |
| **Security Onion, SELKS, Malcolm** | Ya generan `eve.json`: envía las alertas con el §3 |

Regla general:

- si el equipo puede **replicar tráfico**, monta tu propio Suricata;
- si puede **enviar EVE JSON por syslog**, usa un relé Vector;
- si puede **escribir EVE en Redis**, apúntalo directamente a Surimapa.
