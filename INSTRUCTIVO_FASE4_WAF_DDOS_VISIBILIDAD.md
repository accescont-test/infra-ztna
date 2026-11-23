# Instructivo Definitivo: Fase 4 — Capa WAF, Rate Limiting y Visibilidad (`192.168.68.142`)

**Proyecto:** Reto de Ciberseguridad ACCESCONT — Arquitectura Zero Trust y Bastioning  
**Host objetivo:** Synology NAS DS1823xs+ (`accescontnas` — `192.168.68.142`)  
**Subdominios exclusivos de `.142`:** `dsm.accescont.com` y `dsm-api.accescont.com`  
**Zona Cloudflare:** `accescont.com` (`Zone ID: 4b5b0f74a78423c8b540ae47cd9057d5`, plan `Free Website`)

> [!IMPORTANT]
> **Invariantes de seguridad y aislamiento:**
> 1. **Cero afectación a `.141` (`api.accescont.com` y otros servicios):** todas las reglas restrictivas operan exclusivamente sobre `dsm.accescont.com` y `dsm-api.accescont.com`, precedidas por una regla `#1` de `Skip`.
> 2. **Ajustes globales intactos:** mantener `bot_management.fight_mode = false` y `security_level = essentially_off`.
> 3. **Sin cambios en `docker-compose.yml` de `dal-api`:** el contenedor conserva su driver `json-file` para preservar `docker logs dal-api-server`.
> 4. **Mínimo privilegio en el NAS:** en `.142` se almacena **únicamente** un token de **solo lectura** (`CLOUDFLARE_API_TOKEN`); cualquier token de edición usado en el despliegue se conserva solo en local y se revoca al cerrar.

---

## Tabla Resumen de la Fase 4

| Paso | Componente | Acción Implementada y Verificada |
| :--- | :--- | :--- |
| **Paso 4.0** | Bypass & Ajustes Globales | Regla #1 **`Skip WAF - Todo excepto NAS 142`** (`not (http.host in {"dsm.accescont.com" "dsm-api.accescont.com"})`) + `Bot Fight Mode` OFF + `Security Level` `essentially_off`. |
| **Paso 4.1** | WAF Capa 7 (SQLi / XSS / Traversal) | **Cloudflare Managed Free Ruleset** activo + Regla #2 **`WAF Block SQLi XSS Traversal - NAS 142`** (literales + URL-encoded, acción `Block`). |
| **Paso 4.2** | Rate Limiting | Regla **`Rate Limit Login y Auth - NAS 142`** en rutas de autenticación de `.142`: `10` req / `10 s` por IP ➔ `Block` `10 s`. |
| **Paso 4.3** | Auditoría en Synology LogCenter | Paquete `LogCenter` con receptor **Syslog UDP `514` (`BSD`)** + `.cf_logs.env` (`600`) + `cf_log_forwarder.py` (`700`, `CF-WAF` + `CF-ACCESS`) + `systemd timer` cada 5 min. |
| **Paso 4.4** | Batería de Pruebas | Bloqueos WAF `403` en `.142`, no-regresión `200 OK` en `api.accescont.com`, Rate Limit `429` + recuperación `302`, e ingesta automática en `SYNOSYSLOGDB__ARCH.DB` sin duplicados. |

---

## 1. Paso 4.0 — Aislamiento de `.141` (`Skip` Prioritario) y Política Global

### 4.0.1. Crear la regla #1 `Skip WAF - Todo excepto NAS 142`

En lugar de mantener listas manuales de subdominios externos a `.142`, invertimos la condición para que todo servicio actual o futuro fuera de `.142` (como `api.accescont.com`, `n8n`, `nas`, etc.) omita automáticamente las reglas de WAF y límite de tasa:

1. Entra a [dash.cloudflare.com](https://dash.cloudflare.com/) ➔ selecciona la zona **`accescont.com`**.
2. Ve a **Security** ➔ **WAF** ➔ **Custom rules** ➔ **Create rule**.
3. Configura exactamente en **Orden 1**:
   * **Rule name:** `Skip WAF - Todo excepto NAS 142`
   * **Expression (Edit expression):**
     ```text
     not (http.host in {"dsm.accescont.com" "dsm-api.accescont.com"})
     ```
   * **Choose action:** **Skip**
   * **WAF components to skip:**
     * **All remaining custom rules** (`ruleset: "current"`)
     * **All rate limiting rules** (`http_ratelimit`)
     * **All managed rules** (`http_request_firewall_managed`)
4. Haz clic en **Deploy** y confirma que figure en **posición #1**.

### 4.0.2. Mantener ajustes globales sin impacto en `.141`

1. En **Security** ➔ **Bots**, mantén **Bot Fight Mode = OFF** (`fight_mode: false`).  
   *(En el plan `Free Website`, Bot Fight Mode aplica a toda la zona e ignora excepciones `Skip`, por lo que activarlo bloquearía clientes automatizados contra `api.accescont.com`).*
2. En **Security** ➔ **Settings**, mantén **Security Level = Essentially Off** (`essentially_off`).

---

## 2. Paso 4.1 — Protección WAF de Capa 7 (SQLi, XSS y Directory Traversal)

### 4.1.1. Verificar reglas gestionadas base

1. Ve a **Security** ➔ **WAF** ➔ **Managed rules**.
2. Confirma que **Cloudflare Managed Free Ruleset** esté en **Enabled**, sin añadir bloqueos globales sobre toda la zona.

### 4.1.2. Crear la regla #2 `WAF Block SQLi XSS Traversal - NAS 142`

> [!NOTE]
> El plan `Free Website` no dispone de la función `url_decode()` en expresiones WAF, y Cloudflare evalúa `http.request.uri.query` tal como llega codificado (`%20`, `+`, `%3c`, `%2e%2e`). Por ello la regla incluye tanto variantes literales como URL-encoded.

1. Ve a **Security** ➔ **WAF** ➔ **Custom rules** ➔ **Create rule**.
2. Asegúrate de que quede en **Orden 2** (debajo de `Skip WAF - Todo excepto NAS 142`):
   * **Rule name:** `WAF Block SQLi XSS Traversal - NAS 142`
   * **Expression (Edit expression):**
     ```text
     (http.host in {"dsm.accescont.com" "dsm-api.accescont.com"}) and (
       lower(http.request.uri.query) contains "union select" or
       lower(http.request.uri.query) contains "union%20select" or
       lower(http.request.uri.query) contains "union+select" or
       lower(http.request.uri.query) contains "1=1" or
       lower(http.request.uri.query) contains "sleep(" or
       lower(http.request.uri.query) contains "benchmark(" or
       lower(http.request.uri.query) contains "<script" or
       lower(http.request.uri.query) contains "%3cscript" or
       lower(http.request.uri.query) contains "javascript:" or
       lower(http.request.uri.query) contains "onerror=" or
       lower(http.request.uri.query) contains "onload=" or
       http.request.uri.path contains ".." or
       lower(http.request.uri.path) contains "%2e%2e" or
       lower(http.request.uri.query) contains ".." or
       lower(http.request.uri.query) contains "%2e%2e" or
       lower(http.request.uri.path) contains "/etc/passwd" or
       lower(http.request.uri.path) contains "/etc/shadow" or
       lower(http.request.uri.query) contains "/etc/passwd" or
       lower(http.request.uri.query) contains "/etc/shadow"
     )
     ```
   * **Choose action:** **Block**
3. Haz clic en **Deploy**.

---

## 3. Paso 4.2 — Rate Limiting (Mitigación de Fuerza Bruta en `.142`)

El plan Free incluye **1 regla activa de Rate Limiting**:

1. Ve a **Security** ➔ **WAF** ➔ **Rate limiting rules** ➔ **Create rule**.
2. Configura:
   * **Rule name:** `Rate Limit Login y Auth - NAS 142`
   * **Expression (Edit expression):**
     ```text
     (http.host in {"dsm.accescont.com" "dsm-api.accescont.com"}) and (
       http.request.uri.path contains "/login" or
       http.request.uri.path contains "/auth" or
       http.request.uri.path contains "/webman/login.cgi" or
       http.request.uri.path contains "/api/admin/login" or
       http.request.uri.path contains "/nexus-api/auth"
     )
     ```
   * **If requests exceed:** `10` requests
   * **Period:** `10 seconds`
   * **With the same characteristics:** `IP` *(en API: `["cf.colo.id", "ip.src"]`)*
   * **Then take action:** **Block**
   * **For duration:** `10 seconds`
3. Haz clic en **Deploy**.

---

## 4. Paso 4.3 — Auditoría y Visibilidad en Synology Log Center (`.142`)

Dado que **Cloudflare Logpush** requiere plan Enterprise, implementamos un recolector local seguro en Python 3.8 que consulta las APIs gratuitas de lectura de Cloudflare (`firewallEventsAdaptive` y `access/logs/access_requests`) y emite datagramas Syslog nativos hacia el Centro de Registros de DSM.

### 4.3.1. Instalar `Centro de registros` (`LogCenter`) y activar Syslog UDP `514`

1. En DSM (`192.168.68.142`) ➔ **Centro de paquetes**, busca e instala el paquete gratuito **Centro de registros (`LogCenter`)** *(el visor de sistema básico no incluye servidor Syslog)*.
2. Abre **Centro de registros** ➔ **Recepción de registros** ➔ **Crear**:
   * **Nombre:** `SyslogUDP`
   * **Formato de registro:** **`BSD (RFC 3164)`**
   * **Protocolo de transferencia:** **`UDP`**
   * **Puerto:** **`514`** *(SSL desmarcado)*
3. En **Almacenamiento de registros**, selecciona la carpeta compartida de destino (por ejemplo **`Syslog-UDP`**, que crea `/volume1/Syslog-UDP/SYNOSYSLOGDB__ARCH.DB`).
4. Conéctate por SSH a `.142` para confirmar que `syslog-ng` de LogCenter escucha en `0.0.0.0:514/udp`:
   ```bash
   ssh test@192.168.68.142
   sudo sh -c 'if [ -f /var/log/synolog/.SYNOSYSLOGDB ] && [ ! -s /var/log/synolog/.SYNOSYSLOGDB ]; then rm -f /var/log/synolog/.SYNOSYSLOGDB; fi'
   sudo ss -ulnp | grep ":514"
   ```
   *(El `docker-compose.yml` de `dal-api` se deja intacto con `json-file` para no perder `docker logs dal-api-server`).*

### 4.3.2. Crear archivo aislado de credenciales de solo lectura

En `.142`, crea `/volume1/docker/dal-platform/scripts/.cf_logs.env` usando **solo** tu token de lectura de Cloudflare (nunca pongas aquí un token con permisos de edición):

```bash
sudo mkdir -p /volume1/docker/dal-platform/scripts
sudo tee /volume1/docker/dal-platform/scripts/.cf_logs.env >/dev/null << 'EOF'
CLOUDFLARE_API_TOKEN=<TU_CLOUDFLARE_API_TOKEN_SOLO_LECTURA>
CLOUDFLARE_ACCOUNT_ID=<TU_ACCOUNT_ID>
CLOUDFLARE_ZONE_ID=4b5b0f74a78423c8b540ae47cd9057d5
EOF
sudo chown root:root /volume1/docker/dal-platform/scripts/.cf_logs.env
sudo chmod 600 /volume1/docker/dal-platform/scripts/.cf_logs.env
```

### 4.3.3. Desplegar `/volume1/docker/dal-platform/scripts/cf_log_forwarder.py`

Crea el script (librería estándar de Python `3.8`, sin dependencias externas):

```bash
sudo tee /volume1/docker/dal-platform/scripts/cf_log_forwarder.py >/dev/null << 'EOF'
#!/usr/bin/env python3
"""Forward Cloudflare WAF & Access security events for NAS 142 to Synology LogCenter (UDP 514 BSD)."""

import calendar
import hashlib
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request

ENV_PATH = "/volume1/docker/dal-platform/scripts/.cf_logs.env"
STATE_PATH = "/volume1/docker/dal-platform/scripts/.cf_logs_state.json"
SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 514
HOSTNAME = "accescontnas"

TARGET_HOSTS = {"dsm.accescont.com", "dsm-api.accescont.com"}
TARGET_APP_UIDS = {
    "b7fb3116-eaf2-4078-bfdd-1ea4f123fedd",  # dsm.accescont.com
    "a1856004-fd6e-4854-af62-102c8ba63f87",  # dsm-api.accescont.com
}
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
MAX_SEEN = 200
MAX_DGRAM_BYTES = 1000


def load_env(path):
    cfg = {}
    with open(path, "r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg


def iso_utc(unix_ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(unix_ts)))


def parse_iso_utc(iso_str):
    clean = (iso_str or "").strip()
    if not clean:
        return int(time.time())
    if clean.endswith("Z"):
        clean = clean[:-1]
    if "." in clean:
        clean = clean.split(".", 1)[0]
    try:
        tm = time.strptime(clean, "%Y-%m-%dT%H:%M:%S")
        return int(calendar.timegm(tm))
    except Exception:
        return int(time.time())


def format_bsd_timestamp(unix_ts):
    tm = time.localtime(unix_ts)
    mon = MONTHS[tm.tm_mon - 1]
    return "%s %2d %02d:%02d:%02d" % (mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec)


def sanitize(val):
    if val is None:
        return ""
    s = str(val)
    return " ".join(s.replace("\r", " ").replace("\n", " ").replace("\x00", "").split())


def make_seen_key(prefix, payload_str):
    digest = hashlib.sha256((prefix + "|" + payload_str).encode("utf-8")).hexdigest()[:24]
    return "%s:%s" % (prefix, digest)


def build_bsd_syslog(pri, iso_ts, prog, body):
    ts_str = format_bsd_timestamp(parse_iso_utc(iso_ts))
    header = "<%d>%s %s %s: " % (pri, ts_str, HOSTNAME, prog)
    header_bytes = header.encode("utf-8")
    max_body = MAX_DGRAM_BYTES - len(header_bytes)
    if max_body < 32:
        max_body = 32
    clean_body = sanitize(body)
    encoded_body = clean_body.encode("utf-8")
    if len(encoded_body) > max_body:
        cut = encoded_body[: max_body - 3]
        while cut:
            try:
                clean_body = cut.decode("utf-8") + "..."
                break
            except UnicodeDecodeError:
                cut = cut[:-1]
        else:
            clean_body = "..."
        encoded_body = clean_body.encode("utf-8")
    return header_bytes + encoded_body


def load_state(now_ts):
    default_state = {
        "last_waf_ts": iso_utc(now_ts - 86400),
        "last_access_ts": iso_utc(now_ts - 172800),
        "seen_ids": [],
    }
    if not os.path.exists(STATE_PATH):
        return default_state
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            return default_state
        return {
            "last_waf_ts": data.get("last_waf_ts") or default_state["last_waf_ts"],
            "last_access_ts": data.get("last_access_ts") or default_state["last_access_ts"],
            "seen_ids": list(data.get("seen_ids") or [])[-MAX_SEEN:],
        }
    except Exception:
        return default_state


def save_state(state):
    state["seen_ids"] = list(state.get("seen_ids") or [])[-MAX_SEEN:]
    tmp_path = STATE_PATH + ".tmp"
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
            fh.write("\n")
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise
    os.chmod(tmp_path, 0o600)
    os.replace(tmp_path, STATE_PATH)


def fetch_waf_events(token, zone_id, since_iso):
    query = (
        'query { viewer { zones(filter: {zoneTag: "%s"}) { '
        'firewallEventsAdaptive(filter: {datetime_gt: "%s", '
        'clientRequestHTTPHost_in: ["dsm.accescont.com", "dsm-api.accescont.com"]}, '
        'limit: 50, orderBy: [datetime_ASC]) { '
        'datetime action clientIP clientRequestHTTPHost '
        'clientRequestHTTPMethodName clientRequestPath clientRequestQuery ruleId source '
        '} } } }'
    ) % (zone_id, since_iso)
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4/graphql",
        data=json.dumps({"query": query}).encode("utf-8"),
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "accescont-nas142-log-forwarder/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("errors"):
        raise RuntimeError("GraphQL errors: " + json.dumps(data["errors"]))
    zones = data.get("data", {}).get("viewer", {}).get("zones", [])
    if not zones:
        return []
    return zones[0].get("firewallEventsAdaptive") or []


def fetch_access_events(token, account_id, since_iso):
    url = "https://api.cloudflare.com/client/v4/accounts/%s/access/logs/access_requests" % account_id
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": "Bearer " + token,
            "Content-Type": "application/json",
            "User-Agent": "accescont-nas142-log-forwarder/1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("success", False):
        raise RuntimeError("Access API failed: " + json.dumps(data.get("errors")))
    raw = data.get("result") or []
    filtered = []
    for ev in raw:
        uid = ev.get("app_uid") or ""
        dom = (ev.get("app_domain") or "").lower()
        created = ev.get("created_at") or ""
        if (uid in TARGET_APP_UIDS or dom in TARGET_HOSTS) and created >= since_iso:
            filtered.append(ev)
    filtered.sort(key=lambda x: x.get("created_at") or "")
    return filtered


def main():
    verbose = "--verbose" in sys.argv[1:]
    cfg = load_env(ENV_PATH)
    token = cfg.get("CLOUDFLARE_API_TOKEN", "")
    account_id = cfg.get("CLOUDFLARE_ACCOUNT_ID", "")
    zone_id = cfg.get("CLOUDFLARE_ZONE_ID", "")
    if not token or not account_id or not zone_id:
        raise RuntimeError("Missing Cloudflare RO credentials in " + ENV_PATH)

    now_ts = int(time.time())
    state = load_state(now_ts)
    seen = set(state["seen_ids"])
    seen_order = list(state["seen_ids"])

    waf_events = fetch_waf_events(token, zone_id, state["last_waf_ts"])
    access_events = fetch_access_events(token, account_id, state["last_access_ts"])

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    waf_sent = 0
    access_sent = 0
    new_waf_ts = state["last_waf_ts"]
    new_access_ts = state["last_access_ts"]

    try:
        for ev in waf_events:
            dt = ev.get("datetime") or ""
            key_str = "%s|%s|%s|%s|%s|%s|%s" % (
                dt,
                ev.get("action") or "",
                ev.get("clientIP") or "",
                ev.get("clientRequestHTTPHost") or "",
                ev.get("clientRequestPath") or "",
                ev.get("clientRequestQuery") or "",
                ev.get("ruleId") or "",
            )
            key = make_seen_key("WAF", key_str)
            if dt > new_waf_ts:
                new_waf_ts = dt
            if key in seen:
                continue

            action = (ev.get("action") or "").lower()
            pri = 132 if action in ("block", "managed_challenge", "jschallenge", "challenge") else 134
            body = "action=%s source=%s rule=%s ip=%s host=%s method=%s path=%s query=%s" % (
                sanitize(ev.get("action")),
                sanitize(ev.get("source")),
                sanitize(ev.get("ruleId")),
                sanitize(ev.get("clientIP")),
                sanitize(ev.get("clientRequestHTTPHost")),
                sanitize(ev.get("clientRequestHTTPMethodName")),
                sanitize(ev.get("clientRequestPath")),
                sanitize(ev.get("clientRequestQuery") or "-"),
            )
            dgram = build_bsd_syslog(pri, dt, "CF-WAF", body)
            sock.sendto(dgram, (SYSLOG_HOST, SYSLOG_PORT))
            waf_sent += 1
            seen.add(key)
            seen_order.append(key)

        for ev in access_events:
            dt = ev.get("created_at") or ""
            key_str = "%s|%s|%s|%s|%s" % (
                dt,
                ev.get("ray_id") or "",
                ev.get("app_uid") or "",
                ev.get("user_email") or "",
                ev.get("allowed"),
            )
            key = make_seen_key("ACC", key_str)
            if dt > new_access_ts:
                new_access_ts = dt
            if key in seen:
                continue

            allowed = bool(ev.get("allowed"))
            pri = 134 if allowed else 132
            body = "allowed=%s action=%s app=%s user=%s ip=%s country=%s conn=%s ray=%s" % (
                "true" if allowed else "false",
                sanitize(ev.get("action")),
                sanitize(ev.get("app_domain") or ev.get("app_name")),
                sanitize(ev.get("user_email") or ev.get("user_id") or "-"),
                sanitize(ev.get("ip_address")),
                sanitize(ev.get("country")),
                sanitize(ev.get("connection") or "-"),
                sanitize(ev.get("ray_id") or "-"),
            )
            dgram = build_bsd_syslog(pri, dt, "CF-ACCESS", body)
            sock.sendto(dgram, (SYSLOG_HOST, SYSLOG_PORT))
            access_sent += 1
            seen.add(key)
            seen_order.append(key)
    finally:
        sock.close()

    state["last_waf_ts"] = new_waf_ts
    state["last_access_ts"] = new_access_ts
    state["seen_ids"] = seen_order[-MAX_SEEN:]
    save_state(state)

    if verbose:
        print("WAF_SENT=%d ACCESS_SENT=%d TOTAL_SENT=%d" % (waf_sent, access_sent, waf_sent + access_sent))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        sys.stderr.write("cf_log_forwarder ERROR: %s\n" % exc)
        sys.exit(1)
EOF
sudo chown root:root /volume1/docker/dal-platform/scripts/cf_log_forwarder.py
sudo chmod 700 /volume1/docker/dal-platform/scripts/cf_log_forwarder.py
```

Compila y ejecuta una prueba manual inicial:

```bash
sudo /usr/bin/python3 -m py_compile /volume1/docker/dal-platform/scripts/cf_log_forwarder.py
sudo /usr/bin/python3 /volume1/docker/dal-platform/scripts/cf_log_forwarder.py --verbose
```
*Salida esperada:* `WAF_SENT=<n> ACCESS_SENT=<m> TOTAL_SENT=<k>`, creando `.cf_logs_state.json` con permisos `600`.

### 4.3.4. Programar ejecución cada 5 minutos con `systemd` timer

1. Crea los archivos de servicio y timer:

```bash
sudo tee /etc/systemd/system/cf-log-forwarder.service >/dev/null << 'EOF'
[Unit]
Description=Cloudflare Security Logs Forwarder to Synology LogCenter (NAS 142)
After=network-online.target

[Service]
Type=oneshot
User=root
ExecStart=/usr/bin/python3 /volume1/docker/dal-platform/scripts/cf_log_forwarder.py
EOF

sudo tee /etc/systemd/system/cf-log-forwarder.timer >/dev/null << 'EOF'
[Unit]
Description=Run Cloudflare Security Logs Forwarder every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
Unit=cf-log-forwarder.service

[Install]
WantedBy=timers.target
EOF

sudo chmod 644 /etc/systemd/system/cf-log-forwarder.service /etc/systemd/system/cf-log-forwarder.timer
```

2. Habilita e inicia el timer (**nota:** DSM usa `systemd 219`, que no admite `--now`, por lo que `enable` y `start` van separados):

```bash
sudo systemctl daemon-reload
sudo systemctl enable cf-log-forwarder.timer
sudo systemctl start cf-log-forwarder.timer
sudo systemctl start cf-log-forwarder.service
sudo systemctl list-timers cf-log-forwarder.timer --no-pager
```

---

## 5. Paso 4.4 — Batería de Pruebas de Verificación (`.142` + No-Regresión `.141`)

Ejecuta desde **Windows PowerShell**:

### 1. Pruebas WAF (`.142`: `dsm-api.accescont.com` y `dsm.accescont.com`)
```powershell
(curl.exe -sS -I "https://dsm-api.accescont.com/api/test?id=1%20UNION%20SELECT%20NULL")[0]
(curl.exe -sS -I "https://dsm-api.accescont.com/api/test?q=%3Cscript%3Ealert(1)%3C/script%3E")[0]
(curl.exe -sS -I "https://dsm-api.accescont.com/api/test?file=../../etc/passwd")[0]
(curl.exe -sS -I "https://dsm.accescont.com/?id=1%20UNION%20SELECT%20NULL")[0]
```
*Esperado:* **`HTTP/1.1 403 Forbidden`** en las 4 peticiones (bloqueadas en Edge antes de Cloudflare Access).

### 2. Pruebas de no-regresión `.141` (`api.accescont.com`)
```powershell
(curl.exe -sS -I "https://api.accescont.com/api/health")[0]
(curl.exe -sS -I "https://api.accescont.com/api/health?q=1%20UNION%20SELECT%20NULL")[0]
(curl.exe -sS -I "https://api.accescont.com/api/health?x=%3Cscript%3Ealert(1)%3C/script%3E")[0]
(curl.exe -sS -I "https://api.accescont.com/api/health?file=../../etc/passwd")[0]
```
*Esperado:* **`HTTP/1.1 200 OK`** en las 4 peticiones gracias a la regla #1 `Skip`.

### 3. Pruebas de Rate Limiting + aislamiento + recuperación
```powershell
1..14 | ForEach-Object {
    $c = curl.exe -s -o NUL -w "%{http_code}" "https://dsm-api.accescont.com/api/admin/login"
    "Req $($_): HTTP $c"
    Start-Sleep -Milliseconds 100
}
(curl.exe -sS -I "https://dsm-api.accescont.com/api/health")[0]
(curl.exe -sS -I "https://api.accescont.com/api/health")[0]
```
*Esperado:* primeras ~10–11 en `302` y siguientes en **`HTTP 429`**; `/api/health` de `dsm-api` sigue en `302` y `api.accescont.com` sigue en `200 OK`. Tras 10 segundos, `https://dsm-api.accescont.com/api/admin/login` recupera a `302`.

### 4. Verificación en Synology LogCenter (UI + SQLite solo lectura + deduplicación)
* **En DSM (`192.168.68.142`):** abre **Centro de registros ➔ Registros ➔ De otros servidores** (`Syslog-UDP`) para visualizar los eventos **`CF-WAF`** (`warning`) y **`CF-ACCESS`** (`info`/`warning`).
* **Por SSH en `.142` (abriendo SQLite únicamente en modo `?mode=ro`):**
  ```bash
  sudo /usr/bin/python3 -c 'import sqlite3; c=sqlite3.connect("file:/volume1/Syslog-UDP/SYNOSYSLOGDB__ARCH.DB?mode=ro", uri=True); print(c.execute("SELECT prog, llevel, COUNT(*) FROM logs GROUP BY prog, llevel").fetchall())'
  sudo /usr/bin/python3 /volume1/docker/dal-platform/scripts/cf_log_forwarder.py --verbose
  ```
  *Esperado:* filas contabilizadas por `CF-WAF` y `CF-ACCESS`, y en la segunda corrida inmediata **`WAF_SENT=0 ACCESS_SENT=0 TOTAL_SENT=0`** (sin duplicados).

---

## 6. Paso 4.5 — Plan de Rollback Completo e Higiene Final

### Rollback en Cloudflare (< 2 s)
* En **Security ➔ WAF ➔ Custom rules**, desactivar o eliminar `WAF Block SQLi XSS Traversal - NAS 142` (y si deseas dejar la zona limpia, también `Skip WAF - Todo excepto NAS 142`).
* En **Security ➔ WAF ➔ Rate limiting rules**, desactivar o eliminar `Rate Limit Login y Auth - NAS 142`.

### Rollback en `.142` (LogCenter + recolector)
```bash
sudo systemctl stop cf-log-forwarder.timer cf-log-forwarder.service
sudo systemctl disable cf-log-forwarder.timer
sudo rm -f /etc/systemd/system/cf-log-forwarder.timer /etc/systemd/system/cf-log-forwarder.service
sudo systemctl daemon-reload
sudo rm -f /volume1/docker/dal-platform/scripts/cf_log_forwarder.py \
           /volume1/docker/dal-platform/scripts/.cf_logs.env \
           /volume1/docker/dal-platform/scripts/.cf_logs_state.json
```
Y en DSM ➔ **Centro de registros ➔ Recepción de registros**, deshabilitar/eliminar `SyslogUDP`.

### Higiene de cierre
* Revoca o elimina en Cloudflare el token temporal de edición (`CLOUDFLARE_ED_API_TOKEN`) una vez confirmadas todas las reglas.
