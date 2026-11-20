# Instructivo Paso a Paso: Fase 4 — Capa WAF, DDoS, Rate Limiting y Visibilidad

**Proyecto:** Reto de Ciberseguridad ACCESCONT — Arquitectura Zero Trust y Bastioning  
**Host objetivo:** Synology NAS DS1823xs+ (`accescontnas` — `192.168.68.142`)  
**Servicios cubiertos en `.142`:**
* **DSM:** `dsm.accescont.com` (interfaz nativa de Synology en puerto 5000 vía túnel `synology-nas-new`)
* **Backend API / BaaS:** `dsm-api.accescont.com` (`dal-platform` en Docker `dal-api-server:3000`)
* *(Nota de alcance: Este instructivo protege exclusivamente los subdominios de `.142` y no modifica ningún servicio del NAS `.141`).*

---

## 1. Resumen de la Fase 4 y Adaptación al Entorno

| Control del Reto | Requisito Teórico | Implementación Práctica en `.142` (Plan Cloudflare Free) |
| :--- | :--- | :--- |
| **Paso 4.1: WAF L7** | Cloudflare Managed Ruleset (SQLi, XSS) en acción `Block` | Activación de **Cloudflare Managed Free Ruleset** + **Custom WAF Rule** específica para `dsm` y `dsm-api` con acción `Block` ante firmas SQLi, XSS y Directory Traversal. |
| **Paso 4.2: Rate Limiting** | Regla de límite de tasa en endpoints `/login` y `/auth/` (20 req / 1 min ➔ Block 10 min) | Configuración de la **regla gratuita de Rate Limiting** de Cloudflare sobre endpoints de autenticación en `dsm` y `dsm-api` (umbral: 10 req en 10 s ➔ `Block` 10 s). |
| **Paso 4.3: Auditoría y Visibilidad** | Exportación de registros hacia el Centro de Registros de Synology | Habilitación del servidor Syslog en **Centro de Registros de DSM** (`192.168.68.142`) + configuración de logging en Docker y script de recolección de eventos de seguridad Cloudflare hacia Syslog. |

---

## 2. Paso 4.1 — Protección WAF de Capa 7 (SQLi, XSS y Traversal)

### 4.1.1. Verificar las reglas gestionadas básicas de Cloudflare

1. Entra a [dash.cloudflare.com](https://dash.cloudflare.com/) y selecciona el dominio **`accescont.com`**.
2. Ve a **Security** ➔ **WAF** ➔ pestaña **Managed rules**.
3. Asegúrate de que el ruleset **Cloudflare Managed Free Ruleset** esté en estado **Enabled** (este ruleset mitiga vulnerabilidades críticas conocidas como Log4j, CVEs de Spring, etc.).
4. En **Security** ➔ **Settings**, verifica que el **Security Level** esté configurado al menos en **Medium**.

---

### 4.1.2. Crear la regla personalizada (Custom Rule) para `dsm` y `dsm-api`

Dado que el plan Free no incluye el conjunto gestionado OWASP comercial completo, crearemos una regla WAF personalizada con acción **Block** que inspecciona parámetros y cuerpo de petición:

1. En el menú de Cloudflare, ve a **Security** ➔ **WAF** ➔ pestaña **Custom rules**.
2. Haz clic en **Create rule**.
3. Asigna los siguientes valores:
   * **Rule name:** `WAF Block SQLi XSS Traversal - NAS 142`
   * **When incoming requests match:** Haz clic en **Edit expression** (modo texto) y pega exactamente la siguiente expresión:

```text
(http.host in {"dsm.accescont.com" "dsm-api.accescont.com"}) and (
  lower(http.request.uri.query) contains "union select" or
  lower(http.request.uri.query) contains "1=1" or
  lower(http.request.uri.query) contains "sleep(" or
  lower(http.request.uri.query) contains "<script" or
  lower(http.request.uri.query) contains "javascript:" or
  lower(http.request.uri.query) contains "onerror=" or
  lower(http.request.uri.query) contains "onload=" or
  http.request.uri.path contains ".." or
  http.request.uri.path contains "/etc/passwd" or
  http.request.uri.path contains "/etc/shadow" or
  lower(http.request.uri.query) contains "/etc/passwd" or
  lower(http.request.uri.query) contains "benchmark("
)
```

4. En **Choose action**:
   * Selecciona **Block**.
5. Haz clic en **Deploy**.

> [!NOTE]
> Esta regla se ejecuta en el Edge de Cloudflare antes de que la petición toque el túnel `synology-nas-new`, retornando de inmediato un error **`HTTP 403 Forbidden`** con el sello de seguridad de Cloudflare.

---

## 3. Paso 4.2 — Mitigación de Abuso y Fuerza Bruta (Rate Limiting)

El plan Free de Cloudflare permite **1 regla activa de Rate Limiting**. La aplicaremos para proteger los puntos de entrada administrativos de DSM y de la API.

### 4.2.1. Crear la regla de Rate Limiting

1. En Cloudflare, ve a **Security** ➔ **WAF** ➔ pestaña **Rate limiting rules**.
2. Haz clic en **Create rule**.
3. Llena el formulario con estos datos:
   * **Rule name:** `Rate Limit Login y Auth - NAS 142`
   * **If incoming requests match:** Selecciona **Edit expression** y pega:

```text
(http.host in {"dsm.accescont.com" "dsm-api.accescont.com"}) and (
  http.request.uri.path contains "/login" or
  http.request.uri.path contains "/auth" or
  http.request.uri.path contains "/webman/login.cgi" or
  http.request.uri.path contains "/api/admin/login" or
  http.request.uri.path contains "/nexus-api/auth"
)
```

4. En la sección **Rate**:
   * **Requests:** `10`
   * **Period:** `10 seconds` *(parámetro estándar en plan Free)*
   * **Counting characteristics:** `IP`
5. En la sección **Action**:
   * **Choose action:** **Block** (o `Managed Challenge` si prefieres presentar un captcha interactivo)
   * **Duration:** `10 seconds`
6. Haz clic en **Deploy**.

---

## 4. Paso 4.3 — Visibilidad y Auditoría Centralizada en Synology Log Center

### 4.3.1. Habilitar la recepción Syslog en el Centro de Registros de DSM (`.142`)

1. Entra a la interfaz web de DSM: `https://dsm.accescont.com` o internamente por LAN `https://192.168.68.142:5001` (o `http://192.168.68.142:5000`).
2. Abre el menú principal y haz clic en **Centro de registros (Log Center)**.
3. En el menú lateral izquierdo, haz clic en **Recepción de registros (Log Receiving)**.
4. En la pestaña **Crear (Create)**:
   * **Nombre:** `Syslog-ZeroTrust-142`
   * **Formato de registro:** `BSD (RFC 3164)` o `IETF (RFC 5424)`
   * **Protocolo de transferencia:** `UDP` (o `TCP`)
   * **Puerto:** `514`
5. Haz clic en **Aplicar**.
6. Ve a **Almacenamiento de registros (Storage)** dentro de Log Center y define un volumen y carpeta de almacenamiento (ej. `/volume1/docker/logs` o carpeta compartida designada) para retener el archivo histórico de auditoría.
7. *(Opcional)* Si tienes activado el Firewall de DSM (**Panel de control > Seguridad > Firewall**), asegúrate de tener una regla que permita el puerto UDP/TCP `514` desde la red local `192.168.68.0/24` y `127.0.0.1`.

---

### 4.3.2. Conectar los logs de `dal-platform` al Centro de Registros (Syslog Local)

Para que todos los eventos de la API se registren automáticamente en el Centro de Registros de DSM:

1. Conéctate por SSH a `192.168.68.142`:
   ```bash
   ssh test@192.168.68.142
   cd /volume1/docker/dal-platform
   ```
2. Puedes configurar el driver de log en `docker-compose.yml` para el servicio `dal-api` añadiendo:

```yaml
    logging:
      driver: syslog
      options:
        syslog-address: "udp://127.0.0.1:514"
        tag: "dal-api-server"
```
*(Nota: Aplicable cuando desees reconstruir/recrear el contenedor con `docker-compose up -d`).*

---

### 4.3.3. Script de Sincronización de Eventos de Seguridad Cloudflare hacia DSM (Task Scheduler)

Como Cloudflare Logpush requiere plan Enterprise, se utiliza un script ligero en Python en el NAS que consulta la API de Cloudflare Security Events cada 5 minutos y los reenvía vía Syslog local al Centro de Registros.

1. **Crear el script en el NAS (`/volume1/docker/dal-platform/scripts/cf_log_forwarder.py`):**

```bash
sudo mkdir -p /volume1/docker/dal-platform/scripts
sudo tee /volume1/docker/dal-platform/scripts/cf_log_forwarder.py >/dev/null << 'EOF'
#!/usr/bin/env python3
import os
import sys
import time
import socket
import json
import urllib.request

ZONE_ID = "4b5b0f74a78423c8b540ae47cd9057d5"
SYSLOG_HOST = "127.0.0.1"
SYSLOG_PORT = 514
STATE_FILE = "/tmp/.cf_last_log_ts"

# Leer token de forma segura del entorno o argumento
API_TOKEN = os.environ.get("CLOUDFLARE_API_TOKEN")
if not API_TOKEN and os.path.exists("/volume1/docker/dal-platform/.env"):
    for line in open("/volume1/docker/dal-platform/.env"):
        if line.startswith("CLOUDFLARE_API_TOKEN="):
            API_TOKEN = line.strip().split("=", 1)[1].strip("'\"")

if not API_TOKEN:
    sys.exit(0)

# Obtener última marca de tiempo consultada (por defecto últimos 10 minutos)
now = int(time.time())
since = now - 600
if os.path.exists(STATE_FILE):
    try:
        since = int(open(STATE_FILE).read().strip())
    except:
        pass

since_iso = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(since))
query = f"""
query {{
  viewer {{
    zones(filter: {{zoneTag: "{ZONE_ID}"}}) {{
      firewallEventsAdaptive(
        filter: {{
          datetime_gt: "{since_iso}"
          clientRequestHTTPHost_in: ["dsm.accescont.com", "dsm-api.accescont.com"]
        }}
        limit: 50
        orderBy: [datetime_ASC]
      ) {{
        datetime
        action
        clientIP
        clientRequestHTTPHost
        clientRequestHTTPMethodName
        clientRequestPath
        ruleId
        source
      }}
    }}
  }}
}}
"""

req = urllib.request.Request(
    "https://api.cloudflare.com/client/v4/graphql",
    data=json.dumps({"query": query}).encode("utf-8"),
    headers={
        "Authorization": f"Bearer {API_TOKEN}",
        "Content-Type": "application/json"
    }
)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        zones = data.get("data", {}).get("viewer", {}).get("zones", [])
        events = zones[0].get("firewallEventsAdaptive", []) if zones else []
        
        last_ts = since
        for ev in events:
            msg = f"<14>1 {ev['datetime']} accescontnas CF-WAF - - [event action=\"{ev['action']}\" ip=\"{ev['clientIP']}\" host=\"{ev['clientRequestHTTPHost']}\" path=\"{ev['clientRequestPath']}\" source=\"{ev['source']}\"] Evento de Seguridad Cloudflare"
            sock.sendto(msg.encode("utf-8"), (SYSLOG_HOST, SYSLOG_PORT))
            
        if events:
            open(STATE_FILE, "w").write(str(now))
except Exception as e:
    pass
EOF
sudo chmod 700 /volume1/docker/dal-platform/scripts/cf_log_forwarder.py
```

2. **Programar la tarea en Synology DSM:**
   * Entra a DSM ➔ **Panel de control** ➔ **Programador de tareas (Task Scheduler)**.
   * Clic en **Crear** ➔ **Tarea programada** ➔ **Script definido por el usuario**.
   * **General:**
     * Tarea: `Cloudflare-Security-Logs-Sync`
     * Usuario: `root`
   * **Horario:** Ejecutar diariamente cada 5 o 10 minutos.
   * **Configuración de tareas:**
     * Comando: `python3 /volume1/docker/dal-platform/scripts/cf_log_forwarder.py`
   * Guardar.

---

## 5. Paso 4.4 — Batería de Pruebas de Verificación (Entregables)

Ejecuta estas pruebas desde tu terminal Windows PowerShell para verificar el cumplimiento:

### 1. Prueba de WAF contra SQL Injection (SQLi)

```powershell
curl.exe -i "https://dsm-api.accescont.com/api/test?id=1%20UNION%20SELECT%20NULL"
```
* **Resultado esperado:** `HTTP/1.1 403 Forbidden` directo de Cloudflare con encabezados `Server: cloudflare` y código de error de bloqueo WAF.

---

### 2. Prueba de WAF contra Cross-Site Scripting (XSS)

```powershell
curl.exe -i "https://dsm-api.accescont.com/api/test?search=%3Cscript%3Ealert(1)%3C/script%3E"
```
* **Resultado esperado:** `HTTP/1.1 403 Forbidden` bloqueado por la regla personalizada.

---

### 3. Prueba de WAF contra Path Traversal

```powershell
curl.exe -i "https://dsm-api.accescont.com/../../etc/passwd"
```
* **Resultado esperado:** `HTTP/1.1 403 Forbidden` o normalización inmediata de URL bloqueada.

---

### 4. Prueba de Rate Limiting (Ataque de fuerza bruta simulado)

Ejecuta una ráfaga rápida de 15 solicitudes seguidas al endpoint de login:

```powershell
1..15 | ForEach-Object {
    $resp = curl.exe -s -o NUL -w "%{http_code}`n" "https://dsm-api.accescont.com/api/admin/login"
    "Peticion $_ : HTTP $resp"
    Start-Sleep -Milliseconds 200
}
```
* **Resultado esperado:** Las primeras solicitudes devuelven `403` (por falta de credenciales o de token JWT) y a partir de la petición 10 u 11 la respuesta cambia a **`HTTP 429 Too Many Requests`** o **`403 Blocked by Cloudflare`** durante la ventana de rate limiting.

---

### 5. Verificación de Visibilidad en Synology Log Center

1. Abre el **Centro de Registros (Log Center)** en DSM (`192.168.68.142`).
2. Ve a la pestaña **Registros (Logs)** y selecciona el menú desplegable **De otros servidores / Syslog**.
3. Deberás observar los eventos con etiqueta `CF-WAF` y `dal-api-server` detallando la fecha, la IP de origen y la acción de mitigación (`block`).

---

## 6. Plan de Rollback (Por si se requiere revertir)

* **Para desactivar la regla WAF:** En Cloudflare ➔ **Security > WAF > Custom rules**, apagar el interruptor de la regla `WAF Block SQLi XSS Traversal - NAS 142`.
* **Para desactivar el Rate Limiting:** En Cloudflare ➔ **Security > WAF > Rate limiting rules**, desactivar la regla `Rate Limit Login y Auth - NAS 142`.
* **Para desactivar la recepción Syslog en DSM:** En DSM ➔ **Centro de registros > Recepción de registros**, desmarcar la casilla de recepción y hacer clic en **Aplicar**.
