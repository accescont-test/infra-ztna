# Instructivo de Ejecución: Fase 1 — Aislamiento de Redes Docker y Zero Trust Ingress (`192.168.68.142`)

**Proyecto:** Reto de Ciberseguridad ACCESCONT  
**Host:** Synology NAS DS1823xs+ (`accescontnas` — `192.168.68.142`)  
**Stack:** `/volume1/docker/dal-platform/` + Túnel Cloudflare `synology-nas-new` (`cloudflare-cloudflared-1`)  
**Modalidad:** Ejecución en caliente (*Opción B — Cero desconexión del túnel*)  
**Fecha de validación:** Noviembre 2026  

---

## 1. Objetivo de Seguridad y Cambio de Arquitectura

Antes de la Fase 1, `dal-api-server` (`3000:3000`) y `dal-mongodb-server` (`27017:27017`) publicaban puertos directamente en la red local (`0.0.0.0`), y el conector `cloudflare-cloudflared-1` compartía la misma red bridge que la base de datos (`dal-platform_dal-network`).

Con este procedimiento logramos:
1. **Cerrar los puertos `3000` y `27017` en la LAN:** Ningún equipo de la red local puede conectarse directamente a la API ni a MongoDB.
2. **Enrutamiento interno por DNS Docker:** El subdominio público `dsm-api.accescont.com` entra por el túnel hacia `http://dal-api-server:3000`.
3. **Microsegmentación en dos redes Docker:**
   * **`ztna-network` (`172.19.0.0/16`):** Conecta únicamente a `cloudflare-cloudflared-1` ↔ `dal-api-server`.
   * **`dal-platform_dal-network` (`172.18.0.0/16`):** Conecta únicamente a `dal-api-server` ↔ `dal-mongodb-server` (el túnel no tiene visibilidad de red hacia MongoDB).

```text
                [ Internet / Cloudflare Edge ]
                              │
                              ▼ (Túnel QUIC - synology-nas-new)
                 [ cloudflare-cloudflared-1 ]
                        172.19.0.2/16
                              │
             ┌────────────────┴────────────────┐
             │ Red ZTNA: ztna-network          │
             │ Subred: 172.19.0.0/16           │
             ▼                                 ▼
      (dsm-api.accescont.com)        (dsm.accescont.com)
    [ dal-api-server ]              [ Host DSM :5000 ]
      172.19.0.3/16
      172.18.0.3/16
             │
             │ Red Privada: dal-platform_dal-network (172.18.0.0/16)
             ▼
    [ dal-mongodb-server ]
      172.18.0.2/16
      (Aislada de ztna-network y sin puerto 27017 en LAN)
```

---

## 2. Reglas Operativas Aplicadas para No Perder el Túnel

> [!CAUTION]
> * **Nunca ejecutar `docker-compose down`** en `/volume1/docker/dal-platform/` mientras `cloudflare-cloudflared-1` esté conectado a `dal-platform_dal-network`, ya que intentaría destruir la red del túnel.
> * **No usar `nano`** en DSM (no viene instalado por defecto); usar `vim`, `vi` o edición controlada con `python3`.
> * **Cuidado con `.env` vs `docker-compose.yml`:** En `.142`, `.env` contenía `MONGO_URI` apuntando a `mongo.accescont.com:27017`, mientras `docker-compose.yml` usa el DNS interno `@mongodb:27017`. Se conservó intacto el bloque `environment:` de `docker-compose.yml` para mantener la conexión interna a MongoDB tras cerrar el puerto `27017`.

---

## 3. Procedimiento Paso a Paso Ejecutado

### Paso 1: Conexión SSH y Respaldos Preventivos

```bash
ssh test@192.168.68.142
```

Respaldo de archivos de configuración e inspección del contenedor del túnel con permisos restringidos (`600`):

```bash
cd /volume1/docker/dal-platform
sudo cp docker-compose.yml docker-compose.yml.bak
sudo cp .env .env.bak
sudo chmod 600 .env .env.bak docker-compose.yml.bak
sudo /usr/local/bin/docker inspect cloudflare-cloudflared-1 | sudo tee /volume1/docker/cloudflared-142.inspect.bak.json >/dev/null
sudo chmod 600 /volume1/docker/cloudflared-142.inspect.bak.json
```

---

### Paso 2: Crear `ztna-network` y Conectar el Túnel en Caliente

Se creó la nueva red bridge aislada y se conectó `cloudflare-cloudflared-1` sin detener ni reiniciar el proceso:

```bash
sudo /usr/local/bin/docker network create ztna-network
sudo /usr/local/bin/docker network connect ztna-network cloudflare-cloudflared-1
```

Verificación inmediata:

```bash
sudo /usr/local/bin/docker network inspect ztna-network --format '{{range .Containers}}{{.Name}} {{end}}'
# Resultado: cloudflare-cloudflared-1
```

---

### Paso 3: Ruta Interna en Cloudflare Zero Trust

En [one.dash.cloudflare.com](https://one.dash.cloudflare.com/) ➔ **Networks ➔ Tunnels ➔ `synology-nas-new` ➔ Published application routes**, quedó configurado:

| Hostname Público | Destino Configurado | Tipo de Enrutamiento |
| :--- | :--- | :--- |
| `dsm-api.accescont.com` | `http://dal-api-server:3000` | Interno por DNS Docker (`ztna-network`) |
| `dsm.accescont.com` | `http://192.168.68.142:5000` | Servicio nativo Synology DSM |

---

### Paso 4: Hardening de `/volume1/docker/dal-platform/docker-compose.yml`

Se aplicaron tres modificaciones al archivo `docker-compose.yml`:
1. **Servicio `mongodb`:** Se eliminó `ports: - "27017:27017"` y permaneció únicamente en `dal-network`.
2. **Servicio `dal-api`:** Se eliminó `ports: - "3000:3000"` y se conectó a `dal-network` y `ztna-network`.
3. **Sección `networks:`:** Se mantuvo `dal-network` (`name: dal-platform_dal-network`, `driver: bridge`) y se declaró `ztna-network: external: true`.

Comando ejecutado para aplicar la edición limpia sobre el YAML:

```bash
sudo python3 -c '
p = "/volume1/docker/dal-platform/docker-compose.yml"
s = open(p).read()
s = s.replace("    ports:\n      - \"27017:27017\"\n", "")
s = s.replace("    ports:\n      - \"3000:3000\"\n", "")
s = s.replace("    depends_on:\n      - mongodb\n    networks:\n      - dal-network\n", "    depends_on:\n      - mongodb\n    networks:\n      - dal-network\n      - ztna-network\n")
s = s.replace("networks:\n  dal-network:\n    name: dal-platform_dal-network\n    driver: bridge", "networks:\n  dal-network:\n    name: dal-platform_dal-network\n    driver: bridge\n  ztna-network:\n    external: true")
open(p, "w").write(s)
'
```

Estructura final de `/volume1/docker/dal-platform/docker-compose.yml` *(credenciales omitidas)*:

```yaml
version: '3.8'

services:
  mongodb:
    image: mongo:latest
    container_name: dal-mongodb-server
    restart: unless-stopped
    environment:
      MONGO_INITDB_ROOT_USERNAME: admin_user_db
      MONGO_INITDB_ROOT_PASSWORD: "<PROTEGIDO>"
    volumes:
      - ./data/db:/data/db
    networks:
      - dal-network

  dal-api:
    build: .
    container_name: dal-api-server
    restart: unless-stopped
    environment:
      PORT: 3000
      MONGO_URI: "<PROTEGIDO - @mongodb:27017>"
      DAL_API_KEY: "<PROTEGIDO>"
      JWT_SECRET: "<PROTEGIDO>"
      NEXT_PUBLIC_ROOT_DOMAIN: ${NEXT_PUBLIC_ROOT_DOMAIN:-dsm-api.accescont.com}
    volumes:
      - ./public/uploads:/app/public/uploads
    depends_on:
      - mongodb
    networks:
      - dal-network
      - ztna-network

networks:
  dal-network:
    name: dal-platform_dal-network
    driver: bridge
  ztna-network:
    external: true
```

Validación previa de sintaxis y cambios:

```bash
sudo /usr/local/bin/docker-compose config -q && echo "YAML OK"
diff -u docker-compose.yml.bak docker-compose.yml
```

---

### Paso 5: Recreación Selectiva de Servicios (Sin Bajar el Túnel)

```bash
cd /volume1/docker/dal-platform
sudo /usr/local/bin/docker-compose up -d
```

Docker Compose recreó únicamente `dal-mongodb-server` y `dal-api-server` sin puertos en la LAN, dejando `cloudflare-cloudflared-1` en ejecución continua.

---

### Paso 6: Desacoplar `cloudflared` de la Red de Base de Datos

Una vez comprobado que `https://dsm-api.accescont.com/` respondía por `ztna-network`, se desconectó el túnel de la red privada donde reside MongoDB:

```bash
sudo /usr/local/bin/docker network disconnect dal-platform_dal-network cloudflare-cloudflared-1
```

---

## 4. Evidencias de Verificación Realizadas

### 4.1. Contenedores y Redes en Docker (`.142`)

```bash
sudo /usr/local/bin/docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```
* `dal-api-server` ➔ `Up` | `PORTS: 3000/tcp` *(solo interno, sin `0.0.0.0:`)*
* `dal-mongodb-server` ➔ `Up` | `PORTS: 27017/tcp` *(solo interno, sin `0.0.0.0:`)*
* `cloudflare-cloudflared-1` ➔ `Up 34 hours` *(0 reinicios; 4 conexiones QUIC activas hacia Cloudflare)*

```bash
sudo /usr/local/bin/docker network inspect ztna-network --format '{{range .Containers}}{{.Name}}({{.IPv4Address}}) {{end}}'
# dal-api-server(172.19.0.3/16) cloudflare-cloudflared-1(172.19.0.2/16)

sudo /usr/local/bin/docker network inspect dal-platform_dal-network --format '{{range .Containers}}{{.Name}}({{.IPv4Address}}) {{end}}'
# dal-api-server(172.18.0.3/16) dal-mongodb-server(172.18.0.2/16)
```

### 4.2. Escaneo de Superficie LAN desde Windows (`Nmap`)

```powershell
nmap -sT -Pn -n -p 3000,27017,5000 192.168.68.142
```
```text
PORT      STATE    SERVICE
3000/tcp  filtered ppp
5000/tcp  open     upnp
27017/tcp filtered mongod
```
*Los puertos `3000` y `27017` ya no aceptan conexiones desde la red local.*

### 4.3. Pruebas End-to-End por Túnel HTTPS

* `https://dsm-api.accescont.com/` ➔ **`HTTP 200`** (Consola Next.js DAL Platform).
* `https://dsm-api.accescont.com/api/health` ➔ **`HTTP 200`**:
  ```json
  {"status":"OK","database":"Connected","host":"mongodb:27017","environment":"Docker"}
  ```
* `https://dsm.accescont.com/` ➔ **`HTTP 200`** (`Sign in · Cloudflare Access`).

---

## 5. Plan de Rollback (Reversión Rápida)

En caso de requerir volver a la configuración anterior:

```bash
sudo /usr/local/bin/docker network connect dal-platform_dal-network cloudflare-cloudflared-1
cd /volume1/docker/dal-platform
sudo cp docker-compose.yml.bak docker-compose.yml
sudo /usr/local/bin/docker-compose up -d
```
