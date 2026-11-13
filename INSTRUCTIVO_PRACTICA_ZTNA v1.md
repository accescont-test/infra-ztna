# Instructivo Práctico: Implementación de Arquitectura Zero Trust y Bastioning (ACCESCONT)

Este instructivo te guiará paso a paso para ejecutar las 4 fases del reto con los comandos exactos, configuraciones y explicaciones conceptuales de cada decisión de seguridad.

---

## 📌 Preparación de la Terminal (SSH en el Synology)

Conéctate por SSH a tu servidor:
```powershell
ssh test@192.168.68.141
```


# FASE 1: Aislamiento de Redes en Docker (Hardening de Red)

### Objetivo:
Eliminar la exposición de puertos en la red local (LAN) y forzar que todo el tráfico pase exclusivamente por el túnel `cloudflared` de forma interna.

---

### Paso 1.1: Crear el Stack de Infraestructura Transversal (`infra-ztna`)

Vamos a crear un directorio independiente para el conector y la red de entrada.

1. **Crear la carpeta del stack transversal:**
   ```bash
   sudo mkdir -p /volume1/docker/infra-ztna
   cd /volume1/docker/infra-ztna
   ```

2. **Crear el archivo de variables protegidas (`.env`):**
   *¿Por qué?* El token del túnel de Cloudflare nunca debe quedar expuesto en texto plano dentro de un repositorio de código.
   ```bash
   sudo bash -c 'cat << "EOF" > /volume1/docker/infra-ztna/.env
   TUNNEL_TOKEN=eyJhIjoiMTQyMjNkYzcxMGNiZTdiMjA5MjYyNDVlNzBjZDJhM2UiLCJ0IjoiZjZkZThjNWEtMzViNC00ODU2LWI3NWYtMDI3ZTNiY2NjMWQ1IiwicyI6Illqa3paak0yTjJZdE1EUTRPQzAwTUdOaUxUaGpOR0l0Tkdaa01tTmlaRFZtT1dNeSJ9
   EOF'
   sudo chmod 600 /volume1/docker/infra-ztna/.env
   ```

3. **Crear el archivo `docker-compose.yml` de infraestructura:**
   ```bash
   sudo bash -c 'cat << "EOF" > /volume1/docker/infra-ztna/docker-compose.yml
   version: "3.8"

   services:
     cloudflared:
       image: cloudflare/cloudflared:latest
       container_name: cloudflared-nas
       restart: unless-stopped
       command: tunnel --no-autoupdate run
       environment:
         - TUNNEL_TOKEN=${TUNNEL_TOKEN}
       networks:
         - ztna-network

   networks:
     ztna-network:
       name: ztna-network
       driver: bridge
   EOF'
   ```

4. **Respaldar el contenedor actual y levantar el nuevo stack:**
   ```bash
   # Respaldar la configuración e inspección del contenedor original por seguridad
   docker inspect cloudflared-nas > /volume1/docker/cloudflared-nas.inspect.bak.json

   # Detener y remover el contenedor anterior no versionado
   docker stop cloudflared-nas  
   docker rm cloudflared-nas

   # Levantar el stack transversal formalizado
   cd /volume1/docker/infra-ztna
   docker-compose up -d
   ```

5. **Verificar que la red y el contenedor estén activos:**
   ```bash
   docker network ls | grep ztna-network
   docker ps | grep cloudflared-nas
   ```

---

### Paso 1.2: Hardening de Red en `dal-platform` (Desvincular puertos)

*¿Por qué?* Actualmente `dal-api` tiene `3000:3000` y `mongodb` tiene `27017:27017`. Si alguien en la red local (WiFi/LAN) hace un escaneo, puede saltarse Cloudflare y conectarse directamente a la base de datos o API. Al quitar la directiva `ports:`, los puertos solo existen dentro del socket de red de Docker.

1. **Ir a la carpeta de la aplicación:**
   ```bash
   cd /volume1/docker/dal-platform
   ```

2. **Respaldar los archivos actuales antes de cualquier cambio:**
   ```bash
   # Respaldo preventivo de docker-compose.yml y .env
   sudo cp docker-compose.yml docker-compose.yml.bak
   sudo cp .env .env.bak
   ```

3. **Gestionar Secretos en `.env` protegido (Mitigación CWE-798):**
   *¿Por qué?* Las contraseñas y claves criptográficas nunca deben quemarse en el archivo `docker-compose.yml`. Mantenemos las variables existentes (incluyendo la configuración de 2FA OTP) y organizamos los secretos con permisos restringidos (`chmod 600`):
   ```bash
   sudo bash -c 'cat << "EOF" > /volume1/docker/dal-platform/.env
   PORT=3000
   MONGO_ROOT_USER=admin_user_db
   MONGO_ROOT_PASSWORD=8SMma18*x8aRFSI#YTj#
   MONGO_URI=mongodb://admin_user_db:8SMma18*x8aRFSI%23YTj%23@mongodb:27017/?authSource=admin
   DAL_API_KEY=sk_dal_accescont_984f932847a98b71239841_v1
   JWT_SECRET=nexusvault_prod_jwt_super_secret_key_9921

   # Brevo SMTP Configuration for ACCESCONT Security 2FA OTP
   SMTP_HOST=smtp-relay.brevo.com
   SMTP_PORT=587
   SMTP_USER=825e11001@smtp-brevo.com
   SMTP_PASS=xsmtpsib-db58279e718ec45c11da2e116f5827cd2eb5da66dbae3ebae00acc1d593c234a-h7KqQVezoCbPVKaH
   SMTP_FROM="ACCESCONT Cía. Ltda. - Seguridad" <system@accescont.com>
   EOF'
   sudo chmod 600 /volume1/docker/dal-platform/.env
   ```

4. **Actualizar `docker-compose.yml` (Sin puertos expuestos y sin secretos quemados):**
   ```bash
   sudo bash -c 'cat << "EOF" > /volume1/docker/dal-platform/docker-compose.yml
   version: "3.8"

   services:
     mongodb:
       image: mongo:latest
       container_name: dal-mongodb-server
       restart: unless-stopped
       environment:
         MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER}
         MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
       volumes:
         - ./data/db:/data/db
       networks:
         - dal-network
       # Hardening 1: Sin mapeo de puertos ('ports:') hacia la red local LAN

     dal-api:
       build: .
       container_name: dal-api-server
       restart: unless-stopped
       environment:
         PORT: ${PORT}
         MONGO_URI: ${MONGO_URI}
         DAL_API_KEY: ${DAL_API_KEY}
         JWT_SECRET: ${JWT_SECRET}
       volumes:
         - ./public/uploads:/app/public/uploads
       depends_on:
         - mongodb
       networks:
         - dal-network
         - ztna-network
       # Hardening 2: Conectado a la red ZTNA y aislado de la LAN

   networks:
     dal-network:
       driver: bridge
     ztna-network:
       external: true
   EOF'
   ```

5. **Aplicar los cambios:**
   ```bash
   docker-compose up -d
   ```

---

### Paso 1.3: Estandarización y Aislamiento de `n8n` con Docker Compose

*¿Por qué?* En lugar de usar comandos manuales sueltos (`docker run`), creamos un archivo `docker-compose.yml` dedicado para `n8n`. Esto estandariza toda la infraestructura del NAS bajo el principio de **Infraestructura como Código (IaC)**, previene configuraciones huérfanas y garantiza que el contenedor se conecte a la red aislada `ztna-network` sin exponer puertos en el host.

1. **Respaldar el contenedor n8n actual:**
   ```bash
   # Respaldar la configuración e inspección del contenedor original
   docker inspect n8n > /volume1/docker/n8n.inspect.bak.json

   # Respaldar el docker-compose previo si existiera
   if [ -f /volume1/docker/n8n/docker-compose.yml ]; then
     sudo cp /volume1/docker/n8n/docker-compose.yml /volume1/docker/n8n/docker-compose.yml.bak
   fi
   ```

2. **Crear el archivo `docker-compose.yml` en `/volume1/docker/n8n/`:**
   ```bash
   sudo bash -c 'cat << "EOF" > /volume1/docker/n8n/docker-compose.yml
   version: "3.8"

   services:
     n8n:
       image: n8nio/n8n:1.44.0
       container_name: n8n
       restart: unless-stopped
       environment:
         - N8N_PORT=5678
         - N8N_PROTOCOL=https
         - N8N_HOST=n8n.accescont.com
         - WEBHOOK_URL=https://n8n.accescont.com/
       volumes:
         - /volume1/docker/n8n_data:/home/node/.n8n
         - /volume1/print:/data/escaneos
       networks:
         - ztna-network
       # Hardening: Sin mapeo de puertos ('ports:') hacia el host

   networks:
     ztna-network:
       external: true
   EOF'
   ```

3. **Detener el contenedor antiguo y levantarlo con Compose:**
   ```bash
   # Detener y remover el contenedor suelto anterior
   docker stop n8n
   docker rm n8n

   # Levantar el nuevo servicio estandarizado
   cd /volume1/docker/n8n
   docker-compose up -d
   ```

---

### Paso 1.4: Actualización de Rutas en el Panel de Cloudflare Zero Trust

1. Ingresa a [https://one.dash.cloudflare.com/](https://one.dash.cloudflare.com/).
2. Dirígete a **Networks > Tunnels**.
3. Selecciona el túnel en ejecución (`cloudflared-nas`) y haz clic en **Configure**.
4. Ve a la pestaña **Public Hostname** y edita las siguientes rutas:

| Subdominio | Tipo | Destino Anterior (Inseguro) | Nuevo Destino (Seguro por Red Docker) |
| :--- | :--- | :--- | :--- |
| `api.accescont.com` | HTTP | `192.168.68.141:3000` | `dal-api-server:3000` |
| `n8n.accescont.com` | HTTP | `192.168.68.141:5678` | `n8n:5678` |
| `nas.accescont.com` | HTTP | `192.168.68.141:5000` | `172.17.0.1:5000` *(o IP LAN si es servicio nativo)* |
| `webdav.accescont.com`| HTTP | `192.168.68.141:5005` | `172.17.0.1:5005` |

---

### Paso 1.5: Verificación de la Fase 1

Desde tu máquina local (Windows PowerShell), verifica que los puertos ya **no** estén abiertos en la IP local:
```powershell
Test-NetConnection 192.168.68.141 -Port 3000
Test-NetConnection 192.168.68.141 -Port 27017
Test-NetConnection 192.168.68.141 -Port 5678
```
*Resultado esperado:* `TcpTestSucceeded: False`.

Y prueba desde dentro del conector la resolución interna:
```bash
docker exec cloudflared-nas ping -c 2 dal-api-server
```
*Resultado esperado:* Debe responder con éxito sobre la IP interna de la red `ztna-network`.

---

# FASE 2: Políticas de Acceso Granular (Identity & SSO)

### Objetivo:
Eliminar la política genérica y abierta "Acceso VPN" y aplicar el principio de **Mínimo Privilegio (Least Privilege)** por aplicación en Cloudflare Access.

---

### Paso 2.1: Desacoplar la aplicación global y crear aplicaciones dedicadas

1. En el panel de Cloudflare Zero Trust, ve a **Access > Applications**.
2. Haz clic en **Add an Application** ➔ Selecciona **Self-hosted**.
3. Configura las aplicaciones de forma individual:
   * **Aplicación 1 (DSM):**
     * Application name: `Synology DSM Admin`
     * Subdomain: `nas` | Domain: `accescont.com`
   * **Aplicación 2 (n8n):**
     * Application name: `Automatización n8n`
     * Subdomain: `n8n` | Domain: `accescont.com`
   * **Aplicación 3 (Backend API):**
     * Application name: `Backend API`
     * Subdomain: `api` | Domain: `accescont.com`

---

### Paso 2.2: Configurar MFA Obligatorio para Acceso a DSM

Para la aplicación `Synology DSM Admin` (`nas.accescont.com`):
1. En la pestaña **Policies**, haz clic en **Add a policy**:
   * **Policy Name:** `Politica Admin con MFA Obligatorio`
   * **Action:** `Allow`
2. En la sección **Configure rules**:
   * **Include:**
     * Selector: `Emails Ending in` ➔ `@accescont.com` *(o `Email` ➔ `administradores@accescont.com`)*.
   * **Require:**
     * Selector: **Authentication Method** ➔ Seleccionar `MFA` (o `One-time PIN / Hardware Key`).
     * *¿Por qué?* Esto impide que un atacante con credenciales robadas pueda entrar a la interfaz administrativa del NAS sin el segundo factor verificado por Cloudflare.

---

### Paso 2.3: Configurar Políticas de Bloqueo Geográfico y Redes Anónimas

Dentro de la misma política de la aplicación o como regla adicional de bloqueo (`Block Rule`):
1. **Regla de Bloqueo Geográfico (Geo-blocking):**
   * Crear regla con **Action:** `Block`.
   * **Include:**
     * Selector: `Country` ➔ Seleccionar todos los países excepto tu país operativo (o crear regla Allow con país permitido y el resto bloqueado).
2. **Bloqueo de Anonimato:**
   * Selector: `Device Posture` o `IP List` ➔ Bloquear orígenes conocidos como redes de anonimato / Tor Exit Nodes.

---

# FASE 3: Hardening Interno de Microservicios

### Objetivo:
Asegurar el contenedor de la API para prevenir escalada de privilegios y persistencia de malware.

---

### Paso 3.1: Configuración Non-Root y File System Read-Only

1. **Ajustar permisos del directorio de subidas:**
   *¿Por qué?* El usuario no privilegiado `1000:1000` (`node`) debe poder escribir en `/app/public/uploads`, pero el resto del sistema de archivos debe ser de solo lectura.
   ```bash
   sudo chown -R 1000:1000 /volume1/docker/dal-platform/public/uploads
   ```

2. **Respaldar el archivo actual y editar `docker-compose.yml` para añadir Non-Root y Read-Only:**
   ```bash
   # Respaldo preventivo del estado funcional de Fase 1
   sudo cp docker-compose.yml docker-compose.yml.fase1.bak

   # Aplicar hardening de ejecución sin privilegios y sistema de archivos de solo lectura
   sudo bash -c 'cat << "EOF" > /volume1/docker/dal-platform/docker-compose.yml
   version: "3.8"

   services:
     mongodb:
       image: mongo:latest
       container_name: dal-mongodb-server
       restart: unless-stopped
       environment:
         MONGO_INITDB_ROOT_USERNAME: ${MONGO_ROOT_USER}
         MONGO_INITDB_ROOT_PASSWORD: ${MONGO_ROOT_PASSWORD}
       volumes:
         - ./data/db:/data/db
       networks:
         - dal-network

     dal-api:
       build: .
       container_name: dal-api-server
       restart: unless-stopped
       user: "1000:1000"         # Hardening 1: Ejecución como usuario sin privilegios
       read_only: true           # Hardening 2: Sistema de archivos raíz inmutable
       tmpfs:                    # Directorios temporales permitidos en memoria RAM
         - /tmp:size=64M
         - /var/tmp:size=16M
         - /app/.next/cache:size=128M
       environment:
         PORT: ${PORT}
         MONGO_URI: ${MONGO_URI}
         DAL_API_KEY: ${DAL_API_KEY}
         JWT_SECRET: ${JWT_SECRET}
       volumes:
         - ./public/uploads:/app/public/uploads
       depends_on:
         - mongodb
       networks:
         - dal-network
         - ztna-network

   networks:
     dal-network:
       driver: bridge
     ztna-network:
       external: true
   EOF'
   ```

3. **Reconstruir y levantar el contenedor:**
   ```bash
   cd /volume1/docker/dal-platform
   docker-compose up -d --build
   ```

4. **Verificación de Hardening en Contenedor:**
   ```bash
   # Debe retornar uid=1000 gid=1000:
   docker exec dal-api-server id

   # Debe retornar "Read-only file system":
   docker exec dal-api-server touch /hack.txt
   ```

---

### Paso 3.2: Middleware de Validación Criptográfica JWT (`Cf-Access-Jwt-Assertion`)

*¿Por qué?* En Zero Trust, la aplicación **no debe confiar ciegamente** en que la petición viene del túnel; debe verificar la firma criptográfica del encabezado inyectado por Cloudflare.

1. **Respaldar el archivo `middleware.ts` actual:**
   ```bash
   cd /volume1/docker/dal-platform
   sudo cp middleware.ts middleware.ts.bak
   ```

2. **Editar `/volume1/docker/dal-platform/middleware.ts`:**
   Añade al inicio de la función `middleware(request: NextRequest)` la validación del encabezado de Cloudflare:

```typescript
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  // Verificación estricta de Zero Trust en endpoints de API
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const jwtAssertion = request.headers.get('cf-access-jwt-assertion');

    // 1. Validar presencia del encabezado inyectado por Cloudflare Access
    if (!jwtAssertion) {
      return new NextResponse(
        JSON.stringify({ error: "Zero Trust Violation: Missing CF-Access-Jwt-Assertion" }),
        { status: 403, headers: { 'content-type': 'application/json' } }
      );
    }

    // 2. Validación criptográfica:
    // Cloudflare publica sus certificados públicos en:
    // https://<TU-TEAM-NAME>.cloudflareaccess.com/cdn-cgi/access/certs
    // El token debe tener firma válida y audiencia (AUD) correcta.
  }

  return NextResponse.next();
}
```

---

# FASE 4: Capa WAF, DDoS y Visibilidad

### Objetivo:
Activar defensas de capa 7 contra ataques web y centralizar los registros para auditoría forense.

---

### Paso 4.1: Activación de Cloudflare Managed Ruleset (WAF)

1. En el dashboard de Cloudflare para el dominio `accescont.com`:
2. Ve a **Security > WAF > Managed Rules**.
3. Asegúrate de tener activado el **Cloudflare Managed Ruleset**.
4. Verifica que las reglas contra **SQL Injection (SQLi)** y **Cross-Site Scripting (XSS)** estén con la acción configurada en **Block**.

---

### Paso 4.2: Configuración de Rate Limiting (Mitigación de Abuso)

1. Ve a **Security > WAF > Rate limiting rules**.
2. Haz clic en **Create rule**:
   * **Rule name:** `Rate Limit Login y API`
   * **If incoming requests match:**
     * `URI Path` contains `/auth/` o `URI Path` contains `/login`
   * **Rate:**
     * `Requests:` `20` por `1 minute`
   * **Action:**
     * `Block` durante `10 minutes` (o `Managed Challenge`).
3. Guarda e implementa la regla.

---

### Paso 4.3: Auditoría Centralizada hacia el Centro de Registros del Synology

1. En el Synology DSM, abre el **Centro de Registros (Log Center)**.
2. Ve a **Recepción de Registros** y habilita el puerto Syslog (UDP 514 o TCP 514 / SSL).
3. En el panel de Cloudflare (sección **Analytics & Logs > Logpush**):
   * Configura el envío de los logs de **Access Requests** hacia el endpoint o SIEM para tener trazabilidad de todas las identidades que ingresan o son bloqueadas.

---

# 🏁 Verificación y Pruebas del Entregable Final

Para verificar que cumpliste con éxito el reto, realiza estas 3 pruebas:

1. **Prueba de Resistencia a Escaneos LAN:**
   ```powershell
   nmap -p 3000,27017,5678,5000 192.168.68.141
   ```
   *Debe confirmar que los puertos de contenedores (3000, 27017, 5678) ya no responden.*

2. **Prueba de Validación de Identidad (Zero Trust):**
   ```bash
   curl -I https://api.accescont.com/api/test
   ```
   *Debe ser bloqueado o redirigido a la autenticación de Cloudflare Access.*

3. **Prueba de WAF:**
   ```bash
   curl -I "https://api.accescont.com/api/test?id=1%20UNION%20SELECT%20NULL"
   ```
   *Debe responder con `HTTP 403 Forbidden` directamente desde el WAF de Cloudflare.*
