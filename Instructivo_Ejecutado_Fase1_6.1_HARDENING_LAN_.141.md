# Reporte Técnico: Hardening de Red Local y Cierre de Puertos en Host (Paso 6.1)

**Proyecto:** Reto de Ciberseguridad ACCESCONT  
**Programa:** Maestría en Ciberseguridad  
**Fase:** Fase 1 - Hardening de Red Local (Paso 6.1)  
**Fecha de Auditoría:** Octubre 2026  
**Host Evaluado:** Synology NAS (`accescontserver` - `192.168.68.141`)

---

## 1. Como parte fundamental de la arquitectura **Zero Trust Network Access (ZTNA)**, se completó la desvinculación total de puertos de microservicios expuestos en la red de área local (LAN). Se eliminaron las directivas `ports:` en los contenedores Docker de la aplicación `dal-platform` (API y base de datos MongoDB) y del microservicio de flujos `n8n`.

La auditoría de red mediante **Nmap** certifica que la superficie de ataque hacia los microservicios en la LAN física se redujo a cero, pasando de puertos abiertos (`OPEN`) a un estado completamente filtrado (`FILTERED`), mientras que los servicios permanecen 100% disponibles y operativos a través de la red privada **`ztna-network`** y el túnel perimetral de Cloudflare.

---

## 2. Justificación de Ciberseguridad (Principio Zero Trust)

1. **Eliminación del *Perimeter Bypass*:**  
   Previamente, cualquier usuario o dispositivo conectado a la red local (`192.168.68.0/24`) podía evadir la inspección de Cloudflare y acceder directamente a `http://192.168.68.141:3000` o `http://192.168.68.141:5678` sin autenticación, sin validación de identidad ni reglas WAF.
2. **Aislamiento Estricto de la Base de Datos (Mitigación CWE-668 / CWE-200):**  
   El puerto `27017` de MongoDB estaba expuesto a toda la red local. Al retirar el mapeo de puertos, MongoDB solo responde internamente dentro de la red privada de Docker (`dal-network`), impidiendo cualquier intento de ataque de fuerza bruta o movimiento lateral desde la LAN.
3. **Reducción de Superficie de Ataque:**  
   Se desactivaron los procesos intermediarios `docker-proxy` en el host, eliminando sockets en escucha no gestionados.

---

## 3. Procedimiento Técnico Ejecutado

### 3.1. Hardening en `dal-platform` (API y MongoDB)
* **Ubicación:** `/volume1/docker/dal-platform/`
* **Respaldos generados:** `docker-compose.yml.bak` y `.env.bak`.
* **Modificación en `docker-compose.yml`:**
  * Se eliminó la directiva `ports: - "3000:3000"` del servicio `dal-api`.
  * Se eliminó la directiva `ports: - "27017:27017"` del servicio `mongodb`.
  * Se conservó la comunicación entre la API y MongoDB mediante su red interna `dal-network`.
* **Recreación del servicio:** `docker-compose up -d`.

### 3.2. Estandarización y Hardening en `n8n`
* **Ubicación:** `/volume1/docker/n8n/`
* **Respaldo generado:** `n8n.inspect.bak.json`.
* **Formalización IaC:** Se creó el archivo formal `docker-compose.yml` manteniendo idénticas todas las variables de entorno (`N8N_PORT`, `WEBHOOK_URL`, `N8N_HOST`), usuario (`node`) y volúmenes de datos (`/volume1/docker/n8n_data` y `/volume1/print`).
* **Modificación de puertos:** Se eliminó la publicación de puertos `-p 5678:5678` hacia el host, conectando el servicio exclusivamente a `ztna-network`.
* **Recreación del servicio:** `docker-compose up -d`.

---

## 4. Evidencias de Auditoría y Verificación

### 4.1. Escaneo de Red Local con Nmap
Comando ejecutado desde el segmento de red del auditor/atacante hacia la IP del host:

```bash
nmap -p 3000,27017,5678,5000 192.168.68.141
```

#### Salida del Escaneo Nmap:
```text
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-20 21:09 -0500
Nmap scan report for 192.168.68.141
Host is up (0.015s latency).

PORT      STATE    SERVICE
3000/tcp  filtered ppp
5000/tcp  open     upnp
5678/tcp  filtered unknown
27017/tcp filtered mongod

Nmap done: 1 IP address (1 host up) scanned in 2.14 seconds
```

#### Análisis Técnico de los Resultados Nmap:
* **Puertos `3000`, `27017` y `5678` en estado `FILTERED`:**  
  Los paquetes TCP SYN son descartados silenciosamente (*DROP*) sin emitir paquetes `TCP RST`. Esto impide que herramientas automáticas identifiquen la existencia de los servicios o realicen técnicas de *fingerprinting* de versiones.
* **Puerto `5000` en estado `OPEN`:**  
  Corresponde a la interfaz web de administración nativa de Synology DSM (no es un contenedor Docker). Este puerto permanece abierto deliberadamente para ser asegurado en la **Fase 2** mediante políticas estrictas de identidad y MFA en Cloudflare Access.

---

### 4.2. Auditoría de Sockets Internos del Host (`netstat`)
Comando ejecutado por SSH en el servidor NAS:
```bash
netstat -tulpn | grep -E ':(3000|27017|5678)\b'
```
**Resultado:**
```text
NINGUNO (Salida vacía: Ningún proceso en 0.0.0.0 escucha en los puertos 3000, 27017 ni 5678).
```

---

### 4.3. Prueba de Conectividad End-to-End (Cloudflare Zero Trust)
Se verificó que los servicios aislados de la LAN siguen plenamente operativos a través del túnel:

| Servicio | Endpoint FQDN | Método | Código HTTP | Estado de Disponibilidad |
| :--- | :--- | :---: | :---: | :---: |
| **Backend API** | `https://api.accescont.com` | GET | **`200 OK`** | Totalmente Operativo |
| **Automatización n8n** | `https://n8n.accescont.com` | GET | **`200 OK`** | Totalmente Operativo |

---

## 5. Matriz Comparativa: Antes vs. Después (Paso 6.1)

| Vector de Exposición | Estado Inicial (Línea Base) | Estado Posterior al Hardening 6.1 |
| :--- | :--- | :--- |
| **API en LAN (`:3000`)** | `0.0.0.0:3000` (OPEN / Vulnerable) | **FILTERED** (Sin puerto mapeado en host) |
| **MongoDB en LAN (`:27017`)**| `0.0.0.0:27017` (OPEN / Vulnerable) | **FILTERED** (Aislado en `dal-network`) |
| **n8n en LAN (`:5678`)** | `0.0.0.0:5678` (OPEN / Vulnerable) | **FILTERED** (Aislado en `ztna-network`) |
| **Enrutamiento de Entrada** | IP directa del host (`192.168.68.141`) | Nombres DNS internos de Docker (`ztna-network`) |
| **Gobierno de Configuración**| Contenedores sueltos por comando | 100% Infraestructura como Código (`docker-compose.yml`)|
| **Disponibilidad de Servicio**| Expuesto con riesgo de bypass | **100% Disponible con postura Zero Trust** |

---

## 6. Conclusión y Cierre de la Fase 1

El paso 6.1 concluye satisfactoriamente los requerimientos de la **Fase 1 (Hardening de Red)**. La infraestructura se encuentra fortificada contra escaneos e intrusiones de red local, preparada para avanzar hacia la **Fase 2: Políticas de Acceso Granular (Identity & SSO)**.
