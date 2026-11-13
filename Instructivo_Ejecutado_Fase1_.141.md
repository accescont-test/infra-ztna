# Reporte Técnico: Implementación de Redes Aisladas y Enrutamiento ZTNA (Fase 1)

**Proyecto:** Reto de Ciberseguridad ACCESCONT  
**Programa:** Maestría en Ciberseguridad  
**Fase Ejecutada:** Fase 1 - Aislamiento de Redes en Docker y Enrutamiento por Túnel (Ejecución en Caliente / Zero Downtime)  
**Fecha de Ejecución:** Octubre 2026  
**Host Destino:** Synology NAS (`accescontserver` - `192.168.68.141`)

---

## 1. Resumen Ejecutivo

En el marco de la adopción de una arquitectura **Zero Trust Network Access (ZTNA)**, se completó la transición del enrutamiento de entrada (*Ingress*) desde la IP local del host (`192.168.68.141`) hacia una red bridge interna dedicada (**`ztna-network`**).

La ejecución se realizó bajo la modalidad **en caliente (*hot-plugging*)**, manteniendo la disponibilidad del 100% en los servicios y evitando la interrupción de la sesión de administración remota (SSH vía Cloudflare WARP). Como resultado, el tráfico público hacia `api.accescont.com` ahora se entrega directamente al contenedor `dal-api-server` mediante resolución DNS interna de Docker, sin depender de la exposición de puertos en la red local (LAN).

---

## 2. Línea Base y Desafío de Ciberseguridad

### 2.1. Vulnerabilidad Identificada
* Las rutas del túnel de Cloudflare apuntaban directamente a la dirección IP física del NAS (`http://192.168.68.141:3000`).
* Para que esto funcionara, los contenedores debían publicar sus puertos en `0.0.0.0` mediante `docker-proxy`.
* **Riesgo:** Cualquier atacante o dispositivo no autorizado en la red local (LAN/Wi-Fi) podía evadir las políticas de seguridad, autenticación, MFA e inspección WAF de Cloudflare, atacando directamente la API y la base de datos MongoDB.

### 2.2. Restricción de Gestión: Bloqueo en Banda (*In-Band Lockout*)
* La sesión de administración SSH utilizada para las labores técnicas se conecta a través de la VPN de Cloudflare WARP, la cual transita por el mismo contenedor `cloudflared-nas`.
* **Condición de seguridad:** No era posible detener ni reiniciar el contenedor `cloudflared-nas`, ya que cualquier caída del proceso cerraría el socket SSH inmediatamente antes de poder reanudar el servicio.
* **Solución técnica implementada:** Inyección de interfaces de red virtuales en caliente mediante `docker network connect`.

---

## 3. Procedimiento Técnico Ejecutado en Caliente

### 3.1. Estado de la Red Aislada
Se verificó la existencia del segmento de red dedicado:
* **Nombre de la red:** `ztna-network`
* **Driver:** `bridge`
* **Subred:** `172.18.0.0/16`
* **Gateway virtual:** `172.18.0.1`

### 3.2. Conexión de Contenedores en Caliente (Sin Downtime)
Se ejecutaron los siguientes comandos a nivel de host sin enviar señales de terminación a los procesos:

```bash
# 1. Unir el conector perimetral a la red aislada
docker network connect ztna-network cloudflared-nas

# 2. Unir el microservicio Backend API a la red aislada
docker network connect ztna-network dal-api-server

# 3. Unir el microservicio de Automatización n8n a la red aislada
docker network connect ztna-network n8n
```

### 3.3. Topología de Red Resultante

```text
               [ Internet / Clientes ]
                          │
                          ▼ (Túnel Cifrado Cloudflare)
                 [ cloudflared-nas ]
                   IP: 172.18.0.2
                          │
         ┌────────────────┴────────────────┐
         │ Red Interna: ztna-network       │
         │ Subred: 172.18.0.0/16           │
         ▼                                 ▼
 [ dal-api-server ]                     [ n8n ]
   IP: 172.18.0.3                    IP: 172.18.0.4
   Puerto: 3000                      Puerto: 5678
         │
         │ (dal-network - Privada)
         ▼
[ dal-mongodb-server ]
   IP: 172.20.0.3
   (Aislada de ztna-network)
```

---

## 4. Evidencias y Pruebas de Validación

### 4.1. Verificación de Membresía en Docker
Comando ejecutado:
```bash
docker network inspect ztna-network --format '{{range $id, $c := .Containers}}{{$c.Name}} -> IP: {{$c.IPv4Address}} {{end}}'
```
**Resultado obtenido:**
* `cloudflared-nas` ➔ `172.18.0.2/16`
* `dal-api-server` ➔ `172.18.0.3/16`
* `n8n` ➔ `172.18.0.4/16`

### 4.2. Validación de Resolución DNS Interna y Conectividad
Se ejecutó una solicitud HTTP interna desde `dal-api-server` hacia `n8n` utilizando únicamente el nombre de servicio de Docker:
```javascript
http.get('http://n8n:5678', res => console.log('STATUS N8N:', res.statusCode));
```
**Resultado obtenido:**
* `STATUS N8N: 200`
* **Conclusión:** El DNS interno embebido de Docker en `ztna-network` resuelve nombres de contenedor de forma correcta, permitiendo enrutar tráfico sin necesidad de conocer direcciones IP fijas.

### 4.3. Actualización de Rutas en Cloudflare Zero Trust
En el panel de Cloudflare Zero Trust (*Networks > Tunnels > cloudflared-nas > Public Hostname*), se actualizó la ruta crítica:

| Hostname Público | Tipo | Destino Anterior (Inseguro) | Nuevo Destino (ZTNA / Red Docker) | Estado |
| :--- | :--- | :--- | :--- | :--- |
| `api.accescont.com` | HTTP | `192.168.68.141:3000` | `dal-api-server:3000` | **Activo** |
| `n8n.accescont.com` | HTTP | `192.168.68.141:5678` | `n8n:5678` | Pendiente / En curso |
| `nas.accescont.com` | HTTP | `192.168.68.141:5000` | `172.17.0.1:5000` | Servicio Host |
| `webdav.accescont.com` | HTTP | `192.168.68.141:5005` | `172.17.0.1:5005` | Servicio Host |

### 4.4. Prueba de Tráfico Externo (E2E)
Se realizó una petición HTTP externa hacia el FQDN público:
```bash
curl -I https://api.accescont.com
```
**Evidencia capturada:**
* **HTTP Status:** `200 OK`
* **Servidor de terminación:** `cloudflare`
* **Identificador de traza:** `CF-Ray: a4b3fe6698773f10-GYE`
* **Cuerpo de respuesta:** Código HTML de la aplicación Next.js (`dal-platform`).
* **Logs de `cloudflared-nas`:** Enrutamiento transparente hacia el origen `http://dal-api-server:3000` sin errores de resolución ni de socket.

---

## 5. Plan de Rollback (Mecanismo de Reversión)

Si se requiriera retirar cualquiera de los microservicios de la red sin reiniciar los contenedores:

```bash
# Desconexión no destructiva en caliente
docker network disconnect ztna-network dal-api-server
docker network disconnect ztna-network n8n
docker network disconnect ztna-network cloudflared-nas
```

---

## 6. Próximos Pasos (Hoja de Ruta)

1. **Cierre de Puertos en Host (Hardening LAN):**
   * Respaldar y editar `docker-compose.yml` en `/volume1/docker/dal-platform/` para eliminar las directivas `ports: - "3000:3000"` y `ports: - "27017:27017"`.
   * Proteger el archivo `.env` (`chmod 600`).
   * Aplicar `docker-compose up -d` y validar con Nmap que los puertos ya no responden en la LAN.
2. **Fase 2: Políticas de Acceso Granular:**
   * Crear aplicaciones individuales en Cloudflare Access.
   * Regla de MFA obligatoria para `nas.accescont.com` restringida a administradores.
   * Reglas de Geo-blocking y bloqueo de nodos Tor.
3. **Fase 3: Hardening de Microservicios:**
   * Ejecución Non-Root (`user: 1000:1000`).
   * Sistema de archivos de solo lectura (`read_only: true` con `tmpfs`).
   * Middleware de validación criptográfica del token `Cf-Access-Jwt-Assertion`.
4. **Fase 4: Capa WAF y Rate Limiting:**
   * Activación de reglas gestionadas contra SQLi y XSS.
   * Rate limiting de 20 peticiones/min en endpoints de autenticación.
