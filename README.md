# Fase 1: Aislamiento de redes en Docker (Hardening de Red)

## 1. Objetivo

Reducir la exposición de servicios en la red LAN y establecer una arquitectura de acceso mediante Cloudflare Tunnel y redes internas de Docker, evitando publicar puertos del host que no sean necesarios.

La fase contempla integrar el conector Cloudflare Tunnel con los servicios autorizados, revisar las publicaciones de puertos y actualizar las rutas para utilizar destinos internos de Docker cuando corresponda.

## 2. Actividades realizadas y verificaciones

### 2.1. Creación del stack de infraestructura

Se creó el directorio `/volume1/docker/infra-ztna` y el archivo `docker-compose.yml` para gestionar el conector Cloudflare Tunnel de forma independiente.

El archivo define el servicio `cloudflared`, utiliza la imagen `cloudflare/cloudflared:latest` y declara la red `ztna-network`.

### 2.2. Protección de variables de entorno

Se verificó que el archivo `.env` tiene permisos `600`, restringiendo el acceso de lectura y escritura al propietario del archivo.

El token de Cloudflare se gestiona mediante la variable `TUNNEL_TOKEN`.

**Medida de seguridad:** el archivo `.env` no debe subirse al repositorio GitHub. Se debe mantener excluido mediante `.gitignore`.

### 2.3. Validación de Docker Compose

Se ejecutó la validación de la configuración mediante:

```bash
sudo docker-compose -f /volume1/docker/infra-ztna/docker-compose.yml config -q
```

La ejecución terminó sin mostrar errores visibles.

Esta comprobación valida la configuración de Compose, pero no garantiza que todos los servicios estén conectados ni que todas las rutas de Cloudflare funcionen correctamente.

### 2.4. Creación de la red Docker

Se creó la red bridge `ztna-network` mediante:

```bash
sudo docker network create --driver bridge ztna-network
```

Se confirmó su existencia mediante:

```bash
sudo docker network ls
```

La red existe, pero es necesario conectar los contenedores que deban utilizarla y reflejar la configuración definitiva en sus archivos Compose.

### 2.5. Verificación de las redes actuales

Se inspeccionaron las redes de los contenedores mediante:

```bash
sudo docker inspect --format '{{.Name}} -> {{range $name, $conf := .NetworkSettings.Networks}}{{$name}} {{end}}' cloudflared-nas dal-api-server dal-mongodb-server accescont-mailserver
```

Se observó lo siguiente:

- `cloudflared-nas` está conectado a `bridge` y `dal-platform_dal-network`.
- `dal-api-server` está conectado a `dal-platform_dal-network`.
- `dal-mongodb-server` está conectado a `dal-platform_dal-network`.
- `accescont-mailserver` está conectado a `docker-mail_mail-network`.

En una comprobación anterior, `ztna-network` tenía cero contenedores conectados. Posteriormente se realizaron comprobaciones de conectividad e integración de redes, pero todavía debe confirmarse la topología definitiva y persistente.

### 2.6. Verificación de conectividad HTTP con la API

Se ejecutó una prueba desde la red `dal-platform_dal-network`:

```bash
sudo docker run --rm --network dal-platform_dal-network curlimages/curl:latest -sS -o /dev/null -w 'HTTP %{http_code}\n' --connect-timeout 5 http://dal-api-server:3000/
```

**Resultado observado:** `HTTP 200`.

Esto confirma que la API respondió correctamente desde esa red en el momento de la prueba.

### 2.7. Verificación de conectividad TCP con MongoDB

Se realizó una prueba TCP desde el contenedor de la API hacia `dal-mongodb-server:27017`.

**Resultado observado:** `TCP MongoDB: OK`.

Esto confirma que se pudo establecer la conexión TCP durante la prueba, pero no demuestra por sí solo que la autenticación ni todas las operaciones de base de datos funcionen.

### 2.8. Verificación del estado de Cloudflare Tunnel

Se ejecutó:

```bash
sudo docker inspect --format 'Estado={{.State.Status}} Reinicios={{.RestartCount}}' cloudflared-nas
```

**Resultado observado:** `Estado=running Reinicios=0`.

El contenedor estaba en ejecución y su contador de reinicios era cero en esa comprobación. Esto no garantiza que todos los servicios publicados sean accesibles.

### 2.9. Identificación de puertos publicados

Se revisaron los contenedores y sus puertos mediante:

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

Se observó que:

- `dal-api-server` publica el puerto `3000` en todas las interfaces IPv4 del host.
- `dal-mongodb-server` publica el puerto `27017` en todas las interfaces IPv4 del host.
- `accescont-mailserver` publica varios puertos relacionados con el servicio de correo.
- `cloudflared-nas` no muestra puertos publicados en la salida observada.

Estas publicaciones deben revisarse para determinar cuáles son realmente necesarias.

### 2.10. Revisión de rutas y registros de Cloudflare

En el panel de Cloudflare se observó que la ruta `api.accescont.com` apunta al destino `http://192.168.68.141:3000`.

También se observaron errores en los registros del conector hacia algunos destinos configurados, incluidos mensajes `connection refused` y `no route to host`.

Es necesario identificar cada servicio de origen y comprobar su disponibilidad antes de cambiar las rutas.

## 3. Hallazgos pendientes de corregir

### 3.1. Integración definitiva de `ztna-network`

Debe definirse qué contenedores utilizarán la red aislada y cómo se comunicarán entre ellos.

La topología debe mantener las dependencias existentes de la API, MongoDB y el servidor de correo.

### 3.2. Retirada de publicaciones de puertos innecesarias

La API publica el puerto `3000` y MongoDB el puerto `27017` en todas las interfaces IPv4 del host.

Se debe revisar el archivo `/volume1/docker/dal-platform/docker-compose.yml` y retirar únicamente las publicaciones que Bryan confirme que no son necesarias.

También debe revisarse el alcance de los puertos publicados por el servidor de correo antes de efectuar cambios.

### 3.3. Actualización de las rutas de Cloudflare

Las rutas que apuntan a direcciones de la LAN deben revisarse individualmente.

Cuando el servicio de origen sea un contenedor y exista conectividad desde la red compartida, se evaluará utilizar su nombre interno y el puerto del servicio.

Ejemplo propuesto para la API:

`http://dal-api-server:3000`

Este cambio debe realizarse únicamente después de verificar la resolución del nombre y la conectividad desde `cloudflared-nas`.

### 3.4. Revisión de errores de conectividad

Los registros del conector muestran fallos de conexión hacia algunos destinos.

Se debe identificar cada servicio de origen, revisar su estado y confirmar si la dirección, el puerto, el protocolo y la red son correctos.

No se debe atribuir estos errores a una causa específica sin pruebas adicionales.

## 4. Comandos propuestos para completar la Fase 1

Los siguientes comandos forman parte del plan técnico. Los cambios de red y la recreación de servicios requieren revisión y aprobación del coordinador.

### 4.1. Revisar la red aislada

```bash
sudo docker network inspect ztna-network
```

Permite comprobar la configuración de la red y qué contenedores están conectados.

### 4.2. Conectar el conector a la red aislada

**Propuesta sujeta a aprobación:**

```bash
sudo docker network connect ztna-network cloudflared-nas
```

Conecta el contenedor existente `cloudflared-nas` a `ztna-network`, conservando las redes a las que ya está conectado.

### 4.3. Conectar la API a la red aislada

**Propuesta sujeta a aprobación:**

```bash
sudo docker network connect ztna-network dal-api-server
```

Conecta la API a `ztna-network` y conserva su conexión actual a `dal-platform_dal-network`, necesaria para mantener las dependencias existentes.

### 4.4. Hacer persistente la configuración de redes

Las conexiones efectuadas mediante `docker network connect` deben reflejarse en los archivos Compose correspondientes.

En `infra-ztna/docker-compose.yml`, se debe revisar la declaración de la red externa:

```yaml
networks:
  ztna-network:
    external: true
    name: ztna-network
```

En `/volume1/docker/dal-platform/docker-compose.yml`, el servicio `dal-api` debe conservar su red actual y declarar también `ztna-network`.

Ejemplo conceptual:

```yaml
services:
  dal-api:
    networks:
      - dal-network
      - ztna-network

networks:
  ztna-network:
    external: true
    name: ztna-network
```

Este ejemplo debe integrarse en el archivo existente, sin sustituir las demás configuraciones del servicio.

### 4.5. Validar los archivos Compose

```bash
sudo docker-compose -f /volume1/docker/infra-ztna/docker-compose.yml config -q
sudo docker-compose -f /volume1/docker/dal-platform/docker-compose.yml config -q
```

Valida la sintaxis de ambos archivos antes de aplicar cambios.

### 4.6. Revisar las publicaciones de la API y MongoDB

En `/volume1/docker/dal-platform/docker-compose.yml`, revisar los bloques `ports` de los servicios `dal-api` y `mongodb`.

Publicaciones que se deben evaluar:

```yaml
ports:
  - "3000:3000"
```

```yaml
ports:
  - "27017:27017"
```

Si se confirma que estos servicios no necesitan publicar sus puertos en el host, retirar las publicaciones correspondientes del archivo Compose. La comunicación interna debe mantenerse mediante las redes Docker aprobadas.

**No basta con modificar el archivo:** es necesario aplicar los cambios de forma controlada y comprobar el resultado.

### 4.7. Aplicar los cambios de Compose

**Solo después de la aprobación de Bryan y de validar el plan de reversión:**

```bash
sudo docker-compose -f /volume1/docker/dal-platform/docker-compose.yml up -d
```

Este comando actualiza o recrea los servicios gestionados por el archivo Compose cuando sea necesario. Puede provocar una interrupción temporal y no debe ejecutarse sin autorización.

No se propone detener ni eliminar manualmente `cloudflared-nas` como parte de este procedimiento.

### 4.8. Actualizar la ruta de la API en Cloudflare

Después de verificar la conectividad interna, revisar la ruta `api.accescont.com`.

Destino actual observado:

`http://192.168.68.141:3000`

Destino propuesto, sujeto a la aprobación y las pruebas:

`http://dal-api-server:3000`

El cambio debe hacerse desde el panel de Cloudflare Zero Trust. Las demás rutas deben revisarse individualmente según su servicio de origen.

## 5. Comandos de validación final

### 5.1. Verificar las redes de los contenedores

```bash
sudo docker inspect --format '{{.Name}} -> {{range $name, $conf := .NetworkSettings.Networks}}{{$name}} {{end}}' cloudflared-nas dal-api-server dal-mongodb-server
```

Permite confirmar que los contenedores están conectados a las redes previstas.

### 5.2. Verificar los puertos publicados

```bash
sudo docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

Permite comprobar si se retiraron las publicaciones de puertos aprobadas.

### 5.3. Probar la API desde la red aislada

```bash
sudo docker run --rm --network ztna-network curlimages/curl:latest -sS -o /dev/null -w 'HTTP %{http_code}\n' --connect-timeout 5 http://dal-api-server:3000/
```

Se espera una respuesta HTTP válida, por ejemplo `200`, si la ruta `/` de la aplicación devuelve ese estado.

### 5.4. Comprobar el estado del conector

```bash
sudo docker inspect --format 'Estado={{.State.Status}} Reinicios={{.RestartCount}}' cloudflared-nas
```

Permite comprobar el estado del contenedor y su contador de reinicios.

### 5.5. Revisar los registros recientes

```bash
sudo docker logs --tail 50 cloudflared-nas
```

Permite identificar errores recientes de conexión con los servicios de origen.

### 5.6. Verificar las aplicaciones publicadas

Acceder a los hostnames autorizados de Cloudflare y comprobar que las aplicaciones responden correctamente. Revisar los registros del túnel y confirmar que no queden errores de conectividad sin investigar para las rutas necesarias.

## 6. Criterios para completar la Fase 1

La fase podrá considerarse completada cuando:

1. La topología de redes Docker esté definida y documentada.
2. El conector y los servicios autorizados estén conectados a las redes correctas.
3. Los archivos Compose reflejen de forma persistente la topología aprobada.
4. Se hayan retirado las publicaciones de puertos que no sean necesarias.
5. Las rutas de Cloudflare utilicen destinos internos alcanzables cuando corresponda.
6. La API, MongoDB, el correo y las demás aplicaciones necesarias superen las pruebas funcionales.
7. Los errores de conectividad de las rutas requeridas hayan sido investigados.
8. Existan respaldos y un procedimiento de reversión documentado.

## 7. Seguridad

- Mantener privado el repositorio mientras se revisa la implementación.
- No subir `.env`, tokens ni credenciales.
- Excluir los archivos de entorno mediante `.gitignore`.
- No modificar ni eliminar contenedores en producción sin aprobación.
- Si un token de Cloudflare quedó expuesto en una captura o documento compartido, solicitar su rotación al responsable del túnel.
- Documentar por separado los resultados comprobados y las actividades pendientes.

## 8. Estado final

**Fase 1: en proceso.**

Se completaron actividades de preparación, validación de configuración y diagnóstico de conectividad. La integración definitiva de la red aislada, la retirada de publicaciones de puertos innecesarias y la actualización de las rutas de Cloudflare siguen pendientes de revisión, aprobación e implementación.
