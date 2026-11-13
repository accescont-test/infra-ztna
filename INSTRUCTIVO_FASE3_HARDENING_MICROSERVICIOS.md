# Instructivo Paso a Paso: Fase 3 — Hardening de Microservicios (`192.168.68.142`)

**Host:** `192.168.68.142` (`accescontnas`)  
**Directorio de trabajo:** `/volume1/docker/dal-platform`

---

## Introducción

La fase 3 desarrolla el endurecimiento de la plataforma alojada en el NAS `192.168.68.142`, mediante restricciones de ejecución en Docker y validación de identidad en el servicio web/API. Su propósito es reducir los permisos disponibles para la aplicación y evitar que las rutas protegidas acepten solicitudes sin una autorización válida de Cloudflare Access.

El procedimiento combina dos medidas complementarias. Primero, limita las acciones del proceso y las ubicaciones donde puede escribir. Después, incorpora una verificación criptográfica en el backend, de modo que alcanzar el servidor no sea suficiente para acceder a la API. Este enfoque aplica los principios de mínimo privilegio y defensa en profundidad.

El alcance comprende el servicio `dal-api`, su configuración en `docker-compose.yml`, el archivo `middleware.ts` y la aplicación de acceso asociada al dominio `dsm-api.accescont.com`. Se conserva a continuación la numeración, la secuencia y todos los comandos del instructivo original. Las explicaciones describen la finalidad de las acciones; no constituyen evidencia de una nueva ejecución ni de pruebas sobre el servidor.

## Objetivo general

Fortalecer la seguridad del servicio web/API de `dal-platform` en el NAS `192.168.68.142`, mediante el endurecimiento de su contenedor Docker y la validación criptográfica de tokens de Cloudflare Access, manteniendo las funciones necesarias de la aplicación.

## Objetivos específicos

1. Respaldar los archivos de configuración y código antes de modificarlos para facilitar la recuperación ante incidencias.
2. Ajustar el usuario, los permisos y las zonas de escritura del contenedor conforme al principio de mínimo privilegio.
3. Configurar una política de acceso para las identidades autorizadas y vincular el backend con el emisor y la audiencia esperados.
4. Incorporar la verificación del formato, vigencia, emisor, audiencia y firma de los tokens en las rutas de API protegidas.
5. Reconstruir y desplegar la aplicación para aplicar los cambios, preservando la lógica de enrutamiento y evitando la detención deliberada del túnel.

---

## Paso 3.1 — Hardening de Ejecución en Docker (`Non-Root` + `Read-Only`)

### 3.1.1. Conectarse por SSH y respaldar `docker-compose.yml`

La conexión SSH permite administrar el NAS desde una terminal. Una vez iniciada la sesión con el usuario `test`, se accede al directorio donde se encuentra la plataforma y se crea una copia de su configuración. Este respaldo conserva el estado anterior a los cambios y facilita la recuperación si una modificación afecta el funcionamiento.

El comando `sudo` ejecuta las operaciones indicadas con privilegios administrativos. `cp` copia el archivo y `chmod 600` permite que únicamente su propietario lo lea y modifique. Antes de repetir este paso, se debe considerar que copiar sobre el mismo nombre de respaldo reemplaza su contenido anterior.

```bash
ssh test@192.168.68.142
cd /volume1/docker/dal-platform
sudo cp docker-compose.yml docker-compose.yml.fase1.bak
sudo chmod 600 docker-compose.yml.fase1.bak
```

### 3.1.2. Ajustar propietario y permisos de `public/uploads`

La carpeta `public/uploads` almacena los archivos subidos y debe continuar siendo escribible por la aplicación. `chown -R 1001:1001` asigna de forma recursiva el usuario y grupo previstos para el servicio. Esta correspondencia evita errores de permisos cuando el proceso se ejecuta con esa identidad.

En `chmod`, `u+rwX` y `g+rwX` añaden lectura y escritura al propietario y al grupo; la `X` mayúscula habilita acceso a directorios y conserva la ejecución donde ya corresponde, sin convertir indiscriminadamente todos los archivos en ejecutables. `o-w` retira a otros usuarios la escritura, pero no elimina sus permisos de lectura existentes. Así, se delimita quién puede modificar los archivos sin impedir el trabajo de la aplicación.

```bash
sudo chown -R 1001:1001 /volume1/docker/dal-platform/public/uploads
sudo chmod -R u+rwX,g+rwX,o-w /volume1/docker/dal-platform/public/uploads
```

### 3.1.3. Agregar directivas de endurecimiento en `docker-compose.yml`

Las directivas siguientes restringen el entorno de ejecución de `dal-api`. `user: "1001:1001"` fija la identidad del proceso sin usar el administrador `root`; `read_only: true` impide escribir en el sistema de archivos raíz del contenedor; `cap_drop: ALL` retira capacidades especiales de Linux y `no-new-privileges` impide obtener privilegios adicionales mediante mecanismos de ejecución que los concederían. Estos controles reducen el impacto potencial de una vulnerabilidad, aunque no eliminan todas las posibilidades de ataque.

Los montajes `tmpfs` proporcionan espacios temporales para `/tmp`, `/var/tmp` y la caché de Next.js. `rw` permite escritura, `size` limita su tamaño, `noexec` restringe la ejecución directa desde el montaje y `nosuid` evita aplicar privilegios setuid/setgid. El modo `1777` permite su uso compartido con el bit sticky, que restringe la eliminación de archivos ajenos. El almacenamiento temporal no conserva su contenido como lo haría un volumen persistente; además, `noexec` no impide que un intérprete lea y ejecute un script.

El fragmento YAML se incorpora al servicio existente y debe conservar sus demás parámetros, como variables, volúmenes y redes. Estas restricciones se dirigen a `dal-api`; no implican aplicar el mismo usuario o las mismas condiciones de escritura a MongoDB.

El comando Python automatiza una sustitución de texto: localiza el bloque `old` y lo reemplaza por `new`. La instrucción `assert old in s` comprueba que el texto esperado existe, pero no valida por sí misma la sintaxis YAML. El procedimiento no es idempotente: repetirlo sobre un archivo ya modificado puede duplicar directivas, por lo que debe comprobarse el estado del archivo antes de volver a aplicarlo.

En `/volume1/docker/dal-platform/docker-compose.yml`, añadir las siguientes directivas bajo el servicio `dal-api`:

```yaml
  dal-api:
    build: .
    container_name: dal-api-server
    restart: unless-stopped
    user: "1001:1001"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64M,mode=1777
      - /var/tmp:rw,noexec,nosuid,size=16M,mode=1777
      - /app/.next/cache:rw,noexec,nosuid,size=128M,mode=1777
```

Comando aplicado:

```bash
sudo python3 -c '
p = "/volume1/docker/dal-platform/docker-compose.yml"
s = open(p).read()
old = """  dal-api:
    build: .
    container_name: dal-api-server
    restart: unless-stopped
"""
new = """  dal-api:
    build: .
    container_name: dal-api-server
    restart: unless-stopped
    user: "1001:1001"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=64M,mode=1777
      - /var/tmp:rw,noexec,nosuid,size=16M,mode=1777
      - /app/.next/cache:rw,noexec,nosuid,size=128M,mode=1777
"""
assert old in s
open(p, "w").write(s.replace(old, new, 1))
'
```

### 3.1.4. Validar sintaxis y aplicar sin bajar el túnel

`docker-compose config -q` comprueba que la configuración pueda interpretarse correctamente. Si finaliza sin errores, `up -d` crea o actualiza los servicios necesarios y los mantiene en segundo plano. Como los comandos están escritos en líneas independientes, se debe comprobar el resultado de la validación antes de ejecutar el siguiente.

El procedimiento evita utilizar `down`, que detendría los servicios del proyecto. No obstante, `up -d` actúa sobre el conjunto definido en Compose y puede recrear servicios cuyos cambios lo requieran. Mantener el túnel activo no garantiza que la API no experimente una breve interrupción durante la recreación de su contenedor.

```bash
cd /volume1/docker/dal-platform
sudo /usr/local/bin/docker-compose config -q
sudo /usr/local/bin/docker-compose up -d
```

---

## Paso 3.2 — Validación Criptográfica de Identidad (`Cf-Access-Jwt-Assertion`)

### 4.1. Crear la aplicación y política en Cloudflare Zero Trust

Cloudflare Access controla quién puede entrar al dominio publicado. La aplicación Self-hosted representa el recurso alojado en el NAS y la política `Allow` autoriza las identidades incluidas en la lista de correos. La sesión de `24h` establece la duración configurada de acceso para esa aplicación.

El `Application Audience (AUD) Tag` permite comprobar que un token fue emitido para esta aplicación concreta. El valor consignado en el instructivo corresponde al entorno descrito; si se crea una aplicación distinta, debe utilizarse el identificador que esta genere. El nombre de la política no concede roles administrativos dentro de la plataforma y las condiciones mostradas no incluyen un requisito explícito de MFA.

1. Ingresar a **Cloudflare Zero Trust** (`one.dash.cloudflare.com`) ➔ **Access controls** ➔ **Applications** ➔ **Add an application** ➔ **Self-hosted**.
2. Configurar los datos de la aplicación:
   * **Name:** `dsm-api`
   * **Session Duration:** `24h`
   * **Application domain:** `dsm-api.accescont.com`
3. Asignar una política de acceso (`Allow`):
   * **Policy name:** `Acceso Administradores NAS`
   * **Action:** `Allow`
   * **Include ➔ Emails:** `administradores@accescont.com`, `cx.practica@gmail.com`, `test@accescont.com`
4. Guardar la aplicación y copiar el **Application Audience (`AUD`) Tag** de la pestaña **Overview**:
   * `b456796809277c308af5ef508fe1d03595b792551a3f4b58ef736cdd4449074a`

### 4.2. Respaldar `docker-compose.yml`, inyectar variables de Cloudflare Access y recrear `dal-api`

Este respaldo conserva el estado posterior al endurecimiento de Docker y anterior a la incorporación de las variables de Cloudflare. De este modo, se distingue el cambio de restricciones del contenedor del cambio de configuración para validar la identidad.

`CF_ACCESS_TEAM_DOMAIN` indica el emisor de confianza y la ubicación desde la que se obtienen las claves públicas; `CF_ACCESS_AUD` identifica la aplicación destinataria del token. Ninguno de estos valores es la clave privada de firma ni sustituye las credenciales de la aplicación. Se añaden dentro de `environment`, conservando las demás variables existentes. Tras validar la configuración sin errores, la actualización del contenedor permite aplicar los cambios.

1. Crear respaldo del estado del Paso 3.1:

```bash
cd /volume1/docker/dal-platform
sudo cp docker-compose.yml docker-compose.yml.paso31.bak
sudo chmod 600 docker-compose.yml.paso31.bak
```

2. Añadir las dos variables dentro de `services.dal-api.environment` en `/volume1/docker/dal-platform/docker-compose.yml`:

```yaml
      CF_ACCESS_TEAM_DOMAIN: https://accescont-vpn-2026.cloudflareaccess.com
      CF_ACCESS_AUD: b456796809277c308af5ef508fe1d03595b792551a3f4b58ef736cdd4449074a
```

3. Validar y aplicar el cambio:

```bash
cd /volume1/docker/dal-platform
sudo /usr/local/bin/docker-compose config -q
sudo /usr/local/bin/docker-compose up -d
```

### 4.3. Respaldar `/volume1/docker/dal-platform/middleware.ts`

El middleware contiene la lógica que intercepta y dirige las solicitudes antes de que alcancen las funcionalidades de la aplicación. Se respalda antes de introducir la verificación JWT para disponer de una referencia y poder recuperar el código previo.

La opción `-p` de `cp` intenta conservar los atributos del archivo original durante la copia. Después, `chmod 600` restringe expresamente los permisos del respaldo a su propietario. Como en los respaldos anteriores, ejecutar nuevamente la copia sobre el mismo destino reemplaza el respaldo existente.

```bash
cd /volume1/docker/dal-platform
sudo cp -p middleware.ts middleware.ts.bak
sudo chmod 600 middleware.ts.bak
```

### 4.4. Actualizar `/volume1/docker/dal-platform/middleware.ts`

La modificación incorpora una comprobación independiente en el backend. No basta con que una solicitud incluya la cabecera `Cf-Access-Jwt-Assertion`: su contenido debe ser un token válido para la organización y la aplicación configuradas. Esta validación dificulta que una solicitud directa a las rutas protegidas eluda el control de identidad mediante una cabecera inventada.

El código divide el JWT en cabecera, contenido y firma. Comprueba el algoritmo `RS256`, la existencia de `kid`, la caducidad `exp`, el inicio de validez `nbf` cuando está presente, el emisor `iss` y la audiencia `aud`. Posteriormente obtiene la clave pública correspondiente y utiliza `crypto.subtle.verify` para verificar la firma. La clave privada permanece en el emisor: conocer una clave pública no permite fabricar un token firmado legítimamente.

`base64UrlToUint8Array` convierte las partes codificadas del token en bytes. `getCloudflareKeys` consulta las claves públicas y las mantiene en caché durante cinco minutos; si el identificador `kid` no aparece, se fuerza una nueva consulta. `verifyCloudflareAccessJwt` reúne las comprobaciones y devuelve `false` ante una validación fallida o una excepción. Este comportamiento fail-closed provoca el rechazo si falta una configuración esencial, como el `AUD`, o si no puede demostrarse la validez del token.

La función principal exige la validación para las rutas que comienzan por `/api/` y `/nexus-api/`, salvo las solicitudes `OPTIONS`, que reciben respuesta previamente. Una vez superado el control, el código identifica el proyecto y conserva las reescrituras de rutas. Esta selección multi-tenant no sustituye los permisos sobre los datos de cada proyecto. Las cabeceras CORS regulan el comportamiento del navegador entre orígenes y tampoco sustituyen la autenticación.

El patrón `'/((?!health).*)'` deja fuera del middleware las rutas cuyo comienzo es `health`, no solamente la ruta exacta `/health`. La ruta `/api/health` sí queda comprendida por la condición de API. Esta precisión describe el código conservado y permite interpretar correctamente las pruebas de acceso.

El comando `tee` reemplaza el archivo completo con el contenido situado entre los delimitadores `EOF`. Al estar el delimitador inicial entre comillas, el shell no expande las variables ni las expresiones del código. La redirección `>/dev/null` evita imprimir nuevamente el contenido en la terminal, pero no impide que se escriba en el archivo. La conservación del comportamiento previo debe comprobarse frente al archivo respaldado y mediante pruebas funcionales.

Reemplazar `/volume1/docker/dal-platform/middleware.ts` manteniendo la lógica de enrutamiento multi-tenant/CORS y añadiendo la verificación **RS256** de `Cf-Access-Jwt-Assertion` mediante Web Crypto API:

```bash
sudo tee /volume1/docker/dal-platform/middleware.ts >/dev/null << 'EOF'
import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const CF_TEAM_DOMAIN = (
  process.env.CF_ACCESS_TEAM_DOMAIN || 'https://accescont-vpn-2026.cloudflareaccess.com'
).replace(/\/$/, '');
const CF_POLICY_AUD = (process.env.CF_ACCESS_AUD || '').trim();

interface CloudflareJwk extends JsonWebKey {
  kid?: string;
}

let cachedKeys: CloudflareJwk[] = [];
let cacheExpiresAt = 0;

function base64UrlToUint8Array(base64Url: string): Uint8Array {
  const padLen = (4 - (base64Url.length % 4)) % 4;
  const padded = base64Url.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padLen);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function getCloudflareKeys(forceRefresh = false): Promise<CloudflareJwk[]> {
  const now = Date.now();
  if (!forceRefresh && cachedKeys.length > 0 && now < cacheExpiresAt) {
    return cachedKeys;
  }

  const res = await fetch(`${CF_TEAM_DOMAIN}/cdn-cgi/access/certs`, {
    cache: 'no-store',
  });
  if (!res.ok) {
    throw new Error(`Cloudflare JWKS fetch failed: ${res.status}`);
  }

  const data = (await res.json()) as { keys?: CloudflareJwk[] };
  cachedKeys = Array.isArray(data.keys) ? data.keys : [];
  cacheExpiresAt = now + 5 * 60 * 1000;
  return cachedKeys;
}

async function verifyCloudflareAccessJwt(token: string): Promise<boolean> {
  try {
    if (!CF_POLICY_AUD) {
      return false;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      return false;
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(headerB64))) as {
      alg?: string;
      kid?: string;
    };
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToUint8Array(payloadB64))) as {
      aud?: string | string[];
      iss?: string;
      exp?: number;
      nbf?: number;
    };

    if (header.alg !== 'RS256' || !header.kid) {
      return false;
    }

    const nowSec = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number' || payload.exp <= nowSec) {
      return false;
    }
    if (typeof payload.nbf === 'number' && payload.nbf > nowSec + 30) {
      return false;
    }
    const tokenIss = (payload.iss || '').replace(/\/$/, '');
    if (tokenIss !== CF_TEAM_DOMAIN) {
      return false;
    }

    const audMatch = Array.isArray(payload.aud)
      ? payload.aud.includes(CF_POLICY_AUD)
      : payload.aud === CF_POLICY_AUD;
    if (!audMatch) {
      return false;
    }

    let keys = await getCloudflareKeys(false);
    let jwk = keys.find((k) => k.kid === header.kid);
    if (!jwk) {
      keys = await getCloudflareKeys(true);
      jwk = keys.find((k) => k.kid === header.kid);
    }
    if (!jwk) {
      return false;
    }

    const cryptoKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify']
    );

    const signingInput = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
    const signature = base64UrlToUint8Array(signatureB64);

    return await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      cryptoKey,
      signature as BufferSource,
      signingInput as BufferSource
    );
  } catch {
    return false;
  }
}

const reservedSubdomains = [
  'api',
  'dsm-api',
  'dsm',
  'nas',
  'web',
  'dal',
  'admin',
  'app',
  'console',
  'localhost',
  '127.0.0.1',
  'dal-api-server'
];

function extractSubdomain(hostStr?: string | null): string | null {
  if (!hostStr) return null;
  const cleanHost = hostStr.split(',')[0].split(':')[0].trim().toLowerCase();
  if (cleanHost === 'localhost' || cleanHost === '127.0.0.1' || cleanHost.match(/^\d+\.\d+\.\d+\.\d+$/)) {
    return null;
  }

  // Dominios de la plataforma principal (NAS 141 y NAS 142)
  if (
    cleanHost === 'api.accescont.com' ||
    cleanHost === 'dsm-api.accescont.com' ||
    cleanHost === 'dsm.accescont.com' ||
    cleanHost === 'nas.accescont.com'
  ) {
    return null;
  }

  const rootDomain = process.env.NEXT_PUBLIC_ROOT_DOMAIN?.split(':')[0].trim().toLowerCase();
  if (rootDomain && (cleanHost === rootDomain || cleanHost === `www.${rootDomain}`)) {
    return null;
  }

  if (cleanHost.endsWith('.accescont.com')) {
    const parts = cleanHost.split('.');
    if (parts.length >= 3 && !reservedSubdomains.includes(parts[0])) {
      return parts[0];
    }
    return null;
  } else if (cleanHost.endsWith('.nexusvault.io')) {
    const parts = cleanHost.split('.');
    if (parts.length >= 3 && !reservedSubdomains.includes(parts[0])) {
      return parts[0];
    }
    return null;
  }

  // Any other external custom domain (e.g. micarrera.com, prueba.com)
  if (!reservedSubdomains.includes(cleanHost) && cleanHost.includes('.')) {
    return cleanHost;
  }

  return null;
}

export async function middleware(request: NextRequest) {
  const referer = request.headers.get('referer') || '';
  const origin = request.headers.get('origin') || '*';
  const cookieProject = request.cookies.get('nv_active_project')?.value;

  // Preflight OPTIONS para cualquier origen o subdominio
  if (request.method === 'OPTIONS') {
    return new NextResponse(null, {
      status: 200,
      headers: {
        'Access-Control-Allow-Origin': origin === '*' ? '*' : origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, Cf-Access-Jwt-Assertion, x-api-key, x-nexus-project-id, X-Requested-With',
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Max-Age': '86400',
      },
    });
  }

  // =========================================================================
  // FASE 3 ZERO TRUST: Verificación criptográfica de Cloudflare Access JWT
  // =========================================================================
  if (
    request.nextUrl.pathname.startsWith('/api/') ||
    request.nextUrl.pathname.startsWith('/nexus-api/')
  ) {
    const jwtAssertion = request.headers.get('cf-access-jwt-assertion');

    if (!jwtAssertion) {
      return NextResponse.json(
        { error: 'Zero Trust Violation: Missing Cf-Access-Jwt-Assertion' },
        { status: 403 }
      );
    }

    const isValidJwt = await verifyCloudflareAccessJwt(jwtAssertion);
    if (!isValidJwt) {
      return NextResponse.json(
        { error: 'Zero Trust Violation: Invalid or expired Cloudflare Access JWT' },
        { status: 403 }
      );
    }
  }

  // Detectar subdominio por x-forwarded-host, host, o nextUrl.hostname
  let subdomain: string | null =
    extractSubdomain(request.headers.get('x-forwarded-host')) ||
    extractSubdomain(request.headers.get('host')) ||
    extractSubdomain(request.nextUrl.hostname);

  // Fallback a cookie o referer si no se detectó por Host
  if (!subdomain) {
    if (cookieProject && !reservedSubdomains.includes(cookieProject)) {
      subdomain = cookieProject;
    } else if (referer) {
      try {
        const refUrl = new URL(referer);
        subdomain = extractSubdomain(refUrl.hostname);
      } catch (e) {}
    }
  }

  // SI SE TRATA DE UN SUBDOMINIO DE PROYECTO (ej: trail-camp-series-294)
  if (subdomain) {
    const originalPath = request.nextUrl.pathname;
    let targetPath = originalPath;

    // A. Rutas de API en subdominio -> Reescribir dinámicamente a los endpoints v1 del BaaS
    if (originalPath.startsWith('/api/')) {
      const subPath = originalPath.replace('/api/', '');
      if (subPath === 'consultar-cedula' || subPath === 'cedula') {
        targetPath = `/api/v1/${subdomain}/cedula`;
      } else if (subPath === 'consultar-ruc' || subPath === 'ruc') {
        targetPath = `/api/v1/${subdomain}/ruc`;
      } else if (!subPath.startsWith('v1/')) {
        targetPath = `/api/v1/${subdomain}/${subPath}`;
      }
    } else if (originalPath.startsWith('/nexus-api/')) {
      const subPath = originalPath.replace('/nexus-api/', '');
      targetPath = `/api/v1/${subdomain}/${subPath}`;
    } else if (!originalPath.startsWith('/sites') && !originalPath.startsWith('/hosting')) {
      // B. Rutas de frontend estático del proyecto -> Reescribir a /sites/[subdomain]/...
      targetPath = `/sites/${subdomain}${originalPath}`;
    }

    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('x-forwarded-host', request.headers.get('host') || '');
    requestHeaders.set('x-nexus-project', subdomain);

    if (targetPath !== originalPath) {
      request.nextUrl.pathname = targetPath;
      const response = NextResponse.rewrite(request.nextUrl, {
        request: { headers: requestHeaders },
      });
      response.headers.set('Access-Control-Allow-Origin', origin === '*' ? '*' : origin);
      response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
      response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cf-Access-Jwt-Assertion, x-api-key, x-nexus-project-id, X-Requested-With');
      response.headers.set('Access-Control-Allow-Credentials', 'true');
      return response;
    }

    const response = NextResponse.next({ request: { headers: requestHeaders } });
    response.headers.set('Access-Control-Allow-Origin', origin === '*' ? '*' : origin);
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cf-Access-Jwt-Assertion, x-api-key, x-nexus-project-id, X-Requested-With');
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    return response;
  }

  // MANEJO GLOBAL DE CORS PARA RUTAS DIRECTAS DE API (/api/*)
  if (request.nextUrl.pathname.startsWith('/api/')) {
    const response = NextResponse.next();
    response.headers.set('Access-Control-Allow-Origin', origin === '*' ? '*' : origin);
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization, Cf-Access-Jwt-Assertion, x-api-key, x-nexus-project-id, X-Requested-With');
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    return response;
  }

  // REFERER REWRITING (Para assets /_next/static/)
  if (request.nextUrl.pathname.startsWith('/_next/static/') || request.nextUrl.pathname.startsWith('/_next/image')) {
    const refererMatch = referer.match(/\/(sites|hosting)\/([a-zA-Z0-9_-]+)/);
    if (refererMatch) {
      const type = refererMatch[1];
      const projectId = refererMatch[2];
      request.nextUrl.pathname = `/${type}/${projectId}${request.nextUrl.pathname}`;
      return NextResponse.rewrite(request.nextUrl);
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/((?!health).*)',
  ],
};
EOF
```

### 4.5. Reconstruir imagen y desplegar sin cortar el túnel

La reconstrucción incorpora el código modificado a la imagen que ejecutará el contenedor. Cambiar `middleware.ts` en el directorio de trabajo no asegura por sí solo que el servicio esté utilizando ese código, por lo que se ejecuta `up -d --build` después de validar la configuración. `--build` solicita la reconstrucción y `-d` mantiene los servicios en segundo plano.

Se debe continuar con el despliegue únicamente si `config -q` termina sin errores. Una compilación correcta demuestra que se ha generado la aplicación, pero no acredita por sí sola la aceptación de tokens válidos ni el rechazo de todas las solicitudes indebidas. Para comprobar el resultado se requiere distinguir entre el funcionamiento del túnel, la disponibilidad del contenedor y el acceso a las rutas protegidas.

```bash
cd /volume1/docker/dal-platform
sudo /usr/local/bin/docker-compose config -q
sudo /usr/local/bin/docker-compose up -d --build
```


---

## Criterios para comprobar el resultado

Los siguientes criterios explican cómo interpretar el resultado del procedimiento. Son resultados esperados, no pruebas ejecutadas durante la elaboración de este documento.

| Aspecto | Resultado esperado e interpretación |
| :--- | :--- |
| Configuración Docker | El servicio conserva el usuario `1001:1001`, el sistema raíz de solo lectura, las capacidades retiradas y la restricción de nuevos privilegios. |
| Escritura de la aplicación | Los temporales, la caché y el volumen de cargas permiten las operaciones necesarias; las escrituras no autorizadas en el sistema raíz se rechazan. |
| API sin token válido | Una solicitud directa al backend sobre las rutas protegidas, distinta de `OPTIONS`, recibe `403` si falta el token o no supera la validación. |
| Acceso público sin sesión | El usuario debe pasar por el control de Cloudflare Access antes de acceder al recurso. |
| Acceso autorizado | Una sesión válida permite alcanzar una ruta protegida y obtener su respuesta funcional esperada; para `/api/health`, debe comprobarse el resultado conforme a la implementación de esa ruta. |
| Enrutamiento de proyectos | Las operaciones habituales continúan llegando al proyecto correcto y mantienen los permisos propios de la aplicación. |
| Continuidad | Se comprueban separadamente el estado del túnel, de MongoDB y del servicio web/API después del despliegue. |

La evidencia de cierre debe incluir tanto el rechazo de solicitudes no autorizadas como el acceso legítimo. Este instructivo no aporta por sí solo resultados medidos de esas comprobaciones.

## Conclusiones

1. **El procedimiento combina restricciones de ejecución y controles de acceso.** El endurecimiento Docker reduce los permisos del proceso y las zonas de escritura, mientras que la validación del token permite verificar la autorización antes de atender las rutas de API protegidas.

2. **La escritura se limita sin eliminar las necesidades funcionales del servicio.** Los espacios temporales y la carpeta de cargas permiten mantener las operaciones necesarias de la aplicación, aunque esas ubicaciones escribibles siguen requiriendo controles adecuados sobre su contenido.

3. **La validación criptográfica aporta una comprobación adicional en el backend.** Revisar el emisor, la audiencia, la vigencia y la firma evita aceptar un token únicamente por su presencia o apariencia. El comportamiento fail-closed rechaza las solicitudes cuando no puede establecerse su validez.

4. **Los respaldos y la validación de configuración facilitan una implementación controlada.** La recuperación debe mantener coherencia entre código y variables: un middleware que exige `CF_ACCESS_AUD` rechazará las rutas protegidas si se restaura una configuración que ya no proporcione ese valor.

5. **El despliegue debe completarse con evidencia funcional y de seguridad.** La reconstrucción de la imagen y la conservación del túnel no bastan para demostrar el éxito integral de la fase. Deben comprobarse la persistencia de las restricciones, el rechazo de accesos inválidos y la aceptación de solicitudes legítimas. Hasta contar con esos resultados, las mejoras descritas representan el propósito y el comportamiento esperado del procedimiento, no una certificación de su ejecución.

# Verificación de que la fase 3 este funcionando
Pruebas de verificación — Fase 3: Hardening de microservicios

**Proyecto:** Prácticas de Ciberseguridad — ACCESCONT  
**NAS:** `192.168.68.142` (`accescontnas`)  
**Servicio:** `dal-api-server`  
**Dominio:** `dsm-api.accescont.com`  
**Documento base:** `INSTRUCTIVO_PASOS_FASE3.md`

## 1. Objetivo

Comprobar que las restricciones de Docker están activas, que el backend rechaza solicitudes sin una autorización válida y que una persona autorizada puede acceder mediante Cloudflare Access. Las pruebas también verifican que la aplicación mantiene las funciones necesarias de lectura y escritura.

Este documento contiene procedimientos y resultados esperados. Las pruebas no se han ejecutado desde esta revisión documental. Registrar los resultados reales antes de concluir que la fase está completada.

## 2. Preparación: conectarse al NAS

Desde PowerShell o una terminal de tu computadora, ejecutar:

```bash
ssh test@192.168.68.142
```

Introducir la contraseña cuando se solicite. Después, ejecutar:

```bash
cd /volume1/docker/dal-platform
```

**Dónde ejecutar los comandos:** todos los bloques siguientes se ejecutan en esta sesión SSH, salvo la prueba que indica expresamente utilizar el navegador. Copiar cada bloque completo tal como aparece; no sustituir los textos entre llaves de Docker.

Estas pruebas no necesitan reconstruir la imagen ni detener los servicios. Los archivos de prueba se crean con nombres temporales y se eliminan después. No volver a ejecutar los pasos de instalación para realizar estas verificaciones.

## 3. Prueba 1 — Comprobar que los contenedores están activos

```bash
sudo docker ps -a --format 'table {{.Names}}\t{{.Status}}'
```

**Resultado esperado:** `dal-api-server`, `dal-mongodb-server` y el contenedor del túnel aparecen con estado `Up`. En el entorno documentado, el túnel se identifica como `cloudflare-cloudflared-1`.

**Qué demuestra:** los contenedores están ejecutándose. El estado `Up` del túnel no demuestra por sí solo que tenga conexión con Cloudflare; la prueba de acceso público comprobará esa parte.

**Si falla:** si la API aparece como `Exited` o `Restarting`, consultar:

```bash
sudo docker logs --tail 50 dal-api-server
```

Revisar el error antes de continuar. No incluir contraseñas, tokens o datos personales de los registros en las capturas del informe.

**Evidencia:** captura del listado de contenedores y sus estados.

## 4. Prueba 2 — Verificar las restricciones de Docker

Ejecutar este comando completo:

```bash
sudo docker inspect --format 'User={{.Config.User}} ReadOnly={{.HostConfig.ReadonlyRootfs}} CapDrop={{.HostConfig.CapDrop}} SecOpt={{.HostConfig.SecurityOpt}} Tmpfs={{.HostConfig.Tmpfs}}' dal-api-server
```

**Resultado esperado:**

- `User=1001:1001`.
- `ReadOnly=true`.
- `CapDrop=[ALL]`.
- `SecOpt` incluye `no-new-privileges:true`.
- `Tmpfs` incluye `/tmp`, `/var/tmp` y `/app/.next/cache`, con las opciones configuradas en el instructivo.

Comprobar además la identidad utilizada dentro del contenedor:

```bash
sudo docker exec dal-api-server id
```

**Resultado esperado:** UID `1001` y GID `1001`; pueden mostrarse también los nombres `nextjs` y `nodejs`.

**Qué demuestra:** Docker tiene configuradas las restricciones previstas y los comandos internos usan la identidad esperada. Aunque `sudo` permite administrar Docker desde el NAS, este `docker exec` no solicita ejecutar como root dentro del contenedor.

**Si falla:** un usuario distinto, `ReadOnly=false` o la ausencia de las opciones indican que la configuración aplicada no coincide con el instructivo. Revisar antes de dar la prueba por aprobada.

**Evidencia:** captura de ambos resultados.

## 5. Prueba 3 — Verificar que el sistema raíz rechaza escritura

Copiar el bloque completo:

```bash
sudo docker exec -i dal-api-server node <<'NODE'
const fs = require('node:fs');
const file = '/prueba-fase3-' + Date.now() + '-' + process.pid + '.txt';
try {
  fs.writeFileSync(file, 'Prueba de escritura', { flag: 'wx' });
  fs.unlinkSync(file);
  console.log('FALLO: se pudo escribir en el sistema raiz; archivo de prueba eliminado.');
} catch (error) {
  console.log('Escritura rechazada. Codigo:', error.code);
  if (error.code === 'EROFS') {
    console.log('CORRECTO: sistema de archivos de solo lectura.');
  } else {
    console.log('Este error no demuestra por si solo read_only. Revisar junto con la prueba 2.');
  }
}
NODE
```

**Resultado esperado:** código `EROFS` y mensaje `CORRECTO: sistema de archivos de solo lectura`.

**Qué demuestra:** no se puede crear un archivo en la raíz del contenedor. Si aparece `EACCES`, la escritura está bloqueada por permisos, pero ese resultado por sí solo no prueba que el sistema de archivos sea de solo lectura.

**Evidencia:** captura del código de error y del mensaje.

## 6. Prueba 4 — Verificar escritura en las carpetas permitidas

```bash
sudo docker exec -i dal-api-server node <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
for (const dir of ['/tmp', '/var/tmp', '/app/.next/cache', '/app/public/uploads']) {
  let file;
  try {
    file = path.join(dir, 'prueba-fase3-' + Date.now() + '-' + process.pid + '.txt');
    fs.writeFileSync(file, 'Prueba temporal de fase 3', { flag: 'wx' });
    fs.unlinkSync(file);
    console.log('CORRECTO:', dir, '- escritura y eliminacion verificadas');
  } catch (error) {
    console.log('FALLO:', dir, '-', error.code);
    if (file && fs.existsSync(file)) console.log('Revisar archivo de prueba pendiente:', file);
  }
}
NODE
```

**Resultado esperado:** cuatro líneas con `CORRECTO`.

**Qué demuestra:** el usuario del servicio puede escribir donde la aplicación necesita temporales, caché y archivos subidos. Los archivos creados por esta prueba se eliminan inmediatamente. No verifica la persistencia tras una recreación del contenedor.

**Si falla:** `EACCES` indica permisos insuficientes y `ENOENT` puede indicar una carpeta inexistente. Revisar el montaje o los propietarios correspondientes.

**Evidencia:** captura de las cuatro carpetas comprobadas.

## 7. Prueba 5 — Comprobar el backend sin autorización y con token inválido

Se usa Node dentro del contenedor para consultar directamente la aplicación, sin depender de que esté instalado `curl`. En este contexto, `127.0.0.1:3000` es la propia aplicación dentro del contenedor, no tu computadora ni el puerto publicado del NAS.

```bash
sudo docker exec -i dal-api-server node <<'NODE'
(async () => {
  const tests = [
    { name: 'API sin token', route: '/api/health', headers: {} },
    { name: 'Nexus API sin token', route: '/nexus-api/auth/login', headers: {} },
    { name: 'API con token malformado', route: '/api/health', headers: { 'Cf-Access-Jwt-Assertion': 'token-invalido-fase3' } },
    { name: 'Health interno sin token', route: '/health', headers: {} }
  ];
  for (const test of tests) {
    try {
      const response = await fetch('http://127.0.0.1:3000' + test.route, {
        method: 'GET', headers: test.headers, redirect: 'manual',
        signal: AbortSignal.timeout(10000)
      });
      console.log('\nPRUEBA:', test.name);
      console.log('HTTP:', response.status);
      console.log('RESPUESTA:', (await response.text()).slice(0, 600));
    } catch (error) {
      console.log('\nERROR:', test.name, '-', error.message);
    }
  }
})();
NODE
```

**Resultados esperados:**

| Solicitud | Resultado esperado |
| --- | --- |
| `/api/health` sin token | `403`, con `Missing Cf-Access-Jwt-Assertion`. |
| `/nexus-api/auth/login` sin token | `403`, con `Missing Cf-Access-Jwt-Assertion`. |
| `/api/health` con token malformado | `403`, con `Invalid or expired Cloudflare Access JWT`. |
| `/health` sin token | `200` si ese endpoint está implementado y disponible. |

**Qué demuestra:** el backend aplica el control aunque se acceda directamente desde dentro del contenedor. La consulta a la ruta de login es un `GET` sin credenciales; se comprueba el rechazo previo del middleware, no se intenta iniciar sesión.

Un token malformado permite comprobar el rechazo básico, pero **no demuestra por sí solo que se compruebe la firma RSA**. Para eso se incluye la prueba siguiente.

Si `/health` devuelve `404`, comprobar que el endpoint exista: excluir una ruta del middleware no la crea. Si una ruta protegida responde `200` sin token, la protección descrita no está actuando como se esperaba.

**Evidencia:** captura de los cuatro códigos HTTP y sus respuestas.

## 8. Prueba 6 — Rechazar un token con firma falsa e identificadores correctos

Esta prueba genera en memoria un token de ensayo con el emisor, la audiencia y un identificador de clave pública reales, pero con una firma aleatoria. No utiliza credenciales de personas ni modifica archivos. Realiza una consulta al endpoint público de claves y una solicitud al backend.

```bash
sudo docker exec -i dal-api-server node <<'NODE'
(async () => {
  const { randomBytes } = require('node:crypto');
  const team = (process.env.CF_ACCESS_TEAM_DOMAIN || '').replace(/\/$/, '');
  const aud = (process.env.CF_ACCESS_AUD || '').trim();
  if (!team || !aud) throw new Error('Faltan CF_ACCESS_TEAM_DOMAIN o CF_ACCESS_AUD');
  const response = await fetch(team + '/cdn-cgi/access/certs', {
    signal: AbortSignal.timeout(10000)
  });
  if (!response.ok) throw new Error('Consulta de claves: HTTP ' + response.status);
  const data = await response.json();
  const key = (data.keys || []).find(k => k.kty === 'RSA' && k.kid && k.n);
  if (!key) throw new Error('No se encontro una clave publica RSA');
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: 'RS256', kid: key.kid, typ: 'JWT' });
  const payload = encode({ iss: team, aud: [aud], exp: now + 300, nbf: now - 30, iat: now });
  const signature = randomBytes(Buffer.from(key.n, 'base64url').length).toString('base64url');
  const token = header + '.' + payload + '.' + signature;
  const result = await fetch('http://127.0.0.1:3000/api/health', {
    headers: { 'Cf-Access-Jwt-Assertion': token },
    redirect: 'manual', signal: AbortSignal.timeout(15000)
  });
  console.log('HTTP:', result.status);
  console.log('RESPUESTA:', (await result.text()).slice(0, 600));
  console.log(result.status === 403
    ? 'Resultado esperado: token de firma falsa rechazado.'
    : 'Resultado inesperado: revisar la validacion.');
})().catch(error => { console.error('ERROR:', error.message); process.exitCode = 1; });
NODE
```

**Resultado esperado:** `403`, con `Invalid or expired Cloudflare Access JWT`.

**Interpretación:** el rechazo es compatible con la comprobación de firma prevista. Para tener una evidencia sólida, debe combinarse con la aceptación de un token legítimo en la prueba 7: un backend mal configurado que rechace todo también devolvería `403`.

**Si falla la consulta de claves:** revisar conectividad del contenedor, dominio configurado y acceso HTTPS. Un error de conexión no cuenta como prueba aprobada.

**Evidencia:** captura del resultado, sin necesidad de mostrar ni copiar el token generado.

## 9. Prueba 7 — Comprobar el acceso real desde el navegador

Esta prueba se hace en tu computadora.

1. Abrir una ventana de incógnito nueva, sin sesión previa de Access.
2. Entrar a `https://dsm-api.accescont.com/api/health`.
3. Comprobar que se solicita autenticación mediante Cloudflare Access.
4. Iniciar sesión con una cuenta autorizada en la política, por ejemplo `test@accescont.com`, utilizando su método habitual de autenticación.
5. Comprobar la respuesta final de `/api/health`. Se espera `200` y la respuesta de salud de la API, siempre que la ruta exista y sus dependencias estén disponibles.
6. Para ver el código HTTP, pulsar `F12`, abrir **Network/Red** y recargar la página. Seleccionar la solicitud a `api/health` y revisar **Status Code/Código de estado**.
7. Abrir `https://dsm-api.accescont.com/` y comprobar una consulta habitual de la plataforma que no modifique datos.

**Qué demuestra:** el recorrido completo funciona: autenticación en Access, comunicación por el túnel, validación del token en el backend y respuesta de la aplicación. Cargar únicamente la página principal no basta, porque el bloque de validación JWT se aplica a las rutas de API indicadas.

**Comprobación adicional de la política:** si dispones de una cuenta propia de prueba que no esté incluida en las condiciones de acceso, iniciar una sesión separada con ella y verificar que se deniega el acceso. No cambiar la política para realizar esta comprobación.

**Si falla:**

| Resultado | Interpretación inicial |
| --- | --- |
| Access deniega la cuenta prevista | Revisar identidad utilizada y condiciones de la política. |
| Tras autenticarse aparece `403` con el mensaje JWT del middleware | Revisar emisor, audiencia, llegada de la cabecera y acceso a claves públicas; la autenticación en el borde no basta. |
| Aparece `404` | Revisar que la ruta exista y que el enrutamiento sea correcto. |
| Aparece `502` o un error de túnel | Revisar conectividad hacia el origen y estado del servicio. |
| La API responde `500` | Revisar registros de la aplicación y sus dependencias. |

**Evidencia:** captura de la pantalla de autenticación y de la respuesta final con su código HTTP. No capturar cookies, tokens ni códigos de acceso.

## 11. Criterio de cierre y conclusión

La fase puede considerarse verificada respecto a estos controles cuando las restricciones Docker estén activas, la escritura quede limitada a las zonas previstas, las solicitudes sin autorización o con firma falsa se rechacen y el acceso legítimo a la API funcione. También debe comprobarse una operación habitual de la plataforma.

Si solo se obtienen rechazos `403`, la validación todavía es incompleta: debe demostrarse que el sistema acepta las autorizaciones válidas. Estas pruebas comprueban los controles descritos, pero no sustituyen una evaluación completa de seguridad, permisos por proyecto o aislamiento entre usuarios.


