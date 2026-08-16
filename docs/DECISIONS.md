# Development log & design decisions

This document is the chronological engineering log kept during
development (in Spanish, as working notes for the underlying TFM
memoria). It records specific bugs found and fixed, scaling issues,
and the reasoning behind non-obvious design choices, in the order they
happened.

For a clean project overview and setup instructions, see the main
[README.md](../README.md).

---



TFM: Descubrimiento de infraestructuras de hosting de dominios onion.

Pipeline: Discovery -> Enumeracion -> Safe-mode filter -> Correlacion de fugas -> Grafo (Neo4j) -> Visualizacion.

Este repositorio contiene el esqueleto de las fases F0/F1 del plan de trabajo:
setup del proyecto, cliente Tor, patron de adapters para fuentes semilla y el
modulo safe-mode obligatorio.

## Estructura

```
onion-infra-discovery/
  config.py              Configuracion global, incluido SAFE_MODE (no desactivable)
  requirements.txt
  docker-compose.yml      Tor + Neo4j + Elasticsearch para desarrollo local
  src/
    tor_client.py         Conexion a Tor via stem, rotacion de circuitos
    safe_mode.py           Filtro obligatorio: descarta dominios antes de indexarlos
    models.py              Estructuras de datos (OnionRecord)
    crawler.py              Frontier + fetcher + parser (esqueleto)
    seeds/
      base.py               Clase abstracta SeedSource
      ahmia.py               Adapter de Ahmia (listado + blocklist oficial)
  tests/
    test_safe_mode.py
  data/                    Datasets generados (snapshots fechados), vacio en el repo
```

## Instalacion

### Nota sobre Python 3.14 (o cualquier version muy reciente)

Algunas dependencias (`pydantic`, `cryptography`) usan extensiones nativas
en Rust. Con un interprete de Python muy nuevo, la version exacta fijada
en `requirements.txt` puede no tener rueda precompilada todavia, y el
`pip install` intenta compilar desde el codigo fuente, lo cual falla si
no tienes el toolchain de compilacion instalado (error tipico:
"failed to build wheel", menciones a `maturin`/`cargo`/PyO3). Por eso
esas dos dependencias se dejan sin version exacta (`>=`), para que `pip`
elija automaticamente una version con soporte para tu interprete.

Si aun asi falla la instalacion de algun paquete con extension nativa,
actualiza pip primero (`python3 -m pip install --upgrade pip`) antes de
reintentar: las versiones de pip mas nuevas resuelven mejor que rueda
usar para tu version exacta de Python.

### Opcion A: docker-compose (recomendado)

1. `docker compose up -d tor` (ya incluye `PASSWORD=tfm-onion-dev-2026` para
   habilitar correctamente el control port de Tor; si cambias ese valor en
   `docker-compose.yml`, actualiza tambien `TOR_CONTROL_PASSWORD` en `config.py`).
2. `pip install -r requirements.txt`
3. `python3 scripts/manual_test.py`

Nota importante sobre la imagen `dperson/torproxy`: si no se le pasa
`PASSWORD` (o `-p <password>` por linea de comandos), el `ControlPort` queda
escuchando solo en `127.0.0.1` **dentro** del contenedor y no es alcanzable
desde fuera, aunque el puerto este publicado — esto produce un error de tipo
"empty socket content" en `stem` que no tiene nada que ver con el codigo
Python, sino con la configuracion del contenedor.

### Opcion B: Tor instalado localmente (sin Docker)

1. Instalar Tor: `apt install tor` (Linux) o `brew install tor` (Mac).
2. En `torrc`, habilitar `ControlPort 9051` y `CookieAuthentication 1`
   (o fijar `HashedControlPassword` y usar ese valor en
   `config.TOR_CONTROL_PASSWORD`).
3. `pip install -r requirements.txt`
4. `python3 scripts/manual_test.py`

## Principio de diseno: safe-mode no desactivable

`config.py` expone `SAFE_MODE = True` como constante de codigo fuente, no como
variable de entorno. La intencion es que activar contenido sin filtrar requiera
una modificacion explicita y revisable del codigo, nunca un flag de despliegue
accidental. Ver `src/safe_mode.py` para el detalle de la logica de descarte.

## Estado actual (F0/F1/F2/F4/F5/F6)

- [x] Cliente Tor con rotacion de circuito (`stem`) y espera de bootstrap
- [x] Patron adapter para fuentes semilla (`SeedSource`)
- [x] Adapter de Ahmia (listado `/onions/` + blocklist MD5 `/banned/`, torificado)
- [x] Modulo safe-mode con chequeo de hash contra blocklist (fail-closed real)
- [x] Fetcher async completo con `aiohttp-socks` (torificado de principio a fin)
- [x] Enumeracion de servicios (F2)
- [x] Correlacion de fugas (F4, estilo OnionScan)
- [x] Grafo de infraestructura en Neo4j (F5)
- [x] Busqueda por palabra clave en Elasticsearch (F6): indice combinando
      titulo HTTP, tecnologia, cabecera Server y estado de fugas; busqueda
      de texto libre con `multi_match` + fuzziness, y filtros por
      tecnologia o por presencia de fugas extraidas
- [x] Dashboard web propio (F6): FastAPI + HTML/CSS/JS vanilla, reutiliza
      `SearchIndex` sin duplicar logica. `webapp/main.py` expone
      `/api/search`, `/api/stats`, `/api/list` y `/api/related/{address}`;
      `webapp/static/` sirve la interfaz. Cuatro contadores clicables en
      la cabecera (indexados, vivos, con fugas, con relaciones de
      infraestructura), cada uno enlaza a un listado paginado y filtrado.
      El panel de detalle de cada dominio consulta el grafo de Neo4j en
      tiempo real y muestra un arbol de infraestructura relacionada
      (estilo Shodan), con navegacion de profundizacion entre dominios
      vinculados
- [ ] Adapters de Tor66, Excavator y motores de nivel 2 (siguiente iteracion)
- [x] Caso de estudio de desanonimizacion documentado (F7):
      `scripts/generate_case_study.py` busca en el grafo real el mejor
      ejemplo disponible (prioriza certificado/clave SSH compartidos
      sobre similitud de contenido, y dentro de cada tipo, el artefacto
      que conecta a mas dominios a la vez) y redacta automaticamente un
      informe en Markdown listo para la memoria, con cadena de
      correlacion, evidencia tecnica, encuadre metodologico, y la
      consulta Cypher para reproducir la captura visual

### Cómo levantar el dashboard web

```bash
python3 -m pip install -r requirements.txt
uvicorn webapp.main:app --reload --port 8000
```

Abre `http://localhost:8000`. Necesita Elasticsearch corriendo y con
datos indexados (ver `scripts/run_batch.py`) para devolver resultados;
si Elasticsearch no esta disponible, la interfaz lo indica con un
mensaje claro en vez de fallar en silencio.

### Nota sobre dependencias de correlacion (F4)

Se eligio `ppdeep` en vez de `ssdeep` deliberadamente: `ssdeep` no tiene
rueda precompilada para Windows en PyPI y requiere compilar contra la
libreria C `libfuzzy`, lo cual habria bloqueado la instalacion en un
entorno Windows sin compilador configurado. `ppdeep` implementa el mismo
algoritmo en Python puro, con la misma API (`hash()`, `compare()`).

### Ejecuciones a gran escala (miles de dominios)

`scripts/run_batch.py` procesa por bloques (`config.BATCH_CHECKPOINT_SIZE`,
200 por defecto) y guarda progreso en `data/checkpoint_<fecha>.jsonl`
tras cada bloque. Si el proceso se interrumpe (Ctrl+C, corte de luz,
suspension del equipo), basta con relanzar el mismo comando el mismo dia:
reanuda automaticamente desde donde se quedo, sin repetir el escaneo de
los dominios ya procesados.

La comparacion de similitud de contenido en `correlate()` es O(n^2) y no
escala indefinidamente; por encima de `config.CONTENT_SIMILARITY_MAX_ITEMS`
(3000 por defecto) se omite esa comparacion concreta (con aviso en el
log), mientras que la correlacion por certificado/clave SSH compartidos
(O(n), y ademas la señal mas fuerte de las tres) se mantiene siempre
activa. Esto se documenta como limitacion conocida/trabajo futuro en la
memoria (ver seccion de limitaciones).

### Dashboard "Resumen" (pantalla de aterrizaje)

Al abrir el dashboard, la vista por defecto ya no es el buscador sino un
resumen agregado (pestañas "Resumen" / "Buscador" bajo la cabecera):

- Distribucion de tecnologia detectada (top 10) y de puertos/servicios
  (top 10), via `SearchIndex.technology_distribution()` / `port_distribution()`.
- Resumen de artefactos de infraestructura (`GraphStore.artifact_summary()`):
  certificados TLS y claves SSH totales vs. realmente compartidos por mas
  de un dominio, con el top 5 de cada tipo ordenado por cuantos dominios
  conecta (el dato mas util para priorizar el caso de estudio F7).

El endpoint `/api/dashboard` consulta Elasticsearch y Neo4j de forma
independiente: si uno de los dos falla, se sigue mostrando lo que si
funciona junto con el error concreto de la parte caida, en vez de fallar
todo el resumen por un solo componente.

### JARM: fingerprinting de pila TLS (F4, complementario al certificado)

Ademas del certificado TLS, se calcula el hash JARM de cada dominio con
HTTPS abierto (`src/jarm_fingerprint.py`). JARM identifica la
pila/configuracion TLS del servidor (version, orden de cifrados,
extensiones), no el certificado: dos dominios con certificados
totalmente distintos pueden compartir JARM si corren el mismo software
con la misma configuracion, una correlacion que el certificado
compartido no detecta por si solo. Es un dato estrictamente adicional:
nunca sustituye la extraccion de certificado, ambas se calculan siempre
que el puerto 443 este abierto.

Se reutiliza `pyJARM` (implementacion oficial de Palo Alto Networks)
para la construccion de los 10 paquetes ClientHello y el hashing de la
respuesta - la parte delicada a nivel de protocolo/criptografia. Su
propia capa de transporte NO se usa (solo soporta proxies HTTP/HTTPS,
no SOCKS5); el transporte real via Tor se implementa con PySocks, igual
que el resto del pipeline.

**Nota de fidelidad al estandar** (documentar en la memoria): esta es
una implementacion propia de la metodologia JARM sobre la base del
paquete `pyJARM`, no una verificacion byte a byte contra el estandar de
referencia de Salesforce. Lo que garantiza es determinismo y
consistencia interna (misma configuracion real -> mismo hash dentro de
este dataset), no compatibilidad estricta con bases de datos publicas
de hashes JARM externas.

Prioridad en `find_best_case_study()` y en las relaciones del grafo:
certificado/clave SSH compartidos (identidad exacta) > JARM compartido
(misma configuracion, señal algo mas debil) > similitud de contenido
(la mas debil, solo como ultimo recurso).

### Rellenar JARM en un dataset ya escaneado (sin re-escanear todo)

Si ya tienes un checkpoint de una ejecucion anterior a que se anadiera
JARM, no hace falta repetir el escaneo completo:

```bash
python3 scripts/backfill_jarm.py --checkpoint data/checkpoint_<fecha>.jsonl
```

Solo calcula JARM para los dominios que ya tenian el puerto 443 abierto
y aun no tienen `jarm_hash` (normalmente una fraccion pequeña del
dataset total), reutilizando discovery/enumeracion/certificado/SSH/
contenido ya guardados. Al terminar, recalcula `correlate()` sobre todo
el conjunto y vuelve a cargar en Neo4j y Elasticsearch.

### Claves PGP y direcciones de criptomonedas (F4, ampliacion sobre OnionScan)

Ademas de certificado/JARM/SSH, se extraen dos señales de identidad
directa del contenido HTML ya descargado (sin peticiones adicionales):

- **Clave PGP publicada**: se busca un bloque armored
  (`-----BEGIN PGP PUBLIC KEY BLOCK-----`) y se hashea su contenido
  normalizado (sin whitespace). Limitacion documentada: detecta
  bloques armored identicos (mismo export), no compara las claves a
  nivel criptografico.
- **Direcciones de criptomonedas** (BTC, XMR, ETH) mencionadas en el
  texto. BTC (formato legacy) se valida con checksum base58check real
  (verificado contra la direccion publica del bloque genesis de
  Bitcoin); BTC bech32 y XMR se detectan solo por forma/longitud, sin
  checksum (limitacion documentada, mitigada porque solo se usa para
  correlacion entre dominios, no como dato aislado).

A diferencia de certificado/JARM/SSH (un valor por dominio), un dominio
puede mencionar VARIAS direcciones de cripto a la vez; la correlacion
(`shared_crypto_address` en `correlate()`) enlaza dos dominios si
comparten CUALQUIERA de sus direcciones, no solo si coinciden en todas.

Modelado en el grafo como nodos `PGPKey` y `CryptoAddress` (este ultimo
con un id combinado `MONEDA:direccion`, ya que Neo4j Community no
soporta constraints de unicidad compuestos), con las mismas
consultas de resumen y de infraestructura relacionada que el resto de
artefactos.

**Alcance deliberadamente excluido** (ver conversacion): imagenes
genericas y audio, por el perfil de riesgo de descargar contenido
binario de dominios `.onion` no verificados.

### Jerarquia completa de find_best_case_study() (F7)

1. **Certificado TLS, clave SSH o clave PGP compartidos** (identidad
   exacta). Una clave PGP se trata al mismo nivel que certificado/SSH:
   esta pensada especificamente para identificar a una persona u
   operador, no solo a un servidor.
2. **JARM o direccion de criptomoneda compartidos** (fuertes, algo menos
   concluyentes en solitario: configuracion por defecto comun o
   reutilizacion legitima de una wallet de donacion, respectivamente).
3. **Similitud de contenido** (la señal mas debil, ultimo recurso).

El nivel superior siempre gana sobre uno inferior, incluso si el
artefacto de nivel inferior conecta a mas dominios a la vez.

### Rellenar PGP/cripto/artefactos HTML en un dataset ya escaneado

```bash
python3 scripts/backfill_artifacts.py --checkpoint data/checkpoint_<fecha>.jsonl
```

Este SI vuelve a descargar el contenido de cada dominio (nunca se
guarda el HTML crudo), asi que toca a todos los dominios con puerto 80
o 443 abierto, no solo 443 (a diferencia de `backfill_jarm.py`). En una
UNICA descarga por dominio, extrae PGP, direcciones de cripto, y
artefactos HTML (JS/CSS/favicon/documentos) a la vez, sin repetir
peticiones de red. Sigue sin repetir discovery, enumeracion de puertos,
ni certificado/JARM/SSH (ya guardados). Al terminar, recalcula
`correlate()` y recarga en Neo4j y Elasticsearch.

### Fix: relaciones complementarias mostraban solo una a la vez

`find_related_infrastructure()` encadenaba seis `OPTIONAL MATCH` en una
sola consulta Cypher, un patron conocido por generar productos
cartesianos dificiles de razonar entre los distintos tipos de relacion.
Se rediseño con SEIS consultas independientes (una por tipo), combinadas
en Python en un dict agrupado por tipo de relacion. El endpoint
`/api/related/{address}` y el panel de detalle ahora muestran TODAS las
señales presentes (certificado, JARM, SSH, PGP, cripto, contenido) cada
una en su propio apartado, nunca una sustituyendo a otra. Test de
regresion especifico: `test_find_related_infrastructure_groups_by_relation_type`.

### Artefactos hasheados del HTML: JavaScript, CSS, favicon, documentos

Ademas de PGP y direcciones de cripto, se hashean los recursos
enlazados desde el HTML de cada dominio (`src/html_artifact_extraction.py`
+ integracion en `correlation.py`):

- **JavaScript** y **CSS** enlazados (`<script src>`, `<link rel=stylesheet>`).
- **Favicon** (`<link rel=icon>`, con fallback a `/favicon.ico` si no
  esta declarado explicitamente).
- **Documentos** (PDF/DOCX/XLSX/ZIP enlazados con `<a href>`).

Deliberadamente excluidas imagenes genericas y audio (ver conversacion:
perfil de riesgo distinto al descargar contenido binario arbitrario de
dominios `.onion` no verificados). Solo se descargan recursos alojados
en el MISMO dominio que la pagina de origen; los enlaces a dominios
externos se descartan sin seguirlos. Nunca se persiste el contenido
descargado, solo su hash sha256.

Extraccion con `html.parser` de la libreria estandar (no se reintrodujo
BeautifulSoup/lxml, que ya se habian quitado por romper la instalacion
en Python 3.14). Cada tipo correlaciona de forma independiente
(`shared_javascript`, `shared_css`, `shared_favicon`, `shared_document`)
en el grafo, con su propio apartado en el panel de detalle - señales
complementarias entre si y con el resto (certificado/JARM/SSH/PGP/cripto),
nunca sustituyendose.

**Pendiente/no incluido en esta iteracion** (a valorar si se quiere
ampliar mas adelante): tarjetas de resumen especificas para estos
cuatro tipos en el dashboard "Resumen" (el resto de artefactos si las
tiene), y su inclusion como nivel de prioridad en `find_best_case_study()`
de F7 (de momento solo participan en `find_related_infrastructure()`,
el panel de detalle de cada dominio).

### Fix critico: explosion combinatoria en grupos muy grandes (MemoryError)

`_group_and_link()`/`_group_multi_valued_and_link()` conectaban TODOS
los pares dentro de un grupo (topologia completa, O(k^2)). Con un
dataset grande, un artefacto muy comun compartido por muchos dominios
SIN relacion real entre si (ej. un certificado autofirmado "por
defecto" reutilizado por miles de despliegues independientes) podia
generar cientos de miles de pares y agotar la memoria al guardar el
resultado - visto en produccion con un dataset de 8486 dominios: un
solo grupo genero 522.593 relaciones y crasheo con `MemoryError`.

Arreglado con topologia en estrella (cada dominio se enlaza solo con
uno de referencia del grupo, no con todos): O(k) en vez de O(k^2), sin
perder informacion de conectividad (todos los miembros del grupo siguen
apareciendo en el resultado). Grupos de mas de 50 dominios generan un
aviso en el log identificandolos como probablemente genericos/no
distintivos. Test de regresion: `test_correlate_large_group_uses_star_topology_not_full_mesh`.

### Recuperar una ejecucion que crasheo en el paso final (sin re-escanear)

Si `run_batch.py` (o cualquier backfill) escaneo todo correctamente pero
fallo en el ultimo paso (correlacion/guardado), el checkpoint ya tiene
todos los datos - no hace falta repetir el escaneo:

```bash
python3 scripts/recorrelate.py --checkpoint data/checkpoint_<fecha>.jsonl
```

Recalcula `correlate()` (ya con el fix de la explosion combinatoria) y
recarga en Neo4j/Elasticsearch, sin ninguna peticion de red.

### Vista ampliada del arbol de relaciones

El panel de detalle ahora tiene, sobre el arbol de infraestructura
relacionada:

- **Pestanas por tipo de relacion** ("Todos", "Certificado TLS
  compartido", "JARM", ...), solo cuando hay mas de un tipo con datos.
- **Boton "Ampliar"** que abre un modal con un layout radial (mejor
  aprovechamiento del espacio con muchos nodos que el abanico horizontal
  compacto), con zoom (rueda del raton) y arrastre (drag) implementados
  sobre el propio viewBox del SVG, sin ninguna libreria nueva.
- **Consulta Cypher lista para copiar y pegar en Neo4j Browser**, para
  cuando haga falta la exploracion completa que ya ofrece esa
  herramienta (zoom, arrastre, expansion de nodos) en vez de reconstruir
  eso a medida.

Junto a esto, el titulo de cada apartado de artefactos HTML compartidos
(JavaScript/CSS/favicon/documento) muestra ahora el nombre de fichero
encontrado, no solo el hash y el contador. Requirio guardar tambien la
URL original en `search_index.py` (antes solo se guardaba el hash).

### Vista 3D del arbol de relaciones (opcional, junto a la 2D)

Dentro del modal "Ampliar" del panel de detalle, hay un interruptor
"Vista 2D / Vista 3D". La 2D (radial, SVG) sigue siendo la que carga por
defecto - la 3D es una opcion adicional, con carga diferida (las
librerias `three.js` + `3d-force-graph` + `three-spritetext` solo se
piden por CDN la primera vez que se pulsa "Vista 3D", nunca en la carga
inicial de la pagina, para no penalizar a quien no la use).

Caracteristicas: arrastrar un nodo lo fija donde se suelta (deja de
moverlo la simulacion fisica - boton "Reiniciar posiciones" para
deshacerlo), anillo de fiabilidad alrededor de cada nodo no-raiz (dorado
= identidad exacta [certificado/SSH/PGP], plateado = configuracion o
wallet compartida [JARM/cripto] - misma jerarquia que
`find_best_case_study()` en el backend; los artefactos HTML y la
similitud de contenido no tienen anillo porque el backend todavia no
les asigna un nivel de fiabilidad), y clic en un nodo abre su propia
ficha (mismo comportamiento que la vista 2D).

Se probo primero una version aislada con muchos mas ajustes (busqueda
en vivo, expandir nodos en el sitio) en varias iteraciones fuera del
proyecto antes de integrar esta version; la busqueda se omitio en la
integracion real porque en las pruebas causaba un "vibrado" visible
(recalcular `graphData()` en cada tecla reinicia la simulacion fisica) -
queda pendiente si se quiere retomar con un mecanismo de resaltado que
no reinicie la simulacion cada vez.

### Preparacion para subir a GitHub

Las credenciales de desarrollo (Tor, Neo4j) ya no estan escritas
directamente en el codigo: se leen de variables de entorno via
`python-dotenv`, con los mismos valores de siempre como defecto (no
hace falta crear nada para que el proyecto siga funcionando igual que
hasta ahora). Ver `.env.example` para la plantilla, y `.gitignore` para
lo que se excluye del repositorio (secretos, cachés de Python, y los
checkpoints de escaneo completos - demasiado grandes para versionar en
git; los `data/case_study_*.md`, pequeños y en texto, si se suben).

Si quieres incluir una muestra pequeña de datos reales como respaldo,
guardala con un nombre que no coincida con el patron
`checkpoint_*.jsonl` del `.gitignore` (por ejemplo,
`data/sample_50_domains.jsonl`), o sube solo un subconjunto reducido del
checkpoint completo.
