"""
Configuracion global del pipeline de descubrimiento de infraestructura onion.

IMPORTANTE (decision de diseno, ver README):
SAFE_MODE se define aqui como constante de codigo fuente, NO se lee de una
variable de entorno ni de un argumento de linea de comandos. Cualquier
cambio requiere editar este fichero y por tanto queda registrado en el
historial de git, lo cual es intencional: no queremos que un despliegue
mal configurado (ej. una variable de entorno olvidada) deje el sistema
indexando contenido sin filtrar.

No anadir aqui SAFE_MODE = os.environ.get(...). Si en el futuro se necesita
desactivar temporalmente para un test controlado, hacerlo de forma explicita
en el propio test, nunca a nivel global.
"""

from pathlib import Path
import os

from dotenv import load_dotenv

# Carga variables desde un fichero .env local si existe (nunca se sube a
# git, ver .gitignore) - SOLO para credenciales (Tor, Neo4j). SAFE_MODE
# NUNCA debe leerse de aqui, ver nota mas abajo.
load_dotenv()

# ---------------------------------------------------------------------------
# Safe-mode (ver src/safe_mode.py)
# ---------------------------------------------------------------------------
SAFE_MODE = True

# Fuente del blocklist oficial de Ahmia (hashes MD5 de onions bloqueados por
# distribuir material de abuso infantil). Se descarga y cachea localmente.
# AHMIA_BLOCKLIST_ONION_URL es la que se usa en produccion (torificada);
# AHMIA_BLOCKLIST_URL (clearnet) solo se usa en download_blocklist_dev_no_tor,
# para desarrollo sin Tor activo.
AHMIA_BLOCKLIST_URL = "https://ahmia.fi/blacklist/banned/"
AHMIA_ONIONS_URL = "https://ahmia.fi/onions/"
AHMIA_ONION_ADDRESS = (
    "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
)
AHMIA_BLOCKLIST_ONION_URL = f"http://{AHMIA_ONION_ADDRESS}/blacklist/banned/"

BLOCKLIST_CACHE_PATH = Path(__file__).parent / "data" / "ahmia_blocklist.txt"
BLOCKLIST_MAX_AGE_HOURS = 24  # forzar refresco periodico del blocklist

# ---------------------------------------------------------------------------
# Tor
# ---------------------------------------------------------------------------
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_HOST = "127.0.0.1"
TOR_CONTROL_PORT = 9051
# NOTA DE SEGURIDAD: el valor por defecto es solo para el entorno de
# desarrollo local (docker-compose.yml lee el mismo valor via .env, ver
# .env.example). Para cambiarlo, define TOR_CONTROL_PASSWORD en tu propio
# .env - nunca lo escribas aqui directamente (este fichero si va a git).
TOR_CONTROL_PASSWORD = os.environ.get("TOR_CONTROL_PASSWORD", "tfm-onion-dev-2026")

# Rotar de circuito cada N peticiones (no en cada peticion, ver discusion
# sobre por que no aporta valor rotar demasiado a menudo)
CIRCUIT_RENEW_EVERY_N_REQUESTS = 30

# Timeouts
CONNECT_TIMEOUT_SECONDS = 15
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3

# ---------------------------------------------------------------------------
# Crawler / Discovery
# ---------------------------------------------------------------------------
MAX_CRAWL_DEPTH = 3  # saltos maximos desde una semilla
MAX_CONCURRENT_REQUESTS = 8

# Fecha de corte del snapshot actual (se sobreescribe al lanzar el crawler
# con la fecha real de ejecucion, ver src/crawler.py)
DATASET_TAG = "onions_snapshot"

# ---------------------------------------------------------------------------
# Enumeracion de servicios (F2)
# ---------------------------------------------------------------------------
# Puertos comunes a sondear en cada dominio. nmap normal no funciona bien
# contra un proxy SOCKS, asi que el sondeo se hace con conexiones TCP
# propias via PySocks (ver src/enumeration.py).
ENUMERATION_PORTS: dict[int, str] = {
    80: "http",
    443: "https",
    21: "ftp",
    22: "ssh",
    25: "smtp",
    465: "smtps",
    587: "submission",
    6667: "irc",
}

ENUMERATION_CONCURRENCY = 4  # concurrencia de PUERTOS dentro de un mismo dominio
ENUMERATION_DOMAIN_CONCURRENCY = 5  # concurrencia entre DOMINIOS distintos
ENUMERATION_BANNER_TIMEOUT = 5  # segundos esperando banner tras conectar

# Comprobacion rapida de vida ANTES del escaneo completo de 8 puertos.
# Si ni el puerto 80 ni el 443 responden en este timeout (mas corto que
# CONNECT_TIMEOUT_SECONDS), se asume el dominio muerto/inalcanzable y se
# omiten los 6 puertos restantes sin intentar conectar, ahorrando tiempo
# real en un dataset donde una parte significativa de los dominios estan
# caidos (ver discusion sobre tasa de mortalidad de infraestructura onion).
LIVENESS_CHECK_PORTS = (80, 443)
LIVENESS_CHECK_TIMEOUT = 8

# ---------------------------------------------------------------------------
# Correlacion de fugas (F4)
# ---------------------------------------------------------------------------
CORRELATION_CONCURRENCY = 4
TLS_HANDSHAKE_TIMEOUT = 15
SSH_HANDSHAKE_TIMEOUT = 15
JARM_PROBE_TIMEOUT = 10  # timeout por cada una de las 10 sondas JARM
JARM_PROBE_CONCURRENCY = 3  # sondas JARM concurrentes dentro de un mismo dominio
CONTENT_FUZZY_HASH_MAX_BYTES = 200_000  # no hashear paginas enormes completas
CONTENT_SIMILARITY_THRESHOLD = 60  # score ssdeep.compare (0-100) a partir del cual se considera plantilla compartida

# La comparacion de similitud de contenido es O(n^2) sobre los dominios
# con fuzzy hash disponible. Con datasets grandes (miles de dominios)
# esto puede suponer decenas de millones de comparaciones. Por encima de
# este limite, se omite la comparacion de contenido (se documenta como
# limitacion/trabajo futuro en la memoria) pero se mantiene la
# correlacion por certificado/clave SSH compartidos, que es O(n) y ademas
# es la señal mas fuerte de las tres.
CONTENT_SIMILARITY_MAX_ITEMS = 3000

# ---------------------------------------------------------------------------
# Artefactos hasheados del HTML (F4, ampliacion tipo urlscan.io)
# ---------------------------------------------------------------------------
# JavaScript, CSS, favicon y documentos (PDF/DOCX/XLSX/ZIP) enlazados
# desde el HTML. Deliberadamente NO incluye imagenes genericas ni audio
# (ver conversacion): descargar contenido binario arbitrario de dominios
# .onion no verificados es un perfil de riesgo distinto al del resto del
# proyecto. El favicon es la unica excepcion de tipo "imagen": es un
# icono de sitio, no contenido arbitrario (mismo criterio que usa Shodan
# con http.favicon.hash).
#
# Solo se descargan recursos alojados en el MISMO dominio .onion que la
# pagina de origen (no se siguen enlaces a dominios externos).
HTML_ARTIFACT_MAX_PER_TYPE = 3  # maximo de recursos de cada tipo a descargar por dominio
HTML_ARTIFACT_MAX_BYTES = 2_000_000  # no descargar recursos enormes completos
HTML_ARTIFACT_FETCH_TIMEOUT = 10
HTML_ARTIFACT_CONCURRENCY = 2  # descargas extra concurrentes por dominio, bajo a proposito

# ---------------------------------------------------------------------------
# Ejecucion a gran escala (scripts/run_batch.py)
# ---------------------------------------------------------------------------
# Tamaño de bloque para guardado incremental. Con datasets de miles de
# dominios la ejecucion puede durar horas; guardar solo al final significa
# perder TODO el trabajo ante cualquier corte. Cada BATCH_CHECKPOINT_SIZE
# dominios procesados, se anexa el progreso a un fichero JSONL en disco.
BATCH_CHECKPOINT_SIZE = 200

# ---------------------------------------------------------------------------
# Grafo de infraestructura (F5)
# ---------------------------------------------------------------------------
# Debe coincidir con NEO4J_AUTH en docker-compose.yml (usuario/password).
# Define NEO4J_PASSWORD en tu .env para cambiarlo - nunca lo escribas aqui.
NEO4J_URI = "bolt://127.0.0.1:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "changeme-in-env")

# ---------------------------------------------------------------------------
# Busqueda por palabra clave (F6)
# ---------------------------------------------------------------------------
ELASTICSEARCH_URL = "http://127.0.0.1:9200"
ELASTICSEARCH_INDEX = "onion_infra_discovery"

DATA_DIR = Path(__file__).parent / "data"

# ---------------------------------------------------------------------------
# Resumen de contenido con LLM local (Ollama, opcional)
# ---------------------------------------------------------------------------
# Apagado por defecto a proposito: requiere tener Ollama instalado y
# corriendo aparte (no forma parte de docker-compose.yml), y es una pieza
# opcional del proyecto, no del camino critico del escaneo. Si Ollama no
# esta disponible, el relleno lo detecta y no hace nada - nunca rompe el
# resto del pipeline.
ENABLE_LLM_SUMMARY = False
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:1.5b")
OLLAMA_TIMEOUT = 30
LLM_SUMMARY_MAX_INPUT_CHARS = 4000  # recorte del texto plano antes de resumir
LLM_SUMMARY_MIN_CHARS = 40  # por debajo de esto, no vale la pena resumir
LLM_SUMMARY_MAX_WORDS = 60  # limite pedido al modelo en el propio prompt
LLM_SUMMARY_CACHE_PATH = DATA_DIR / "llm_summary_cache.json"
# Pausa entre cada dominio procesado. No es por rendimiento del propio
# proceso (es un cuello de botella menor comparado con el tiempo de red
# de Tor y de inferencia del modelo) - es para dar respiro termico al
# equipo en ejecuciones largas: Tor + Neo4j + Elasticsearch + Ollama
# corriendo a la vez durante horas es carga sostenida real, y en la
# practica ha llegado a apagar el equipo. Ajustable si tu equipo aguanta
# mejor o peor.
LLM_SUMMARY_DELAY_SECONDS = 2.0

# Categorizacion del tipo de servicio, a partir del resumen ya generado
# (no del HTML crudo - no necesita Tor ni volver a descargar nada).
# Tarea de clasificacion cerrada (elegir 1 de N), mucho mas fiable para
# un modelo pequeño que el resumen libre. Lista cerrada deliberadamente
# corta: mas categorias añaden ambiguedad sin aportar mucho valor
# analitico extra.
ENABLE_LLM_CATEGORY = False
LLM_CATEGORY_CHOICES = [
    "marketplace", "foro", "panel_administracion", "exchange_cripto",
    "mensajeria", "blog_personal", "servicio_tecnico", "directorio_enlaces",
    "sin_contenido", "otro",
]
LLM_CATEGORY_CACHE_PATH = DATA_DIR / "llm_category_cache.json"
