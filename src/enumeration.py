"""
Enumeracion de servicios expuestos por un dominio onion (F2 del plan).

nmap normal no funciona bien contra un proxy SOCKS5, asi que el sondeo de
puertos se hace con conexiones TCP propias via PySocks (sincrono, pero
paralelizado con asyncio.to_thread para no bloquear el resto del pipeline
async). Para HTTP/HTTPS se reutiliza la sesion Tor de aiohttp ya existente
(create_tor_session) para hacer un fingerprint basico de tecnologia.

Punto de diseno importante: esta fase SOLO opera sobre dominios que ya
han pasado el filtro safe-mode (ver src/crawler.py). Como capa adicional
de defensa en profundidad, enumerate_batch acepta opcionalmente el mismo
SafeModeFilter y vuelve a comprobar cada direccion antes de tocarla, por
si esta funcion se invoca alguna vez fuera del pipeline principal.
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket
from typing import Optional

import socks  # PySocks

import config
from src.models import OnionRecord, OnionStatus, ServiceEnumeration, ServicePort
from src.safe_mode import SafeModeFilter

logger = logging.getLogger(__name__)

# Si el banner recibido contiene alguna de estas cadenas, se usa para
# corregir el protocolo inferido solo por numero de puerto (util para
# servicios en puertos no estandar).
BANNER_PROTOCOL_HINTS: list[tuple[str, str]] = [
    ("SSH-", "ssh"),
    ("HTTP/1.", "http"),
    ("ESMTP", "smtp"),
    ("SMTP", "smtp"),
    ("220", "ftp"),  # banner FTP tipico empieza por codigo 220; se comprueba
                      # despues de ESMTP/SMTP porque esos banners tambien
                      # empiezan por "220" y son mas especificos
]

# Fingerprint muy basico de tecnologia web, por cabeceras y contenido.
# No pretende ser exhaustivo (para eso existen herramientas como
# Wappalyzer); es suficiente para el analisis agregado del TFM.
TECH_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"wp-content|wp-includes", re.IGNORECASE), "WordPress"),
    (re.compile(r"powered by prestashop", re.IGNORECASE), "PrestaShop"),
    (re.compile(r"powered by phpbb", re.IGNORECASE), "phpBB"),
    (re.compile(r"drupal", re.IGNORECASE), "Drupal"),
    (re.compile(r"joomla", re.IGNORECASE), "Joomla"),
    (re.compile(r"nginx", re.IGNORECASE), "nginx"),
    (re.compile(r"apache", re.IGNORECASE), "Apache"),
]

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def classify_banner(banner: Optional[str], default_protocol: str) -> str:
    """
    Corrige el protocolo inferido solo por numero de puerto si el banner
    recibido da una pista mas fiable (por ejemplo, un servicio SSH
    corriendo en un puerto no estandar).
    """
    if not banner:
        return default_protocol
    for needle, protocol in BANNER_PROTOCOL_HINTS:
        if needle in banner:
            return protocol
    return default_protocol


def _probe_port_sync(address: str, port: int, connect_timeout: float, banner_timeout: float) -> ServicePort:
    """
    Conexion TCP sincrona a traves de Tor (PySocks) a un puerto concreto.
    Se ejecuta en un hilo (ver probe_port) para no bloquear el event loop.
    """
    default_protocol = config.ENUMERATION_PORTS.get(port, "other")
    sock_obj = socks.socksocket()
    sock_obj.set_proxy(socks.SOCKS5, config.TOR_SOCKS_HOST, config.TOR_SOCKS_PORT, rdns=True)
    sock_obj.settimeout(connect_timeout)
    try:
        sock_obj.connect((address, port))
    except (socks.ProxyError, socket.timeout, OSError) as exc:
        logger.debug("Puerto cerrado o inalcanzable %s:%d (%r)", address, port, exc)
        return ServicePort(port=port, protocol=default_protocol, open=False)

    banner: Optional[str] = None
    try:
        sock_obj.settimeout(banner_timeout)
        data = sock_obj.recv(512)
        if data:
            banner = data.decode(errors="replace").strip()
    except socket.timeout:
        # Puerto abierto pero el servicio no habla primero (tipico de HTTP,
        # que espera a que el cliente envie la peticion). Sigue siendo un
        # puerto abierto, solo que sin banner.
        banner = None
    except OSError:
        banner = None
    finally:
        sock_obj.close()

    protocol = classify_banner(banner, default_protocol)
    return ServicePort(port=port, protocol=protocol, open=True, banner=banner)


async def probe_port(
    address: str,
    port: int,
    connect_timeout: float = config.CONNECT_TIMEOUT_SECONDS,
    banner_timeout: float = config.ENUMERATION_BANNER_TIMEOUT,
) -> ServicePort:
    return await asyncio.to_thread(_probe_port_sync, address, port, connect_timeout, banner_timeout)


def _extract_technologies(html: str) -> list[str]:
    return [name for pattern, name in TECH_SIGNATURES if pattern.search(html)]


def _extract_title(html: str) -> Optional[str]:
    match = TITLE_RE.search(html)
    if not match:
        return None
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200]


async def _fingerprint_http(address: str, session, use_https: bool) -> tuple[list[str], Optional[str], Optional[str]]:
    """
    Descarga la raiz del sitio (via la sesion Tor existente) y extrae
    tecnologias conocidas, titulo y cabecera Server. Nunca se persiste el
    HTML completo, solo estos campos derivados.
    """
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{address}/"
    try:
        async with session.get(url, timeout=config.REQUEST_TIMEOUT_SECONDS) as resp:
            server_header = resp.headers.get("Server")
            html = await resp.text(errors="replace")
    except Exception as exc:
        logger.debug("Fingerprint HTTP fallo para %s (%r)", url, exc)
        return [], None, None

    technologies = _extract_technologies(html)
    if server_header:
        for pattern, name in TECH_SIGNATURES:
            if pattern.search(server_header) and name not in technologies:
                technologies.append(name)
    title = _extract_title(html)
    return technologies, title, server_header


async def _quick_liveness_gate(address: str) -> tuple[bool, dict[int, ServicePort]]:
    """
    Prueba solo los puertos en config.LIVENESS_CHECK_PORTS (80 y 443 por
    defecto), EN PARALELO, con un timeout mas corto que el del escaneo
    completo. Si ninguno responde, el dominio se considera muerto/
    inalcanzable para efectos practicos y se evita gastar tiempo en los
    puertos restantes.

    Devuelve (alive, resultados_ya_obtenidos) para poder reutilizar estos
    resultados en el escaneo completo sin volver a conectar dos veces al
    mismo puerto.
    """
    probes = await asyncio.gather(*(
        probe_port(
            address, port,
            connect_timeout=config.LIVENESS_CHECK_TIMEOUT,
            banner_timeout=config.ENUMERATION_BANNER_TIMEOUT,
        )
        for port in config.LIVENESS_CHECK_PORTS
    ))
    results = {port: result for port, result in zip(config.LIVENESS_CHECK_PORTS, probes)}
    alive = any(r.open for r in results.values())
    return alive, results


async def enumerate_domain(
    record: OnionRecord,
    session,
    safe_mode: SafeModeFilter | None = None,
    ports: dict[int, str] | None = None,
) -> ServiceEnumeration:
    """
    Enumera los servicios de un unico dominio. `session` debe ser una
    sesion creada con src.tor_client.create_tor_session (torificada).

    Si se pasa `safe_mode`, se vuelve a comprobar la direccion como capa
    adicional de defensa en profundidad (ver docstring del modulo).

    Antes del escaneo completo se hace una comprobacion rapida de vida
    (ver _quick_liveness_gate); si el dominio no responde en ningun puerto
    comun, se marcan todos los puertos solicitados como cerrados SIN
    intentar conectar a cada uno individualmente.
    """
    if safe_mode is not None and safe_mode.is_blocked(record.address):
        logger.info(
            "enumerate_domain: direccion bloqueada por safe-mode, se omite (hash=%s)",
            safe_mode.hash_address(record.address),
        )
        return ServiceEnumeration(address=record.address)

    ports_to_scan = ports or config.ENUMERATION_PORTS

    alive, gate_results = await _quick_liveness_gate(record.address)

    # Aqui es donde se determina la vida real del dominio (conexion TCP
    # efectiva a un puerto comun), asi que aqui es donde se actualiza
    # OnionRecord.status. F1 (crawler.py, _liveness_pass) dejaba esto
    # pendiente deliberadamente para no duplicar trabajo de red: la
    # comprobacion real vive aqui, no en dos sitios a la vez.
    record.status = OnionStatus.ALIVE if alive else OnionStatus.DEAD

    if not alive:
        logger.info("%s: sin respuesta en puertos de comprobacion rapida, se omite el resto", record.address)
        closed_ports = [
            ServicePort(port=p, protocol=proto, open=False)
            for p, proto in ports_to_scan.items()
        ]
        return ServiceEnumeration(address=record.address, ports=closed_ports)

    semaphore = asyncio.Semaphore(config.ENUMERATION_CONCURRENCY)

    async def _bounded_probe(port: int) -> ServicePort:
        async with semaphore:
            return await probe_port(record.address, port)

    # Reutiliza los resultados de la comprobacion rapida para los puertos
    # que ya se probaron, y solo lanza conexiones nuevas para el resto.
    remaining_ports = [p for p in ports_to_scan if p not in gate_results]
    remaining_results = await asyncio.gather(*(_bounded_probe(p) for p in remaining_ports))

    results = list(gate_results.values()) + list(remaining_results)
    enumeration = ServiceEnumeration(address=record.address, ports=results)

    http_port_open = any(p.open and p.protocol == "http" for p in results)
    https_port_open = any(p.open and p.protocol == "https" for p in results)

    if https_port_open:
        technologies, title, server_header = await _fingerprint_http(record.address, session, use_https=True)
    elif http_port_open:
        technologies, title, server_header = await _fingerprint_http(record.address, session, use_https=False)
    else:
        technologies, title, server_header = [], None, None

    enumeration.technologies = technologies
    enumeration.http_title = title
    enumeration.server_header = server_header
    return enumeration


async def enumerate_batch(
    records: list[OnionRecord],
    session,
    safe_mode: SafeModeFilter | None = None,
    ports: dict[int, str] | None = None,
) -> list[ServiceEnumeration]:
    """
    Enumera una lista de dominios con concurrencia limitada TAMBIEN entre
    dominios (no solo entre puertos de un mismo dominio), acotada por
    config.ENUMERATION_DOMAIN_CONCURRENCY. Sin esto, un dataset de
    cientos de dominios tardaria un tiempo prohibitivo (cada dominio
    muerto ya optimizado tarda ~8s solo en la puerta de vida; en
    secuencial puro, 200 dominios muertos serian mas de 25 minutos solo
    en esa fase). La concurrencia se mantiene deliberadamente moderada
    (no altísima) para no generar un numero excesivo de circuitos Tor
    simultaneos, que es mas facil que provoque fallos en cascada que
    ganar en velocidad.
    """
    domain_semaphore = asyncio.Semaphore(config.ENUMERATION_DOMAIN_CONCURRENCY)

    async def _bounded_enumerate(record: OnionRecord) -> ServiceEnumeration:
        async with domain_semaphore:
            try:
                return await enumerate_domain(record, session, safe_mode=safe_mode, ports=ports)
            except Exception as exc:
                logger.warning("Fallo enumerando %s (%r)", record.address, exc)
                return ServiceEnumeration(address=record.address)

    return await asyncio.gather(*(_bounded_enumerate(r) for r in records))
