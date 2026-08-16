"""
Correlacion de fugas de infraestructura (F4), inspirado en la metodologia
de OnionScan (2016).

Principio metodologico importante (ver memoria del TFM): esto NO es
explotacion de vulnerabilidades de aplicacion. Es correlacion pasiva de
artefactos que el propio servidor expone publicamente por diseno o mala
configuracion:
  - Certificados TLS reutilizados entre dominios distintos (mismo
    fingerprint SHA-256) sugieren el mismo servidor fisico o el mismo
    operador reutilizando material criptografico.
  - Claves publicas SSH identicas entre dominios distintos son una senal
    aun mas fuerte de infraestructura compartida.
  - Plantillas HTML casi identicas (fuzzy hashing con ssdeep) sugieren
    el mismo operador desplegando el mismo software/tema en varios sitios.

Todo el trafico de red de este modulo pasa por Tor (PySocks, mismo host/
puerto SOCKS que el resto del pipeline). Nunca se persiste el contenido
HTML completo: solo el hash difuso (ssdeep) y los metadatos derivados de
certificado/clave.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from typing import Optional
from urllib.parse import urlparse

import paramiko
import socks  # PySocks
import ppdeep as ssdeep  # mismo algoritmo, reimplementacion pura en Python (ver requirements.txt)
from cryptography import x509

import config
from src.artifact_extraction import extract_crypto_addresses, extract_pgp_key_hash
from src.html_artifact_extraction import extract_resource_links
from src.jarm_fingerprint import compute_jarm
from src.models import HtmlArtifactMention, InfrastructureLink, LeakEvidence, OnionRecord, ServiceEnumeration
from src.safe_mode import SafeModeFilter

logger = logging.getLogger(__name__)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/115.0"


def _connect_via_tor(address: str, port: int, timeout: float) -> "socks.socksocket":
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, config.TOR_SOCKS_HOST, config.TOR_SOCKS_PORT, rdns=True)
    sock.settimeout(timeout)
    sock.connect((address, port))
    return sock


def _read_response_body(sock, timeout: float, max_bytes: int) -> bytes:
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    total = 0
    while total < max_bytes:
        try:
            chunk = sock.recv(8192)
        except socket.timeout:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def _parse_certificate(der_bytes: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der_bytes)
    not_valid_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return {
        "sha256": hashlib.sha256(der_bytes).hexdigest(),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_valid_after": not_valid_after,
    }


def _extract_tls_and_content_sync(
    address: str, port: int = 443, timeout: float = config.TLS_HANDSHAKE_TIMEOUT
) -> tuple[Optional[dict], bytes]:
    """
    Una unica conexion TLS sirve para dos fugas a la vez: el certificado
    (aceptando autofirmados, habitual en hidden services) y el contenido
    para el fuzzy hash, evitando una segunda conexion redundante.
    """
    raw_sock = _connect_via_tor(address, port, timeout)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    tls_sock = ctx.wrap_socket(raw_sock, server_hostname=address)
    try:
        der_cert = tls_sock.getpeercert(binary_form=True)
        cert_info = _parse_certificate(der_cert) if der_cert else None

        request = (
            f"GET / HTTP/1.1\r\nHost: {address}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        )
        tls_sock.sendall(request.encode())
        body = _read_response_body(tls_sock, timeout, config.CONTENT_FUZZY_HASH_MAX_BYTES)
    finally:
        tls_sock.close()
    return cert_info, body


def _fetch_plain_http_sync(
    address: str, port: int = 80, timeout: float = config.TLS_HANDSHAKE_TIMEOUT
) -> bytes:
    sock = _connect_via_tor(address, port, timeout)
    try:
        request = (
            f"GET / HTTP/1.1\r\nHost: {address}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        )
        sock.sendall(request.encode())
        return _read_response_body(sock, timeout, config.CONTENT_FUZZY_HASH_MAX_BYTES)
    finally:
        sock.close()


def _extract_ssh_fingerprint_sync(
    address: str, port: int = 22, timeout: float = config.SSH_HANDSHAKE_TIMEOUT
) -> Optional[tuple[str, str]]:
    raw_sock = _connect_via_tor(address, port, timeout)
    transport = paramiko.Transport(raw_sock)
    try:
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        fingerprint = hashlib.sha256(key.asbytes()).hexdigest()
        return key.get_name(), fingerprint
    finally:
        transport.close()


def fuzzy_hash_content(raw_bytes: bytes) -> Optional[str]:
    if not raw_bytes:
        return None
    try:
        return ssdeep.hash(raw_bytes)
    except Exception as exc:
        logger.debug("Fallo calculando fuzzy hash (%r)", exc)
        return None


def _extract_identity_artifacts(body: bytes, evidence: LeakEvidence) -> None:
    """
    Extrae clave PGP y direcciones de criptomonedas a partir del MISMO
    contenido ya descargado para el fuzzy hash (nunca se vuelve a pedir
    la pagina). Actualiza `evidence` in-place; cualquier fallo de
    decodificacion o de regex se ignora de forma segura (no todos los
    dominios tienen texto en un formato reconocible, y eso no debe
    interrumpir el resto de la extraccion de evidencia).
    """
    if not body:
        return
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return
    evidence.pgp_key_hash = extract_pgp_key_hash(text)
    evidence.crypto_addresses = extract_crypto_addresses(text)


def _fetch_resource_and_hash_sync(url: str, timeout: float, max_bytes: int) -> Optional[str]:
    """
    Descarga UN recurso enlazado (JS/CSS/favicon/documento) a traves de
    Tor y devuelve su sha256. Solo se llama sobre URLs ya resueltas al
    mismo dominio onion que la pagina de origen (ver
    html_artifact_extraction.extract_resource_links). Nunca se persiste
    el contenido descargado, solo el hash.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"

    try:
        raw_sock = _connect_via_tor(host, port, timeout)
        if parsed.scheme == "https":
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock_obj = ctx.wrap_socket(raw_sock, server_hostname=host)
        else:
            sock_obj = raw_sock

        request = (
            f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n"
            "Connection: close\r\n\r\n"
        )
        sock_obj.sendall(request.encode())
        raw = _read_response_body(sock_obj, timeout, max_bytes)
        sock_obj.close()
    except Exception as exc:
        logger.debug("Fallo descargando recurso %s (%r)", url, exc)
        return None

    if not raw:
        return None
    separator = raw.find(b"\r\n\r\n")
    resource_body = raw[separator + 4:] if separator >= 0 else raw
    if not resource_body:
        return None
    return hashlib.sha256(resource_body).hexdigest()


async def _extract_html_artifacts(body: bytes, address: str, evidence: LeakEvidence) -> None:
    """
    Localiza los recursos enlazados en el HTML (JS/CSS/favicon/
    documentos, siempre del MISMO dominio) y descarga cada uno para
    calcular su hash. Concurrencia deliberadamente baja
    (config.HTML_ARTIFACT_CONCURRENCY): son peticiones EXTRA sobre las
    que ya hace el resto de F4 para el mismo dominio.
    """
    if not body:
        return
    try:
        text = body.decode("utf-8", errors="ignore")
    except Exception:
        return

    links_by_type = extract_resource_links(text, address)
    semaphore = asyncio.Semaphore(config.HTML_ARTIFACT_CONCURRENCY)
    mentions: list[HtmlArtifactMention] = []

    async def _fetch_one(artifact_type: str, url: str) -> None:
        async with semaphore:
            hash_value = await asyncio.to_thread(
                _fetch_resource_and_hash_sync, url,
                config.HTML_ARTIFACT_FETCH_TIMEOUT, config.HTML_ARTIFACT_MAX_BYTES,
            )
        if hash_value:
            mentions.append(HtmlArtifactMention(artifact_type=artifact_type, url=url, hash=hash_value))

    tasks = [
        _fetch_one(artifact_type, url)
        for artifact_type, urls in links_by_type.items()
        for url in urls
    ]
    if tasks:
        await asyncio.gather(*tasks)

    evidence.html_artifacts = mentions


async def extract_leak_evidence(
    record: OnionRecord,
    enumeration: ServiceEnumeration,
    safe_mode: SafeModeFilter | None = None,
) -> LeakEvidence:
    """
    Extrae evidencia de correlacion para un dominio, a partir del
    resultado de su enumeracion (F2): solo intenta TLS si el puerto 443
    aparecio abierto, solo intenta SSH si el 22 aparecio abierto. Esto
    evita repetir el escaneo de puertos: F4 reutiliza lo que F2 ya sabe.

    Defensa en profundidad: vuelve a comprobar safe-mode si se proporciona
    un filtro, igual que en enumerate_domain (ver src/enumeration.py).
    """
    if safe_mode is not None and safe_mode.is_blocked(record.address):
        logger.info(
            "extract_leak_evidence: direccion bloqueada por safe-mode, se omite (hash=%s)",
            safe_mode.hash_address(record.address),
        )
        return LeakEvidence(address=record.address)

    open_ports = {p.port for p in enumeration.open_ports}
    evidence = LeakEvidence(address=record.address)

    if 443 in open_ports:
        try:
            cert_info, body = await asyncio.to_thread(_extract_tls_and_content_sync, record.address, 443)
            if cert_info:
                evidence.tls_cert_sha256 = cert_info["sha256"]
                evidence.tls_cert_subject = cert_info["subject"]
                evidence.tls_cert_issuer = cert_info["issuer"]
                evidence.tls_cert_not_valid_after = cert_info["not_valid_after"]
            evidence.content_fuzzy_hash = fuzzy_hash_content(body)
            _extract_identity_artifacts(body, evidence)
            await _extract_html_artifacts(body, record.address, evidence)
        except Exception as exc:
            logger.debug("Fallo extrayendo TLS/contenido de %s (%r)", record.address, exc)

        # JARM es complementario al certificado, no un sustituto: identifica
        # la pila/configuracion TLS del servidor, no el material criptografico
        # concreto. Dos dominios pueden compartir JARM sin compartir
        # certificado (mismo software, distinto despliegue), asi que se
        # calcula siempre que haya HTTPS, independientemente de si la
        # extraccion del certificado ha tenido exito o no.
        try:
            evidence.jarm_hash = await compute_jarm(record.address, port=443)
        except Exception as exc:
            logger.debug("Fallo calculando JARM de %s (%r)", record.address, exc)
    elif 80 in open_ports:
        try:
            body = await asyncio.to_thread(_fetch_plain_http_sync, record.address, 80)
            evidence.content_fuzzy_hash = fuzzy_hash_content(body)
            _extract_identity_artifacts(body, evidence)
            await _extract_html_artifacts(body, record.address, evidence)
        except Exception as exc:
            logger.debug("Fallo extrayendo contenido HTTP de %s (%r)", record.address, exc)

    if 22 in open_ports:
        try:
            result = await asyncio.to_thread(_extract_ssh_fingerprint_sync, record.address, 22)
            if result:
                evidence.ssh_key_type, evidence.ssh_fingerprint_sha256 = result
        except Exception as exc:
            logger.debug("Fallo extrayendo fingerprint SSH de %s (%r)", record.address, exc)

    return evidence


async def extract_leak_evidence_batch(
    records_with_enum: list[tuple[OnionRecord, ServiceEnumeration]],
    safe_mode: SafeModeFilter | None = None,
) -> list[LeakEvidence]:
    semaphore = asyncio.Semaphore(config.CORRELATION_CONCURRENCY)

    async def _bounded(record: OnionRecord, enumeration: ServiceEnumeration) -> LeakEvidence:
        async with semaphore:
            return await extract_leak_evidence(record, enumeration, safe_mode=safe_mode)

    return await asyncio.gather(*(_bounded(r, e) for r, e in records_with_enum))


def _group_and_link(
    evidences: list[LeakEvidence], key_fn, relation_type: str
) -> list[InfrastructureLink]:
    groups: dict[str, list[str]] = {}
    for ev in evidences:
        key = key_fn(ev)
        if key:
            groups.setdefault(key, []).append(ev.address)

    links: list[InfrastructureLink] = []
    for key, addresses in groups.items():
        if len(addresses) < 2:
            continue
        # Topologia en estrella (cada dominio se enlaza solo con el
        # primero del grupo, no con TODOS los demas): O(k) en vez de
        # O(k^2). Sin este limite, un artefacto muy comun (ej. un
        # certificado autofirmado "por defecto" reutilizado por miles de
        # despliegues SIN relacion real entre si) genera un numero de
        # pares que crece cuadraticamente y puede agotar la memoria al
        # guardar el resultado (visto en produccion: un solo grupo de
        # ese tipo genero mas de 500.000 pares). No se pierde
        # informacion de conectividad: cualquier consulta practica
        # (¿que dominios comparten este artefacto?) solo necesita que
        # cada miembro aparezca al menos una vez, no todas las
        # combinaciones — que es ademas exactamente como se modela en
        # Neo4j (todos apuntan al mismo nodo compartido, no hay aristas
        # Onion-Onion directas para este tipo de relacion).
        if len(addresses) > 50:
            logger.warning(
                "Grupo inusualmente grande para '%s' (%d dominios comparten el mismo "
                "valor): probablemente un artefacto generico/por defecto, no una señal "
                "distintiva de operador compartido. Se enlaza en estrella igualmente.",
                relation_type, len(addresses),
            )
        hub = addresses[0]
        for other in addresses[1:]:
            links.append(InfrastructureLink(
                address_a=hub, address_b=other,
                relation_type=relation_type, evidence=key, confidence=1.0,
            ))
    return links


def _group_multi_valued_and_link(
    evidences: list[LeakEvidence], values_fn, relation_type: str
) -> list[InfrastructureLink]:
    """
    Igual que _group_and_link, pero para campos donde un dominio puede
    aportar VARIOS valores a la vez (por ejemplo, varias direcciones de
    criptomonedas en la misma pagina). Dos dominios quedan enlazados si
    comparten CUALQUIERA de sus valores, no solo si tienen un unico
    valor identico. Misma topologia en estrella que _group_and_link
    (ver su comentario), por el mismo motivo: evitar la explosion O(k^2)
    en grupos muy grandes.
    """
    groups: dict[str, list[str]] = {}
    for ev in evidences:
        for key in values_fn(ev):
            if key:
                groups.setdefault(key, []).append(ev.address)

    links: list[InfrastructureLink] = []
    for key, addresses in groups.items():
        addresses = list(dict.fromkeys(addresses))  # dedupe preservando orden
        if len(addresses) < 2:
            continue
        if len(addresses) > 50:
            logger.warning(
                "Grupo inusualmente grande para '%s' (%d dominios comparten el mismo "
                "valor): probablemente un artefacto generico/por defecto, no una señal "
                "distintiva de operador compartido. Se enlaza en estrella igualmente.",
                relation_type, len(addresses),
            )
        hub = addresses[0]
        for other in addresses[1:]:
            links.append(InfrastructureLink(
                address_a=hub, address_b=other,
                relation_type=relation_type, evidence=key, confidence=1.0,
                ))
    return links


def correlate(evidences: list[LeakEvidence]) -> list[InfrastructureLink]:
    """
    Agrupa evidencias por artefacto compartido y genera las aristas de
    correlacion que alimentaran el grafo de Neo4j (F5).

    Complejidad: la comparacion de similitud de contenido es O(n^2) sobre
    los dominios con fuzzy hash disponible, aceptable para las muestras
    manejadas durante el desarrollo del TFM. Para el dataset completo, la
    recomendacion (documentar en la memoria) es indexar por prefijo de
    bloque ssdeep para reducir el numero de comparaciones, en vez de
    comparar todos los pares.
    """
    links: list[InfrastructureLink] = []
    links += _group_and_link(evidences, lambda e: e.tls_cert_sha256, "shared_tls_cert")
    links += _group_and_link(evidences, lambda e: e.jarm_hash, "shared_jarm")
    links += _group_and_link(evidences, lambda e: e.ssh_fingerprint_sha256, "shared_ssh_key")
    links += _group_and_link(evidences, lambda e: e.pgp_key_hash, "shared_pgp_key")
    links += _group_multi_valued_and_link(
        evidences,
        lambda e: [f"{c.currency}:{c.address}" for c in e.crypto_addresses],
        "shared_crypto_address",
    )
    for artifact_type, relation_type in (
        ("javascript", "shared_javascript"),
        ("css", "shared_css"),
        ("favicon", "shared_favicon"),
        ("document", "shared_document"),
    ):
        links += _group_multi_valued_and_link(
            evidences,
            lambda e, t=artifact_type: [m.hash for m in e.html_artifacts if m.artifact_type == t],
            relation_type,
        )

    with_content = [e for e in evidences if e.content_fuzzy_hash]
    if len(with_content) > config.CONTENT_SIMILARITY_MAX_ITEMS:
        logger.warning(
            "Se omite la comparacion de similitud de contenido: %d dominios con "
            "fuzzy hash superan el limite configurado (%d). La comparacion por "
            "pares es O(n^2) y no escala a este tamaño. La correlacion por "
            "certificado y clave SSH compartidos (la señal mas fuerte de las "
            "tres) se mantiene intacta. Documentar como limitacion/trabajo "
            "futuro (ej. indexado LSH por prefijo ssdeep) en la memoria.",
            len(with_content), config.CONTENT_SIMILARITY_MAX_ITEMS,
        )
        return links

    for i in range(len(with_content)):
        for j in range(i + 1, len(with_content)):
            a, b = with_content[i], with_content[j]
            try:
                score = ssdeep.compare(a.content_fuzzy_hash, b.content_fuzzy_hash)
            except Exception:
                continue
            if score >= config.CONTENT_SIMILARITY_THRESHOLD:
                links.append(InfrastructureLink(
                    address_a=a.address, address_b=b.address,
                    relation_type="similar_content", evidence=f"ssdeep_score={score}",
                    confidence=score / 100,
                ))

    return links
