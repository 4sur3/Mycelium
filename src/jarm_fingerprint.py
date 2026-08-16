"""
Fingerprinting JARM (F4, complementario al certificado TLS).

JARM identifica la PILA/CONFIGURACION TLS de un servidor (version,
orden de cifrados, extensiones), a diferencia del certificado, que
identifica al servidor por su material criptografico concreto. Son
señales complementarias, no redundantes: dos dominios con certificados
TOTALMENTE DISTINTOS pueden compartir JARM si corren el mismo software
con la misma configuracion (mismo operador desplegando con la misma
imagen de servidor o el mismo script de aprovisionamiento) - una
correlacion que shared_tls_cert no puede detectar por si sola.

Este modulo reutiliza pyJARM (implementacion oficial de Palo Alto
Networks) para la construccion de los 10 paquetes ClientHello y el
hashing/parseo de la respuesta - la parte delicada a nivel de protocolo
y criptografia, igual que se reutiliza `cryptography` para certificados
y `paramiko` para SSH en vez de reimplementarlos.

Lo que NO se reutiliza es la capa de transporte de pyJARM: su modulo de
proxy (jarm.proxy.proxy) solo soporta proxies HTTP/HTTPS via CONNECT,
no SOCKS5. Usarla tal cual habria roto la torificacion completa del
proyecto. En su lugar, cada una de las 10 sondas se envia a traves de
un socket propio via PySocks (mismo patron que src/correlation.py), y
los bytes de respuesta se entregan a las funciones de parseo/hashing
de pyJARM sin modificarlas.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import socks  # PySocks
from jarm.constants import TOTAL_FAILURE
from jarm.hashing.hashing import Hasher
from jarm.scanner.scanner import Scanner

import config

logger = logging.getLogger(__name__)

# Hash que devuelve Hasher.jarm() cuando las 10 sondas fallan (ver
# jarm.constants.TOTAL_FAILURE). Se usa para distinguir "no se pudo
# calcular JARM" (debe guardarse como None) de un hash real: tratar
# "0"*62 como si fuera un hash valido crearia una correlacion falsa
# entre cualquier par de dominios donde las sondas fallaran por
# completo, que no tiene nada que ver con compartir infraestructura.
_TOTAL_FAILURE_HASH = "0" * 62


def _probe_via_tor_sync(address: str, port: int, packet: bytes, timeout: float) -> Optional[bytes]:
    """
    Envia un unico paquete ClientHello de JARM a traves de Tor y
    devuelve la respuesta cruda (hasta 1484 bytes, mismo tamaño que usa
    pyJARM internamente). None si la conexion o el envio fallan; esto
    es un resultado esperado y frecuente (timeouts, el servidor cierra
    la conexion en according a como responde a cada sonda concreta), no
    una condicion de error a propagar.
    """
    sock_obj = socks.socksocket()
    sock_obj.set_proxy(socks.SOCKS5, config.TOR_SOCKS_HOST, config.TOR_SOCKS_PORT, rdns=True)
    sock_obj.settimeout(timeout)
    try:
        sock_obj.connect((address, port))
        sock_obj.sendall(packet)
        return sock_obj.recv(1484)
    except Exception as exc:
        logger.debug("Sonda JARM fallo para %s:%d (%r)", address, port, exc)
        return None
    finally:
        sock_obj.close()


async def compute_jarm(
    address: str,
    port: int = 443,
    timeout: float = config.JARM_PROBE_TIMEOUT,
    concurrency: int = config.JARM_PROBE_CONCURRENCY,
) -> Optional[str]:
    """
    Calcula el hash JARM (62 caracteres) de un dominio, enviando las 10
    sondas de pyJARM a traves de Tor con concurrencia acotada.

    Devuelve None si las 10 sondas fallan (en vez del hash "0"*62 que
    pyJARM devolveria internamente en ese caso), para poder distinguir
    con claridad "no se pudo calcular" de un hash real en LeakEvidence
    y en la correlacion posterior.
    """
    packet_tuples = Scanner._generate_packets(dest_host=address, dest_port=port)
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded_probe(packet_bytes: bytes) -> Optional[bytes]:
        async with semaphore:
            return await asyncio.to_thread(_probe_via_tor_sync, address, port, packet_bytes, timeout)

    responses = await asyncio.gather(*(_bounded_probe(pkt) for _, pkt in packet_tuples))

    parsed = [
        Scanner._parse_server_hello(response, (format_name, packet_bytes))
        for (format_name, packet_bytes), response in zip(packet_tuples, responses)
    ]

    raw_result = ",".join(parsed)
    jarm_hash = Hasher.jarm(raw_result)

    if jarm_hash == _TOTAL_FAILURE_HASH or raw_result == TOTAL_FAILURE:
        return None
    return jarm_hash
