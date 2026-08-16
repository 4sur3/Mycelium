"""
Adapter de Ahmia.

Ahmia es la fuente semilla de mayor confianza del proyecto: aplica
moderacion propia y publica dos endpoints utiles (ver conversacion):
  - /onions/   listado de dominios no baneados conocidos
  - /banned/   blocklist de hashes MD5 usado directamente por
               src/safe_mode.py

Este adapter solo se ocupa del listado; la descarga del blocklist vive en
safe_mode.py porque es una responsabilidad transversal, no especifica de
esta fuente semilla.
"""

from __future__ import annotations

import logging
import re

from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
import aiohttp

import config
from src.seeds.base import SeedSource

logger = logging.getLogger(__name__)

ONION_ADDRESS_RE = re.compile(r"[a-z2-7]{56}\.onion", re.IGNORECASE)

# El primer intento de conexion a un hidden service falla con relativa
# frecuencia (establecer el circuito de rendezvous via introduction points
# tarda mas y es menos fiable que una conexion clearnet normal). Esto es
# comportamiento esperado de Tor, no un fallo de configuracion: por eso
# se reintenta en vez de asumir que el servicio esta caido al primer fallo.
onion_retry = retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=2, max=10),
    retry=retry_if_exception_type((aiohttp.ClientError, TimeoutError)),
    reraise=True,
)


class AhmiaSource(SeedSource):
    name = "ahmia"
    has_direct_listing = True

    # Se define tanto la version clearnet como la onion. Para el crawling
    # de produccion usar siempre la version onion (via Tor); la clearnet
    # sirve como fallback de verificacion rapida durante desarrollo.
    onion_url = f"http://{config.AHMIA_ONION_ADDRESS}/onions/"
    clearnet_url = config.AHMIA_ONIONS_URL

    @onion_retry
    async def _get(self, session, url: str, timeout: float):
        async with session.get(url, timeout=timeout) as resp:
            resp.raise_for_status()
            return await resp.text(), resp.status

    async def fetch_listing(self, session) -> list[str]:
        """
        Descarga el listado de /onions/ y extrae todas las direcciones
        onion v3 presentes en el HTML. Ahmia no pagina este endpoint de
        forma compleja, pero se deja el bucle preparado por si el formato
        cambia a paginacion en el futuro.
        """
        addresses: set[str] = set()
        try:
            html, _ = await self._get(session, self.onion_url, config.REQUEST_TIMEOUT_SECONDS)
            addresses.update(m.group(0).lower() for m in ONION_ADDRESS_RE.finditer(html))
        except Exception as exc:
            logger.warning("Fallo al obtener el listado de Ahmia tras reintentos (%r)", exc)
        return sorted(addresses)

    async def is_alive(self, session) -> bool:
        try:
            _, status = await self._get(session, self.onion_url, config.CONNECT_TIMEOUT_SECONDS)
            return status == 200
        except Exception as exc:
            logger.warning("Ahmia is_alive fallo tras reintentos: %r", exc)
            return False
