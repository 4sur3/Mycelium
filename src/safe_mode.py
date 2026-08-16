"""
Filtro safe-mode.

Principio de diseno (ver README y config.py): este filtro se aplica ANTES
de encolar un dominio nuevo en el frontier del crawler y ANTES de persistir
cualquier contenido descargado. Nunca se descarga, renderiza ni almacena
el contenido de un dominio bloqueado; solo se registra su hash y la razon
del descarte, para poder auditar el proceso sin manejar el contenido en si.

Fuente del blocklist: Ahmia mantiene y publica un blocklist en forma de
hashes MD5 de direcciones onion conocidas por distribuir material de abuso
infantil (https://ahmia.fi/blacklist/). Usamos ese blocklist como primera
linea de defensa en lugar de construir un clasificador propio desde cero.

Este modulo NO expone ninguna forma de consultar si un hash concreto esta
en la lista de forma interactiva ni de listar el contenido del blocklist;
solo expone la funcion de filtrado agregada `is_blocked`.

TORIFICACION (importante, ver conversacion de verificacion):
El __init__ de SafeModeFilter NO hace ninguna llamada de red, ni siquiera
no torificada. Solo lee de cache local si existe. La actualizacion del
blocklist es SIEMPRE una accion explicita y separada:
  - `await refresh_via_tor(session)`      -> unico metodo usado en produccion,
                                              pasa por la sesion Tor del pipeline.
  - `download_blocklist_dev_no_tor()`     -> SOLO para desarrollo/tests sin Tor
                                              levantado. No se llama nunca de
                                              forma automatica ni implicita.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

import requests

import config
from src.models import OnionRecord, OnionStatus

logger = logging.getLogger(__name__)

if not config.SAFE_MODE:
    # Este modulo se niega a operar si alguien ha modificado config.py
    # para desactivar SAFE_MODE. No hay bypass de tiempo de ejecucion.
    raise RuntimeError(
        "SAFE_MODE esta desactivado en config.py. Este modulo requiere "
        "SAFE_MODE = True para poder importarse. Revisar config.py."
    )

DEV_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/115.0"


class SafeModeFilter:
    def __init__(self, cache_path: Path = config.BLOCKLIST_CACHE_PATH) -> None:
        self.cache_path = cache_path
        self._blocked_hashes: set[str] = set()
        self._blocklist_available: bool = False
        self._loaded_at: float | None = None
        self._load_from_cache_only()

    # -- carga (sin red) ----------------------------------------------------

    def _load_from_cache_only(self) -> None:
        """
        Unico paso que corre en el constructor. No hace ninguna peticion
        de red, ni siquiera al espejo clearnet: solo lee el fichero local
        de cache si existe. Actualizarlo es responsabilidad explicita de
        quien instancia el filtro (ver refresh_via_tor mas abajo).
        """
        if self.cache_path.exists():
            self._blocked_hashes = set(
                line.strip().lower()
                for line in self.cache_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            )
            self._blocklist_available = True
            self._loaded_at = self.cache_path.stat().st_mtime
            logger.info("Blocklist cargado desde cache: %d hashes", len(self._blocked_hashes))
        else:
            # Fail-closed real: is_blocked() bloqueara TODO hasta que se
            # cargue un blocklist real via refresh_via_tor (ver el bug
            # detectado y corregido: un set vacio NO es fail-closed, hay
            # que comprobar _blocklist_available explicitamente).
            self._blocklist_available = False
            logger.error(
                "No hay blocklist en cache (%s). El filtro bloqueara TODAS "
                "las direcciones hasta llamar a refresh_via_tor(session).",
                self.cache_path,
            )

    def needs_refresh(self) -> bool:
        if not self._blocklist_available or self._loaded_at is None:
            return True
        age_hours = (time.time() - self._loaded_at) / 3600
        return age_hours > config.BLOCKLIST_MAX_AGE_HOURS

    # -- refresco torificado (produccion) ------------------------------------

    async def refresh_via_tor(self, session) -> None:
        """
        Descarga el blocklist a traves de la sesion Tor proporcionada
        (ver src/tor_client.create_tor_session). Este es el UNICO metodo
        de refresco usado en produccion: toda peticion de red del sistema
        pasa por Tor sin excepcion, incluida esta. DiscoveryPipeline llama
        a esto antes de procesar ningun dominio (ver src/crawler.py).
        """
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        async with session.get(
            config.AHMIA_BLOCKLIST_ONION_URL, timeout=config.REQUEST_TIMEOUT_SECONDS
        ) as resp:
            resp.raise_for_status()
            text = await resp.text()

        self.cache_path.write_text(text, encoding="utf-8")
        self._blocked_hashes = set(line.strip().lower() for line in text.splitlines() if line.strip())
        self._blocklist_available = True
        self._loaded_at = time.time()
        logger.info(
            "Blocklist de Ahmia descargado via Tor y cacheado en %s (%d hashes)",
            self.cache_path, len(self._blocked_hashes),
        )

    # -- refresco NO torificado, solo desarrollo/tests -----------------------

    def download_blocklist_dev_no_tor(self) -> None:
        """
        ATENCION: este metodo NO pasa por Tor. Existe unicamente para
        desarrollo local rapido y para tests que no quieren depender de
        un Tor activo. Nunca se llama automaticamente desde __init__ ni
        desde ningun otro punto del pipeline de produccion.

        Si necesitas refrescar el blocklist en un entorno real, usa
        `await refresh_via_tor(session)`.
        """
        headers = {"User-Agent": DEV_USER_AGENT}
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        response = requests.get(
            config.AHMIA_BLOCKLIST_URL, headers=headers, timeout=config.REQUEST_TIMEOUT_SECONDS
        )
        response.raise_for_status()
        self.cache_path.write_text(response.text, encoding="utf-8")
        self._blocked_hashes = set(
            line.strip().lower() for line in response.text.splitlines() if line.strip()
        )
        self._blocklist_available = True
        self._loaded_at = time.time()
        logger.warning(
            "Blocklist descargado SIN Tor (download_blocklist_dev_no_tor, "
            "solo para desarrollo) y cacheado en %s", self.cache_path
        )

    # -- filtrado -------------------------------------------------------------

    @staticmethod
    def hash_address(onion_address: str) -> str:
        normalized = OnionRecord.normalize(onion_address)
        if not normalized.endswith(".onion"):
            normalized = f"{normalized}.onion"
        return hashlib.md5(normalized.encode("utf-8")).hexdigest()

    def is_blocked(self, onion_address: str) -> bool:
        """
        Punto de entrada unico del filtro. Debe llamarse:
          1. Antes de encolar una URL nueva descubierta por el parser.
          2. Antes de persistir cualquier registro en el dataset.

        Si no hay blocklist disponible, devuelve True para CUALQUIER
        direccion: fail-closed real. La alternativa (dejar pasar todo
        cuando no se pudo verificar nada) es exactamente el fallo de
        seguridad que este diseño existe para evitar.

        Nunca devuelve el motivo detallado del bloqueo en un log accesible
        junto al contenido; solo el hash, para permitir auditoria sin
        reconstruir la direccion original a partir de los logs.
        """
        if not self._blocklist_available:
            return True
        return self.hash_address(onion_address) in self._blocked_hashes

    def filter_record(self, record: OnionRecord) -> OnionRecord:
        """
        Aplica el filtro sobre un OnionRecord y devuelve el registro
        actualizado. Si el dominio esta bloqueado, se marca con
        OnionStatus.BLOCKED y no se debe procesar mas adelante en el
        pipeline (ni enumeracion, ni correlacion, ni visualizacion).
        """
        if self.is_blocked(record.address):
            record.status = OnionStatus.BLOCKED
            logger.info(
                "Dominio descartado por safe-mode (hash=%s)",
                self.hash_address(record.address),
            )
        return record
