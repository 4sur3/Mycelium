"""
Orquestador principal del modulo Discovery (F1 del plan de trabajo).

Flujo (ver diagrama de arquitectura):
  fuentes semilla -> frontier -> fetcher via Tor -> parser de enlaces
  -> [safe_mode.filter_record] -> dedupe/liveness -> dataset fechado

Este fichero es un esqueleto funcional: la orquestacion de alto nivel y
los puntos de integracion estan completos y documentados; el fetcher
async completo con aiohttp-socks se implementa en la siguiente iteracion
(ver README, seccion "Estado actual").
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, timezone
from pathlib import Path

import config
from src.models import OnionRecord, OnionStatus
from src.safe_mode import SafeModeFilter
from src.seeds.ahmia import AhmiaSource
from src.seeds.base import SeedSource

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


class DiscoveryPipeline:
    def __init__(self, sources: list[SeedSource] | None = None) -> None:
        self.sources = sources or [AhmiaSource()]
        # El filtro safe-mode se instancia una vez, aqui, en el punto mas
        # alto del pipeline. No se instancia mas adelante en el codigo:
        # cualquier registro que llegue a las fases posteriores ya ha
        # pasado por aqui.
        self.safe_mode = SafeModeFilter()
        self.registry: dict[str, OnionRecord] = {}

    async def run(self, session) -> list[OnionRecord]:
        # Refresco explicito y torificado del blocklist ANTES de procesar
        # cualquier dominio. El constructor de SafeModeFilter no hace
        # ninguna llamada de red por si solo (ver src/safe_mode.py); si
        # esto falla y no hay cache previa, is_blocked() bloqueara todo
        # (fail-closed real), lo cual es el comportamiento correcto aunque
        # sea menos util que tener el blocklist cargado.
        if self.safe_mode.needs_refresh():
            try:
                await self.safe_mode.refresh_via_tor(session)
            except Exception as exc:
                logger.warning(
                    "No se pudo refrescar el blocklist via Tor (%r). "
                    "Se usara la copia en cache si existe; si no existe, "
                    "el filtro bloqueara todo (fail-closed).", exc
                )

        for source in self.sources:
            logger.info("Consultando fuente semilla: %s", source.name)
            alive = await source.is_alive(session)
            logger.info("Fuente %s viva: %s", source.name, alive)
            if not alive:
                continue

            raw_addresses = await source.fetch_listing(session)
            logger.info("Fuente %s devolvio %d direcciones candidatas", source.name, len(raw_addresses))
            records = source.to_records(raw_addresses)

            for record in records:
                self._ingest(record)

        self._liveness_pass(session)
        return list(self.registry.values())

    def _ingest(self, record: OnionRecord) -> None:
        """
        Aplica el filtro safe-mode ANTES de deduplicar o persistir. Un
        dominio bloqueado se cuenta a efectos de auditoria (solo el hash,
        ver safe_mode.py) pero nunca entra en self.registry con contenido.
        """
        record = self.safe_mode.filter_record(record)
        if record.status == OnionStatus.BLOCKED:
            return  # descartado, no se persiste

        existing = self.registry.get(record.address)
        if existing is None:
            self.registry[record.address] = record
        else:
            for source_name in record.discovered_via:
                existing.add_source(source_name)

    def _liveness_pass(self, session) -> None:
        """
        Esta fase de F1 NO hace la comprobacion de vida real: hacerlo aqui,
        contra todo el dataset (potencialmente miles de dominios) antes de
        enumeracion, duplicaria trabajo de red innecesariamente. La
        comprobacion real (conexion TCP efectiva a un puerto comun) ocurre
        en F2 (src/enumeration.py, enumerate_domain), que ya la necesita
        de todas formas para decidir si escanear el resto de puertos, y es
        ahi donde se actualiza OnionRecord.status a ALIVE/DEAD.

        Aqui solo se deja constancia de que el registro sigue pendiente de
        esa verificacion (permanece en UNKNOWN hasta que F2 lo procese).
        """
        for record in self.registry.values():
            record.last_checked = datetime.now(timezone.utc)
            if record.status == OnionStatus.UNKNOWN:
                logger.debug("Pendiente de liveness check real (se resuelve en F2): %s", record.address)

    def save_snapshot(self, tag: str | None = None) -> Path:
        """
        Persiste el dataset como snapshot inmutable y fechado, tal como
        exige el enunciado ("un set de dominios onion en una fecha
        concreta"). El nombre de fichero incluye la fecha para que
        snapshots sucesivos permitan comparar supervivencia de
        infraestructura en el tiempo.
        """
        tag = tag or config.DATASET_TAG
        today = date.today().isoformat()
        config.DATA_DIR.mkdir(parents=True, exist_ok=True)
        out_path = config.DATA_DIR / f"{tag}_{today}.json"

        payload = [json.loads(r.model_dump_json()) for r in self.registry.values()]
        out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        logger.info("Snapshot guardado: %s (%d dominios)", out_path, len(payload))
        return out_path
