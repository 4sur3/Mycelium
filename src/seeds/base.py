"""
Patron adapter para fuentes semilla, ver discusion en la conversacion sobre
por que un scraper monolitico se rompe en cuanto una fuente cambia de
estructura o de direccion.

Cada fuente semilla implementa esta interfaz. El crawler solo conoce
SeedSource, nunca los detalles de Ahmia, Tor66, etc.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.models import OnionRecord


class SeedSource(ABC):
    #: nombre corto, estable, usado como valor en OnionRecord.discovered_via
    name: str

    #: True si esta fuente tiene un listado navegable (ej. Ahmia /onions/);
    #: False si solo acepta queries de busqueda (ej. motores tipo Torch,
    #: que requieren lanzar terminos genericos para forzar resultados)
    has_direct_listing: bool = True

    @abstractmethod
    async def fetch_listing(self, session) -> list[str]:
        """
        Devuelve una lista de direcciones .onion (sin normalizar) obtenidas
        de esta fuente. Para fuentes sin listado directo, debe internamente
        lanzar un conjunto de queries genericas y agregar los resultados.
        """
        raise NotImplementedError

    @abstractmethod
    async def is_alive(self, session) -> bool:
        """
        Chequeo rapido de que la fuente sigue operativa. Se usa para
        registrar en el dataset que fuentes estaban vivas en la fecha
        del snapshot (dato de interes para el analisis de mortalidad
        de motores de busqueda onion, ver memoria).
        """
        raise NotImplementedError

    def to_records(self, addresses: list[str]) -> list[OnionRecord]:
        records = []
        for raw in addresses:
            normalized = OnionRecord.normalize(raw)
            if not normalized.endswith(".onion"):
                continue
            record = OnionRecord(address=normalized)
            record.add_source(self.name)
            records.append(record)
        return records
