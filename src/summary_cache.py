"""
Cache de resumenes por hash de contenido (idea complementaria, no
solo una optimizacion de rendimiento). El proyecto real ya calcula un
hash del contenido de cada dominio para el fuzzy hashing (F4) - aqui se
reutiliza esa misma idea: si el contenido de la pagina es BYTE-IDENTICO
entre dos dominios (plantillas compartidas, mismo generador de
contenido - algo que ya hemos visto en el dataset real, ver F7), no
tiene sentido pagar dos veces el coste de generar el mismo resumen.

Guardado como JSON simple en disco: nada de sqlite ni dependencias
nuevas, solo lo necesario para una cache persistente y legible a mano.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Optional


def content_cache_key(plain_text: str) -> str:
    """
    Hash del TEXTO YA LIMPIO (no del HTML crudo): asi dos paginas con
    HTML ligeramente distinto pero el mismo texto visible (ej. solo
    cambia un comentario HTML o el orden de atributos) siguen
    compartiendo cache. Complementario al hash de fuzzy hashing del
    proyecto real (que opera sobre el HTML crudo), no un sustituto.
    """
    return hashlib.sha256(plain_text.encode("utf-8")).hexdigest()


class SummaryCache:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, str] = {}
        self.hits = 0
        self.misses = 0
        if self.path.exists():
            try:
                self._data = json.loads(self.path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, key: str) -> Optional[str]:
        value = self._data.get(key)
        if value is not None:
            self.hits += 1
        else:
            self.misses += 1
        return value

    def set(self, key: str, summary: str) -> None:
        self._data[key] = summary

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self._data, ensure_ascii=False, indent=2), encoding="utf-8")

    @property
    def size(self) -> int:
        return len(self._data)

    def stats(self) -> dict:
        total = self.hits + self.misses
        hit_rate = (self.hits / total) if total else 0.0
        return {"hits": self.hits, "misses": self.misses, "hit_rate": round(hit_rate, 3), "cached_entries": self.size}
