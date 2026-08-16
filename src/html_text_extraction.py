"""
Extraccion de texto plano legible desde HTML, como paso previo a
resumir con un LLM local (F4, ampliacion opcional).

Igual que src/html_artifact_extraction.py en el proyecto real, usa
`html.parser` de la libreria estandar en vez de BeautifulSoup/lxml (esas
dependencias se quitaron del proyecto por romper la instalacion en
Python 3.14). Aqui el objetivo es distinto: no extraer enlaces, sino
quedarnos solo con el TEXTO que ve un visitante humano, descartando
scripts, estilos, y etiquetas - el tipo de entrada que un LLM pequeño
puede resumir razonablemente bien sin gastar contexto en marcado HTML.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser


class _TextExtractor(HTMLParser):
    """Acumula el texto visible, ignorando <script>/<style>/<noscript>."""

    _SKIP_TAGS = {"script", "style", "noscript", "template"}

    def __init__(self) -> None:
        super().__init__()
        self._skip_depth = 0
        self.chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in self._SKIP_TAGS:
            self._skip_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip_depth == 0 and data.strip():
            self.chunks.append(data.strip())


def html_to_plain_text(html_text: str, max_chars: int = 4000) -> str:
    """
    Convierte HTML a texto plano legible, colapsando espacios repetidos
    y recortando a `max_chars` (para no gastar de mas el contexto de un
    modelo pequeño, que suele tener una ventana reducida). El recorte es
    deliberadamente simple (por caracteres, no por tokens): un LLM local
    pequeño no necesita precision de tokenizer aqui, solo un limite
    razonable que evite entradas desproporcionadas.
    """
    parser = _TextExtractor()
    try:
        parser.feed(html_text)
    except Exception:
        pass  # HTML mal formado: mejor esfuerzo con lo que se haya parseado

    text = " ".join(parser.chunks)
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rsplit(" ", 1)[0] + "\u2026"
    return text


def is_worth_summarizing(plain_text: str, min_chars: int = 40) -> bool:
    """
    Filtro barato antes de gastar una llamada al LLM: paginas casi
    vacias (redirecciones, placeholders, errores de servidor) no
    aportan nada que resumir y solo desperdiciarian tiempo de computo.
    """
    return len(plain_text) >= min_chars
