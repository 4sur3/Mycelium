"""
Extraccion de enlaces a recursos del HTML (F4, ampliacion tipo
urlscan.io): JavaScript, CSS, favicon y documentos enlazados desde una
pagina. Este modulo es puro (no hace red, solo analiza texto HTML ya
descargado) y deliberadamente usa `html.parser` de la libreria estandar
en vez de BeautifulSoup/lxml: esas dependencias se quitaron del
proyecto por romper la instalacion en Python 3.14 (ver requirements.txt),
y aqui no hace falta un parser completo, solo extraer un puñado de
atributos de unas pocas etiquetas.

Solo se resuelven enlaces al MISMO dominio .onion que la pagina de
origen; los enlaces a dominios externos se descartan (no se amplia la
superficie de red a hosts no verificados fuera del propio dataset).
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import config

_DOCUMENT_EXTENSION_RE = re.compile(r"\.(pdf|docx?|xlsx?|zip)(\?|#|$)", re.IGNORECASE)


class _ResourceLinkParser(HTMLParser):
    """Extrae los atributos relevantes de <script>, <link> y <a>."""

    def __init__(self) -> None:
        super().__init__()
        self.scripts: list[str] = []
        self.stylesheets: list[str] = []
        self.icons: list[str] = []
        self.doc_links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {k: v for k, v in attrs if v is not None}
        if tag == "script" and attrs_dict.get("src"):
            self.scripts.append(attrs_dict["src"])
        elif tag == "link":
            rel = attrs_dict.get("rel", "").lower()
            href = attrs_dict.get("href")
            if href and "stylesheet" in rel:
                self.stylesheets.append(href)
            elif href and "icon" in rel:
                self.icons.append(href)
        elif tag == "a":
            href = attrs_dict.get("href")
            if href and _DOCUMENT_EXTENSION_RE.search(href):
                self.doc_links.append(href)


def _resolve_same_origin(base_url: str, base_host: str, links: list[str], limit: int) -> list[str]:
    resolved: list[str] = []
    seen: set[str] = set()
    for href in links:
        try:
            absolute = urljoin(base_url, href)
        except ValueError:
            continue
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        if parsed.netloc and parsed.netloc != base_host:
            continue  # dominio externo, se descarta a proposito
        if absolute in seen:
            continue
        seen.add(absolute)
        resolved.append(absolute)
        if len(resolved) >= limit:
            break
    return resolved


def extract_resource_links(html_text: str, base_address: str) -> dict[str, list[str]]:
    """
    Devuelve, agrupadas por tipo, las URLs absolutas (mismo dominio) de
    los recursos enlazados desde el HTML: javascript, css, favicon,
    document. Si no hay ningun <link rel="icon"> explicito, se anade
    como candidato la ruta convencional /favicon.ico (muchos sitios lo
    sirven ahi aunque no lo declaren en el HTML).
    """
    parser = _ResourceLinkParser()
    try:
        parser.feed(html_text)
    except Exception:
        pass  # HTML mal formado: mejor esfuerzo con lo que se haya parseado

    base_url = f"http://{base_address}/"
    limit = config.HTML_ARTIFACT_MAX_PER_TYPE

    favicons = _resolve_same_origin(base_url, base_address, parser.icons, limit=1)
    if not favicons:
        favicons = [urljoin(base_url, "/favicon.ico")]

    return {
        "javascript": _resolve_same_origin(base_url, base_address, parser.scripts, limit),
        "css": _resolve_same_origin(base_url, base_address, parser.stylesheets, limit),
        "favicon": favicons,
        "document": _resolve_same_origin(base_url, base_address, parser.doc_links, limit),
    }
