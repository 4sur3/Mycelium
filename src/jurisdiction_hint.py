"""
Extraccion de una PISTA de jurisdiccion/pais a partir de datos que YA
estan guardados en el checkpoint (subject/issuer del certificado TLS,
titulo HTTP) - nunca requiere volver a descargar nada, ni Tor ni un LLM.

Nombrado deliberadamente "hint" (pista), no "location" (ubicacion): Tor
esta diseñado precisamente para que la ubicacion de red real de un
servicio onion nunca sea determinable por medios legitimos, y nada de lo
que hace este modulo cambia eso. Lo que SI puede pasar es que el propio
operador filtre, sin querer, una pista de jurisdiccion - el ejemplo real
de este dataset es un certificado autofirmado con
"O=Jonavos Policijos Komisariatas,L=Jonava,C=LT" (comisaria de policia
lituana). Esto es, como mucho, un descuido del operador - una señal
DEBIL, del mismo tipo que ya se documenta para artefactos genericos en
correlation.py, nunca una prueba.

Jerarquia de fiabilidad de las dos fuentes (coherente con el resto del
proyecto): el campo C= de un certificado es un campo formal de un
estandar (X.509 Distinguished Name), mas fiable que una coincidencia de
palabra clave en un titulo HTTP en texto libre. Por eso el certificado
tiene prioridad cuando ambas fuentes estan disponibles.
"""

from __future__ import annotations

import re
from typing import NamedTuple, Optional


class JurisdictionHint(NamedTuple):
    country_code: str  # ISO 3166-1 alpha-2
    country_name: str
    lat: float
    lng: float
    source: str  # "tls_cert" o "http_title" - de donde vino la pista


# Coordenadas aproximadas (centroide/capital) para un subconjunto de
# paises. No cubre los ~195 paises del mundo - se amplia sobre la marcha
# si aparece un codigo nuevo en el dataset real que no este aqui.
COUNTRY_DATA: dict[str, tuple[str, float, float]] = {
    "US": ("Estados Unidos", 39.8, -98.6),
    "GB": ("Reino Unido", 55.4, -3.4),
    "DE": ("Alemania", 51.2, 10.4),
    "FR": ("Francia", 46.6, 2.2),
    "ES": ("España", 40.5, -3.7),
    "IT": ("Italia", 42.5, 12.6),
    "PT": ("Portugal", 39.6, -8.0),
    "NL": ("Países Bajos", 52.1, 5.3),
    "BE": ("Bélgica", 50.6, 4.5),
    "CH": ("Suiza", 46.8, 8.2),
    "AT": ("Austria", 47.6, 14.6),
    "SE": ("Suecia", 62.2, 15.6),
    "NO": ("Noruega", 64.6, 11.0),
    "DK": ("Dinamarca", 56.1, 9.5),
    "FI": ("Finlandia", 63.2, 25.7),
    "IE": ("Irlanda", 53.2, -8.0),
    "PL": ("Polonia", 51.9, 19.4),
    "CZ": ("Chequia", 49.8, 15.5),
    "SK": ("Eslovaquia", 48.7, 19.5),
    "HU": ("Hungría", 47.2, 19.5),
    "RO": ("Rumanía", 45.9, 24.9),
    "BG": ("Bulgaria", 42.7, 25.5),
    "GR": ("Grecia", 39.1, 21.8),
    "LT": ("Lituania", 55.2, 23.9),
    "LV": ("Letonia", 56.9, 24.6),
    "EE": ("Estonia", 58.6, 25.0),
    "UA": ("Ucrania", 48.4, 31.2),
    "RU": ("Rusia", 61.5, 105.3),
    "BY": ("Bielorrusia", 53.7, 27.9),
    "MD": ("Moldavia", 47.4, 28.4),
    "IS": ("Islandia", 64.9, -19.0),
    "LU": ("Luxemburgo", 49.8, 6.1),
    "MT": ("Malta", 35.9, 14.4),
    "CY": ("Chipre", 35.1, 33.4),
    "TR": ("Turquía", 38.9, 35.2),
    "CA": ("Canadá", 56.1, -106.3),
    "MX": ("México", 23.6, -102.5),
    "BR": ("Brasil", -14.2, -51.9),
    "AR": ("Argentina", -38.4, -63.6),
    "CL": ("Chile", -35.7, -71.5),
    "CO": ("Colombia", 4.6, -74.3),
    "CN": ("China", 35.9, 104.2),
    "JP": ("Japón", 36.2, 138.3),
    "KR": ("Corea del Sur", 35.9, 127.8),
    "IN": ("India", 20.6, 79.0),
    "AU": ("Australia", -25.3, 133.8),
    "NZ": ("Nueva Zelanda", -40.9, 174.9),
    "ZA": ("Sudáfrica", -30.6, 22.9),
    "NG": ("Nigeria", 9.1, 8.7),
    "EG": ("Egipto", 26.8, 30.8),
    "IL": ("Israel", 31.0, 34.9),
    "SA": ("Arabia Saudí", 23.9, 45.1),
    "AE": ("Emiratos Árabes Unidos", 23.4, 53.8),
    "SG": ("Singapur", 1.4, 103.8),
    "HK": ("Hong Kong", 22.3, 114.2),
    "TW": ("Taiwán", 23.7, 121.0),
    "VN": ("Vietnam", 14.1, 108.3),
    "TH": ("Tailandia", 15.9, 100.99),
    "ID": ("Indonesia", -0.8, 113.9),
    "PH": ("Filipinas", 12.9, 121.8),
    "PK": ("Pakistán", 30.4, 69.3),
}

# Campo C= (pais) dentro de un Distinguished Name X.509, ej:
# "CN=example.onion,O=Org,L=Ciudad,C=LT" -> "LT"
_CERT_COUNTRY_RE = re.compile(r"(?:^|,)\s*C=([A-Z]{2})(?:,|$)")


def extract_country_from_cert_subject(subject: Optional[str]) -> Optional[str]:
    """Busca el campo C= (pais) en un subject/issuer X.509. Solo cuenta
    si el codigo esta en COUNTRY_DATA (evita codigos invalidos/no-ISO
    que a veces aparecen en certificados autofirmados de pruebas)."""
    if not subject:
        return None
    match = _CERT_COUNTRY_RE.search(subject)
    if not match:
        return None
    code = match.group(1)
    return code if code in COUNTRY_DATA else None


# Palabras clave DEBILES de jurisdiccion en el titulo HTTP. Lista corta
# a proposito: cuantas mas palabras, mas falsos positivos en una señal
# que ya es de por si la mas debil de las dos. Pensada para capturar
# el caso real observado (entidades gubernamentales/policiales que
# revelan su pais en el propio titulo), no para detectar idioma en
# general.
TITLE_KEYWORDS: dict[str, str] = {
    "polizei": "DE",
    "bundeskriminalamt": "DE",
    "policia": "ES",
    "policía": "ES",
    "komisariatas": "LT",
    "politie": "NL",
    "gendarmerie": "FR",
    "carabinieri": "IT",
    "polizia": "IT",
    "politia": "RO",
    "policie": "CZ",
}


def extract_country_hint_from_title(title: Optional[str]) -> Optional[str]:
    """Busqueda de palabras clave debiles en el titulo HTTP. Devuelve la
    PRIMERA coincidencia encontrada (orden de TITLE_KEYWORDS)."""
    if not title:
        return None
    lowered = title.lower()
    for keyword, code in TITLE_KEYWORDS.items():
        if keyword in lowered:
            return code
    return None


def resolve_jurisdiction(
    tls_cert_subject: Optional[str],
    tls_cert_issuer: Optional[str],
    http_title: Optional[str],
) -> Optional[JurisdictionHint]:
    """
    Combina las fuentes disponibles, con el certificado (subject, y si
    no, issuer) por delante del titulo HTTP, siguiendo la jerarquia de
    fiabilidad documentada arriba. Devuelve None si ninguna fuente da
    una pista reconocida.
    """
    code = extract_country_from_cert_subject(tls_cert_subject)
    source = "tls_cert"
    if not code:
        code = extract_country_from_cert_subject(tls_cert_issuer)
        source = "tls_cert"
    if not code:
        code = extract_country_hint_from_title(http_title)
        source = "http_title"
    if not code:
        return None

    name, lat, lng = COUNTRY_DATA[code]
    return JurisdictionHint(country_code=code, country_name=name, lat=lat, lng=lng, source=source)
