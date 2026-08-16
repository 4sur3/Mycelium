"""
Extraccion de artefactos de identidad del contenido HTML (F4, ampliacion
sobre OnionScan): claves PGP publicadas y direcciones de criptomonedas
mencionadas en la pagina.

Estas son señales de correlacion de identidad muy fuertes, en el mismo
espiritu que certificado/SSH compartidos: si dos dominios `.onion`
distintos publican la MISMA clave PGP o la MISMA direccion de wallet,
es evidencia directa de que los gestiona la misma persona/operador,
independientemente de que la infraestructura tecnica (servidor,
certificado) sea distinta.

Este modulo es puro: no hace ninguna peticion de red, solo procesa texto
ya descargado (reutiliza el HTML que ya se obtiene en
correlation.py para el fuzzy hashing de contenido, sin descargarlo de
nuevo).
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional

from src.models import CryptoAddressMention

# ---------------------------------------------------------------------------
# Claves PGP
# ---------------------------------------------------------------------------

_PGP_BLOCK_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)


def extract_pgp_key_hash(text: str) -> Optional[str]:
    """
    Busca un bloque de clave publica PGP armored en el texto y devuelve
    el sha256 de su contenido normalizado (todo el whitespace eliminado,
    para no depender de como el HTML haya envuelto las lineas).

    Si hay varios bloques en la misma pagina, se usa el primero: cubre
    el caso mas comun (una clave de contacto por sitio) sin complicar el
    modelo de datos con una lista para un caso poco frecuente.

    Limitacion documentada: esto detecta bloques armored IDENTICOS
    (mismo export), no compara las claves a nivel criptografico. Dos
    exports distintos de la misma clave con opciones de armor distintas
    no coincidirian. Suficiente para el caso comun de copiar/pegar el
    mismo bloque en varios sitios.
    """
    match = _PGP_BLOCK_RE.search(text)
    if not match:
        return None
    normalized = re.sub(r"\s+", "", match.group(0))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Direcciones de criptomonedas
# ---------------------------------------------------------------------------

_BTC_LEGACY_RE = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_BTC_BECH32_RE = re.compile(r"\bbc1[a-z0-9]{25,90}\b")
_XMR_RE = re.compile(r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _base58_decode(s: str) -> bytes:
    num = 0
    for char in s:
        idx = _BASE58_ALPHABET.find(char)
        if idx < 0:
            raise ValueError(f"Caracter fuera del alfabeto base58: {char!r}")
        num = num * 58 + idx
    n_bytes = max((num.bit_length() + 7) // 8, 1)
    combined = num.to_bytes(n_bytes, "big")
    n_leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * n_leading_zeros + combined


def _is_valid_btc_legacy(address: str) -> bool:
    """
    Verifica el checksum base58check real (doble SHA-256), no solo la
    forma del texto. Reduce falsos positivos frente a un regex suelto:
    una cadena aleatoria con la forma correcta solo pasa esta
    comprobacion por casualidad con probabilidad ~1 entre 4.000 millones.
    """
    try:
        decoded = _base58_decode(address)
    except (ValueError, OverflowError):
        return False
    if len(decoded) < 5:
        return False
    payload, checksum = decoded[:-4], decoded[-4:]
    expected = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return expected == checksum


def extract_crypto_addresses(text: str) -> list[CryptoAddressMention]:
    """
    Extrae direcciones de criptomonedas mencionadas en el texto.

    BTC (formato legacy) se valida con checksum base58check real. BTC
    bech32 y XMR se detectan solo por forma/longitud (sin verificar
    checksum: bech32 usa un codigo BCH y XMR un base58 de bloques de 8
    bytes, ambos mas complejos de validar sin dependencias adicionales),
    documentado como limitacion conocida - el riesgo de falso positivo
    se mitiga en la practica porque solo se usa para correlacion: una
    coincidencia exacta de la MISMA cadena entre DOS dominios distintos
    por puro azar es extremadamente improbable, aunque la cadena
    individual no se haya verificado criptograficamente.
    """
    found: list[CryptoAddressMention] = []
    seen: set[tuple[str, str]] = set()

    for match in _BTC_LEGACY_RE.finditer(text):
        address = match.group(0)
        if _is_valid_btc_legacy(address) and ("BTC", address) not in seen:
            seen.add(("BTC", address))
            found.append(CryptoAddressMention(currency="BTC", address=address))

    for match in _BTC_BECH32_RE.finditer(text):
        address = match.group(0)
        if ("BTC", address) not in seen:
            seen.add(("BTC", address))
            found.append(CryptoAddressMention(currency="BTC", address=address))

    for match in _XMR_RE.finditer(text):
        address = match.group(0)
        if ("XMR", address) not in seen:
            seen.add(("XMR", address))
            found.append(CryptoAddressMention(currency="XMR", address=address))

    for match in _ETH_RE.finditer(text):
        address = match.group(0)
        if ("ETH", address) not in seen:
            seen.add(("ETH", address))
            found.append(CryptoAddressMention(currency="ETH", address=address))

    return found
