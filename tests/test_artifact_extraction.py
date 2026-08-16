"""
Tests del modulo de extraccion de artefactos (PGP, direcciones de
criptomonedas). Puros, sin red: solo procesan texto en memoria.
"""

from src.artifact_extraction import (
    _is_valid_btc_legacy,
    extract_crypto_addresses,
    extract_pgp_key_hash,
)

# Direccion real del bloque genesis de Bitcoin (Satoshi Nakamoto), usada
# aqui unicamente como caso de prueba conocido y publico para verificar
# el checksum base58check, no como dato sensible de ningun tipo.
_REAL_BTC_ADDRESS = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"


def test_is_valid_btc_legacy_accepts_real_address():
    assert _is_valid_btc_legacy(_REAL_BTC_ADDRESS) is True


def test_is_valid_btc_legacy_rejects_altered_checksum():
    altered = _REAL_BTC_ADDRESS[:-1] + ("a" if _REAL_BTC_ADDRESS[-1] != "a" else "b")
    assert _is_valid_btc_legacy(altered) is False


def test_is_valid_btc_legacy_rejects_garbage():
    assert _is_valid_btc_legacy("no-es-una-direccion-bitcoin") is False


def test_extract_crypto_addresses_finds_valid_btc():
    text = f"Donaciones bienvenidas: {_REAL_BTC_ADDRESS}"
    results = extract_crypto_addresses(text)
    assert len(results) == 1
    assert results[0].currency == "BTC"
    assert results[0].address == _REAL_BTC_ADDRESS


def test_extract_crypto_addresses_rejects_invalid_btc_checksum():
    altered = _REAL_BTC_ADDRESS[:-1] + ("a" if _REAL_BTC_ADDRESS[-1] != "a" else "b")
    text = f"Direccion: {altered}"
    results = extract_crypto_addresses(text)
    assert results == []


def test_extract_crypto_addresses_finds_xmr():
    xmr = "47JLdZBgyup2KWnEbCrDVEE8CyRuNsMxGRviuS7yWnTgLHDN9WuYqrJVaU2Z1s2c7ZQD9vwqzKBCVMcdiK6WgQeCA9d61Ux"
    text = f"XMR: {xmr}"
    results = extract_crypto_addresses(text)
    assert len(results) == 1
    assert results[0].currency == "XMR"
    assert results[0].address == xmr


def test_extract_crypto_addresses_finds_eth():
    eth = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"
    text = f"ETH: {eth}"
    results = extract_crypto_addresses(text)
    assert len(results) == 1
    assert results[0].currency == "ETH"


def test_extract_crypto_addresses_dedupes_repeated_mentions():
    text = f"{_REAL_BTC_ADDRESS} ... mismo texto repetido: {_REAL_BTC_ADDRESS}"
    results = extract_crypto_addresses(text)
    assert len(results) == 1


def test_extract_crypto_addresses_returns_empty_for_plain_text():
    assert extract_crypto_addresses("Hola, esto es una pagina normal sin nada especial.") == []


def test_extract_pgp_key_hash_finds_block():
    text = """
    Contacto seguro, mi clave PGP:
    -----BEGIN PGP PUBLIC KEY BLOCK-----

    mQINBFtest1234567890ABCDEFabcdef
    ==ABCD
    -----END PGP PUBLIC KEY BLOCK-----
    Gracias por escribir.
    """
    result = extract_pgp_key_hash(text)
    assert result is not None
    assert len(result) == 64  # sha256 hexdigest


def test_extract_pgp_key_hash_ignores_whitespace_differences():
    """
    El mismo bloque, con distinto envoltorio de linea (como haria un
    navegador al renderizar HTML), debe dar el mismo hash.
    """
    block_a = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQINBFtest\n==ABCD\n-----END PGP PUBLIC KEY BLOCK-----"
    block_b = "-----BEGIN PGP PUBLIC KEY BLOCK-----   \n\n  mQINBFtest\n\n==ABCD  \n-----END PGP PUBLIC KEY BLOCK-----"
    assert extract_pgp_key_hash(block_a) == extract_pgp_key_hash(block_b)


def test_extract_pgp_key_hash_returns_none_when_absent():
    assert extract_pgp_key_hash("Pagina normal, sin ninguna clave PGP.") is None


def test_extract_pgp_key_hash_different_content_gives_different_hash():
    block_a = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nAAAA\n-----END PGP PUBLIC KEY BLOCK-----"
    block_b = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nBBBB\n-----END PGP PUBLIC KEY BLOCK-----"
    assert extract_pgp_key_hash(block_a) != extract_pgp_key_hash(block_b)
