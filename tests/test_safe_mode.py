"""
Tests del filtro safe-mode. Usa un blocklist de prueba local (nunca el
blocklist real de produccion) con hashes de direcciones ficticias, para
poder validar la logica de bloqueo sin manejar datos sensibles reales.
"""

import hashlib

import pytest

import config
from src.models import OnionRecord
from src.safe_mode import SafeModeFilter

FAKE_BLOCKED_ADDRESS = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuv.onion"
FAKE_ALLOWED_ADDRESS = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz.onion"


@pytest.fixture
def filter_with_fake_blocklist(tmp_path, monkeypatch):
    fake_cache = tmp_path / "fake_blocklist.txt"
    fake_hash = hashlib.md5(FAKE_BLOCKED_ADDRESS.encode("utf-8")).hexdigest()
    fake_cache.write_text(fake_hash + "\n")

    monkeypatch.setattr(config, "BLOCKLIST_CACHE_PATH", fake_cache)
    return SafeModeFilter(cache_path=fake_cache)


def test_blocked_address_is_detected(filter_with_fake_blocklist):
    assert filter_with_fake_blocklist.is_blocked(FAKE_BLOCKED_ADDRESS) is True


def test_allowed_address_is_not_blocked(filter_with_fake_blocklist):
    assert filter_with_fake_blocklist.is_blocked(FAKE_ALLOWED_ADDRESS) is False


def test_filter_record_marks_status(filter_with_fake_blocklist):
    from src.models import OnionStatus

    record = OnionRecord(address=FAKE_BLOCKED_ADDRESS)
    result = filter_with_fake_blocklist.filter_record(record)
    assert result.status == OnionStatus.BLOCKED


def test_hash_is_case_and_scheme_insensitive(filter_with_fake_blocklist):
    variants = [
        FAKE_BLOCKED_ADDRESS.upper(),
        f"http://{FAKE_BLOCKED_ADDRESS}/",
        f"https://{FAKE_BLOCKED_ADDRESS}/some/path",
    ]
    for variant in variants:
        assert filter_with_fake_blocklist.is_blocked(variant) is True


def test_missing_blocklist_blocks_everything(tmp_path):
    """
    Caso critico: si no hay blocklist en cache, el filtro debe bloquear
    TODO por defecto (fail-closed real). Este test existe especificamente
    porque una version anterior tenia un bug donde un set de hashes vacio
    hacia que is_blocked() devolviera False para cualquier direccion
    (fail-open), justo el fallo de seguridad que este diseño existe para
    evitar. El constructor tampoco debe intentar ninguna descarga por su
    cuenta (ver test_refresh_via_tor_is_the_only_network_path).
    """
    missing_cache = tmp_path / "no_existe.txt"
    filt = SafeModeFilter(cache_path=missing_cache)
    assert filt._blocklist_available is False
    assert filt.is_blocked(FAKE_ALLOWED_ADDRESS) is True
    assert filt.is_blocked(FAKE_BLOCKED_ADDRESS) is True


class _FakeResponse:
    def __init__(self, text: str):
        self._text = text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def raise_for_status(self):
        pass

    async def text(self):
        return self._text


class _FakeTorSession:
    """
    Sesion falsa que imita la interfaz minima de aiohttp.ClientSession
    usada por refresh_via_tor, para poder testear el metodo sin necesitar
    Tor real ni red de ningun tipo.
    """

    def __init__(self, response_text: str):
        self.requested_urls: list[str] = []
        self._response_text = response_text

    def get(self, url, timeout=None):
        self.requested_urls.append(url)
        return _FakeResponse(self._response_text)


def test_refresh_via_tor_is_the_only_network_path(tmp_path):
    """
    Verifica que refresh_via_tor:
      1. Usa la URL onion configurada (AHMIA_BLOCKLIST_ONION_URL), no la
         clearnet, confirmando que el refresco de produccion esta torificado.
      2. Deja el filtro operativo tras cargar el blocklist recibido.
    """
    import asyncio

    cache_path = tmp_path / "blocklist.txt"
    fake_hash = hashlib.md5(FAKE_BLOCKED_ADDRESS.encode("utf-8")).hexdigest()
    fake_session = _FakeTorSession(response_text=fake_hash + "\n")

    filt = SafeModeFilter(cache_path=cache_path)
    assert filt._blocklist_available is False  # todavia sin cache

    asyncio.run(filt.refresh_via_tor(fake_session))

    assert fake_session.requested_urls == [config.AHMIA_BLOCKLIST_ONION_URL]
    assert config.AHMIA_BLOCKLIST_ONION_URL.endswith(".onion/blacklist/banned/")
    assert filt._blocklist_available is True
    assert filt.is_blocked(FAKE_BLOCKED_ADDRESS) is True
    assert filt.is_blocked(FAKE_ALLOWED_ADDRESS) is False
