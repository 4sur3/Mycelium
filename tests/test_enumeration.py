"""
Tests de la logica pura del modulo de enumeracion (F2). No requieren red
ni Tor: solo prueban clasificacion de banners y extraccion de tecnologia
sobre cadenas de texto controladas.
"""

import asyncio

import pytest

import config
from src.enumeration import (
    classify_banner,
    _extract_technologies,
    _extract_title,
    enumerate_domain,
)
from src.models import OnionRecord


@pytest.mark.parametrize(
    "banner,default,expected",
    [
        ("220 (vsFTPd 3.0.3)", "other", "ftp"),
        ("SSH-2.0-OpenSSH_8.9", "other", "ssh"),
        ("HTTP/1.1 200 OK", "other", "http"),
        ("220 mail.example ESMTP Postfix", "other", "smtp"),
        (None, "http", "http"),  # sin banner, se mantiene el default por puerto
        ("", "https", "https"),
        ("algo irreconocible", "other", "other"),
    ],
)
def test_classify_banner(banner, default, expected):
    assert classify_banner(banner, default) == expected


def test_extract_technologies_wordpress():
    html = "<html><body><link href='/wp-content/theme.css'></body></html>"
    assert "WordPress" in _extract_technologies(html)


def test_extract_technologies_no_match():
    assert _extract_technologies("<html><body>hola</body></html>") == []


def test_extract_title_strips_whitespace():
    html = "<title>\n   Mi Sitio   \n</title>"
    assert _extract_title(html) == "Mi Sitio"


def test_extract_title_missing():
    assert _extract_title("<html><body>sin titulo</body></html>") is None


def test_enumerate_domain_respects_safe_mode_double_check(monkeypatch):
    """
    Verifica la capa de defensa en profundidad: si se pasa un SafeModeFilter
    y la direccion esta bloqueada, enumerate_domain no debe intentar
    ninguna conexion de red, solo devolver un resultado vacio.
    """

    class _AlwaysBlocked:
        def is_blocked(self, address):
            return True

        def hash_address(self, address):
            return "deadbeef"

    called = {"probe": False}

    async def _fake_probe(*args, **kwargs):
        called["probe"] = True
        raise AssertionError("no deberia llamarse: la direccion esta bloqueada")

    monkeypatch.setattr("src.enumeration.probe_port", _fake_probe)

    record = OnionRecord(address="bloqueado.onion")
    result = asyncio.run(enumerate_domain(record, session=None, safe_mode=_AlwaysBlocked()))

    assert result.ports == []
    assert called["probe"] is False


def test_enumerate_domain_skips_remaining_ports_when_dead(monkeypatch):
    """
    Si la comprobacion rapida de vida (puertos 80 y 443) no obtiene
    respuesta, enumerate_domain NO debe intentar conectar a los 6 puertos
    restantes: deben quedar marcados como cerrados sin ninguna llamada
    de red adicional.
    """
    from src.models import ServicePort

    calls: list[int] = []

    async def _fake_probe(address, port, connect_timeout=None, banner_timeout=None):
        calls.append(port)
        return ServicePort(port=port, protocol=config.ENUMERATION_PORTS.get(port, "other"), open=False)

    monkeypatch.setattr("src.enumeration.probe_port", _fake_probe)

    record = OnionRecord(address="muerto.onion")
    result = asyncio.run(enumerate_domain(record, session=None))

    # Solo se debe haber llamado a probe_port para los puertos de la
    # comprobacion rapida (80 y 443), nunca para los otros 6.
    assert set(calls) == set(config.LIVENESS_CHECK_PORTS)
    assert len(result.ports) == len(config.ENUMERATION_PORTS)
    assert all(not p.open for p in result.ports)


def test_enumerate_domain_marks_record_dead_when_no_response(monkeypatch):
    """
    Regresion del bug reportado: el 'status' indexado en Elasticsearch
    venia de OnionRecord.status, que nunca se actualizaba desde UNKNOWN,
    mientras que los puertos abiertos si se calculaban correctamente en
    ServiceEnumeration. Esto hacia que el dashboard mostrara 'Vivos: 0'
    aunque hubiera dominios con puertos abiertos en la lista.
    """
    from src.models import OnionStatus, ServicePort

    async def _fake_probe(address, port, connect_timeout=None, banner_timeout=None):
        return ServicePort(port=port, protocol=config.ENUMERATION_PORTS.get(port, "other"), open=False)

    monkeypatch.setattr("src.enumeration.probe_port", _fake_probe)

    record = OnionRecord(address="muerto.onion")
    assert record.status == OnionStatus.UNKNOWN
    asyncio.run(enumerate_domain(record, session=None))
    assert record.status == OnionStatus.DEAD


def test_enumerate_domain_marks_record_alive_when_port_open(monkeypatch):
    from src.models import OnionStatus, ServicePort

    async def _fake_probe(address, port, connect_timeout=None, banner_timeout=None):
        return ServicePort(port=port, protocol=config.ENUMERATION_PORTS.get(port, "other"), open=(port == 80))

    async def _fake_fingerprint(address, session, use_https):
        return [], None, None

    monkeypatch.setattr("src.enumeration.probe_port", _fake_probe)
    monkeypatch.setattr("src.enumeration._fingerprint_http", _fake_fingerprint)

    record = OnionRecord(address="vivo.onion")
    asyncio.run(enumerate_domain(record, session=None))
    assert record.status == OnionStatus.ALIVE
    """
    Si el dominio responde en la comprobacion rapida, se deben probar
    TODOS los puertos configurados, sin repetir conexion a los que ya
    se probaron durante la comprobacion rapida.
    """
    from src.models import ServicePort

    calls: list[int] = []

    async def _fake_probe(address, port, connect_timeout=None, banner_timeout=None):
        calls.append(port)
        open_ = port == 80  # solo el 80 esta "abierto" en este escenario simulado
        return ServicePort(port=port, protocol=config.ENUMERATION_PORTS.get(port, "other"), open=open_)

    async def _fake_fingerprint(address, session, use_https):
        return [], None, None

    monkeypatch.setattr("src.enumeration.probe_port", _fake_probe)
    monkeypatch.setattr("src.enumeration._fingerprint_http", _fake_fingerprint)

    record = OnionRecord(address="vivo.onion")
    result = asyncio.run(enumerate_domain(record, session=None))

    # Cada puerto configurado se prueba exactamente una vez (sin duplicados
    # entre la comprobacion rapida y el escaneo completo).
    assert sorted(calls) == sorted(config.ENUMERATION_PORTS.keys())
    assert len(calls) == len(set(calls))
    assert len(result.ports) == len(config.ENUMERATION_PORTS)
