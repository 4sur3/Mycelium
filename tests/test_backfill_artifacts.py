"""
Tests de la logica de filtrado de scripts/backfill_artifacts.py. Puros,
sin red: verifican unicamente que needs_artifact_backfill() identifica
bien que dominios son candidatos (80 o 443 abiertos).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from backfill_artifacts import needs_artifact_backfill  # noqa: E402

from src.models import ServiceEnumeration, ServicePort


def test_needs_backfill_when_443_open():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    assert needs_artifact_backfill(enumeration) is True


def test_needs_backfill_when_80_open():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=80, protocol="http", open=True)],
    )
    assert needs_artifact_backfill(enumeration) is True


def test_does_not_need_backfill_when_only_ssh_open():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=22, protocol="ssh", open=True)],
    )
    assert needs_artifact_backfill(enumeration) is False


def test_does_not_need_backfill_when_all_ports_closed():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[
            ServicePort(port=80, protocol="http", open=False),
            ServicePort(port=443, protocol="https", open=False),
        ],
    )
    assert needs_artifact_backfill(enumeration) is False
