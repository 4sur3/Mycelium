"""
Tests de la logica de filtrado de scripts/backfill_summaries.py. Puros,
sin red: verifican que needs_summary_backfill() identifica bien los
dominios candidatos, incluida la idempotencia (un dominio que YA tiene
resumen no se vuelve a procesar).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from backfill_summaries import needs_summary_backfill  # noqa: E402

from src.models import ServiceEnumeration, ServicePort


def test_needs_backfill_when_443_open_and_no_summary_yet():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    assert needs_summary_backfill(enumeration) is True


def test_needs_backfill_when_80_open_and_no_summary_yet():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=80, protocol="http", open=True)],
    )
    assert needs_summary_backfill(enumeration) is True


def test_idempotent_does_not_need_backfill_when_already_summarized():
    """
    Regresion especifica de la idempotencia: relanzar el script sobre un
    checkpoint parcialmente procesado NO debe volver a resumir dominios
    que ya tienen un resumen guardado.
    """
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
        llm_summary="Ya resumido anteriormente.",
    )
    assert needs_summary_backfill(enumeration) is False


def test_does_not_need_backfill_when_only_ssh_open():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=22, protocol="ssh", open=True)],
    )
    assert needs_summary_backfill(enumeration) is False


def test_does_not_need_backfill_when_all_ports_closed():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[
            ServicePort(port=80, protocol="http", open=False),
            ServicePort(port=443, protocol="https", open=False),
        ],
    )
    assert needs_summary_backfill(enumeration) is False
