"""
Tests de la logica de filtrado de scripts/backfill_jarm.py. Puros, sin
red: verifican unicamente que needs_jarm_backfill() identifica bien que
dominios necesitan rellenarse (443 abierto y sin jarm_hash todavia).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from backfill_jarm import needs_jarm_backfill  # noqa: E402

from src.models import LeakEvidence, ServiceEnumeration, ServicePort


def test_needs_backfill_when_443_open_and_no_jarm():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    evidence = LeakEvidence(address="a.onion")
    assert needs_jarm_backfill(enumeration, evidence) is True


def test_does_not_need_backfill_when_jarm_already_present():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    evidence = LeakEvidence(address="a.onion", jarm_hash="2ad2a" + "0" * 57)
    assert needs_jarm_backfill(enumeration, evidence) is False


def test_does_not_need_backfill_when_443_closed():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=443, protocol="https", open=False)],
    )
    evidence = LeakEvidence(address="a.onion")
    assert needs_jarm_backfill(enumeration, evidence) is False


def test_does_not_need_backfill_when_no_443_at_all():
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=80, protocol="http", open=True)],
    )
    evidence = LeakEvidence(address="a.onion")
    assert needs_jarm_backfill(enumeration, evidence) is False
