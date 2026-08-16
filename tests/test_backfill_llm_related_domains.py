"""
Tests de la logica de filtrado de scripts/backfill_llm_related_domains.py.
Puros, sin red: verifican que needs_llm_backfill() solo marca como
pendientes los dominios CON relaciones confirmadas, y respeta la
idempotencia (no repetir resumen/categoria ya hechos).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from backfill_llm_related_domains import needs_llm_backfill  # noqa: E402

from src.models import ServiceEnumeration

RELATED = {"a.onion", "b.onion"}


def test_needs_backfill_when_related_and_no_summary_yet():
    enumeration = ServiceEnumeration(address="a.onion")
    assert needs_llm_backfill("a.onion", enumeration, RELATED, do_categorize=True) is True


def test_does_not_need_backfill_when_not_related():
    """El caso central de este script: fuera del conjunto de relaciones, no se toca."""
    enumeration = ServiceEnumeration(address="c.onion")
    assert needs_llm_backfill("c.onion", enumeration, RELATED, do_categorize=True) is False


def test_needs_backfill_when_related_has_summary_but_missing_category():
    enumeration = ServiceEnumeration(address="a.onion", llm_summary="Ya resumido.")
    assert needs_llm_backfill("a.onion", enumeration, RELATED, do_categorize=True) is True


def test_does_not_need_backfill_when_category_disabled_and_summary_exists():
    """Con la categorizacion desactivada, tener ya el resumen basta para no reprocesar."""
    enumeration = ServiceEnumeration(address="a.onion", llm_summary="Ya resumido.")
    assert needs_llm_backfill("a.onion", enumeration, RELATED, do_categorize=False) is False


def test_idempotent_does_not_need_backfill_when_fully_done():
    enumeration = ServiceEnumeration(
        address="a.onion", llm_summary="Ya resumido.", llm_category="marketplace",
    )
    assert needs_llm_backfill("a.onion", enumeration, RELATED, do_categorize=True) is False
