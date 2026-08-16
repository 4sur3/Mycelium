"""
Tests de la logica de filtrado de scripts/backfill_categories.py. Puros,
sin red: verifican que needs_category_backfill() solo marca como
pendientes los dominios que YA tienen resumen pero aun no tienen
categoria.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from backfill_categories import needs_category_backfill  # noqa: E402

from src.models import ServiceEnumeration


def test_needs_backfill_when_summary_exists_and_no_category_yet():
    enumeration = ServiceEnumeration(
        address="a.onion",
        llm_summary="Tienda de productos variados con envio internacional.",
    )
    assert needs_category_backfill(enumeration) is True


def test_does_not_need_backfill_without_summary():
    """Sin resumen previo, no hay nada de donde clasificar todavia."""
    enumeration = ServiceEnumeration(address="a.onion")
    assert needs_category_backfill(enumeration) is False


def test_idempotent_does_not_need_backfill_when_already_categorized():
    enumeration = ServiceEnumeration(
        address="a.onion",
        llm_summary="Tienda de productos variados con envio internacional.",
        llm_category="marketplace",
    )
    assert needs_category_backfill(enumeration) is False
