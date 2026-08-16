import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from backfill_jurisdiction import needs_jurisdiction_backfill  # noqa: E402

from src.models import ServiceEnumeration


def test_needs_backfill_when_no_hint_yet():
    enumeration = ServiceEnumeration(address="a.onion")
    assert needs_jurisdiction_backfill(enumeration) is True


def test_idempotent_does_not_need_backfill_when_already_resolved():
    enumeration = ServiceEnumeration(
        address="a.onion", jurisdiction_country_code="LT", jurisdiction_source="tls_cert",
    )
    assert needs_jurisdiction_backfill(enumeration) is False
