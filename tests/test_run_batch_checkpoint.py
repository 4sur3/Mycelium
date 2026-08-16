"""
Tests del checkpointing incremental de scripts/run_batch.py. Puros, sin
red: verifican que append_checkpoint/load_checkpoint hacen un
round-trip correcto de los objetos (OnionRecord, ServiceEnumeration,
LeakEvidence), que es la pieza critica para no perder trabajo en
ejecuciones largas (ver conversacion sobre la ejecucion de 10000
dominios).
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from run_batch import append_checkpoint, load_checkpoint  # noqa: E402

from src.models import LeakEvidence, OnionRecord, OnionStatus, ServiceEnumeration, ServicePort


def test_load_checkpoint_missing_file_returns_empty(tmp_path):
    result = load_checkpoint(tmp_path / "no_existe.jsonl")
    assert result == {}


def test_append_and_reload_checkpoint_roundtrip(tmp_path):
    checkpoint = tmp_path / "checkpoint.jsonl"

    record = OnionRecord(address="a.onion", status=OnionStatus.ALIVE)
    enumeration = ServiceEnumeration(
        address="a.onion",
        ports=[ServicePort(port=80, protocol="http", open=True)],
        technologies=["nginx"],
    )
    evidence = LeakEvidence(address="a.onion", tls_cert_sha256="abc123")

    append_checkpoint(checkpoint, record, enumeration, evidence)

    reloaded = load_checkpoint(checkpoint)
    assert "a.onion" in reloaded
    r, e, ev = reloaded["a.onion"]
    assert r.status == OnionStatus.ALIVE
    assert e.technologies == ["nginx"]
    assert ev.tls_cert_sha256 == "abc123"


def test_checkpoint_accumulates_across_multiple_appends(tmp_path):
    checkpoint = tmp_path / "checkpoint.jsonl"

    for i in range(3):
        address = f"domain{i}.onion"
        append_checkpoint(
            checkpoint,
            OnionRecord(address=address),
            ServiceEnumeration(address=address),
            LeakEvidence(address=address),
        )

    reloaded = load_checkpoint(checkpoint)
    assert len(reloaded) == 3
    assert {"domain0.onion", "domain1.onion", "domain2.onion"} == set(reloaded.keys())


def test_checkpoint_ignores_blank_lines(tmp_path):
    checkpoint = tmp_path / "checkpoint.jsonl"
    append_checkpoint(checkpoint, OnionRecord(address="a.onion"), ServiceEnumeration(address="a.onion"), LeakEvidence(address="a.onion"))
    with checkpoint.open("a", encoding="utf-8") as f:
        f.write("\n\n")  # lineas en blanco, no deberian romper la carga

    reloaded = load_checkpoint(checkpoint)
    assert len(reloaded) == 1
