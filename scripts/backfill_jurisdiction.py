"""
Relleno de pista de jurisdiccion/pais sobre un checkpoint existente.

A diferencia de TODOS los demas scripts de relleno de este proyecto,
este NO necesita red en absoluto: ni Tor, ni Ollama. Los dos unicos datos
de entrada (subject/issuer del certificado TLS, titulo HTTP) YA estan
guardados en el checkpoint desde el escaneo original. Es pura lectura +
calculo local con src/jurisdiction_hint.py, por lo que es rapido (segundos
sobre miles de dominios) y no tiene ningun riesgo de los problemas de
carga sostenida documentados para los scripts de LLM.

Idempotente: solo toca dominios que aun no tienen jurisdiction_country_code.

Uso:
    python3 scripts/backfill_jurisdiction.py --checkpoint data/checkpoint_2026-07-07.jsonl
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.jurisdiction_hint import resolve_jurisdiction

from run_batch import append_checkpoint, load_checkpoint, load_into_databases, save_and_load  # noqa: E402


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def needs_jurisdiction_backfill(enumeration) -> bool:
    return not enumeration.jurisdiction_country_code


def main(checkpoint_path: Path, skip_reload: bool = False) -> int:
    log(f"Cargando checkpoint: {checkpoint_path}")
    all_records = load_checkpoint(checkpoint_path)
    if not all_records:
        log("El checkpoint esta vacio o no existe. Nada que hacer.")
        return 1
    log(f"Dominios cargados: {len(all_records)}")

    pending = [
        (record, enumeration, evidence)
        for record, enumeration, evidence in all_records.values()
        if needs_jurisdiction_backfill(enumeration)
    ]
    log(f"Dominios a procesar: {len(pending)} de {len(all_records)}")

    stats = {"resolved_cert": 0, "resolved_title": 0, "no_hint": 0}

    for record, enumeration, evidence in pending:
        hint = resolve_jurisdiction(
            tls_cert_subject=evidence.tls_cert_subject,
            tls_cert_issuer=evidence.tls_cert_issuer,
            http_title=enumeration.http_title,
        )
        if hint:
            enumeration.jurisdiction_country_code = hint.country_code
            enumeration.jurisdiction_source = hint.source
            stats["resolved_cert" if hint.source == "tls_cert" else "resolved_title"] += 1
        else:
            stats["no_hint"] += 1
        append_checkpoint(checkpoint_path, record, enumeration, evidence)

    log(f"Relleno de jurisdiccion completado. {stats}")

    if skip_reload:
        log("--skip-reload activado: no se toca Neo4j ni Elasticsearch. "
            "Ejecuta despues scripts/recorrelate.py sobre este mismo checkpoint.")
        return 0

    log("Recargando Elasticsearch/Neo4j...")
    all_results = list(all_records.values())
    evidences_all = [ev for _, _, ev in all_results]
    from src.correlation import correlate
    links = correlate(evidences_all)

    out_path = save_and_load(all_results, all_results, links)
    log(f"Snapshot combinado actualizado guardado en: {out_path}")

    load_into_databases(all_results, links)

    log("Todo OK.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", required=True, type=Path,
        help="Ruta al fichero checkpoint_<fecha>.jsonl generado por run_batch.py",
    )
    parser.add_argument(
        "--skip-reload", action="store_true",
        help="No tocar Neo4j/Elasticsearch al final. Ejecuta despues scripts/recorrelate.py.",
    )
    args = parser.parse_args()
    sys.exit(main(args.checkpoint, skip_reload=args.skip_reload))
