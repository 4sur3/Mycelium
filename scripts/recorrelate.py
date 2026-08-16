"""
Recalcula la correlacion (F4) y recarga Neo4j/Elasticsearch a partir de
un checkpoint YA COMPLETO, sin hacer ninguna peticion de red.

Pensado para recuperar una ejecucion de run_batch.py que fallo en el
paso final (correlacion + guardado) DESPUES de que todo el escaneo de
red ya hubiera terminado y quedara guardado en el checkpoint - por
ejemplo, tras el fix de la explosion combinatoria en _group_and_link
(ver correlation.py): un solo artefacto muy comun compartido por miles
de dominios podia generar cientos de miles de pares y agotar la
memoria al guardar el JSON final, aunque el escaneo en si hubiera ido
perfectamente bien.

Uso:
    python3 scripts/recorrelate.py --checkpoint data/checkpoint_2026-07-23.jsonl
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.correlation import correlate

from run_batch import load_checkpoint, load_into_databases, save_and_load  # noqa: E402


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def main(checkpoint_path: Path) -> int:
    log(f"Cargando checkpoint: {checkpoint_path}")
    all_records = load_checkpoint(checkpoint_path)
    if not all_records:
        log("El checkpoint esta vacio o no existe. Nada que hacer.")
        return 1
    log(f"Dominios cargados: {len(all_records)}")

    results_all = list(all_records.values())
    evidences_all = [ev for _, _, ev in results_all]

    log("Calculando correlacion...")
    t0 = time.monotonic()
    links = correlate(evidences_all)
    log(f"Correlacion completada en {time.monotonic() - t0:.0f}s. "
        f"Relaciones de infraestructura encontradas: {len(links)}")

    by_type: dict[str, int] = {}
    for link in links:
        by_type[link.relation_type] = by_type.get(link.relation_type, 0) + 1
    for relation_type, count in sorted(by_type.items(), key=lambda kv: -kv[1]):
        log(f"  - {relation_type}: {count}")

    log("Guardando snapshot combinado...")
    out_path = save_and_load(results_all, results_all, links)
    log(f"Snapshot combinado guardado en: {out_path}")

    load_into_databases(results_all, links)

    alive_count = sum(1 for _, e, _ in results_all if e.open_ports)
    with_evidence = sum(
        1 for ev in evidences_all
        if ev.tls_cert_sha256 or ev.ssh_fingerprint_sha256 or ev.content_fuzzy_hash
    )
    log("Resumen final:")
    log(f"  - Dominios procesados: {len(results_all)}")
    log(f"  - Con puertos abiertos: {alive_count}")
    log(f"  - Con evidencia de correlacion: {with_evidence}")
    log(f"  - Relaciones de infraestructura: {len(links)}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", required=True, type=Path,
        help="Ruta al fichero checkpoint_<fecha>.jsonl generado por run_batch.py",
    )
    args = parser.parse_args()
    sys.exit(main(args.checkpoint))
