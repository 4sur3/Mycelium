"""
Relleno dirigido de JARM (F4) sobre un checkpoint ya existente.

No repite discovery, enumeracion, certificado, SSH ni fuzzy hashing de
contenido: reutiliza el checkpoint que ya generaste con run_batch.py y
SOLO calcula JARM para los dominios que:
  a) ya tenian el puerto 443 abierto (segun la enumeracion guardada), y
  b) todavia no tienen jarm_hash (porque se escanearon antes de anadir
     este modulo).

Esto es mucho mas rapido que un re-escaneo completo: en un dataset de
miles de dominios, normalmente solo una fraccion pequeña tiene HTTPS
abierto (ver tu propio dato: 196 de 7912 en la ultima ejecucion).

Al terminar, recalcula correlate() sobre TODO el conjunto de evidencias
(las ya existentes + las recien rellenadas) para que las nuevas
relaciones shared_jarm salgan reflejadas, y vuelve a cargar en Neo4j y
Elasticsearch (misma logica de carga que run_batch.py, reutilizada).

Uso:
    python3 scripts/backfill_jarm.py --checkpoint data/checkpoint_2026-07-07.jsonl
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import config
from src.correlation import correlate
from src.jarm_fingerprint import compute_jarm
from src.safe_mode import SafeModeFilter
from src.tor_client import TorCircuitManager

from run_batch import append_checkpoint, load_checkpoint, load_into_databases, save_and_load  # noqa: E402


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def needs_jarm_backfill(enumeration, evidence) -> bool:
    """Puerto 443 ya visto abierto, pero JARM todavia sin calcular."""
    has_https_open = any(p.port == 443 and p.open for p in enumeration.ports)
    return has_https_open and evidence.jarm_hash is None


async def main(checkpoint_path: Path) -> int:
    log("Esperando bootstrap de Tor...")
    with TorCircuitManager() as tor_ctl:
        tor_ctl.wait_for_bootstrap(timeout=90)
    log("Tor listo.")

    log(f"Cargando checkpoint: {checkpoint_path}")
    all_records = load_checkpoint(checkpoint_path)
    if not all_records:
        log("El checkpoint esta vacio o no existe. Nada que hacer.")
        return 1
    log(f"Dominios cargados: {len(all_records)}")

    safe_mode = SafeModeFilter()  # defensa en profundidad, ver src/safe_mode.py

    pending = [
        (record, enumeration, evidence)
        for record, enumeration, evidence in all_records.values()
        if needs_jarm_backfill(enumeration, evidence)
    ]
    log(f"Dominios con HTTPS abierto pendientes de JARM: {len(pending)} de {len(all_records)}")

    if not pending:
        log("Nada pendiente de rellenar. El dataset ya esta completo para JARM.")
        return 0

    semaphore = asyncio.Semaphore(config.JARM_PROBE_CONCURRENCY)

    async def _bounded_jarm(record, enumeration, evidence):
        if safe_mode.is_blocked(record.address):
            log(f"  {record.address}: bloqueado por safe-mode, se omite")
            return
        async with semaphore:
            try:
                evidence.jarm_hash = await compute_jarm(record.address, port=443)
            except Exception as exc:
                log(f"  {record.address}: fallo calculando JARM ({exc!r})")
        append_checkpoint(checkpoint_path, record, enumeration, evidence)

    t0 = time.monotonic()
    for idx, (record, enumeration, evidence) in enumerate(pending, start=1):
        await _bounded_jarm(record, enumeration, evidence)
        if idx % 20 == 0 or idx == len(pending):
            log(f"Progreso: {idx}/{len(pending)} dominios procesados "
                f"({time.monotonic() - t0:.0f}s transcurridos)")

    with_jarm = sum(1 for _, _, ev in all_records.values() if ev.jarm_hash)
    log(f"Relleno completado. Dominios con JARM ahora: {with_jarm}/{len(all_records)}")

    log("Recalculando correlacion sobre el conjunto completo actualizado...")
    all_results = list(all_records.values())
    evidences_all = [ev for _, _, ev in all_results]
    links = correlate(evidences_all)
    log(f"Relaciones de infraestructura tras el relleno: {len(links)}")
    for link in links[:20]:
        log(f"  - {link.address_a} <-> {link.address_b} ({link.relation_type}, confianza={link.confidence:.2f})")

    out_path = save_and_load(all_results, all_results, links)
    log(f"Snapshot combinado actualizado guardado en: {out_path}")

    load_into_databases(all_results, links)

    log("Todo OK. Neo4j y Elasticsearch ya reflejan los datos de JARM rellenados.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", required=True, type=Path,
        help="Ruta al fichero checkpoint_<fecha>.jsonl generado por run_batch.py",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.checkpoint)))
