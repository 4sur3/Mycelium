"""
Ejecucion a mayor escala del pipeline completo, sobre N dominios reales
(por defecto 200). Pensado para datasets grandes (miles de dominios) que
pueden tardar horas:

  - Acepta --limit para ajustar el tamano de la muestra.
  - Procesa por BLOQUES (config.BATCH_CHECKPOINT_SIZE) y guarda progreso
    en un checkpoint JSONL tras cada bloque, no solo al final. Si el
    proceso se corta a mitad (Ctrl+C, corte de luz, suspension del
    equipo), NO se pierde el trabajo ya hecho.
  - Si vuelves a lanzar el mismo dia y existe un checkpoint previo,
    reanuda automaticamente desde donde se quedo (no vuelve a escanear
    los dominios ya procesados).
  - La correlacion final (correlate()) se ejecuta UNA sola vez sobre
    todo lo acumulado (checkpoints previos + nuevo), nunca por bloque
    aislado, porque dos dominios relacionados pueden caer en bloques
    distintos.
  - Carga los resultados en Neo4j y Elasticsearch al final.

Uso:
    python3 scripts/run_batch.py --limit 5000
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import date
from pathlib import Path

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from src.correlation import correlate, extract_leak_evidence_batch
from src.crawler import DiscoveryPipeline
from src.enumeration import enumerate_batch
from src.graph import GraphStore
from src.models import LeakEvidence, OnionRecord, OnionStatus, ServiceEnumeration
from src.search_index import SearchIndex
from src.seeds.ahmia import AhmiaSource
from src.tor_client import TorCircuitManager, create_tor_session


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def checkpoint_path_for_today() -> Path:
    return config.DATA_DIR / f"checkpoint_{date.today().isoformat()}.jsonl"


def load_checkpoint(path: Path) -> dict[str, tuple[OnionRecord, ServiceEnumeration, LeakEvidence]]:
    """Reconstruye los objetos ya procesados desde un checkpoint previo."""
    if not path.exists():
        return {}

    loaded: dict[str, tuple[OnionRecord, ServiceEnumeration, LeakEvidence]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        record = OnionRecord(**row["record"])
        enumeration = ServiceEnumeration(**row["enumeration"])
        evidence = LeakEvidence(**row["evidence"])
        loaded[record.address] = (record, enumeration, evidence)
    return loaded


def append_checkpoint(
    path: Path, record: OnionRecord, enumeration: ServiceEnumeration, evidence: LeakEvidence
) -> None:
    row = {
        "record": json.loads(record.model_dump_json()),
        "enumeration": json.loads(enumeration.model_dump_json()),
        "evidence": json.loads(evidence.model_dump_json()),
    }
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")


async def process_chunk(
    chunk: list[OnionRecord], safe_mode
) -> list[tuple[OnionRecord, ServiceEnumeration, LeakEvidence]]:
    async with create_tor_session() as session:
        enumerations = await enumerate_batch(chunk, session, safe_mode=safe_mode)
    async with create_tor_session() as session:
        records_with_enum = list(zip(chunk, enumerations))
        evidences = await extract_leak_evidence_batch(records_with_enum, safe_mode=safe_mode)
    return list(zip(chunk, enumerations, evidences))


def save_and_load(sample_all, results_all, links) -> Path:
    out_path = config.DATA_DIR / f"batch_{date.today().isoformat()}_{len(sample_all)}.json"
    payload = {
        "onions": [json.loads(r.model_dump_json()) for r, _, _ in results_all],
        "enumerations": [json.loads(e.model_dump_json()) for _, e, _ in results_all],
        "leak_evidence": [json.loads(ev.model_dump_json()) for _, _, ev in results_all],
        "links": [json.loads(l.model_dump_json()) for l in links],
    }
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return out_path


def load_into_databases(results_all, links) -> None:
    related_addresses = {l.address_a for l in links} | {l.address_b for l in links}

    log("Cargando en Neo4j...")
    try:
        with GraphStore() as graph:
            graph.ensure_constraints()
            for record, enumeration, _ in results_all:
                graph.upsert_onion(record, enumeration)
            for _, _, ev in results_all:
                graph.upsert_leak_evidence(ev)
            graph.upsert_links(links)
        log("Carga en Neo4j completada.")
    except Exception as exc:
        log(f"AVISO: fallo cargando en Neo4j ({exc}). El snapshot en disco sigue disponible.")

    log("Indexando en Elasticsearch...")
    try:
        with SearchIndex() as search:
            search.ensure_index()
            for record, enumeration, ev in results_all:
                search.index_onion(record, enumeration, ev, has_relations=record.address in related_addresses)
        log("Indexacion en Elasticsearch completada.")
    except Exception as exc:
        log(f"AVISO: fallo indexando en Elasticsearch ({exc}). El snapshot en disco sigue disponible.")


async def main(limit: int) -> int:
    log("Esperando bootstrap de Tor...")
    with TorCircuitManager() as tor_ctl:
        tor_ctl.wait_for_bootstrap(timeout=90)
    log("Tor listo.")

    log("Fase 1 (Discovery): obteniendo dataset filtrado...")
    async with create_tor_session() as session:
        pipeline = DiscoveryPipeline(sources=[AhmiaSource()])
        records = await pipeline.run(session)
    log(f"Discovery completado: {len(records)} dominios tras safe-mode.")

    sample = [r for r in records if r.status != OnionStatus.BLOCKED][:limit]
    log(f"Muestra seleccionada para esta ejecucion: {len(sample)} dominios.")

    checkpoint_path = checkpoint_path_for_today()
    already_done = load_checkpoint(checkpoint_path)
    if already_done:
        log(f"Checkpoint encontrado: {len(already_done)} dominios ya procesados hoy, se reanuda desde ahi.")

    pending = [r for r in sample if r.address not in already_done]
    results_all: list[tuple[OnionRecord, ServiceEnumeration, LeakEvidence]] = list(already_done.values())

    log(f"Pendientes de procesar en esta ejecucion: {len(pending)} de {len(sample)}.")

    chunks = [
        pending[i:i + config.BATCH_CHECKPOINT_SIZE]
        for i in range(0, len(pending), config.BATCH_CHECKPOINT_SIZE)
    ]

    interrupted = False
    for idx, chunk in enumerate(chunks, start=1):
        t0 = time.monotonic()
        try:
            chunk_results = await process_chunk(chunk, pipeline.safe_mode)
        except KeyboardInterrupt:
            log("Interrumpido por el usuario. Guardando progreso acumulado hasta ahora...")
            interrupted = True
            break

        for record, enumeration, evidence in chunk_results:
            append_checkpoint(checkpoint_path, record, enumeration, evidence)
        results_all.extend(chunk_results)

        alive_in_chunk = sum(1 for _, e, _ in chunk_results if e.open_ports)
        log(f"Bloque {idx}/{len(chunks)} completado en {time.monotonic() - t0:.0f}s "
            f"({alive_in_chunk}/{len(chunk)} con puertos abiertos). "
            f"Progreso total: {len(results_all)}/{len(sample)} dominios.")

    if not interrupted:
        log("Todos los bloques procesados.")

    log("Calculando correlacion final sobre todo lo acumulado...")
    evidences_all = [ev for _, _, ev in results_all]
    t0 = time.monotonic()
    links = correlate(evidences_all)
    log(f"Correlacion completada en {time.monotonic() - t0:.0f}s. "
        f"Relaciones de infraestructura encontradas: {len(links)}")
    for link in links[:20]:
        log(f"  - {link.address_a} <-> {link.address_b} ({link.relation_type}, confianza={link.confidence:.2f})")

    out_path = save_and_load(sample, results_all, links)
    log(f"Snapshot combinado guardado en: {out_path}")

    load_into_databases(results_all, links)

    alive_count = sum(1 for _, e, _ in results_all if e.open_ports)
    with_evidence = sum(1 for ev in evidences_all if ev.tls_cert_sha256 or ev.ssh_fingerprint_sha256 or ev.content_fuzzy_hash)

    log("Resumen final:")
    log(f"  - Dominios procesados: {len(results_all)} de {len(sample)} solicitados"
        f"{' (EJECUCION INTERRUMPIDA, relanza el script para completar el resto)' if interrupted else ''}")
    log(f"  - Con puertos abiertos: {alive_count}")
    log(f"  - Con evidencia de correlacion: {with_evidence}")
    log(f"  - Relaciones de infraestructura: {len(links)}")
    return 1 if interrupted else 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=200, help="Numero de dominios a procesar (default: 200)")
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.limit)))
