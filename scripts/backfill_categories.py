"""
Relleno de categoria de tipo de servicio (marketplace, foro, exchange...)
generada con un LLM local (Ollama, opcional) sobre un checkpoint
existente.

A diferencia de backfill_summaries.py, este NO vuelve a descargar
contenido de red: clasifica a partir del RESUMEN que ya generamos
previamente (campo llm_summary), no del HTML crudo. Esto significa que
no hace falta Tor para nada aqui - solo Ollama. Es deliberadamente un
script separado de backfill_summaries.py por eso: distinto perfil de
coste (mucho mas rapido y ligero), pensado para lanzarse DESPUES de
tener los resumenes ya rellenados.

Toca a todos los dominios que YA tengan resumen pero TODAVIA no tengan
categoria (idempotente).

Uso:
    python3 scripts/backfill_categories.py --checkpoint data/checkpoint_2026-07-07.jsonl
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
from src.circuit_breaker import CircuitBreaker, CircuitOpenError
from src.ollama_client import OllamaClient, OllamaError
from src.progress_bar import clear_progress_line, print_progress
from src.summary_cache import SummaryCache, content_cache_key

from run_batch import append_checkpoint, load_checkpoint, load_into_databases, save_and_load  # noqa: E402


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def needs_category_backfill(enumeration) -> bool:
    """Ya tiene resumen, pero todavia no tiene categoria (idempotente)."""
    return bool(enumeration.llm_summary) and not enumeration.llm_category


async def main(checkpoint_path: Path, limit: int | None = None) -> int:
    if not config.ENABLE_LLM_CATEGORY:
        log("config.ENABLE_LLM_CATEGORY esta en False. No se hace nada "
            "(activalo explicitamente en config.py para usar esta funcion).")
        return 0

    client = OllamaClient(host=config.OLLAMA_HOST, model=config.OLLAMA_MODEL, timeout=config.OLLAMA_TIMEOUT)
    log(f"Comprobando si Ollama esta disponible en {config.OLLAMA_HOST}...")
    if not client.is_available():
        log(f"Ollama no responde en {config.OLLAMA_HOST}. Instalalo/arrancalo "
            "y vuelve a lanzar este script. No se toca nada del resto del pipeline.")
        return 1
    log(f"Ollama disponible (modelo: {config.OLLAMA_MODEL}).")

    log(f"Cargando checkpoint: {checkpoint_path}")
    all_records = load_checkpoint(checkpoint_path)
    if not all_records:
        log("El checkpoint esta vacio o no existe. Nada que hacer.")
        return 1
    log(f"Dominios cargados: {len(all_records)}")

    cache = SummaryCache(config.LLM_CATEGORY_CACHE_PATH)
    breaker = CircuitBreaker(failure_threshold=5)

    pending = [
        (record, enumeration, evidence)
        for record, enumeration, evidence in all_records.values()
        if needs_category_backfill(enumeration)
    ]

    if limit is not None and limit < len(pending):
        total_pending = len(pending)
        pending = pending[:limit]
        log(f"Dominios pendientes en total: {total_pending} de {len(all_records)} "
            f"- por --limit {limit}, esta ejecucion procesara solo {len(pending)}.")
    else:
        log(f"Dominios a categorizar: {len(pending)} de {len(all_records)} "
            "(solo cuenta a los que YA tienen resumen; lanza antes backfill_summaries.py "
            "si aun no lo has hecho).")

    if not pending:
        log("Nada que rellenar (ningun dominio con resumen pendiente de categoria).")
        return 0

    stats = {"categorized": 0, "cache_hits": 0, "skipped_circuit_open": 0, "failed": 0}
    start_time = time.monotonic()

    for idx, (record, enumeration, evidence) in enumerate(pending, start=1):
        address = record.address
        summary = enumeration.llm_summary

        key = content_cache_key(summary)
        cached = cache.get(key)
        if cached is not None:
            enumeration.llm_category = cached
            stats["cache_hits"] += 1
            append_checkpoint(checkpoint_path, record, enumeration, evidence)
            print_progress(idx, len(pending), start_time, suffix=str(stats))
            continue

        try:
            breaker.guard()
        except CircuitOpenError as exc:
            clear_progress_line()
            log(f"  {address}: {exc}")
            stats["skipped_circuit_open"] += 1
            continue

        try:
            category = client.classify(summary, config.LLM_CATEGORY_CHOICES)
            cache.set(key, category)
            enumeration.llm_category = category
            breaker.record_success()
            stats["categorized"] += 1
            append_checkpoint(checkpoint_path, record, enumeration, evidence)
        except OllamaError as exc:
            breaker.record_failure()
            stats["failed"] += 1
            clear_progress_line()
            log(f"  {address}: fallo clasificando ({exc})")

        # Igual que en backfill_summaries.py: pausa deliberada tras cada
        # llamada real al modelo, para no mantener carga sostenida.
        await asyncio.sleep(config.LLM_SUMMARY_DELAY_SECONDS)

        print_progress(idx, len(pending), start_time, suffix=str(stats))

    clear_progress_line()
    cache.save()
    log(f"Relleno de categorias completado. {stats}")
    log(f"Cache de categorias: {cache.stats()}")

    if skip_reload:
        log("--skip-reload activado: no se toca Neo4j/Elasticsearch. "
            "El checkpoint ya tiene las categorias guardadas - cuando quieras, "
            "con Docker arrancado, ejecuta:")
        log(f"  python3 scripts/recorrelate.py --checkpoint {checkpoint_path}")
        return 0

    log("Recargando Elasticsearch/Neo4j con las categorias rellenadas...")
    all_results = list(all_records.values())
    evidences_all = [ev for _, _, ev in all_results]
    from src.correlation import correlate
    links = correlate(evidences_all)

    out_path = save_and_load(all_results, all_results, links)
    log(f"Snapshot combinado actualizado guardado en: {out_path}")

    load_into_databases(all_results, links)

    log("Todo OK. Elasticsearch ya refleja las categorias rellenadas.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", required=True, type=Path,
        help="Ruta al fichero checkpoint_<fecha>.jsonl generado por run_batch.py",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Procesar como maximo N dominios (para probar antes de lanzar sobre todo el dataset)",
    )
    parser.add_argument(
        "--skip-reload", action="store_true",
        help="No recargar Neo4j/Elasticsearch al terminar (permite correr este script "
             "con Docker completamente apagado, para no sumar su consumo de RAM al de "
             "Ollama). El checkpoint queda actualizado igualmente; recarga despues con "
             "scripts/recorrelate.py cuando quieras, con Docker ya arrancado.",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.checkpoint, limit=args.limit, skip_reload=args.skip_reload)))
