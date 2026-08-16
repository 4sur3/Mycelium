"""
Relleno de resumen Y categoria (ambos, en un solo paso) con LLM local
(Ollama, opcional), pero SOLO para los dominios que tienen alguna
relacion de infraestructura confirmada (comparten certificado, JARM,
SSH, PGP, cripto, o algun artefacto HTML con otro dominio).

Pensado para dos cosas a la vez:
1. Preparar una demo: solo tiene sentido enseñar el resumen/categoria
   de los dominios que aparecen en el grafo de correlacion - son los
   casos realmente interesantes, no los ~8000 dominios sueltos sin
   relacion.
2. Reducir drasticamente el alcance: el conjunto de dominios CON
   relaciones suele ser mucho mas pequeño que el dataset completo, lo
   cual tambien ayuda con el problema de carga sostenida que hemos visto
   (menos dominios = ejecucion mucho mas corta).

Usa el mismo calculo de "dominios con relaciones" que ya usa
run_batch.py (el campo has_relations que ves en el dashboard) -
mismo criterio en todo el proyecto, no uno nuevo solo para esto.

Apagado por defecto: requiere config.ENABLE_LLM_SUMMARY = True para el
resumen, y config.ENABLE_LLM_CATEGORY = True para la categoria. Si solo
el primero esta activo, se generan resumenes pero no categorias (con
aviso claro en el log), nunca falla por eso.

Uso:
    python3 scripts/backfill_llm_related_domains.py --checkpoint data/checkpoint_2026-07-07.jsonl
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
from src.correlation import _extract_tls_and_content_sync, _fetch_plain_http_sync, correlate
from src.html_text_extraction import html_to_plain_text, is_worth_summarizing
from src.ollama_client import OllamaClient, OllamaError
from src.progress_bar import clear_progress_line, print_progress
from src.safe_mode import SafeModeFilter
from src.summary_cache import SummaryCache, content_cache_key
from src.tor_client import TorCircuitManager

from run_batch import append_checkpoint, load_checkpoint, load_into_databases, save_and_load  # noqa: E402


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _write_last_attempted(address: str) -> None:
    """
    Escribe en disco (sobrescribiendo) el ultimo dominio que se empezo a
    procesar, ANTES de tocar red ni Ollama. Si el equipo se apaga de
    golpe, la salida de la terminal se pierde con la ventana - este
    fichero, al escribirse a disco, sobrevive y permite identificar con
    certeza cual fue el ultimo dominio intentado. Best-effort: un fallo
    aqui (disco lleno, permisos) nunca debe interrumpir el relleno.
    """
    try:
        marker_path = config.DATA_DIR / "llm_backfill_last_attempted.txt"
        marker_path.write_text(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {address}\n", encoding="utf-8",
        )
    except Exception:
        pass


def needs_llm_backfill(address: str, enumeration, related_addresses: set[str], do_categorize: bool) -> bool:
    """
    Candidato a esta pasada: tiene alguna relacion de infraestructura
    confirmada, Y ademas le falta el resumen o (si la categorizacion
    esta activada) le falta la categoria.
    """
    if address not in related_addresses:
        return False
    if not enumeration.llm_summary:
        return True
    return do_categorize and not enumeration.llm_category


async def _fetch_body(address: str, enumeration) -> bytes | None:
    open_ports = {p.port for p in enumeration.open_ports}
    if 443 in open_ports:
        try:
            _, body = await asyncio.to_thread(_extract_tls_and_content_sync, address, 443)
            return body
        except Exception as exc:
            clear_progress_line()
            log(f"  {address}: fallo descargando via HTTPS ({exc!r})")
            return None
    if 80 in open_ports:
        try:
            return await asyncio.to_thread(_fetch_plain_http_sync, address, 80)
        except Exception as exc:
            clear_progress_line()
            log(f"  {address}: fallo descargando via HTTP ({exc!r})")
            return None
    return None


async def main(
    checkpoint_path: Path, limit: int | None = None, skip_reload: bool = False,
    only_address: str | None = None,
) -> int:
    if not config.ENABLE_LLM_SUMMARY:
        log("config.ENABLE_LLM_SUMMARY esta en False. No se hace nada "
            "(activalo explicitamente en config.py para usar esta funcion).")
        return 0
    do_categorize = config.ENABLE_LLM_CATEGORY
    if not do_categorize:
        log("Aviso: config.ENABLE_LLM_CATEGORY esta en False - se generaran "
            "resumenes pero NO categorias en esta pasada.")

    client = OllamaClient(host=config.OLLAMA_HOST, model=config.OLLAMA_MODEL, timeout=config.OLLAMA_TIMEOUT)
    log(f"Comprobando si Ollama esta disponible en {config.OLLAMA_HOST}...")
    if not client.is_available():
        log(f"Ollama no responde en {config.OLLAMA_HOST}. Instalalo/arrancalo "
            "y vuelve a lanzar este script. No se toca nada del resto del pipeline.")
        return 1
    log(f"Ollama disponible (modelo: {config.OLLAMA_MODEL}).")

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

    log("Calculando que dominios tienen relaciones de infraestructura...")
    all_results = list(all_records.values())
    evidences_all = [ev for _, _, ev in all_results]
    links = correlate(evidences_all)
    related_addresses = {l.address_a for l in links} | {l.address_b for l in links}
    log(f"Dominios con alguna relacion confirmada: {len(related_addresses)} de {len(all_records)}")

    safe_mode = SafeModeFilter()  # defensa en profundidad, ver src/safe_mode.py
    summary_cache = SummaryCache(config.LLM_SUMMARY_CACHE_PATH)
    category_cache = SummaryCache(config.LLM_CATEGORY_CACHE_PATH)
    breaker = CircuitBreaker(failure_threshold=5)

    if only_address:
        # Prueba de reproduccion aislada: forzar el procesamiento de UN
        # solo dominio en concreto (ignora el filtro de relaciones y el
        # estado ya guardado), para confirmar si es el causante de un
        # fallo sin arriesgar el resto del lote.
        match = all_records.get(only_address)
        if not match:
            log(f"No se encontro {only_address} en el checkpoint.")
            return 1
        record, enumeration, evidence = match
        enumeration.llm_summary = None
        enumeration.llm_category = None
        pending = [(record, enumeration, evidence)]
        log(f"Modo de prueba aislada: procesando SOLO {only_address}.")
    else:
        pending = [
            (record, enumeration, evidence)
            for record, enumeration, evidence in all_records.values()
            if needs_llm_backfill(record.address, enumeration, related_addresses, do_categorize)
        ]

    if limit is not None and limit < len(pending):
        total_pending = len(pending)
        pending = pending[:limit]
        log(f"Dominios con relaciones pendientes en total: {total_pending} "
            f"- por --limit {limit}, esta ejecucion procesara solo {len(pending)}.")
    else:
        log(f"Dominios con relaciones a procesar: {len(pending)}")

    if not pending:
        log("Nada que rellenar (ningun dominio con relaciones pendiente de resumen/categoria).")
        return 0

    stats = {"summarized": 0, "categorized": 0, "cache_hits": 0, "skipped_thin": 0,
              "skipped_circuit_open": 0, "failed": 0}
    start_time = time.monotonic()

    for idx, (record, enumeration, evidence) in enumerate(pending, start=1):
        address = record.address
        _write_last_attempted(address)

        # --- Resumen (si falta) ---
        if not enumeration.llm_summary:
            if safe_mode.is_blocked(address):
                clear_progress_line()
                log(f"  {address}: bloqueado por safe-mode, se omite")
                print_progress(idx, len(pending), start_time, suffix=str(stats))
                continue

            body = await _fetch_body(address, enumeration)
            plain_text = None
            if body:
                try:
                    text = body.decode("utf-8", errors="ignore")
                    plain_text = html_to_plain_text(text, max_chars=config.LLM_SUMMARY_MAX_INPUT_CHARS)
                except Exception:
                    plain_text = None

            if not body:
                # Fallo de descarga (ej. GeneralProxyError): probablemente
                # transitorio (Tor puede ir mejor en el siguiente intento),
                # NO se marca resumen centinela - se reintentara en la
                # proxima ejecucion.
                stats["skipped_thin"] += 1
                append_checkpoint(checkpoint_path, record, enumeration, evidence)
                print_progress(idx, len(pending), start_time, suffix=str(stats))
                continue

            if not plain_text or not is_worth_summarizing(plain_text, min_chars=config.LLM_SUMMARY_MIN_CHARS):
                # Contenido genuinamente insuficiente (la pagina SI se
                # descargo, pero esta vacia o es demasiado corta): esto es
                # permanente, reintentarlo en la siguiente ejecucion no
                # cambiaria nada. Se marca con un resumen centinela para
                # que --limit deje de contarlo como pendiente en cada
                # relanzamiento (sin esto, un dominio asi consume hueco de
                # --limit para siempre, sin que se note ningun avance real).
                stats["skipped_thin"] += 1
                enumeration.llm_summary = "Sin contenido suficiente para resumir."
                append_checkpoint(checkpoint_path, record, enumeration, evidence)
                print_progress(idx, len(pending), start_time, suffix=str(stats))
                continue

            key = content_cache_key(plain_text)
            cached_summary = summary_cache.get(key)
            if cached_summary is not None:
                enumeration.llm_summary = cached_summary
                stats["cache_hits"] += 1
            else:
                try:
                    breaker.guard()
                    summary = client.summarize(plain_text, max_words=config.LLM_SUMMARY_MAX_WORDS)
                    summary_cache.set(key, summary)
                    enumeration.llm_summary = summary
                    breaker.record_success()
                    stats["summarized"] += 1
                    await asyncio.sleep(config.LLM_SUMMARY_DELAY_SECONDS)
                except CircuitOpenError as exc:
                    clear_progress_line()
                    log(f"  {address}: {exc}")
                    stats["skipped_circuit_open"] += 1
                    print_progress(idx, len(pending), start_time, suffix=str(stats))
                    continue
                except OllamaError as exc:
                    breaker.record_failure()
                    stats["failed"] += 1
                    clear_progress_line()
                    log(f"  {address}: fallo generando resumen ({exc})")
                    print_progress(idx, len(pending), start_time, suffix=str(stats))
                    continue

        # --- Categoria (si falta y esta activada) ---
        if do_categorize and enumeration.llm_summary and not enumeration.llm_category:
            cat_key = content_cache_key(enumeration.llm_summary)
            cached_category = category_cache.get(cat_key)
            if cached_category is not None:
                enumeration.llm_category = cached_category
                stats["cache_hits"] += 1
            else:
                try:
                    breaker.guard()
                    category = client.classify(enumeration.llm_summary, config.LLM_CATEGORY_CHOICES)
                    category_cache.set(cat_key, category)
                    enumeration.llm_category = category
                    breaker.record_success()
                    stats["categorized"] += 1
                    await asyncio.sleep(config.LLM_SUMMARY_DELAY_SECONDS)
                except CircuitOpenError as exc:
                    clear_progress_line()
                    log(f"  {address}: {exc}")
                    stats["skipped_circuit_open"] += 1
                except OllamaError as exc:
                    breaker.record_failure()
                    stats["failed"] += 1
                    clear_progress_line()
                    log(f"  {address}: fallo clasificando ({exc})")

        append_checkpoint(checkpoint_path, record, enumeration, evidence)
        print_progress(idx, len(pending), start_time, suffix=str(stats))

    clear_progress_line()
    summary_cache.save()
    category_cache.save()
    log(f"Relleno completado (solo dominios con relaciones). {stats}")

    if skip_reload:
        log("--skip-reload activado: no se toca Neo4j ni Elasticsearch. "
            "Ejecuta despues scripts/recorrelate.py sobre este mismo checkpoint.")
        return 0

    log("Recargando Elasticsearch/Neo4j...")
    all_results = list(all_records.values())
    evidences_all = [ev for _, _, ev in all_results]
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
        "--limit", type=int, default=None,
        help="Procesar como maximo N dominios con relaciones (para probar antes de lanzar sobre todos)",
    )
    parser.add_argument(
        "--skip-reload", action="store_true",
        help="No tocar Neo4j/Elasticsearch al final (util si los tienes parados para liberar memoria). "
             "Ejecuta despues scripts/recorrelate.py sobre el mismo checkpoint.",
    )
    parser.add_argument(
        "--address", type=str, default=None,
        help="Prueba de reproduccion aislada: procesa SOLO esta direccion .onion "
             "(ignora el filtro de relaciones y el estado ya guardado), para "
             "confirmar si es la causante de un fallo sin arriesgar el resto del lote.",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(main(
        args.checkpoint, limit=args.limit, skip_reload=args.skip_reload, only_address=args.address,
    )))
