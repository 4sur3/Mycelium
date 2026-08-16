"""
Relleno de resumenes de contenido generados con un LLM local (Ollama,
opcional) sobre un checkpoint existente.

Igual que backfill_artifacts.py, vuelve a descargar el contenido de cada
dominio (nunca se guarda el HTML crudo), lo convierte a texto plano, y
se lo pasa a Ollama para generar un resumen breve. Reutiliza una cache
por hash del texto plano (no del HTML crudo, para que dos paginas con
el mismo texto visible pero HTML ligeramente distinto sigan
compartiendo cache) - si varios dominios comparten plantilla, solo se
paga el coste del LLM una vez.

Apagado por defecto (config.ENABLE_LLM_SUMMARY = False): si no esta
activado, o si Ollama no esta corriendo, el script lo detecta al
principio y no hace nada, sin tocar el resto del pipeline.

Toca a todos los dominios con puerto 80 o 443 abierto que TODAVIA no
tengan un resumen (idempotente: relanzar el script no vuelve a
resumir lo ya hecho).

Uso:
    python3 scripts/backfill_summaries.py --checkpoint data/checkpoint_2026-07-07.jsonl
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
from src.correlation import _extract_tls_and_content_sync, _fetch_plain_http_sync
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
    """Ver el mismo helper en backfill_llm_related_domains.py."""
    try:
        marker_path = config.DATA_DIR / "llm_backfill_last_attempted.txt"
        marker_path.write_text(
            f"{time.strftime('%Y-%m-%d %H:%M:%S')} - {address}\n", encoding="utf-8",
        )
    except Exception:
        pass


def needs_summary_backfill(enumeration) -> bool:
    """Puerto 80 o 443 abierto, y todavia sin resumen (idempotente)."""
    has_web_port = any(p.port in (80, 443) and p.open for p in enumeration.ports)
    return has_web_port and not enumeration.llm_summary


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


async def main(checkpoint_path: Path, limit: int | None = None, skip_reload: bool = False) -> int:
    if not config.ENABLE_LLM_SUMMARY:
        log("config.ENABLE_LLM_SUMMARY esta en False. No se hace nada "
            "(activalo explicitamente en config.py para usar esta funcion).")
        return 0

    client = OllamaClient(host=config.OLLAMA_HOST, model=config.OLLAMA_MODEL, timeout=config.OLLAMA_TIMEOUT)
    log(f"Comprobando si Ollama esta disponible en {config.OLLAMA_HOST}...")
    if not client.is_available():
        log(f"Ollama no responde en {config.OLLAMA_HOST}. Instalalo/arrancalo "
            "(ver README) y vuelve a lanzar este script. No se toca nada del resto del pipeline.")
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

    safe_mode = SafeModeFilter()  # defensa en profundidad, ver src/safe_mode.py
    cache = SummaryCache(config.LLM_SUMMARY_CACHE_PATH)
    breaker = CircuitBreaker(failure_threshold=5)

    pending = [
        (record, enumeration, evidence)
        for record, enumeration, evidence in all_records.values()
        if needs_summary_backfill(enumeration)
    ]

    if limit is not None and limit < len(pending):
        total_pending = len(pending)
        pending = pending[:limit]
        log(f"Dominios pendientes en total: {total_pending} de {len(all_records)} "
            f"- por --limit {limit}, esta ejecucion procesara solo {len(pending)}.")
    else:
        log(f"Dominios a resumir: {len(pending)} de {len(all_records)}")

    if not pending:
        log("Nada que rellenar (ningun dominio pendiente de resumen).")
        return 0

    stats = {"summarized": 0, "cache_hits": 0, "skipped_thin": 0, "skipped_circuit_open": 0, "failed": 0}
    start_time = time.monotonic()

    for idx, (record, enumeration, evidence) in enumerate(pending, start=1):
        address = record.address
        _write_last_attempted(address)
        if safe_mode.is_blocked(address):
            clear_progress_line()
            log(f"  {address}: bloqueado por safe-mode, se omite")
            continue

        body = await _fetch_body(address, enumeration)
        if not body:
            print_progress(idx, len(pending), start_time, suffix=str(stats))
            continue
        try:
            text = body.decode("utf-8", errors="ignore")
        except Exception:
            print_progress(idx, len(pending), start_time, suffix=str(stats))
            continue
        plain_text = html_to_plain_text(text, max_chars=config.LLM_SUMMARY_MAX_INPUT_CHARS)

        if not is_worth_summarizing(plain_text, min_chars=config.LLM_SUMMARY_MIN_CHARS):
            # Contenido genuinamente insuficiente (permanente, no algo que
            # vaya a cambiar en el siguiente intento): se marca con un
            # resumen centinela para no seguir contandolo como pendiente
            # en cada relanzamiento (sin esto, consumiria hueco de --limit
            # para siempre sin ningun avance real).
            stats["skipped_thin"] += 1
            enumeration.llm_summary = "Sin contenido suficiente para resumir."
            append_checkpoint(checkpoint_path, record, enumeration, evidence)
            print_progress(idx, len(pending), start_time, suffix=str(stats))
            continue

        key = content_cache_key(plain_text)
        cached = cache.get(key)
        if cached is not None:
            enumeration.llm_summary = cached
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
            summary = client.summarize(plain_text, max_words=config.LLM_SUMMARY_MAX_WORDS)
            cache.set(key, summary)
            enumeration.llm_summary = summary
            breaker.record_success()
            stats["summarized"] += 1
            append_checkpoint(checkpoint_path, record, enumeration, evidence)
        except OllamaError as exc:
            breaker.record_failure()
            stats["failed"] += 1
            clear_progress_line()
            log(f"  {address}: fallo generando resumen ({exc})")

        # Pausa deliberada tras cada llamada REAL al modelo (no en cache
        # hits ni descartes por contenido vacio, que son baratos): dar
        # respiro termico al equipo en ejecuciones largas. Ver
        # config.LLM_SUMMARY_DELAY_SECONDS.
        await asyncio.sleep(config.LLM_SUMMARY_DELAY_SECONDS)

        print_progress(idx, len(pending), start_time, suffix=str(stats))

    clear_progress_line()
    cache.save()
    log(f"Relleno de resumenes completado. {stats}")
    log(f"Cache de resumenes: {cache.stats()}")

    if skip_reload:
        log("--skip-reload activado: no se toca Neo4j ni Elasticsearch. "
            "El checkpoint ya tiene todo guardado - cuando quieras, arranca "
            "esos dos servicios y ejecuta scripts/recorrelate.py sobre este "
            "mismo checkpoint para reflejarlo en el dashboard.")
        return 0

    log("Recargando Elasticsearch/Neo4j con los resumenes rellenados...")
    all_results = list(all_records.values())
    # Los resumenes son metadato descriptivo (ServiceEnumeration), no
    # afectan a correlate(): se recarga con los links ya existentes en el
    # checkpoint, sin recalcularlos.
    evidences_all = [ev for _, _, ev in all_results]
    from src.correlation import correlate
    links = correlate(evidences_all)

    out_path = save_and_load(all_results, all_results, links)
    log(f"Snapshot combinado actualizado guardado en: {out_path}")

    load_into_databases(all_results, links)

    log("Todo OK. Elasticsearch ya refleja los resumenes rellenados.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", required=True, type=Path,
        help="Ruta al fichero checkpoint_<fecha>.jsonl generado por run_batch.py",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Procesar como maximo N dominios (para probar la calidad de los "
             "resumenes antes de lanzarlo sobre el dataset completo)",
    )
    parser.add_argument(
        "--skip-reload", action="store_true",
        help="No tocar Neo4j/Elasticsearch al final (util si los tienes parados "
             "para liberar memoria durante el resumen). Ejecuta despues "
             "scripts/recorrelate.py sobre el mismo checkpoint para reflejarlo.",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.checkpoint, limit=args.limit, skip_reload=args.skip_reload)))
