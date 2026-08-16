"""
Relleno dirigido de PGP, direcciones de criptomonedas, y artefactos
HTML (JavaScript/CSS/favicon/documentos) sobre un checkpoint existente.

Todos estos comparten la misma necesidad: volver a descargar el
contenido de cada dominio, ya que nunca se guarda el HTML crudo, solo
los hashes derivados. Se hace en UNA sola pasada de red (una descarga
por dominio, no una por cada tipo de dato) para no duplicar peticiones.
Sigue sin repetir discovery, enumeracion de puertos, ni
certificado/JARM/SSH (ya guardados).

Toca a todos los dominios con puerto 80 O 443 abierto.

Uso:
    python3 scripts/backfill_artifacts.py --checkpoint data/checkpoint_2026-07-07.jsonl
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
from src.correlation import (
    _extract_html_artifacts,
    _extract_identity_artifacts,
    _extract_tls_and_content_sync,
    _fetch_plain_http_sync,
    correlate,
)
from src.safe_mode import SafeModeFilter
from src.tor_client import TorCircuitManager

from run_batch import append_checkpoint, load_checkpoint, load_into_databases, save_and_load  # noqa: E402


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def needs_artifact_backfill(enumeration) -> bool:
    """Puerto 80 o 443 ya visto abierto: candidato a tener PGP/cripto."""
    return any(p.port in (80, 443) and p.open for p in enumeration.ports)


async def _fetch_body(address: str, enumeration) -> bytes | None:
    open_ports = {p.port for p in enumeration.open_ports}
    if 443 in open_ports:
        try:
            _, body = await asyncio.to_thread(_extract_tls_and_content_sync, address, 443)
            return body
        except Exception as exc:
            log(f"  {address}: fallo descargando via HTTPS ({exc!r})")
            return None
    if 80 in open_ports:
        try:
            return await asyncio.to_thread(_fetch_plain_http_sync, address, 80)
        except Exception as exc:
            log(f"  {address}: fallo descargando via HTTP ({exc!r})")
            return None
    return None


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
        if needs_artifact_backfill(enumeration)
    ]
    log(f"Dominios con HTTP/HTTPS abierto a reprocesar: {len(pending)} de {len(all_records)}")

    if not pending:
        log("Nada que rellenar (ningun dominio con puerto web abierto).")
        return 0

    semaphore = asyncio.Semaphore(config.CORRELATION_CONCURRENCY)
    pgp_found = 0
    crypto_found = 0
    html_artifacts_found = 0

    async def _bounded_extract(record, enumeration, evidence):
        nonlocal pgp_found, crypto_found, html_artifacts_found
        if safe_mode.is_blocked(record.address):
            log(f"  {record.address}: bloqueado por safe-mode, se omite")
            return
        async with semaphore:
            body = await _fetch_body(record.address, enumeration)
        if body:
            _extract_identity_artifacts(body, evidence)
            await _extract_html_artifacts(body, record.address, evidence)
            if evidence.pgp_key_hash:
                pgp_found += 1
            if evidence.crypto_addresses:
                crypto_found += 1
            if evidence.html_artifacts:
                html_artifacts_found += 1
        append_checkpoint(checkpoint_path, record, enumeration, evidence)

    t0 = time.monotonic()
    for idx, (record, enumeration, evidence) in enumerate(pending, start=1):
        await _bounded_extract(record, enumeration, evidence)
        if idx % 50 == 0 or idx == len(pending):
            log(f"Progreso: {idx}/{len(pending)} dominios procesados "
                f"({time.monotonic() - t0:.0f}s transcurridos). "
                f"PGP: {pgp_found}, cripto: {crypto_found}, artefactos HTML: {html_artifacts_found}.")

    log(f"Relleno completado. PGP: {pgp_found}. Dominios con cripto: {crypto_found}. "
        f"Dominios con algun artefacto HTML: {html_artifacts_found}.")

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

    log("Todo OK. Neo4j y Elasticsearch ya reflejan los datos de PGP/cripto/artefactos HTML rellenados.")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--checkpoint", required=True, type=Path,
        help="Ruta al fichero checkpoint_<fecha>.jsonl generado por run_batch.py",
    )
    args = parser.parse_args()
    sys.exit(asyncio.run(main(args.checkpoint)))
