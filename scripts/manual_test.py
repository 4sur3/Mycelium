"""
Script de prueba manual para F0/F1.

Se ejecuta en tu maquina, con Tor real corriendo (via docker-compose o
instalado localmente). Este script NO se ejecuta en el sandbox de
desarrollo porque necesita salida real a la red Tor.

Uso:
    python3 scripts/manual_test.py

Que valida, en orden, parando en el primer fallo:
    1. El puerto SOCKS de Tor esta escuchando (chequeo TCP simple).
    2. El puerto de control responde y se puede autenticar (stem).
    3. Se puede forzar un circuito nuevo (NEWNYM).
    4. AhmiaSource.is_alive() responde True a traves de Tor.
    5. AhmiaSource.fetch_listing() devuelve al menos una direccion onion.
    6. El pipeline completo corre y genera un snapshot en data/.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

# En Windows, el ProactorEventLoop (por defecto desde Python 3.8) tiene
# incompatibilidades conocidas con librerias async de bajo nivel como
# aiohttp-socks y stem: sintomas tipicos son avisos "WinError 10038" al
# cerrar sockets y ServerDisconnectedError persistentes e identicos en
# cada reintento, independientemente del servicio de destino. Forzar el
# SelectorEventLoop antes de arrancar el bucle resuelve esta clase de
# problema. No tiene efecto en Linux/Mac (la funcion no existe ahi, de
# ahi el chequeo de plataforma).
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from src.correlation import correlate, extract_leak_evidence_batch
from src.crawler import DiscoveryPipeline
from src.enumeration import enumerate_batch
from src.graph import GraphStore
from src.models import OnionStatus
from src.search_index import SearchIndex
from src.seeds.ahmia import AhmiaSource
from src.tor_client import TorCircuitManager, check_socks_port_reachable, create_tor_session

SAMPLE_SIZE_ENUMERATION = 5  # cortesia con la red Tor: no escanear el dataset entero en una prueba manual


def step(msg: str) -> None:
    print(f"\n--- {msg} ---")


async def main() -> int:
    step("1. Puerto SOCKS de Tor")
    if not check_socks_port_reachable():
        print(f"FALLO: no se puede conectar a {config.TOR_SOCKS_HOST}:{config.TOR_SOCKS_PORT}")
        print("Revisa que Tor este corriendo (docker compose up -d tor) y que el puerto")
        print("este publicado correctamente.")
        return 1
    print("OK: puerto SOCKS alcanzable")

    step("2. Bootstrap de Tor")
    try:
        with TorCircuitManager() as tor_ctl:
            print("Esperando a que Tor complete el bootstrap (puede tardar hasta ~60s tras un arranque en frio)...")
            tor_ctl.wait_for_bootstrap(timeout=90)
            print("OK: Tor ha completado el bootstrap (100%)")
    except TimeoutError as exc:
        print(f"FALLO: {exc}")
        return 1
    except Exception as exc:
        print(f"FALLO: no se pudo hablar con el control port ({exc})")
        print("Revisa ControlPort/CookieAuthentication en tu torrc, o")
        print("TOR_CONTROL_PASSWORD en config.py si usas contrasena.")
        return 1

    step("3. Control port y renovacion de circuito")
    try:
        with TorCircuitManager() as tor_ctl:
            tor_ctl.renew_circuit()
        print("OK: control port responde y NEWNYM funciona")
    except Exception as exc:
        print(f"FALLO: no se pudo hablar con el control port ({exc})")
        return 1

    step("4-5. AhmiaSource via Tor real")
    async with create_tor_session() as session:
        ahmia = AhmiaSource()
        alive = await ahmia.is_alive(session)
        print(f"Ahmia alive: {alive}")
        if not alive:
            print("FALLO: Ahmia no respondio. Puede ser un problema puntual de red Tor,")
            print("reintenta antes de asumir que el codigo esta mal.")
            return 1

        addresses = await ahmia.fetch_listing(session)
        print(f"Direcciones .onion obtenidas de Ahmia: {len(addresses)}")
        if addresses:
            print("Ejemplo (primeras 3):")
            for addr in addresses[:3]:
                print(f"  - {addr}")
        else:
            print("AVISO: Ahmia esta vivo pero no se extrajo ninguna direccion.")
            print("Puede que el HTML de /onions/ haya cambiado de formato; revisar")
            print("ONION_ADDRESS_RE y la estructura de la pagina en src/seeds/ahmia.py.")

    step("6. Pipeline completo + snapshot")
    async with create_tor_session() as session:
        pipeline = DiscoveryPipeline(sources=[AhmiaSource()])
        records = await pipeline.run(session)
        out_path = pipeline.save_snapshot(tag="manual_test")
        print(f"OK: {len(records)} dominios en el registro final")
        print(f"Snapshot guardado en: {out_path}")

    step("7. Enumeracion de servicios (F2) sobre una muestra pequena")
    sample = [r for r in records if r.status != OnionStatus.BLOCKED][:SAMPLE_SIZE_ENUMERATION]
    print(f"Enumerando {len(sample)} dominios de muestra (de cortesia con la red Tor, no se escanean todos)...")
    async with create_tor_session() as session:
        enumerations = await enumerate_batch(sample, session, safe_mode=pipeline.safe_mode)

    for enum_result in enumerations:
        open_ports = enum_result.open_ports
        ports_str = ", ".join(f"{p.port}/{p.protocol}" for p in open_ports) or "ninguno abierto"
        print(f"  - {enum_result.address}: puertos abiertos = [{ports_str}]")
        if enum_result.technologies:
            print(f"      tecnologias detectadas: {', '.join(enum_result.technologies)}")
        if enum_result.http_title:
            print(f"      titulo HTTP: {enum_result.http_title}")

    step("8. Correlacion de fugas (F4) sobre la misma muestra")
    records_with_enum = list(zip(sample, enumerations))
    leak_evidences = await extract_leak_evidence_batch(records_with_enum, safe_mode=pipeline.safe_mode)

    for ev in leak_evidences:
        parts = []
        if ev.tls_cert_sha256:
            parts.append(f"TLS cert={ev.tls_cert_sha256[:12]}...")
        if ev.ssh_fingerprint_sha256:
            parts.append(f"SSH fp={ev.ssh_fingerprint_sha256[:12]}...")
        if ev.content_fuzzy_hash:
            parts.append("fuzzy hash de contenido obtenido")
        print(f"  - {ev.address}: {'; '.join(parts) if parts else 'sin evidencia extraida'}")

    links = correlate(leak_evidences)
    if links:
        print(f"\n{len(links)} relacion(es) de infraestructura encontradas en la muestra:")
        for link in links:
            print(f"  - {link.address_a} <-> {link.address_b} ({link.relation_type}, confianza={link.confidence:.2f})")
    else:
        print("\nNinguna relacion de infraestructura encontrada en esta muestra pequena (esperado: la")
        print("probabilidad de coincidencia sube con el tamano de la muestra).")

    step("9. Grafo de infraestructura (F5): carga y consulta")
    try:
        with GraphStore() as graph:
            graph.ensure_constraints()
            for record, enum_result in zip(sample, enumerations):
                graph.upsert_onion(record, enum_result)
            for ev in leak_evidences:
                graph.upsert_leak_evidence(ev)
            graph.upsert_links(links)
            print(f"OK: {len(sample)} dominios cargados en Neo4j (constraints, nodos y relaciones)")

            # Consulta de ejemplo sobre el primer dominio de la muestra
            example_address = sample[0].address
            related = graph.find_related_infrastructure(example_address)
            if related:
                print(f"Infraestructura relacionada con {example_address}:")
                for r in related:
                    print(f"  - {r['address']} (via {r['relation']}: {r['via']})")
            else:
                print(f"Ninguna infraestructura relacionada encontrada para {example_address} "
                      "(esperado con una muestra tan pequena).")
    except Exception as exc:
        print(f"FALLO: no se pudo conectar/cargar en Neo4j ({exc})")
        print("Revisa que 'docker compose up -d neo4j' este corriendo y que")
        print("NEO4J_URI/NEO4J_USER/NEO4J_PASSWORD en config.py coincidan con docker-compose.yml.")
        return 1

    step("10. Busqueda por palabra clave (F6): indexar y consultar")
    related_addresses = {l.address_a for l in links} | {l.address_b for l in links}
    try:
        with SearchIndex() as search:
            search.ensure_index()
            for record, enum_result, ev in zip(sample, enumerations, leak_evidences):
                search.index_onion(record, enum_result, ev, has_relations=record.address in related_addresses)
            print(f"OK: {len(sample)} dominios indexados en Elasticsearch")

            results = search.search("hacker")
            print(f"Busqueda 'hacker': {len(results)} resultado(s)")
            for r in results:
                print(f"  - {r['address']}: {r.get('http_title')}")

            with_leaks = search.filter_with_leaks()
            print(f"Dominios con al menos una fuga extraida (TLS o SSH): {len(with_leaks)}")
    except Exception as exc:
        print(f"FALLO: no se pudo conectar/indexar en Elasticsearch ({exc})")
        print("Revisa que 'docker compose up -d elasticsearch' este corriendo.")
        return 1

    print("\nTodo OK. El esqueleto F0/F1/F2/F4/F5/F6 funciona end-to-end contra Tor, Neo4j y Elasticsearch reales.")
    print("Para ver el mapa visual de infraestructura, abre http://localhost:7474 (Neo4j Browser)")
    print("y ejecuta, por ejemplo: MATCH (o:Onion)-[r]-(x) RETURN o, r, x LIMIT 100")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
