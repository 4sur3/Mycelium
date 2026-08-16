"""
Dashboard de busqueda (F6) - backend FastAPI.

No reimplementa logica de busqueda: reutiliza src.search_index.SearchIndex
tal cual ya esta probado. Este fichero solo traduce peticiones HTTP a
llamadas a ese modulo y sirve la interfaz estatica (webapp/static/).

Ejecutar con:
    uvicorn webapp.main:app --reload --port 8000
y abrir http://localhost:8000
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

from src.graph import GraphStore
from src.jurisdiction_hint import COUNTRY_DATA
from src.search_index import SearchIndex

STATIC_DIR = Path(__file__).parent / "static"


class NoCacheStaticMiddleware(BaseHTTPMiddleware):
    """
    Evita que el navegador cachee los ficheros estaticos (HTML/CSS/JS).
    Sin esto, tras cada cambio en webapp/static/ el navegador puede
    seguir sirviendo una copia antigua indefinidamente (ver conversacion:
    esto ya nos hizo perder tiempo varias veces creyendo que un cambio
    "no se habia aplicado" cuando en realidad si estaba en disco).
    """

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        return response


app = FastAPI(title="Onion Infrastructure Discovery")
app.add_middleware(NoCacheStaticMiddleware)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
def root() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/dashboard")
def api_dashboard() -> JSONResponse:
    """
    Resumen para la pantalla de aterrizaje del dashboard (Resumen): cifras
    globales, distribucion de tecnologia y puertos (Elasticsearch), y
    resumen de artefactos de infraestructura (Neo4j). Cada fuente se
    consulta de forma independiente: si Neo4j esta caido pero
    Elasticsearch no (o viceversa), se devuelve lo que si funciona junto
    con el error concreto de la parte que ha fallado, en vez de fallar
    todo el endpoint por un solo componente.
    """
    result: dict = {}

    try:
        with SearchIndex() as index:
            result["stats"] = index.stats()
            result["technologies"] = index.technology_distribution()
            result["ports"] = index.port_distribution()
            result["categories"] = index.category_distribution()
    except Exception as exc:
        result["search_error"] = str(exc)

    try:
        with GraphStore() as graph:
            result["artifacts"] = graph.artifact_summary()
    except Exception as exc:
        result["graph_error"] = str(exc)

    return JSONResponse(result)


@app.get("/api/map")
def api_map() -> JSONResponse:
    """
    Datos para el mapa de pistas de jurisdiccion (dashboard, bloque
    opcional). Los puntos vienen de Elasticsearch (dominios con
    jurisdiction_country_code resuelto, ver src/jurisdiction_hint.py);
    las lineas de conexion vienen de Neo4j (pares de esos mismos
    dominios con alguna relacion de infraestructura confirmada entre
    si). Cada fuente se consulta de forma independiente, mismo patron
    que /api/dashboard: si una falla, se devuelve lo que si funciona
    junto con el error concreto, en vez de fallar el endpoint entero.

    IMPORTANTE (ver src/jurisdiction_hint.py): esto es una PISTA debil de
    jurisdiccion derivada de datos que el propio operador ha filtrado sin
    querer (certificado TLS, titulo HTTP) - nunca una geolocalizacion de
    red real, que Tor hace indeterminable por diseño.
    """
    result: dict = {"points": [], "edges": []}

    addresses: list[str] = []
    try:
        with SearchIndex() as index:
            geolocated = index.list_geolocated()
        for doc in geolocated:
            code = doc.get("jurisdiction_country_code")
            if not code or code not in COUNTRY_DATA:
                continue
            name, lat, lng = COUNTRY_DATA[code]
            addresses.append(doc["address"])
            result["points"].append({
                "address": doc["address"],
                "country_code": code,
                "country_name": name,
                "lat": lat,
                "lng": lng,
                "source": doc.get("jurisdiction_source"),
                "http_title": doc.get("http_title"),
                "category": doc.get("llm_category"),
                "status": doc.get("status"),
                "has_relations": doc.get("has_relations", False),
            })
    except Exception as exc:
        result["search_error"] = str(exc)

    if addresses:
        try:
            with GraphStore() as graph:
                edges = graph.find_relation_edges_among(addresses)
            result["edges"] = [{"a": a, "b": b} for a, b in edges]
        except Exception as exc:
            result["graph_error"] = str(exc)

    return JSONResponse(result)


@app.get("/api/stats")
def api_stats() -> JSONResponse:
    try:
        with SearchIndex() as index:
            return JSONResponse(index.stats())
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)


@app.get("/api/list")
def api_list(
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="Filtrar por estado exacto (ej. 'alive')"),
    only_leaks: bool = Query(False, description="Solo dominios con alguna fuga extraida"),
    only_relations: bool = Query(False, description="Solo dominios con alguna relacion de infraestructura confirmada"),
) -> JSONResponse:
    try:
        with SearchIndex() as index:
            return JSONResponse(index.list_all(
                page=page, size=size, status=status,
                only_leaks=only_leaks, only_relations=only_relations,
            ))
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)


@app.get("/api/related/{address}")
def api_related(address: str) -> JSONResponse:
    """
    Infraestructura relacionada con un dominio, consultando el grafo de
    Neo4j (F5): otros dominios que comparten certificado TLS, clave SSH,
    JARM, clave PGP, direccion de cripto, o contenido similar. Devuelve
    un dict agrupado por tipo de relacion (certificado/JARM/SSH/PGP/
    cripto/contenido son señales complementarias, no excluyentes: se
    muestran cada una en su propio apartado, nunca una sustituyendo a
    otra). Alimenta el arbol/lista de relacion del panel de detalle
    (estilo Shodan).
    """
    try:
        with GraphStore() as graph:
            related = graph.find_related_infrastructure(address)
        return JSONResponse({"address": address, "related": related})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)


@app.get("/api/search")
def api_search(
    q: str = Query("", description="Palabra clave de busqueda"),
    technology: Optional[str] = Query(None, description="Filtrar por tecnologia exacta"),
    only_leaks: bool = Query(False, description="Solo dominios con alguna fuga extraida"),
) -> JSONResponse:
    try:
        with SearchIndex() as index:
            if q.strip():
                results = index.search(q.strip())
            elif technology:
                results = index.filter_by_technology(technology)
            elif only_leaks:
                results = index.filter_with_leaks()
            else:
                results = []
        return JSONResponse({"count": len(results), "results": results})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=503)
