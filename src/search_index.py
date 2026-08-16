"""
Busqueda por palabra clave (F6).

Combina en un unico documento por dominio los datos de las fases
anteriores (discovery, enumeracion, correlacion) para poder buscar por
titulo HTTP, tecnologia detectada, cabecera Server, puertos abiertos o
la propia direccion, sin tener que consultar varias fuentes a la vez.

El mapa de infraestructura (relaciones entre dominios) NO se reimplementa
aqui: para eso ya esta el grafo de Neo4j (F5), navegable visualmente en
Neo4j Browser (http://localhost:7474) sin necesitar una interfaz propia.
Este modulo se centra exclusivamente en la busqueda por palabra clave que
pedia el punto 4 del planteamiento original del TFM.

Nunca se indexa el HTML completo de un dominio, solo los metadatos
derivados que ya generaban F1/F2/F4 (titulo, tecnologia, cabeceras,
hashes). Los dominios descartados por safe-mode nunca llegan a este
modulo (ver DiscoveryPipeline, que los filtra antes de que avancen).
"""

from __future__ import annotations

import logging
from typing import Optional

from elasticsearch import Elasticsearch, NotFoundError

import config
from src.models import LeakEvidence, OnionRecord, ServiceEnumeration

logger = logging.getLogger(__name__)


def _extract_filename(url: str) -> Optional[str]:
    """
    Ultimo segmento no vacio de la ruta de una URL, ej.
    "http://x.onion/docs/DrugUsersBible.pdf" -> "DrugUsersBible.pdf".
    Misma logica, deliberadamente, que parseHtmlArtifactEntry() en
    webapp/static/app.js: el nombre que se indexa aqui para buscar debe
    ser exactamente el mismo que el que ya se muestra en pantalla, o
    buscar "por el nombre que veo" dejaria de funcionar de forma sutil.
    """
    segments = [s for s in url.split("/") if s]
    return segments[-1] if segments else None


INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "address": {"type": "keyword"},
            "status": {"type": "keyword"},
            "open_ports": {"type": "keyword"},
            "technologies": {"type": "keyword"},
            "http_title": {"type": "text"},
            "llm_summary": {"type": "text"},
            "llm_category": {"type": "keyword"},
            "jurisdiction_country_code": {"type": "keyword"},
            "jurisdiction_source": {"type": "keyword"},
            "server_header": {"type": "text"},
            "discovered_via": {"type": "keyword"},
            "has_tls_cert": {"type": "boolean"},
            "has_ssh_key": {"type": "boolean"},
            "has_jarm": {"type": "boolean"},
            "has_pgp_key": {"type": "boolean"},
            "has_crypto_address": {"type": "boolean"},
            "has_javascript": {"type": "boolean"},
            "has_css": {"type": "boolean"},
            "has_favicon": {"type": "boolean"},
            "has_document": {"type": "boolean"},
            "has_relations": {"type": "boolean"},
            "tls_cert_sha256": {"type": "keyword"},
            "tls_cert_subject": {"type": "text"},
            "tls_cert_issuer": {"type": "text"},
            "jarm_hash": {"type": "keyword"},
            "ssh_fingerprint_sha256": {"type": "keyword"},
            "ssh_key_type": {"type": "keyword"},
            "pgp_key_hash": {"type": "keyword"},
            "crypto_addresses": {"type": "keyword"},
            "html_artifacts": {"type": "keyword"},
            "artifact_filenames": {"type": "text"},
            "first_seen": {"type": "date"},
        }
    }
}


class SearchIndex:
    def __init__(
        self,
        url: str = config.ELASTICSEARCH_URL,
        index_name: str = config.ELASTICSEARCH_INDEX,
    ) -> None:
        self._client = Elasticsearch(url)
        self.index_name = index_name

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SearchIndex":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def ensure_index(self) -> None:
        """
        Comprueba si el indice existe usando GET (indices.get) en vez de
        HEAD (indices.exists). Se descarto indices.exists() porque, con
        ciertas combinaciones de version cliente/servidor, esa peticion
        HEAD concreta puede devolver un 400 en vez del 404 esperado (ver
        conversacion de depuracion: el mismo GET manual desde el navegador
        funcionaba perfectamente devolviendo un 404 valido). indices.get()
        usa el mismo verbo (GET) que ya se verifico manualmente que
        funciona bien contra este servidor.
        """
        try:
            self._client.indices.get(index=self.index_name)
            logger.info("Indice '%s' ya existe, se reutiliza", self.index_name)
        except NotFoundError:
            self._client.indices.create(index=self.index_name, body=INDEX_MAPPING)
            logger.info("Indice '%s' creado en Elasticsearch", self.index_name)

    def index_onion(
        self,
        record: OnionRecord,
        enumeration: Optional[ServiceEnumeration] = None,
        leak_evidence: Optional[LeakEvidence] = None,
        has_relations: bool = False,
    ) -> None:
        doc = {
            "address": record.address,
            "status": record.status.value,
            "discovered_via": record.discovered_via,
            "first_seen": record.first_seen.isoformat(),
            "open_ports": [],
            "technologies": [],
            "http_title": None,
            "llm_summary": None,
            "llm_category": None,
            "jurisdiction_country_code": None,
            "jurisdiction_source": None,
            "server_header": None,
            "has_tls_cert": False,
            "has_ssh_key": False,
            "has_jarm": False,
            "has_pgp_key": False,
            "has_crypto_address": False,
            "has_javascript": False,
            "has_css": False,
            "has_favicon": False,
            "has_document": False,
            "has_relations": has_relations,
            "tls_cert_sha256": None,
            "tls_cert_subject": None,
            "tls_cert_issuer": None,
            "jarm_hash": None,
            "ssh_fingerprint_sha256": None,
            "ssh_key_type": None,
            "pgp_key_hash": None,
            "crypto_addresses": [],
            "html_artifacts": [],
            "artifact_filenames": "",
        }
        if enumeration is not None:
            doc["open_ports"] = [f"{p.port}/{p.protocol}" for p in enumeration.open_ports]
            doc["technologies"] = enumeration.technologies
            doc["http_title"] = enumeration.http_title
            doc["llm_summary"] = enumeration.llm_summary
            doc["llm_category"] = enumeration.llm_category
            doc["jurisdiction_country_code"] = enumeration.jurisdiction_country_code
            doc["jurisdiction_source"] = enumeration.jurisdiction_source
            doc["server_header"] = enumeration.server_header
        if leak_evidence is not None:
            doc["has_tls_cert"] = leak_evidence.tls_cert_sha256 is not None
            doc["has_ssh_key"] = leak_evidence.ssh_fingerprint_sha256 is not None
            doc["has_jarm"] = leak_evidence.jarm_hash is not None
            doc["has_pgp_key"] = leak_evidence.pgp_key_hash is not None
            doc["has_crypto_address"] = len(leak_evidence.crypto_addresses) > 0
            artifact_types_present = {a.artifact_type for a in leak_evidence.html_artifacts}
            doc["has_javascript"] = "javascript" in artifact_types_present
            doc["has_css"] = "css" in artifact_types_present
            doc["has_favicon"] = "favicon" in artifact_types_present
            doc["has_document"] = "document" in artifact_types_present
            doc["tls_cert_sha256"] = leak_evidence.tls_cert_sha256
            doc["tls_cert_subject"] = leak_evidence.tls_cert_subject
            doc["tls_cert_issuer"] = leak_evidence.tls_cert_issuer
            doc["jarm_hash"] = leak_evidence.jarm_hash
            doc["ssh_fingerprint_sha256"] = leak_evidence.ssh_fingerprint_sha256
            doc["ssh_key_type"] = leak_evidence.ssh_key_type
            doc["pgp_key_hash"] = leak_evidence.pgp_key_hash
            doc["crypto_addresses"] = [
                f"{c.currency}:{c.address}" for c in leak_evidence.crypto_addresses
            ]
            doc["html_artifacts"] = [
                # tipo:hash:url - la URL siempre va al final, ya que puede
                # contener sus propios ":" (ej. "http://..."); el frontend
                # separa por el PRIMER ":" en cada nivel para no romperse.
                f"{a.artifact_type}:{a.hash}:{a.url}" for a in leak_evidence.html_artifacts
            ]
            # Campo separado, analizado como texto (a diferencia de
            # html_artifacts, que es keyword y por tanto NO buscable por
            # subcadena): permite encontrar un dominio por el nombre real
            # de un recurso enlazado (ej. buscar "DrugUsersBible" debe
            # encontrar el dominio que enlaza ese PDF), sin tener que
            # conocer ni el hash ni la URL completa de antemano.
            doc["artifact_filenames"] = " ".join(
                filter(None, (_extract_filename(a.url) for a in leak_evidence.html_artifacts))
            )

        self._client.index(index=self.index_name, id=record.address, document=doc)

    def search(self, keyword: str, size: int = 20) -> list[dict]:
        """
        Busqueda de texto libre. Combina dos estrategias, cada una donde
        tiene sentido:

        - multi_match con fuzziness sobre campos de texto libre en
          lenguaje natural (titulo HTTP, cabecera Server): tolera
          errores tipograficos, pero NO hace coincidencia por
          subcadena (buscar "word" no encuentra "wordpress" con esto,
          fuzziness compara tokens completos, no fragmentos).
        - wildcard *termino* sobre campos tipo identificador (direccion,
          tecnologia, nombre de fichero de artefacto): coincidencia real
          por subcadena, insensible a mayusculas. Necesario porque estos
          campos son identificadores compuestos (ej. "DrugUsersBible.pdf")
          donde buscar solo una parte del nombre debe funcionar - un
          fallo real detectado: buscar "DrugUsersBible" no encontraba
          nada, solo el nombre completo "DrugUsersBible.pdf" coincidia.
        """
        query = {
            "query": {
                "bool": {
                    "should": [
                        {
                            "multi_match": {
                                "query": keyword,
                                "fields": ["http_title", "server_header"],
                                "fuzziness": "AUTO",
                            }
                        },
                        {"wildcard": {"address": {"value": f"*{keyword}*", "case_insensitive": True}}},
                        {"wildcard": {"technologies": {"value": f"*{keyword}*", "case_insensitive": True}}},
                        {"wildcard": {"artifact_filenames": {"value": f"*{keyword}*", "case_insensitive": True}}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": size,
        }
        response = self._client.search(index=self.index_name, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]

    def filter_by_technology(self, technology: str, size: int = 50) -> list[dict]:
        query = {"query": {"term": {"technologies": technology}}, "size": size}
        response = self._client.search(index=self.index_name, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]

    def list_geolocated(self, size: int = 2000) -> list[dict]:
        """
        Dominios con una pista de jurisdiccion resuelta (ver
        src/jurisdiction_hint.py), para el mapa del dashboard. Solo
        devuelve los campos que la vista de mapa necesita realmente -
        no el documento completo - para mantener la respuesta ligera
        aunque el numero de puntos crezca.
        """
        query = {
            "query": {"exists": {"field": "jurisdiction_country_code"}},
            "size": size,
            "_source": [
                "address", "jurisdiction_country_code", "jurisdiction_source",
                "http_title", "llm_category", "status", "has_relations",
            ],
        }
        response = self._client.search(index=self.index_name, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]

    def filter_with_leaks(self, size: int = 50) -> list[dict]:
        """Dominios con al menos un tipo de fuga extraida (TLS o SSH)."""
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"has_tls_cert": True}},
                        {"term": {"has_ssh_key": True}},
                        {"term": {"has_jarm": True}},
                        {"term": {"has_pgp_key": True}},
                        {"term": {"has_crypto_address": True}},
                        {"term": {"has_javascript": True}},
                        {"term": {"has_css": True}},
                        {"term": {"has_favicon": True}},
                        {"term": {"has_document": True}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "size": size,
        }
        response = self._client.search(index=self.index_name, body=query)
        return [hit["_source"] for hit in response["hits"]["hits"]]

    def list_all(
        self,
        page: int = 1,
        size: int = 50,
        status: Optional[str] = None,
        only_leaks: bool = False,
        only_relations: bool = False,
    ) -> dict:
        """
        Listado paginado de todo lo indexado, ordenado por direccion, para
        la vista por defecto del dashboard. Admite filtro opcional por
        estado (p.ej. 'alive'), por presencia de fugas, y/o por presencia
        de relaciones de infraestructura confirmadas (ver has_relations),
        para que los contadores de la cabecera puedan enlazar a un
        listado filtrado y paginado, no solo a un numero.
        """
        must_clauses: list[dict] = []
        if status:
            must_clauses.append({"term": {"status": status}})
        if only_leaks:
            must_clauses.append({
                "bool": {
                    "should": [
                        {"term": {"has_tls_cert": True}},
                        {"term": {"has_ssh_key": True}},
                        {"term": {"has_jarm": True}},
                        {"term": {"has_pgp_key": True}},
                        {"term": {"has_crypto_address": True}},
                        {"term": {"has_javascript": True}},
                        {"term": {"has_css": True}},
                        {"term": {"has_favicon": True}},
                        {"term": {"has_document": True}},
                    ],
                    "minimum_should_match": 1,
                }
            })
        if only_relations:
            must_clauses.append({"term": {"has_relations": True}})

        query_clause = {"bool": {"must": must_clauses}} if must_clauses else {"match_all": {}}
        query = {
            "query": query_clause,
            "sort": [{"address": "asc"}],
            "from": max(page - 1, 0) * size,
            "size": size,
        }
        response = self._client.search(index=self.index_name, body=query)
        total_raw = response["hits"].get("total", 0)
        total = total_raw["value"] if isinstance(total_raw, dict) else total_raw
        results = [hit["_source"] for hit in response["hits"]["hits"]]
        return {"total": total, "page": page, "size": size, "results": results}

    def stats(self) -> dict:
        """
        Resumen agregado para la cabecera del dashboard: total indexado,
        desglose por estado, cuantos tienen alguna fuga extraida, y
        cuantos tienen alguna relacion de infraestructura confirmada
        (comparten certificado, clave SSH, o contenido similar con
        otro dominio del dataset).
        """
        query = {
            "size": 0,
            "aggs": {
                "by_status": {"terms": {"field": "status"}},
                "with_leaks": {
                    "filter": {
                        "bool": {
                            "should": [
                                {"term": {"has_tls_cert": True}},
                                {"term": {"has_ssh_key": True}},
                                {"term": {"has_jarm": True}},
                                {"term": {"has_pgp_key": True}},
                                {"term": {"has_crypto_address": True}},
                                {"term": {"has_javascript": True}},
                                {"term": {"has_css": True}},
                                {"term": {"has_favicon": True}},
                                {"term": {"has_document": True}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                },
                "with_relations": {"filter": {"term": {"has_relations": True}}},
            },
        }
        response = self._client.search(index=self.index_name, body=query)
        total_raw = response["hits"]["total"]
        total = total_raw["value"] if isinstance(total_raw, dict) else total_raw
        by_status = {
            b["key"]: b["doc_count"]
            for b in response["aggregations"]["by_status"]["buckets"]
        }
        with_leaks = response["aggregations"]["with_leaks"]["doc_count"]
        with_relations = response["aggregations"]["with_relations"]["doc_count"]
        return {
            "total": total,
            "by_status": by_status,
            "with_leaks": with_leaks,
            "with_relations": with_relations,
        }

    def category_distribution(self, top_n: int = 10) -> list[dict]:
        """
        Distribucion de dominios por categoria de servicio detectada por
        el LLM local (marketplace, foro, exchange_cripto...), para el
        dashboard resumen. Solo cuenta dominios que SI tienen categoria
        asignada (campo opcional, requiere config.ENABLE_LLM_CATEGORY).
        """
        query = {
            "size": 0,
            "aggs": {"top_categories": {"terms": {"field": "llm_category", "size": top_n}}},
        }
        response = self._client.search(index=self.index_name, body=query)
        buckets = response["aggregations"]["top_categories"]["buckets"]
        return [{"name": b["key"], "count": b["doc_count"]} for b in buckets]

    def technology_distribution(self, top_n: int = 10) -> list[dict]:
        """
        Top N tecnologias detectadas (WordPress, nginx, Apache...) con su
        recuento, para el dashboard resumen. Usa el campo 'technologies'
        (keyword) ya indexado por F2.
        """
        query = {
            "size": 0,
            "aggs": {"top_technologies": {"terms": {"field": "technologies", "size": top_n}}},
        }
        response = self._client.search(index=self.index_name, body=query)
        buckets = response["aggregations"]["top_technologies"]["buckets"]
        return [{"name": b["key"], "count": b["doc_count"]} for b in buckets]

    def port_distribution(self, top_n: int = 10) -> list[dict]:
        """
        Top N puertos/protocolos abiertos (ej. '80/http', '443/https')
        con su recuento, para el dashboard resumen.
        """
        query = {
            "size": 0,
            "aggs": {"top_ports": {"terms": {"field": "open_ports", "size": top_n}}},
        }
        response = self._client.search(index=self.index_name, body=query)
        buckets = response["aggregations"]["top_ports"]["buckets"]
        return [{"name": b["key"], "count": b["doc_count"]} for b in buckets]
