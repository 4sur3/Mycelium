"""
Tests del modulo de busqueda (F6). No requieren una instancia real de
Elasticsearch: usan un cliente simulado que captura las llamadas, igual
que en test_graph.py para Neo4j.
"""

from datetime import datetime, timezone

import pytest

from elasticsearch import NotFoundError
from src.models import CryptoAddressMention, HtmlArtifactMention, LeakEvidence, OnionRecord, OnionStatus, ServiceEnumeration, ServicePort
from src.search_index import SearchIndex, _extract_filename


class _FakeMeta:
    status = 404


class _FakeIndicesClient:
    def __init__(self):
        self.created = []
        self._existing = set()

    def get(self, index):
        if index not in self._existing:
            raise NotFoundError("index_not_found_exception", _FakeMeta(), {})
        return {index: {}}

    def create(self, index, body=None):
        self._existing.add(index)
        self.created.append((index, body))


class _FakeElasticsearch:
    def __init__(self, search_response=None):
        self.indices = _FakeIndicesClient()
        self.indexed_docs: list[dict] = []
        self.search_calls: list[dict] = []
        self._search_response = search_response or {"hits": {"hits": []}}

    def index(self, index, id, document):
        self.indexed_docs.append({"index": index, "id": id, "document": document})

    def search(self, index, body):
        self.search_calls.append({"index": index, "body": body})
        return self._search_response

    def close(self):
        pass


@pytest.fixture
def search_index(monkeypatch):
    fake_client = _FakeElasticsearch()
    monkeypatch.setattr("src.search_index.Elasticsearch", lambda *a, **k: fake_client)
    index = SearchIndex(url="http://fake", index_name="test_index")
    return index, fake_client


def test_ensure_index_creates_when_missing(search_index):
    index, client = search_index
    index.ensure_index()
    assert len(client.indices.created) == 1
    assert client.indices.created[0][0] == "test_index"


def test_ensure_index_skips_when_existing(search_index):
    index, client = search_index
    client.indices._existing.add("test_index")
    index.ensure_index()
    assert client.indices.created == []


def test_index_onion_stores_llm_summary(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(
        address="test.onion",
        llm_summary="Tienda que vende productos electronicos con envio internacional.",
    )
    index.index_onion(record, enumeration)
    doc = client.indexed_docs[0]["document"]
    assert doc["llm_summary"] == "Tienda que vende productos electronicos con envio internacional."


def test_index_onion_without_llm_summary_defaults_none(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(address="test.onion")
    index.index_onion(record, enumeration)
    doc = client.indexed_docs[0]["document"]
    assert doc["llm_summary"] is None


def test_extract_filename_from_url_with_path():
    assert _extract_filename("http://x.onion/docs/DrugUsersBible.pdf") == "DrugUsersBible.pdf"


def test_extract_filename_from_url_root_only():
    assert _extract_filename("http://x.onion/favicon.ico") == "favicon.ico"


def test_extract_filename_with_trailing_slash_takes_last_segment():
    """Con barra final, el ultimo segmento no vacio de la ruta se trata
    igual que un nombre de fichero - mismo comportamiento que el
    frontend (misma limitacion, no es un caso especial aqui)."""
    assert _extract_filename("http://x.onion/docs/") == "docs"


def test_extract_filename_none_when_url_empty():
    assert _extract_filename("") is None


def test_index_onion_stores_artifact_filenames(search_index):
    """
    Caso real que motivo este cambio: un documento con nombre propio
    (DrugUsersBible.pdf) debe quedar indexado de forma buscable por ese
    nombre, no solo accesible via su hash o URL completa.
    """
    index, client = search_index
    record = OnionRecord(address="test.onion")
    evidence = LeakEvidence(
        address="test.onion",
        html_artifacts=[
            HtmlArtifactMention(
                artifact_type="document",
                url="http://test.onion/docs/DrugUsersBible.pdf",
                hash="c068db87638c9e13c8dbad64d726dcb4d4d9422b85109b58248255692cda32b2",
            ),
            HtmlArtifactMention(artifact_type="javascript", url="http://test.onion/app.js", hash="jshash1"),
        ],
    )
    index.index_onion(record, ServiceEnumeration(address="test.onion"), evidence)
    doc = client.indexed_docs[0]["document"]
    assert "DrugUsersBible.pdf" in doc["artifact_filenames"]
    assert "app.js" in doc["artifact_filenames"]


def test_index_onion_without_artifacts_defaults_empty_filenames(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    index.index_onion(record, ServiceEnumeration(address="test.onion"))
    doc = client.indexed_docs[0]["document"]
    assert doc["artifact_filenames"] == ""


def test_index_onion_stores_jurisdiction(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(
        address="test.onion", jurisdiction_country_code="LT", jurisdiction_source="tls_cert",
    )
    index.index_onion(record, enumeration)
    doc = client.indexed_docs[0]["document"]
    assert doc["jurisdiction_country_code"] == "LT"
    assert doc["jurisdiction_source"] == "tls_cert"


def test_index_onion_without_jurisdiction_defaults_none(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(address="test.onion")
    index.index_onion(record, enumeration)
    doc = client.indexed_docs[0]["document"]
    assert doc["jurisdiction_country_code"] is None


def test_list_geolocated_queries_by_field_existence():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": [
            {"_source": {"address": "a.onion", "jurisdiction_country_code": "LT"}},
        ]},
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        result = index.list_geolocated()
    finally:
        module.Elasticsearch = orig

    assert result == [{"address": "a.onion", "jurisdiction_country_code": "LT"}]
    body = fake_client.search_calls[0]["body"]
    assert body["query"] == {"exists": {"field": "jurisdiction_country_code"}}


def test_index_onion_stores_llm_category(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(address="test.onion", llm_category="marketplace")
    index.index_onion(record, enumeration)
    doc = client.indexed_docs[0]["document"]
    assert doc["llm_category"] == "marketplace"


def test_index_onion_without_llm_category_defaults_none(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(address="test.onion")
    index.index_onion(record, enumeration)
    doc = client.indexed_docs[0]["document"]
    assert doc["llm_category"] is None


def test_index_onion_builds_expected_document(search_index):
    index, client = search_index
    record = OnionRecord(
        address="test.onion",
        status=OnionStatus.ALIVE,
        discovered_via=["ahmia"],
        first_seen=datetime(2026, 7, 4, tzinfo=timezone.utc),
    )
    enumeration = ServiceEnumeration(
        address="test.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
        technologies=["nginx"],
        http_title="Mi Sitio",
        server_header="nginx/1.18",
    )
    leak_evidence = LeakEvidence(address="test.onion", tls_cert_sha256="abc123")

    index.index_onion(record, enumeration, leak_evidence)

    assert len(client.indexed_docs) == 1
    doc = client.indexed_docs[0]["document"]
    assert doc["address"] == "test.onion"
    assert doc["open_ports"] == ["443/https"]
    assert doc["technologies"] == ["nginx"]
    assert doc["has_tls_cert"] is True
    assert doc["has_ssh_key"] is False


def test_index_onion_without_enumeration_or_evidence(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    index.index_onion(record)
    doc = client.indexed_docs[0]["document"]
    assert doc["open_ports"] == []
    assert doc["has_tls_cert"] is False


def test_search_uses_fuzzy_multi_match_on_free_text_fields(search_index):
    index, client = search_index
    index.search("wordpress")
    assert len(client.search_calls) == 1
    body = client.search_calls[0]["body"]
    should = body["query"]["bool"]["should"]
    multi_match = next(clause["multi_match"] for clause in should if "multi_match" in clause)
    assert multi_match["query"] == "wordpress"
    assert set(multi_match["fields"]) == {"http_title", "server_header"}


def test_search_uses_wildcard_substring_match_on_identifier_fields(search_index):
    """
    Regresion del fallo real: buscar "DrugUsersBible" (parte de un nombre
    de fichero) no encontraba nada, solo el nombre completo
    "DrugUsersBible.pdf" coincidia - multi_match con fuzziness no hace
    coincidencia por subcadena. Estos tres campos son identificadores
    compuestos (direccion, tecnologia, nombre de fichero) donde buscar
    solo una parte debe funcionar, via wildcard *termino*.
    """
    index, client = search_index
    index.search("DrugUsersBible")
    body = client.search_calls[0]["body"]
    should = body["query"]["bool"]["should"]
    wildcard_fields = {
        field: clause["wildcard"][field]
        for clause in should if "wildcard" in clause
        for field in clause["wildcard"]
    }
    assert set(wildcard_fields) == {"address", "technologies", "artifact_filenames"}
    for field_query in wildcard_fields.values():
        assert field_query["value"] == "*DrugUsersBible*"
        assert field_query["case_insensitive"] is True


def test_search_returns_sources_from_hits():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": [{"_source": {"address": "a.onion"}}, {"_source": {"address": "b.onion"}}]}
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        results = index.search("algo")
    finally:
        module.Elasticsearch = orig

    assert results == [{"address": "a.onion"}, {"address": "b.onion"}]


def test_filter_with_leaks_queries_boolean_should(search_index):
    index, client = search_index
    index.filter_with_leaks()
    body = client.search_calls[0]["body"]
    assert body["query"]["bool"]["minimum_should_match"] == 1
    should = body["query"]["bool"]["should"]
    assert {"term": {"has_tls_cert": True}} in should
    assert {"term": {"has_ssh_key": True}} in should
    assert {"term": {"has_jarm": True}} in should
    assert {"term": {"has_pgp_key": True}} in should
    assert {"term": {"has_crypto_address": True}} in should
    assert {"term": {"has_javascript": True}} in should
    assert {"term": {"has_css": True}} in should
    assert {"term": {"has_favicon": True}} in should
    assert {"term": {"has_document": True}} in should


def test_stats_parses_aggregations():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"total": {"value": 42, "relation": "eq"}, "hits": []},
        "aggregations": {
            "by_status": {"buckets": [{"key": "alive", "doc_count": 30}, {"key": "dead", "doc_count": 12}]},
            "with_leaks": {"doc_count": 5},
            "with_relations": {"doc_count": 2},
        },
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        stats = index.stats()
    finally:
        module.Elasticsearch = orig

    assert stats == {
        "total": 42,
        "by_status": {"alive": 30, "dead": 12},
        "with_leaks": 5,
        "with_relations": 2,
    }


def test_stats_handles_plain_integer_total():
    """Algunas versiones/configuraciones de ES devuelven hits.total como
    entero simple en vez de {"value": N, "relation": ...}."""
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"total": 7, "hits": []},
        "aggregations": {
            "by_status": {"buckets": []},
            "with_leaks": {"doc_count": 0},
            "with_relations": {"doc_count": 0},
        },
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        stats = index.stats()
    finally:
        module.Elasticsearch = orig

    assert stats["total"] == 7


def test_list_all_uses_pagination_and_sort(search_index):
    index, client = search_index
    index.list_all(page=2, size=10)
    body = client.search_calls[0]["body"]
    assert body["query"] == {"match_all": {}}
    assert body["sort"] == [{"address": "asc"}]
    assert body["from"] == 10  # (page 2 - 1) * size 10
    assert body["size"] == 10


def test_list_all_filters_by_status(search_index):
    index, client = search_index
    index.list_all(status="alive")
    body = client.search_calls[0]["body"]
    assert body["query"] == {"bool": {"must": [{"term": {"status": "alive"}}]}}


def test_list_all_filters_by_leaks(search_index):
    index, client = search_index
    index.list_all(only_leaks=True)
    body = client.search_calls[0]["body"]
    must = body["query"]["bool"]["must"]
    assert len(must) == 1
    assert must[0]["bool"]["minimum_should_match"] == 1


def test_list_all_combines_status_and_leaks_filters(search_index):
    index, client = search_index
    index.list_all(status="alive", only_leaks=True)
    body = client.search_calls[0]["body"]
    must = body["query"]["bool"]["must"]
    assert {"term": {"status": "alive"}} in must
    assert len(must) == 2


def test_list_all_returns_total_and_results():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {
            "total": {"value": 3, "relation": "eq"},
            "hits": [{"_source": {"address": "a.onion"}}, {"_source": {"address": "b.onion"}}],
        }
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        result = index.list_all(page=1, size=2)
    finally:
        module.Elasticsearch = orig

    assert result["total"] == 3
    assert result["page"] == 1
    assert len(result["results"]) == 2


def test_index_onion_stores_full_leak_detail(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    leak_evidence = LeakEvidence(
        address="test.onion",
        tls_cert_sha256="abc123",
        tls_cert_subject="CN=test",
        tls_cert_issuer="CN=test-ca",
        ssh_fingerprint_sha256="fp999",
        ssh_key_type="ssh-ed25519",
    )
    index.index_onion(record, leak_evidence=leak_evidence)
    doc = client.indexed_docs[0]["document"]
    assert doc["tls_cert_subject"] == "CN=test"
    assert doc["ssh_key_type"] == "ssh-ed25519"


def test_index_onion_stores_pgp_and_crypto_addresses(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    leak_evidence = LeakEvidence(
        address="test.onion",
        pgp_key_hash="pgp-hash-abc",
        crypto_addresses=[
            CryptoAddressMention(currency="BTC", address="addr1"),
            CryptoAddressMention(currency="XMR", address="addr2"),
        ],
    )
    index.index_onion(record, leak_evidence=leak_evidence)
    doc = client.indexed_docs[0]["document"]
    assert doc["has_pgp_key"] is True
    assert doc["pgp_key_hash"] == "pgp-hash-abc"
    assert doc["has_crypto_address"] is True
    assert doc["crypto_addresses"] == ["BTC:addr1", "XMR:addr2"]


def test_index_onion_without_pgp_or_crypto_defaults_false(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    leak_evidence = LeakEvidence(address="test.onion")
    index.index_onion(record, leak_evidence=leak_evidence)
    doc = client.indexed_docs[0]["document"]
    assert doc["has_pgp_key"] is False
    assert doc["has_crypto_address"] is False
    assert doc["crypto_addresses"] == []


def test_index_onion_stores_html_artifacts(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    leak_evidence = LeakEvidence(
        address="test.onion",
        html_artifacts=[
            HtmlArtifactMention(artifact_type="javascript", url="http://test.onion/app.js", hash="jshash1"),
            HtmlArtifactMention(artifact_type="favicon", url="http://test.onion/favicon.ico", hash="favhash1"),
        ],
    )
    index.index_onion(record, leak_evidence=leak_evidence)
    doc = client.indexed_docs[0]["document"]
    assert doc["has_javascript"] is True
    assert doc["has_favicon"] is True
    assert doc["has_css"] is False
    assert doc["has_document"] is False
    assert doc["html_artifacts"] == [
        "javascript:jshash1:http://test.onion/app.js",
        "favicon:favhash1:http://test.onion/favicon.ico",
    ]


def test_index_onion_without_html_artifacts_defaults_false(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    leak_evidence = LeakEvidence(address="test.onion")
    index.index_onion(record, leak_evidence=leak_evidence)
    doc = client.indexed_docs[0]["document"]
    assert doc["has_javascript"] is False
    assert doc["has_css"] is False
    assert doc["has_favicon"] is False
    assert doc["has_document"] is False
    assert doc["html_artifacts"] == []


def test_index_onion_stores_has_relations_flag(search_index):
    index, client = search_index
    record = OnionRecord(address="test.onion")
    index.index_onion(record, has_relations=True)
    doc = client.indexed_docs[0]["document"]
    assert doc["has_relations"] is True

    index.index_onion(record)  # por defecto, False
    doc2 = client.indexed_docs[1]["document"]
    assert doc2["has_relations"] is False


def test_list_all_filters_by_relations(search_index):
    index, client = search_index
    index.list_all(only_relations=True)
    body = client.search_calls[0]["body"]
    assert {"term": {"has_relations": True}} in body["query"]["bool"]["must"]


def test_stats_includes_with_relations():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"total": {"value": 42, "relation": "eq"}, "hits": []},
        "aggregations": {
            "by_status": {"buckets": [{"key": "alive", "doc_count": 30}]},
            "with_leaks": {"doc_count": 5},
            "with_relations": {"doc_count": 3},
        },
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        stats = index.stats()
    finally:
        module.Elasticsearch = orig

    assert stats["with_relations"] == 3


def test_category_distribution_parses_buckets():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": []},
        "aggregations": {
            "top_categories": {"buckets": [
                {"key": "marketplace", "doc_count": 25},
                {"key": "foro", "doc_count": 10},
            ]}
        },
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        result = index.category_distribution()
    finally:
        module.Elasticsearch = orig

    assert result == [{"name": "marketplace", "count": 25}, {"name": "foro", "count": 10}]
    body = fake_client.search_calls[0]["body"]
    assert body["aggs"]["top_categories"]["terms"]["field"] == "llm_category"


def test_technology_distribution_builds_terms_aggregation():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": []},
        "aggregations": {"top_technologies": {"buckets": []}},
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        index.technology_distribution(top_n=5)
    finally:
        module.Elasticsearch = orig

    body = fake_client.search_calls[0]["body"]
    assert body["aggs"]["top_technologies"]["terms"] == {"field": "technologies", "size": 5}


def test_technology_distribution_parses_buckets():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": []},
        "aggregations": {
            "top_technologies": {"buckets": [
                {"key": "nginx", "doc_count": 40},
                {"key": "WordPress", "doc_count": 12},
            ]}
        },
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        result = index.technology_distribution()
    finally:
        module.Elasticsearch = orig

    assert result == [{"name": "nginx", "count": 40}, {"name": "WordPress", "count": 12}]


def test_port_distribution_builds_terms_aggregation():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": []},
        "aggregations": {"top_ports": {"buckets": []}},
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        index.port_distribution(top_n=7)
    finally:
        module.Elasticsearch = orig

    body = fake_client.search_calls[0]["body"]
    assert body["aggs"]["top_ports"]["terms"] == {"field": "open_ports", "size": 7}


def test_port_distribution_parses_buckets():
    fake_client = _FakeElasticsearch(search_response={
        "hits": {"hits": []},
        "aggregations": {
            "top_ports": {"buckets": [
                {"key": "80/http", "doc_count": 50},
                {"key": "443/https", "doc_count": 20},
            ]}
        },
    })
    import src.search_index as module
    orig = module.Elasticsearch
    module.Elasticsearch = lambda *a, **k: fake_client
    try:
        index = SearchIndex(url="http://fake", index_name="test_index")
        result = index.port_distribution()
    finally:
        module.Elasticsearch = orig

    assert result == [{"name": "80/http", "count": 50}, {"name": "443/https", "count": 20}]
