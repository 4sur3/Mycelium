"""
Tests del backend FastAPI del dashboard (F6). Sustituyen SearchIndex por
una version simulada, igual que en test_search_index.py, para no
necesitar una instancia real de Elasticsearch.
"""

import pytest
from fastapi.testclient import TestClient

import webapp.main as webapp_main


class _FakeGraphStore:
    related_response = {
        "shared_tls_cert": [], "shared_ssh_key": [], "shared_jarm": [],
        "shared_pgp_key": [], "shared_crypto_address": [], "similar_content": [],
    }
    raise_on_use = False

    def __enter__(self):
        if self.raise_on_use:
            raise ConnectionError("Neo4j no disponible")
        return self

    def __exit__(self, *exc):
        return False

    def find_related_infrastructure(self, address):
        return self.related_response

    def artifact_summary(self, top_n=5):
        return {
            "certificates_total": 10, "certificates_shared": 3,
            "top_certificates": [{"sha256": "cert-a", "subject": "CN=a", "degree": 4}],
            "ssh_keys_total": 5, "ssh_keys_shared": 1,
            "top_ssh_keys": [{"fingerprint": "fp-a", "key_type": "ssh-ed25519", "degree": 2}],
        }

    def find_relation_edges_among(self, addresses):
        return [("a.onion", "b.onion")] if addresses else []


class _FakeSearchIndex:
    """Doble de prueba de SearchIndex con datos y errores configurables."""

    search_response = [{"address": "a.onion", "http_title": "Resultado A"}]
    stats_response = {"total": 42, "by_status": {"alive": 30, "dead": 12}, "with_leaks": 5, "with_relations": 2}
    raise_on_use = False

    def __enter__(self):
        if self.raise_on_use:
            raise ConnectionError("Elasticsearch no disponible")
        return self

    def __exit__(self, *exc):
        return False

    def search(self, keyword, size=20):
        return self.search_response

    def filter_by_technology(self, technology, size=50):
        return [r for r in self.search_response if technology in r.get("technologies", [])]

    def filter_with_leaks(self, size=50):
        return self.search_response

    def stats(self):
        return self.stats_response

    def technology_distribution(self, top_n=10):
        return [{"name": "nginx", "count": 40}, {"name": "WordPress", "count": 12}]

    def port_distribution(self, top_n=10):
        return [{"name": "80/http", "count": 50}, {"name": "443/https", "count": 20}]

    def category_distribution(self, top_n=10):
        return [{"name": "marketplace", "count": 25}, {"name": "foro", "count": 10}]

    def list_geolocated(self, size=2000):
        return [{
            "address": "a.onion", "jurisdiction_country_code": "LT", "jurisdiction_source": "tls_cert",
            "http_title": "Jonavos Policijos Komisariatas", "llm_category": None,
            "status": "alive", "has_relations": True,
        }]

    def list_all(self, page=1, size=50, status=None, only_leaks=False, only_relations=False):
        results = self.search_response
        if status:
            results = [r for r in results if r.get("status") == status]
        if only_relations:
            results = [r for r in results if r.get("has_relations")]
        return {"total": len(results), "page": page, "size": size, "results": results}


@pytest.fixture
def client(monkeypatch):
    fake = _FakeSearchIndex()
    fake_graph = _FakeGraphStore()
    monkeypatch.setattr(webapp_main, "SearchIndex", lambda *a, **k: fake)
    monkeypatch.setattr(webapp_main, "GraphStore", lambda *a, **k: fake_graph)
    return TestClient(webapp_main.app), fake, fake_graph


def test_root_serves_html(client):
    test_client, _, _g = client
    response = test_client.get("/")
    assert response.status_code == 200
    assert "Onion Infrastructure Discovery" in response.text


def test_search_with_keyword(client):
    test_client, _, _g = client
    response = test_client.get("/api/search", params={"q": "hacker"})
    assert response.status_code == 200
    body = response.json()
    assert body["count"] == 1
    assert body["results"][0]["address"] == "a.onion"


def test_search_only_leaks_without_keyword(client):
    test_client, _, _g = client
    response = test_client.get("/api/search", params={"only_leaks": "true"})
    assert response.status_code == 200
    assert response.json()["count"] == 1


def test_search_empty_query_returns_empty(client):
    test_client, _, _g = client
    response = test_client.get("/api/search")
    assert response.status_code == 200
    assert response.json() == {"count": 0, "results": []}


def test_search_reports_backend_failure(client):
    test_client, fake, _g = client
    fake.raise_on_use = True
    response = test_client.get("/api/search", params={"q": "algo"})
    assert response.status_code == 503
    assert "error" in response.json()


def test_stats_endpoint(client):
    test_client, _, _g = client
    response = test_client.get("/api/stats")
    assert response.status_code == 200
    assert response.json()["total"] == 42


def test_stats_reports_backend_failure(client):
    test_client, fake, _g = client
    fake.raise_on_use = True
    response = test_client.get("/api/stats")
    assert response.status_code == 503


def test_list_default_pagination(client):
    test_client, _, _g = client
    response = test_client.get("/api/list")
    assert response.status_code == 200
    body = response.json()
    assert body["page"] == 1
    assert body["size"] == 50
    assert len(body["results"]) == 1


def test_list_with_custom_page_and_size(client):
    test_client, _, _g = client
    response = test_client.get("/api/list", params={"page": 3, "size": 25})
    assert response.status_code == 200
    body = response.json()
    assert body["page"] == 3
    assert body["size"] == 25


def test_list_reports_backend_failure(client):
    test_client, fake, _g = client
    fake.raise_on_use = True
    response = test_client.get("/api/list")
    assert response.status_code == 503


def test_list_with_status_filter(client):
    test_client, fake, _g = client
    fake.search_response = [
        {"address": "a.onion", "status": "alive"},
        {"address": "b.onion", "status": "dead"},
    ]
    response = test_client.get("/api/list", params={"status": "alive"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["results"][0]["address"] == "a.onion"


def test_related_returns_graph_results(client):
    test_client, _, fake_graph = client
    fake_graph.related_response = {
        "shared_tls_cert": [{"address": "b.onion", "relation": "shared_tls_cert", "via": "abc123"}],
        "shared_ssh_key": [], "shared_jarm": [], "shared_pgp_key": [],
        "shared_crypto_address": [], "similar_content": [],
    }
    response = test_client.get("/api/related/a.onion")
    assert response.status_code == 200
    body = response.json()
    assert body["address"] == "a.onion"
    assert body["related"]["shared_tls_cert"][0]["address"] == "b.onion"


def test_related_can_return_multiple_relation_types_simultaneously(client):
    """
    Regresion del fallo real: certificado y JARM son señales
    complementarias, no excluyentes - ambas deben poder venir pobladas
    a la vez en la respuesta, cada una en su propia clave.
    """
    test_client, _, fake_graph = client
    fake_graph.related_response = {
        "shared_tls_cert": [{"address": "b.onion", "relation": "shared_tls_cert", "via": "cert1"}],
        "shared_ssh_key": [], "shared_pgp_key": [], "shared_crypto_address": [], "similar_content": [],
        "shared_jarm": [{"address": "c.onion", "relation": "shared_jarm", "via": "jarmhash"}],
    }
    response = test_client.get("/api/related/a.onion")
    body = response.json()
    assert body["related"]["shared_tls_cert"][0]["address"] == "b.onion"
    assert body["related"]["shared_jarm"][0]["address"] == "c.onion"


def test_related_empty_when_no_relations(client):
    test_client, _, fake_graph = client
    fake_graph.related_response = {
        "shared_tls_cert": [], "shared_ssh_key": [], "shared_jarm": [],
        "shared_pgp_key": [], "shared_crypto_address": [], "similar_content": [],
    }
    response = test_client.get("/api/related/a.onion")
    assert response.status_code == 200
    assert all(v == [] for v in response.json()["related"].values())


def test_related_reports_backend_failure(client):
    test_client, _, fake_graph = client
    fake_graph.raise_on_use = True
    response = test_client.get("/api/related/a.onion")
    assert response.status_code == 503
    assert "error" in response.json()


def test_list_with_relations_filter(client):
    test_client, fake, _g = client
    fake.search_response = [
        {"address": "a.onion", "has_relations": True},
        {"address": "b.onion", "has_relations": False},
    ]
    response = test_client.get("/api/list", params={"only_relations": "true"})
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["results"][0]["address"] == "a.onion"


def test_dashboard_combines_search_and_graph_data(client):
    test_client, _, _g = client
    response = test_client.get("/api/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["stats"]["total"] == 42
    assert body["technologies"][0]["name"] == "nginx"
    assert body["ports"][0]["name"] == "80/http"
    assert body["categories"][0]["name"] == "marketplace"
    assert body["artifacts"]["certificates_total"] == 10
    assert "search_error" not in body
    assert "graph_error" not in body


def test_dashboard_partial_failure_when_only_graph_down(client):
    """
    Si Neo4j esta caido pero Elasticsearch no, el endpoint debe seguir
    devolviendo 200 con las estadisticas de busqueda y solo marcar el
    error de la parte de Neo4j - no debe fallar todo el dashboard por
    un solo componente caido.
    """
    test_client, _, fake_graph = client
    fake_graph.raise_on_use = True
    response = test_client.get("/api/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["stats"]["total"] == 42  # la parte de ES sigue funcionando
    assert "graph_error" in body
    assert "artifacts" not in body


def test_dashboard_partial_failure_when_only_search_down(client):
    test_client, fake, _g = client
    fake.raise_on_use = True
    response = test_client.get("/api/dashboard")
    assert response.status_code == 200
    body = response.json()
    assert body["artifacts"]["certificates_total"] == 10  # la parte de Neo4j sigue funcionando
    assert "search_error" in body
    assert "stats" not in body


def test_map_returns_points_and_edges(client):
    test_client, _f, _g = client
    response = test_client.get("/api/map")
    assert response.status_code == 200
    body = response.json()
    assert len(body["points"]) == 1
    point = body["points"][0]
    assert point["address"] == "a.onion"
    assert point["country_code"] == "LT"
    assert point["country_name"] == "Lituania"
    assert isinstance(point["lat"], float)
    assert isinstance(point["lng"], float)
    assert body["edges"] == [{"a": "a.onion", "b": "b.onion"}]
    assert "search_error" not in body
    assert "graph_error" not in body


def test_map_partial_failure_when_only_graph_down(client):
    """
    Si Neo4j esta caido, el mapa debe seguir mostrando los puntos (de
    Elasticsearch) sin lineas de conexion, no fallar por completo.
    """
    test_client, _f, fake_graph = client
    fake_graph.raise_on_use = True
    response = test_client.get("/api/map")
    assert response.status_code == 200
    body = response.json()
    assert len(body["points"]) == 1  # los puntos siguen ahi
    assert body["edges"] == []
    assert "graph_error" in body


def test_map_partial_failure_when_only_search_down(client):
    """Si Elasticsearch esta caido, no hay puntos (ni por tanto direcciones
    que pasar a Neo4j) - el endpoint sigue devolviendo 200 con el error."""
    test_client, fake, _g = client
    fake.raise_on_use = True
    response = test_client.get("/api/map")
    assert response.status_code == 200
    body = response.json()
    assert body["points"] == []
    assert body["edges"] == []
    assert "search_error" in body
