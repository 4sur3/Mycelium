"""
Tests del modulo de grafo (F5). No requieren una instancia real de Neo4j:
usan un driver/sesion simulados que capturan las queries y parametros
enviados, para verificar la logica de mapeo sin depender de una base de
datos externa (que ademas no esta disponible en este entorno de
desarrollo/CI, ver conversacion).
"""

from datetime import datetime, timezone

import pytest

from src.graph import GraphStore
from src.models import CryptoAddressMention, HtmlArtifactMention, InfrastructureLink, LeakEvidence, OnionRecord, OnionStatus, ServiceEnumeration, ServicePort


class _FakeResult:
    def __init__(self, single_value=None):
        self._single_value = single_value

    def single(self):
        return self._single_value


class _FakeSession:
    def __init__(self, calls: list, single_result=None):
        self._calls = calls
        self._single_result = single_result

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, params=None):
        self._calls.append((query, params or {}))
        return _FakeResult(self._single_result)


class _FakeDriver:
    def __init__(self, single_result=None):
        self.calls: list = []
        self._single_result = single_result

    def session(self):
        return _FakeSession(self.calls, single_result=self._single_result)

    def close(self):
        pass


class _FakeMultiResultSession:
    """
    Sesion simulada que devuelve un resultado distinto segun el contenido
    de la query (necesario para find_best_case_study, que lanza varias
    queries distintas en la misma sesion y elige entre sus resultados).
    """

    def __init__(self, responses_by_keyword: dict[str, dict | None]):
        self._responses = responses_by_keyword

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, params=None):
        for keyword, response in self._responses.items():
            if keyword in query:
                return _FakeResult(response)
        return _FakeResult(None)


class _FakeMultiResultDriver:
    def __init__(self, responses_by_keyword: dict[str, dict | None]):
        self._responses = responses_by_keyword

    def session(self):
        return _FakeMultiResultSession(self._responses)

    def close(self):
        pass


def _make_store_with_responses(monkeypatch, responses_by_keyword):
    fake_driver = _FakeMultiResultDriver(responses_by_keyword)
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    return GraphStore(uri="bolt://fake", user="fake", password="fake")


def test_find_best_case_study_prefers_higher_degree_cert_over_ssh(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"relation": "shared_tls_cert", "evidence": "cert1", "detail_a": None,
                         "detail_b": None, "onions": ["a.onion", "b.onion", "c.onion"], "degree": 3},
        "SSHKey": {"relation": "shared_ssh_key", "evidence": "fp1", "detail_a": None,
                   "detail_b": None, "onions": ["d.onion", "e.onion"], "degree": 2},
    })
    result = store.find_best_case_study()
    assert result["relation"] == "shared_tls_cert"
    assert result["degree"] == 3


def test_find_best_case_study_prefers_ssh_when_higher_degree(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"relation": "shared_tls_cert", "evidence": "cert1", "detail_a": None,
                         "detail_b": None, "onions": ["a.onion", "b.onion"], "degree": 2},
        "SSHKey": {"relation": "shared_ssh_key", "evidence": "fp1", "detail_a": None,
                   "detail_b": None, "onions": ["d.onion", "e.onion", "f.onion"], "degree": 3},
    })
    result = store.find_best_case_study()
    assert result["relation"] == "shared_ssh_key"
    assert result["degree"] == 3


def test_find_best_case_study_uses_jarm_when_no_cert_or_ssh(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": None,
        "SSHKey": None,
        "JarmFingerprint": {"relation": "shared_jarm", "evidence": "2ad2a" + "0" * 57,
                             "detail_a": None, "detail_b": None,
                             "onions": ["a.onion", "b.onion", "c.onion"], "degree": 3},
        "SIMILAR_CONTENT": {"relation": "similar_content", "evidence": "ssdeep_score=90",
                             "detail_a": None, "detail_b": None,
                             "onions": ["d.onion", "e.onion"], "degree": 2},
    })
    result = store.find_best_case_study()
    # JARM tiene prioridad sobre similitud de contenido, aunque ambos existan
    assert result["relation"] == "shared_jarm"
    assert result["degree"] == 3


def test_find_best_case_study_prefers_cert_over_jarm(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"relation": "shared_tls_cert", "evidence": "cert1", "detail_a": None,
                         "detail_b": None, "onions": ["a.onion", "b.onion"], "degree": 2},
        "SSHKey": None,
        "JarmFingerprint": {"relation": "shared_jarm", "evidence": "2ad2a" + "0" * 57,
                             "detail_a": None, "detail_b": None,
                             "onions": ["x.onion", "y.onion", "z.onion", "w.onion"], "degree": 4},
    })
    result = store.find_best_case_study()
    # El certificado compartido gana aunque JARM tenga mayor grado: es una
    # señal de identidad mas fuerte, no solo se compara por numero de dominios.
    assert result["relation"] == "shared_tls_cert"


def test_find_best_case_study_pgp_wins_tier1_when_highest_degree(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"relation": "shared_tls_cert", "evidence": "cert1", "detail_a": None,
                         "detail_b": None, "onions": ["a.onion", "b.onion"], "degree": 2},
        "SSHKey": None,
        "PGPKey": {"relation": "shared_pgp_key", "evidence": "pgp-hash",
                   "detail_a": None, "detail_b": None,
                   "onions": ["x.onion", "y.onion", "z.onion"], "degree": 3},
    })
    result = store.find_best_case_study()
    assert result["relation"] == "shared_pgp_key"
    assert result["degree"] == 3


def test_find_best_case_study_pgp_beats_jarm_and_crypto_regardless_of_degree(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": None,
        "SSHKey": None,
        "PGPKey": {"relation": "shared_pgp_key", "evidence": "pgp-hash",
                   "detail_a": None, "detail_b": None,
                   "onions": ["a.onion", "b.onion"], "degree": 2},
        "JarmFingerprint": {"relation": "shared_jarm", "evidence": "jarmhash",
                             "detail_a": None, "detail_b": None,
                             "onions": ["x.onion", "y.onion", "z.onion", "w.onion", "v.onion"], "degree": 5},
        "CryptoAddress": {"relation": "shared_crypto_address", "evidence": "BTC:addr1",
                           "detail_a": "BTC", "detail_b": "addr1",
                           "onions": ["p.onion", "q.onion", "r.onion", "s.onion"], "degree": 4},
    })
    result = store.find_best_case_study()
    # Nivel 1 (PGP) gana siempre sobre nivel 2 (JARM/cripto), aunque estos
    # ultimos conecten a muchos mas dominios.
    assert result["relation"] == "shared_pgp_key"


def test_find_best_case_study_uses_crypto_when_no_tier1(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": None,
        "SSHKey": None,
        "PGPKey": None,
        "JarmFingerprint": None,
        "CryptoAddress": {"relation": "shared_crypto_address", "evidence": "BTC:addr1",
                           "detail_a": "BTC", "detail_b": "addr1",
                           "onions": ["a.onion", "b.onion", "c.onion"], "degree": 3},
    })
    result = store.find_best_case_study()
    assert result["relation"] == "shared_crypto_address"
    assert result["degree"] == 3


def test_find_best_case_study_tier2_beats_content_regardless_of_confidence(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": None,
        "SSHKey": None,
        "PGPKey": None,
        "JarmFingerprint": None,
        "CryptoAddress": {"relation": "shared_crypto_address", "evidence": "BTC:addr1",
                           "detail_a": "BTC", "detail_b": "addr1",
                           "onions": ["a.onion", "b.onion"], "degree": 2},
        "SIMILAR_CONTENT": {"relation": "similar_content", "evidence": "ssdeep_score=99",
                             "detail_a": None, "detail_b": None,
                             "onions": ["x.onion", "y.onion"], "degree": 2},
    })
    result = store.find_best_case_study()
    assert result["relation"] == "shared_crypto_address"


def test_find_best_case_study_falls_back_to_similar_content(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": None,
        "SSHKey": None,
        "SIMILAR_CONTENT": {"relation": "similar_content", "evidence": "ssdeep_score=90",
                             "detail_a": None, "detail_b": None,
                             "onions": ["a.onion", "b.onion"], "degree": 2},
    })
    result = store.find_best_case_study()
    assert result["relation"] == "similar_content"


def test_find_best_case_study_returns_none_when_graph_empty(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": None,
        "SSHKey": None,
        "SIMILAR_CONTENT": None,
    })
    result = store.find_best_case_study()
    assert result is None


@pytest.fixture
def graph_store(monkeypatch):
    fake_driver = _FakeDriver()
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")
    return store, fake_driver


def test_ensure_constraints_runs_seven_statements(graph_store):
    store, driver = graph_store
    store.ensure_constraints()
    assert len(driver.calls) == 7
    assert all("CONSTRAINT" in q for q, _ in driver.calls)


def test_upsert_onion_sends_expected_params(graph_store):
    store, driver = graph_store
    record = OnionRecord(
        address="test.onion",
        status=OnionStatus.ALIVE,
        first_seen=datetime(2026, 7, 4, tzinfo=timezone.utc),
    )
    enumeration = ServiceEnumeration(
        address="test.onion",
        ports=[ServicePort(port=80, protocol="http", open=True)],
        technologies=["nginx"],
        http_title="Mi sitio",
        server_header="nginx/1.18",
    )
    store.upsert_onion(record, enumeration)

    assert len(driver.calls) == 1
    query, params = driver.calls[0]
    assert "MERGE (o:Onion" in query
    assert params["address"] == "test.onion"
    assert params["status"] == "alive"
    assert params["open_ports"] == ["80/http"]
    assert params["technologies"] == ["nginx"]
    assert params["http_title"] == "Mi sitio"


def test_upsert_leak_evidence_only_cert(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion", tls_cert_sha256="abc123")
    store.upsert_leak_evidence(evidence)

    assert len(driver.calls) == 1
    query, params = driver.calls[0]
    assert "Certificate" in query
    assert params["sha256"] == "abc123"


def test_upsert_leak_evidence_only_ssh(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion", ssh_fingerprint_sha256="fp999")
    store.upsert_leak_evidence(evidence)

    assert len(driver.calls) == 1
    query, params = driver.calls[0]
    assert "SSHKey" in query
    assert params["fingerprint"] == "fp999"


def test_upsert_leak_evidence_only_jarm(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion", jarm_hash="2ad2a" + "0" * 57)
    store.upsert_leak_evidence(evidence)

    assert len(driver.calls) == 1
    query, params = driver.calls[0]
    assert "JarmFingerprint" in query
    assert params["hash"] == "2ad2a" + "0" * 57


def test_upsert_leak_evidence_neither_runs_nothing(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion")
    store.upsert_leak_evidence(evidence)
    assert driver.calls == []


def test_upsert_leak_evidence_only_pgp(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion", pgp_key_hash="pgp-hash-abc")
    store.upsert_leak_evidence(evidence)

    assert len(driver.calls) == 1
    query, params = driver.calls[0]
    assert "PGPKey" in query
    assert params["hash"] == "pgp-hash-abc"


def test_upsert_leak_evidence_multiple_crypto_addresses(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(
        address="test.onion",
        crypto_addresses=[
            CryptoAddressMention(currency="BTC", address="addr1"),
            CryptoAddressMention(currency="XMR", address="addr2"),
        ],
    )
    store.upsert_leak_evidence(evidence)

    # Una query MERGE por cada direccion de la lista
    assert len(driver.calls) == 2
    ids = {params["id"] for _, params in driver.calls}
    assert ids == {"BTC:addr1", "XMR:addr2"}
    assert all("CryptoAddress" in q for q, _ in driver.calls)


def test_upsert_leak_evidence_empty_crypto_list_runs_nothing(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion", crypto_addresses=[])
    store.upsert_leak_evidence(evidence)
    assert driver.calls == []


def test_upsert_leak_evidence_multiple_html_artifacts(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(
        address="test.onion",
        html_artifacts=[
            HtmlArtifactMention(artifact_type="javascript", url="http://test.onion/app.js", hash="jshash1"),
            HtmlArtifactMention(artifact_type="favicon", url="http://test.onion/favicon.ico", hash="favhash1"),
        ],
    )
    store.upsert_leak_evidence(evidence)

    assert len(driver.calls) == 2
    hashes = {params["hash"] for _, params in driver.calls}
    assert hashes == {"jshash1", "favhash1"}
    assert all("HtmlArtifact" in q for q, _ in driver.calls)


def test_upsert_leak_evidence_empty_html_artifacts_runs_nothing(graph_store):
    store, driver = graph_store
    evidence = LeakEvidence(address="test.onion", html_artifacts=[])
    store.upsert_leak_evidence(evidence)
    assert driver.calls == []


def test_upsert_links_only_loads_similar_content(graph_store):
    store, driver = graph_store
    links = [
        InfrastructureLink(address_a="a.onion", address_b="b.onion",
                            relation_type="shared_tls_cert", evidence="cert1"),
        InfrastructureLink(address_a="c.onion", address_b="a.onion",
                            relation_type="similar_content", evidence="ssdeep_score=80", confidence=0.8),
    ]
    store.upsert_links(links)

    # Solo similar_content deberia generar una query (shared_tls_cert ya
    # queda representado via upsert_leak_evidence, ver docstring del modulo)
    assert len(driver.calls) == 1
    query, params = driver.calls[0]
    assert "SIMILAR_CONTENT" in query
    # Orden canonico: direcciones ordenadas alfabeticamente
    assert (params["a"], params["b"]) == tuple(sorted(("c.onion", "a.onion")))


class _FakeRowsSession:
    """
    Sesion simulada que devuelve una lista de filas iterables (no un
    unico .single()) segun el contenido de la query - necesaria para
    find_related_infrastructure, que ahora lanza una query independiente
    por tipo de relacion y itera sus resultados.
    """

    def __init__(self, rows_by_keyword: dict[str, list[dict]]):
        self._rows_by_keyword = rows_by_keyword

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, params=None):
        for keyword, rows in self._rows_by_keyword.items():
            if keyword in query:
                return list(rows)
        return []


class _FakeRowsDriver:
    def __init__(self, rows_by_keyword: dict[str, list[dict]]):
        self._rows_by_keyword = rows_by_keyword

    def session(self):
        return _FakeRowsSession(self._rows_by_keyword)

    def close(self):
        pass


def test_find_relation_edges_among_combines_shared_node_and_similar_content(monkeypatch):
    fake_driver = _FakeRowsDriver({
        "USES_CERT": [{"address_a": "a.onion", "address_b": "b.onion"}],
        "SIMILAR_CONTENT": [{"address_a": "b.onion", "address_b": "c.onion"}],
    })
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")

    edges = store.find_relation_edges_among(["a.onion", "b.onion", "c.onion"])

    assert edges == [("a.onion", "b.onion"), ("b.onion", "c.onion")]


def test_find_relation_edges_among_empty_addresses_returns_empty_without_querying(monkeypatch):
    fake_driver = _FakeRowsDriver({"USES_CERT": [{"address_a": "x", "address_b": "y"}]})
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")

    assert store.find_relation_edges_among([]) == []


def test_find_related_infrastructure_groups_by_relation_type(monkeypatch):
    fake_driver = _FakeRowsDriver({
        "USES_CERT": [{"via": "cert1", "addresses": ["a.onion", "b.onion"]}],
        "USES_SSH_KEY": [],
        "HAS_JARM": [{"via": "jarmhash", "addresses": ["a.onion", "c.onion"]}],
        "PUBLISHES_PGP_KEY": [],
        "MENTIONS_ADDRESS": [],
        "SIMILAR_CONTENT": [],
    })
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")

    results = store.find_related_infrastructure("a.onion")

    # Regresion del fallo real: certificado y JARM son señales
    # complementarias y AMBAS deben aparecer, cada una en su propio
    # apartado, nunca una pisando a la otra.
    assert results["shared_tls_cert"] == [
        {"address": "b.onion", "relation": "shared_tls_cert", "via": "cert1", "group_size": 2},
    ]
    assert results["shared_jarm"] == [
        {"address": "c.onion", "relation": "shared_jarm", "via": "jarmhash", "group_size": 2},
    ]
    assert results["shared_ssh_key"] == []
    assert results["shared_pgp_key"] == []
    assert results["shared_crypto_address"] == []
    assert results["similar_content"] == []


def test_find_related_infrastructure_reports_group_size_for_large_groups(monkeypatch):
    """
    Regresion especifica del cambio: group_size debe reflejar el TOTAL
    de dominios que comparten el valor, no solo cuantos se muestran
    relacionados con `address` - asi se puede distinguir en la interfaz
    una señal fuerte (grupo pequeño) de una probablemente generica
    (grupo grande, mismo umbral de >50 que usa correlate()).
    """
    many_addresses = ["a.onion"] + [f"generic{i}.onion" for i in range(70)]
    fake_driver = _FakeRowsDriver({
        "USES_CERT": [],
        "USES_SSH_KEY": [],
        "HAS_JARM": [{"via": "genericjarm", "addresses": many_addresses}],
        "PUBLISHES_PGP_KEY": [],
        "MENTIONS_ADDRESS": [],
        "SIMILAR_CONTENT": [],
    })
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")

    results = store.find_related_infrastructure("a.onion")

    assert len(results["shared_jarm"]) == 70
    assert all(r["group_size"] == 71 for r in results["shared_jarm"])


def test_find_related_infrastructure_handles_empty_or_null_addresses_defensively(monkeypatch):
    fake_driver = _FakeRowsDriver({
        "USES_CERT": [
            {"via": "cert1", "addresses": ["a.onion", "b.onion"]},
            {"via": "cert2", "addresses": None},
        ],
        "USES_SSH_KEY": [],
        "HAS_JARM": [],
        "PUBLISHES_PGP_KEY": [],
        "MENTIONS_ADDRESS": [],
        "SIMILAR_CONTENT": [],
    })
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")

    results = store.find_related_infrastructure("a.onion")
    assert results["shared_tls_cert"] == [
        {"address": "b.onion", "relation": "shared_tls_cert", "via": "cert1", "group_size": 2},
    ]


def test_find_related_infrastructure_all_types_simultaneously(monkeypatch):
    """
    Un dominio puede tener las señales a la vez, cada una con un
    dominio relacionado distinto: todas deben aparecer, cada una en su
    propio apartado.
    """
    fake_driver = _FakeRowsDriver({
        "USES_CERT": [{"via": "cert1", "addresses": ["a.onion", "cert.onion"]}],
        "USES_SSH_KEY": [{"via": "fp1", "addresses": ["a.onion", "ssh.onion"]}],
        "HAS_JARM": [{"via": "jarmhash", "addresses": ["a.onion", "jarm.onion"]}],
        "PUBLISHES_PGP_KEY": [{"via": "pgphash", "addresses": ["a.onion", "pgp.onion"]}],
        "MENTIONS_ADDRESS": [{"via": "BTC:addr1", "addresses": ["a.onion", "crypto.onion"]}],
        "'javascript'": [{"via": "jshash", "addresses": ["a.onion", "js.onion"]}],
        "'css'": [{"via": "csshash", "addresses": ["a.onion", "css.onion"]}],
        "'favicon'": [{"via": "favhash", "addresses": ["a.onion", "favicon.onion"]}],
        "'document'": [{"via": "dochash", "addresses": ["a.onion", "doc.onion"]}],
        "SIMILAR_CONTENT": [{"address": "content.onion", "via": "ssdeep_score=90"}],
    })
    monkeypatch.setattr("src.graph.GraphDatabase.driver", lambda *a, **k: fake_driver)
    store = GraphStore(uri="bolt://fake", user="fake", password="fake")

    results = store.find_related_infrastructure("a.onion")
    assert {rel: [r["address"] for r in items] for rel, items in results.items()} == {
        "shared_tls_cert": ["cert.onion"],
        "shared_ssh_key": ["ssh.onion"],
        "shared_jarm": ["jarm.onion"],
        "shared_pgp_key": ["pgp.onion"],
        "shared_crypto_address": ["crypto.onion"],
        "shared_javascript": ["js.onion"],
        "shared_css": ["css.onion"],
        "shared_favicon": ["favicon.onion"],
        "shared_document": ["doc.onion"],
        "similar_content": ["content.onion"],
    }


def test_artifact_summary_counts_totals_and_shared(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {
            "total": 10, "shared_total": 3,
            "items": [
                {"sha256": "cert-a", "subject": "CN=a", "degree": 4},
                {"sha256": "cert-b", "subject": "CN=b", "degree": 2},
                {"sha256": "cert-c", "subject": "CN=c", "degree": 1},
            ],
        },
        "SSHKey": {
            "total": 5, "shared_total": 1,
            "items": [
                {"fingerprint": "fp-a", "key_type": "ssh-ed25519", "degree": 2},
                {"fingerprint": "fp-b", "key_type": "ssh-rsa", "degree": 1},
            ],
        },
    })
    summary = store.artifact_summary(top_n=5)

    assert summary["certificates_total"] == 10
    assert summary["certificates_shared"] == 3
    assert summary["ssh_keys_total"] == 5
    assert summary["ssh_keys_shared"] == 1


def test_artifact_summary_top_certificates_sorted_by_degree_and_excludes_unshared(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {
            "total": 3, "shared_total": 2,
            "items": [
                {"sha256": "cert-low", "subject": "CN=low", "degree": 2},
                {"sha256": "cert-high", "subject": "CN=high", "degree": 5},
                {"sha256": "cert-unshared", "subject": "CN=unshared", "degree": 1},
            ],
        },
        "SSHKey": {"total": 0, "shared_total": 0, "items": []},
    })
    summary = store.artifact_summary(top_n=5)

    top = summary["top_certificates"]
    assert [c["sha256"] for c in top] == ["cert-high", "cert-low"]  # ordenado desc, sin el degree=1


def test_artifact_summary_respects_top_n_limit(monkeypatch):
    items = [{"sha256": f"cert-{i}", "subject": None, "degree": i + 2} for i in range(10)]
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"total": 10, "shared_total": 10, "items": items},
        "SSHKey": {"total": 0, "shared_total": 0, "items": []},
    })
    summary = store.artifact_summary(top_n=3)
    assert len(summary["top_certificates"]) == 3


def test_artifact_summary_handles_empty_graph(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"total": 0, "shared_total": 0, "items": []},
        "SSHKey": {"total": 0, "shared_total": 0, "items": []},
    })
    summary = store.artifact_summary()
    assert summary["certificates_total"] == 0
    assert summary["top_certificates"] == []


def test_artifact_summary_includes_pgp_and_crypto(monkeypatch):
    store = _make_store_with_responses(monkeypatch, {
        "Certificate": {"total": 0, "shared_total": 0, "items": []},
        "SSHKey": {"total": 0, "shared_total": 0, "items": []},
        "PGPKey": {
            "total": 4, "shared_total": 1,
            "items": [{"hash": "pgp-a", "degree": 3}, {"hash": "pgp-b", "degree": 1}],
        },
        "CryptoAddress": {
            "total": 8, "shared_total": 2,
            "items": [
                {"id": "BTC:addr1", "currency": "BTC", "address": "addr1", "degree": 5},
                {"id": "XMR:addr2", "currency": "XMR", "address": "addr2", "degree": 1},
            ],
        },
    })
    summary = store.artifact_summary(top_n=5)

    assert summary["pgp_keys_total"] == 4
    assert summary["pgp_keys_shared"] == 1
    assert [p["hash"] for p in summary["top_pgp_keys"]] == ["pgp-a"]

    assert summary["crypto_addresses_total"] == 8
    assert summary["crypto_addresses_shared"] == 2
    assert [c["id"] for c in summary["top_crypto_addresses"]] == ["BTC:addr1"]
