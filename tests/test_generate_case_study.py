"""
Tests de la logica de renderizado del caso de estudio (F7). Puros, sin
red ni Neo4j: prueban unicamente que render_report() produce el
contenido esperado a partir de datos ya obtenidos.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from generate_case_study import render_report  # noqa: E402


def test_render_report_shared_jarm_not_mislabeled_as_content():
    """
    Regresion de un fallo real: al anadir JARM a find_best_case_study()
    no se actualizo render_report(), asi que un caso de JARM caia en la
    rama generica y se describia incorrectamente como similitud de
    contenido (ssdeep). Este test evita que vuelva a pasar.
    """
    case = {
        "relation": "shared_jarm",
        "evidence": "2ad2a" + "0" * 57,
        "detail_a": None,
        "detail_b": None,
        "onions": ["a.onion", "b.onion"],
        "degree": 2,
    }
    report = render_report(case, details={})
    assert "JARM compartido" in report
    assert "pila y configuracion TLS" in report
    assert "ssdeep" not in report.split("## 3. Evidencia tecnica")[1].split("## 4.")[0]


def test_render_report_shared_pgp_key():
    case = {
        "relation": "shared_pgp_key",
        "evidence": "pgphash123",
        "detail_a": None,
        "detail_b": None,
        "onions": ["a.onion", "b.onion"],
        "degree": 2,
    }
    report = render_report(case, details={})
    assert "clave PGP compartida" in report
    assert "pgphash123" in report
    assert "identificar a una PERSONA" in report


def test_render_report_shared_crypto_address():
    case = {
        "relation": "shared_crypto_address",
        "evidence": "BTC:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "detail_a": "BTC",
        "detail_b": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "onions": ["a.onion", "b.onion"],
        "degree": 2,
    }
    report = render_report(case, details={})
    assert "direccion de criptomoneda compartida" in report
    assert "BTC" in report
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in report


def test_render_report_shared_tls_cert():
    case = {
        "relation": "shared_tls_cert",
        "evidence": "abc123",
        "detail_a": "CN=test",
        "detail_b": "CN=test-ca",
        "onions": ["a.onion", "b.onion"],
        "degree": 2,
    }
    report = render_report(case, details={})
    assert "certificado TLS compartido" in report
    assert "abc123" in report
    assert "CN=test" in report
    assert "a.onion" in report and "b.onion" in report
    assert "MATCH (o:Onion)" in report  # consulta Cypher incluida


def test_render_report_shared_ssh_key():
    case = {
        "relation": "shared_ssh_key",
        "evidence": "fp999",
        "detail_a": "ssh-ed25519",
        "detail_b": None,
        "onions": ["a.onion", "b.onion", "c.onion"],
        "degree": 3,
    }
    report = render_report(case, details={})
    assert "clave SSH compartida" in report
    assert "fp999" in report
    assert "acceso administrativo compartido" in report


def test_render_report_similar_content_includes_caveat():
    case = {
        "relation": "similar_content",
        "evidence": "ssdeep_score=85",
        "detail_a": None,
        "detail_b": None,
        "onions": ["a.onion", "b.onion"],
        "degree": 2,
    }
    report = render_report(case, details={})
    assert "nivel de evidencia mas debil" in report


def test_render_report_includes_domain_details_when_available():
    case = {
        "relation": "shared_tls_cert",
        "evidence": "abc123",
        "detail_a": None,
        "detail_b": None,
        "onions": ["a.onion"],
        "degree": 2,
    }
    details = {
        "a.onion": {
            "http_title": "Mi tienda onion",
            "technologies": ["nginx", "WordPress"],
            "open_ports": ["80/http", "443/https"],
        }
    }
    report = render_report(case, details)
    assert "Mi tienda onion" in report
    assert "nginx, WordPress" in report
    assert "80/http, 443/https" in report


def test_render_report_handles_missing_details_gracefully():
    case = {
        "relation": "shared_tls_cert",
        "evidence": "abc123",
        "detail_a": None,
        "detail_b": None,
        "onions": ["sin-datos.onion"],
        "degree": 2,
    }
    report = render_report(case, details={})
    assert "sin titulo HTTP detectado" in report
    assert "sin tecnologia detectada" in report
