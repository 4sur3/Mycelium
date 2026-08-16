"""
Tests del modulo de correlacion (F4). No requieren red ni Tor: prueban
la logica de agrupacion/correlacion sobre LeakEvidence construidos a mano,
y verifican que extract_leak_evidence respeta los puertos ya detectados
por enumeracion y el doble chequeo de safe-mode.
"""

import asyncio
import hashlib

import config
from src.correlation import correlate, extract_leak_evidence, fuzzy_hash_content
from src.models import CryptoAddressMention, HtmlArtifactMention, LeakEvidence, OnionRecord, ServiceEnumeration, ServicePort


def _evidence(address, tls=None, ssh=None, content=None, jarm=None, pgp=None, crypto=None, html_artifacts=None):
    return LeakEvidence(
        address=address,
        tls_cert_sha256=tls,
        ssh_fingerprint_sha256=ssh,
        content_fuzzy_hash=content,
        jarm_hash=jarm,
        pgp_key_hash=pgp,
        crypto_addresses=crypto or [],
        html_artifacts=html_artifacts or [],
    )


def test_correlate_groups_shared_javascript():
    js = HtmlArtifactMention(artifact_type="javascript", url="http://a.onion/app.js", hash="jshash1")
    js_same_hash_other_domain = HtmlArtifactMention(artifact_type="javascript", url="http://b.onion/app.js", hash="jshash1")
    evidences = [
        _evidence("a.onion", html_artifacts=[js]),
        _evidence("b.onion", html_artifacts=[js_same_hash_other_domain]),
        _evidence("c.onion", html_artifacts=[HtmlArtifactMention(artifact_type="javascript", url="x", hash="otro-hash")]),
    ]
    links = correlate(evidences)
    js_links = [l for l in links if l.relation_type == "shared_javascript"]
    assert len(js_links) == 1
    assert {js_links[0].address_a, js_links[0].address_b} == {"a.onion", "b.onion"}


def test_correlate_html_artifact_types_do_not_mix():
    """
    Regresion especifica del truco de cierre tardio en el bucle de
    correlate(): javascript, css, favicon y documento deben
    correlacionar cada uno por su cuenta, incluso si dos artefactos de
    TIPOS DISTINTOS comparten por casualidad el mismo valor de hash.
    """
    shared_hash = "hash-casual-compartido"
    evidences = [
        _evidence("a.onion", html_artifacts=[
            HtmlArtifactMention(artifact_type="javascript", url="x", hash=shared_hash),
        ]),
        _evidence("b.onion", html_artifacts=[
            HtmlArtifactMention(artifact_type="css", url="y", hash=shared_hash),
        ]),
    ]
    links = correlate(evidences)
    # a tiene el hash como JS, b lo tiene como CSS: NO deben correlacionar
    # entre si (son tipos de artefacto distintos), aunque el hash coincida.
    assert links == []


def test_correlate_all_four_html_artifact_types_independently():
    evidences = [
        _evidence("a.onion", html_artifacts=[
            HtmlArtifactMention(artifact_type="javascript", url="x", hash="jshash"),
            HtmlArtifactMention(artifact_type="css", url="x", hash="csshash"),
            HtmlArtifactMention(artifact_type="favicon", url="x", hash="favhash"),
            HtmlArtifactMention(artifact_type="document", url="x", hash="dochash"),
        ]),
        _evidence("b.onion", html_artifacts=[
            HtmlArtifactMention(artifact_type="javascript", url="y", hash="jshash"),
            HtmlArtifactMention(artifact_type="css", url="y", hash="csshash"),
            HtmlArtifactMention(artifact_type="favicon", url="y", hash="favhash"),
            HtmlArtifactMention(artifact_type="document", url="y", hash="dochash"),
        ]),
    ]
    links = correlate(evidences)
    relation_types = {l.relation_type for l in links}
    assert relation_types == {"shared_javascript", "shared_css", "shared_favicon", "shared_document"}
    assert len(links) == 4  # una relacion por tipo, no se duplican ni se pierden


def test_correlate_groups_shared_pgp_key():
    evidences = [
        _evidence("a.onion", pgp="pgp-hash-1"),
        _evidence("b.onion", pgp="pgp-hash-1"),
        _evidence("c.onion", pgp="pgp-hash-otro"),
    ]
    links = correlate(evidences)
    pgp_links = [l for l in links if l.relation_type == "shared_pgp_key"]
    assert len(pgp_links) == 1
    assert {pgp_links[0].address_a, pgp_links[0].address_b} == {"a.onion", "b.onion"}


def test_correlate_groups_shared_crypto_address():
    shared = CryptoAddressMention(currency="BTC", address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
    other = CryptoAddressMention(currency="XMR", address="otra-direccion-distinta")
    evidences = [
        _evidence("a.onion", crypto=[shared]),
        _evidence("b.onion", crypto=[shared, other]),
        _evidence("c.onion", crypto=[other]),
    ]
    links = correlate(evidences)
    crypto_links = [l for l in links if l.relation_type == "shared_crypto_address"]
    # BTC compartida entre a y b; XMR "otra-direccion-distinta" compartida entre b y c
    assert len(crypto_links) == 2
    pairs = {frozenset((l.address_a, l.address_b)) for l in crypto_links}
    assert frozenset({"a.onion", "b.onion"}) in pairs
    assert frozenset({"b.onion", "c.onion"}) in pairs


def test_correlate_crypto_address_no_link_when_no_overlap():
    evidences = [
        _evidence("a.onion", crypto=[CryptoAddressMention(currency="BTC", address="addr1")]),
        _evidence("b.onion", crypto=[CryptoAddressMention(currency="BTC", address="addr2")]),
    ]
    links = correlate(evidences)
    assert [l for l in links if l.relation_type == "shared_crypto_address"] == []


def test_correlate_groups_shared_tls_cert():
    evidences = [
        _evidence("a.onion", tls="cert123"),
        _evidence("b.onion", tls="cert123"),
        _evidence("c.onion", tls="cert999"),
    ]
    links = correlate(evidences)
    tls_links = [l for l in links if l.relation_type == "shared_tls_cert"]
    assert len(tls_links) == 1
    assert {tls_links[0].address_a, tls_links[0].address_b} == {"a.onion", "b.onion"}


def test_correlate_large_group_uses_star_topology_not_full_mesh():
    """
    Regresion de un fallo real en produccion: un certificado "por
    defecto" muy comun compartido por miles de dominios sin relacion
    real entre si genero >500.000 pares (todos contra todos, O(k^2)) y
    provoco un MemoryError al guardar el resultado. Con topologia en
    estrella, un grupo de k dominios debe generar EXACTAMENTE k-1
    enlaces (no k*(k-1)/2), y todos los miembros deben seguir apareciendo
    en el resultado (no se pierde informacion de conectividad).
    """
    n = 200
    evidences = [_evidence(f"domain{i}.onion", tls="certificado-muy-comun") for i in range(n)]
    links = correlate(evidences)
    tls_links = [l for l in links if l.relation_type == "shared_tls_cert"]

    assert len(tls_links) == n - 1  # O(k), no O(k^2) = 19900

    all_addresses_in_links = {l.address_a for l in tls_links} | {l.address_b for l in tls_links}
    all_domains = {f"domain{i}.onion" for i in range(n)}
    assert all_addresses_in_links == all_domains  # todos siguen conectados


def test_correlate_large_group_logs_warning(caplog):
    n = 60
    evidences = [_evidence(f"domain{i}.onion", ssh=f"fp-comun") for i in range(n)]
    with caplog.at_level("WARNING"):
        correlate(evidences)
    assert any("inusualmente grande" in record.message for record in caplog.records)


def test_correlate_groups_shared_jarm():
    jarm_hash = "2ad2a" + "0" * 57
    evidences = [
        _evidence("a.onion", jarm=jarm_hash),
        _evidence("b.onion", jarm=jarm_hash),
        _evidence("c.onion", jarm="otro-hash-completamente-distinto"),
    ]
    links = correlate(evidences)
    jarm_links = [l for l in links if l.relation_type == "shared_jarm"]
    assert len(jarm_links) == 1
    assert {jarm_links[0].address_a, jarm_links[0].address_b} == {"a.onion", "b.onion"}


def test_correlate_jarm_and_cert_are_independent_signals():
    """
    Un dominio puede compartir JARM con uno y certificado con otro
    distinto: son señales complementarias, no excluyentes entre si.
    """
    jarm_hash = "2ad2a" + "0" * 57
    evidences = [
        _evidence("a.onion", tls="cert-compartido", jarm=jarm_hash),
        _evidence("b.onion", tls="cert-compartido"),  # comparte certificado, no JARM
        _evidence("c.onion", jarm=jarm_hash),  # comparte JARM, no certificado
    ]
    links = correlate(evidences)
    cert_links = {(l.address_a, l.address_b) for l in links if l.relation_type == "shared_tls_cert"}
    jarm_links = {(l.address_a, l.address_b) for l in links if l.relation_type == "shared_jarm"}
    assert cert_links == {("a.onion", "b.onion")}
    assert jarm_links == {("a.onion", "c.onion")}


def test_correlate_groups_shared_ssh_key():
    evidences = [
        _evidence("a.onion", ssh="fp-abc"),
        _evidence("b.onion", ssh="fp-abc"),
        _evidence("c.onion", ssh="fp-xyz"),
    ]
    links = correlate(evidences)
    ssh_links = [l for l in links if l.relation_type == "shared_ssh_key"]
    assert len(ssh_links) == 1
    assert {ssh_links[0].address_a, ssh_links[0].address_b} == {"a.onion", "b.onion"}


def test_correlate_no_link_for_unique_artifacts():
    evidences = [
        _evidence("a.onion", tls="cert1"),
        _evidence("b.onion", tls="cert2"),
        _evidence("c.onion", ssh="fp1"),
    ]
    links = correlate(evidences)
    assert links == []


def test_correlate_similar_content_above_threshold():
    # Dos hashes ssdeep reales, calculados sobre textos casi identicos,
    # para que ssdeep.compare() devuelva un score alto de verdad (no
    # simulado), y confirmar que el umbral configurado los enlaza.
    base_text = ("Bienvenido a mi tienda onion. " * 50).encode()
    variant_text = ("Bienvenido a mi tienda onion. " * 50 + "footer distinto").encode()
    hash_a = fuzzy_hash_content(base_text)
    hash_b = fuzzy_hash_content(variant_text)

    evidences = [
        _evidence("a.onion", content=hash_a),
        _evidence("b.onion", content=hash_b),
    ]
    links = correlate(evidences)
    content_links = [l for l in links if l.relation_type == "similar_content"]
    assert len(content_links) == 1
    assert content_links[0].confidence > 0


def test_correlate_dissimilar_content_below_threshold():
    hash_a = fuzzy_hash_content(b"contenido totalmente distinto A " * 50)
    hash_b = fuzzy_hash_content(b"xyz123 qwe456 asd789 completamente diferente " * 50)

    evidences = [
        _evidence("a.onion", content=hash_a),
        _evidence("b.onion", content=hash_b),
    ]
    links = correlate(evidences)
    content_links = [l for l in links if l.relation_type == "similar_content"]
    assert content_links == []


def test_correlate_skips_content_comparison_above_scale_limit(monkeypatch):
    """
    Con datasets grandes, comparar contenido por pares es O(n^2) y no
    escala (ver conversacion sobre la ejecucion de 10000 dominios).
    Por encima del limite configurado, debe omitirse esa comparacion
    (con un aviso) mientras se mantiene la correlacion por certificado/
    SSH compartidos, que es O(n).
    """
    monkeypatch.setattr(config, "CONTENT_SIMILARITY_MAX_ITEMS", 3)

    evidences = [
        _evidence("a.onion", tls="cert-shared"),
        _evidence("b.onion", tls="cert-shared"),
        _evidence("c.onion", content="hash1"),
        _evidence("d.onion", content="hash2"),
        _evidence("e.onion", content="hash3"),
        _evidence("f.onion", content="hash4"),  # 4 con contenido > limite de 3
    ]
    links = correlate(evidences)

    # La correlacion por certificado (O(n)) se mantiene intacta
    cert_links = [l for l in links if l.relation_type == "shared_tls_cert"]
    assert len(cert_links) == 1

    # La comparacion de contenido (O(n^2)) se omite por superar el limite
    content_links = [l for l in links if l.relation_type == "similar_content"]
    assert content_links == []


def test_extract_leak_evidence_respects_safe_mode_double_check():
    class _AlwaysBlocked:
        def is_blocked(self, address):
            return True

        def hash_address(self, address):
            return "deadbeef"

    record = OnionRecord(address="bloqueado.onion")
    enumeration = ServiceEnumeration(
        address="bloqueado.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    result = asyncio.run(extract_leak_evidence(record, enumeration, safe_mode=_AlwaysBlocked()))
    assert result.tls_cert_sha256 is None
    assert result.content_fuzzy_hash is None


def test_extract_leak_evidence_fetches_and_hashes_html_artifacts(monkeypatch):
    page_html = b"""
    <html><body>
    <script src="/app.js"></script>
    <link rel="stylesheet" href="/style.css">
    </body></html>
    """
    resource_bytes = b"contenido de un script cualquiera"
    expected_hash = hashlib.sha256(resource_bytes).hexdigest()

    async def _fake_to_thread(func, *args, **kwargs):
        if func.__name__ == "_extract_tls_and_content_sync":
            return None, page_html
        if func.__name__ == "_fetch_resource_and_hash_sync":
            return expected_hash
        raise AssertionError(f"llamada inesperada a to_thread: {func}")

    async def _fake_compute_jarm(address, port=443):
        return None

    monkeypatch.setattr(asyncio, "to_thread", _fake_to_thread)
    monkeypatch.setattr("src.correlation.compute_jarm", _fake_compute_jarm)

    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(
        address="test.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    evidence = asyncio.run(extract_leak_evidence(record, enumeration))

    # 2 recursos explicitos (JS, CSS) + el candidato de favicon por defecto
    # (/favicon.ico), que siempre se intenta aunque no este declarado.
    assert len(evidence.html_artifacts) == 3
    types_found = {m.artifact_type for m in evidence.html_artifacts}
    assert types_found == {"javascript", "css", "favicon"}
    assert all(m.hash == expected_hash for m in evidence.html_artifacts)


def test_extract_leak_evidence_extracts_identity_artifacts_from_same_body(monkeypatch):
    """
    PGP y direcciones de cripto se extraen del MISMO body ya descargado
    para el fuzzy hash de contenido: no debe generarse ninguna descarga
    adicional.
    """
    btc_address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    page_html = f"""
    <html><body>
    Dona en BTC: {btc_address}
    -----BEGIN PGP PUBLIC KEY BLOCK-----
    mQINBFtest1234567890
    -----END PGP PUBLIC KEY BLOCK-----
    </body></html>
    """.encode("utf-8")

    async def _fake_to_thread(func, *args, **kwargs):
        if func.__name__ == "_extract_tls_and_content_sync":
            return None, page_html
        raise AssertionError(f"llamada inesperada a to_thread: {func}")

    async def _fake_compute_jarm(address, port=443):
        return None

    monkeypatch.setattr(asyncio, "to_thread", _fake_to_thread)
    monkeypatch.setattr("src.correlation.compute_jarm", _fake_compute_jarm)

    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(
        address="test.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    evidence = asyncio.run(extract_leak_evidence(record, enumeration))

    assert evidence.pgp_key_hash is not None
    assert len(evidence.crypto_addresses) == 1
    assert evidence.crypto_addresses[0].currency == "BTC"
    assert evidence.crypto_addresses[0].address == btc_address


def test_extract_leak_evidence_computes_jarm_when_443_open(monkeypatch):
    """
    JARM es complementario al certificado, no depende de que la
    extraccion del certificado tenga exito: debe calcularse siempre que
    el puerto 443 este abierto.
    """
    jarm_hash = "2ad2a" + "0" * 57

    async def _fake_to_thread(func, *args, **kwargs):
        if func.__name__ == "_extract_tls_and_content_sync":
            return None, b""  # sin certificado extraido
        raise AssertionError(f"llamada inesperada a to_thread: {func}")

    async def _fake_compute_jarm(address, port=443):
        return jarm_hash

    monkeypatch.setattr(asyncio, "to_thread", _fake_to_thread)
    monkeypatch.setattr("src.correlation.compute_jarm", _fake_compute_jarm)

    record = OnionRecord(address="test.onion")
    enumeration = ServiceEnumeration(
        address="test.onion",
        ports=[ServicePort(port=443, protocol="https", open=True)],
    )
    evidence = asyncio.run(extract_leak_evidence(record, enumeration))
    assert evidence.jarm_hash == jarm_hash
    assert evidence.tls_cert_sha256 is None


def test_extract_leak_evidence_skips_jarm_when_443_closed(monkeypatch):
    called = {"jarm": False}

    async def _fake_to_thread(func, *args, **kwargs):
        return b""

    async def _fake_compute_jarm(address, port=443):
        called["jarm"] = True
        return "no-deberia-llamarse"

    monkeypatch.setattr(asyncio, "to_thread", _fake_to_thread)
    monkeypatch.setattr("src.correlation.compute_jarm", _fake_compute_jarm)

    record = OnionRecord(address="sin-https.onion")
    enumeration = ServiceEnumeration(
        address="sin-https.onion",
        ports=[
            ServicePort(port=443, protocol="https", open=False),
            ServicePort(port=80, protocol="http", open=True),
        ],
    )
    evidence = asyncio.run(extract_leak_evidence(record, enumeration))
    assert called["jarm"] is False
    assert evidence.jarm_hash is None


def test_extract_leak_evidence_skips_tls_when_port_443_closed(monkeypatch):
    """
    Si la enumeracion (F2) no detecto el puerto 443 abierto, extract_leak_
    evidence no debe intentar ninguna conexion TLS: reutiliza lo que F2
    ya sabe en vez de volver a escanear puertos.
    """
    called = {"tls": False}

    async def _fake_to_thread(func, *args, **kwargs):
        if func.__name__ == "_extract_tls_and_content_sync":
            called["tls"] = True
        raise AssertionError("no deberia llamarse: el puerto 443 no estaba abierto")

    monkeypatch.setattr(asyncio, "to_thread", _fake_to_thread)

    record = OnionRecord(address="solo-ssh.onion")
    enumeration = ServiceEnumeration(
        address="solo-ssh.onion",
        ports=[ServicePort(port=443, protocol="https", open=False)],
    )
    result = asyncio.run(extract_leak_evidence(record, enumeration))
    assert called["tls"] is False
    assert result.tls_cert_sha256 is None
