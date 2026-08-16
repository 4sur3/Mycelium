"""
Tests del modulo de extraccion de enlaces a recursos (JS/CSS/favicon/
documentos). Puros, sin red: solo procesan texto HTML en memoria.
"""

from src.html_artifact_extraction import extract_resource_links


def test_extracts_javascript_and_css():
    html = """
    <script src="/static/app.js"></script>
    <link rel="stylesheet" href="/static/style.css">
    """
    result = extract_resource_links(html, "ejemplo.onion")
    assert result["javascript"] == ["http://ejemplo.onion/static/app.js"]
    assert result["css"] == ["http://ejemplo.onion/static/style.css"]


def test_extracts_favicon_from_explicit_link():
    html = '<link rel="icon" href="/img/icono.png">'
    result = extract_resource_links(html, "ejemplo.onion")
    assert result["favicon"] == ["http://ejemplo.onion/img/icono.png"]


def test_falls_back_to_default_favicon_path_when_not_declared():
    html = "<html><body>Sin favicon declarado</body></html>"
    result = extract_resource_links(html, "ejemplo.onion")
    assert result["favicon"] == ["http://ejemplo.onion/favicon.ico"]


def test_extracts_document_links_by_extension(monkeypatch):
    import config
    monkeypatch.setattr(config, "HTML_ARTIFACT_MAX_PER_TYPE", 10)
    html = """
    <a href="/docs/manual.pdf">Manual</a>
    <a href="/informe.docx">Informe</a>
    <a href="/hoja.xlsx">Hoja</a>
    <a href="/paquete.zip">Paquete</a>
    <a href="/pagina.html">No es documento</a>
    """
    result = extract_resource_links(html, "ejemplo.onion")
    assert len(result["document"]) == 4
    assert "http://ejemplo.onion/docs/manual.pdf" in result["document"]


def test_discards_external_domain_links():
    """
    Solo se resuelven enlaces al MISMO dominio: un script alojado en un
    dominio externo debe descartarse por completo, no seguirse.
    """
    html = '<script src="https://cdn-externo.onion/otro.js"></script>'
    result = extract_resource_links(html, "ejemplo.onion")
    assert result["javascript"] == []


def test_resolves_relative_and_absolute_same_domain_links():
    html = """
    <script src="relativo.js"></script>
    <script src="http://ejemplo.onion/absoluto.js"></script>
    """
    result = extract_resource_links(html, "ejemplo.onion")
    assert "http://ejemplo.onion/relativo.js" in result["javascript"]
    assert "http://ejemplo.onion/absoluto.js" in result["javascript"]


def test_respects_max_per_type_limit(monkeypatch):
    import config
    monkeypatch.setattr(config, "HTML_ARTIFACT_MAX_PER_TYPE", 2)
    html = "".join(f'<script src="/script{i}.js"></script>' for i in range(10))
    result = extract_resource_links(html, "ejemplo.onion")
    assert len(result["javascript"]) == 2


def test_dedupes_repeated_links():
    html = """
    <script src="/app.js"></script>
    <script src="/app.js"></script>
    """
    result = extract_resource_links(html, "ejemplo.onion")
    assert result["javascript"] == ["http://ejemplo.onion/app.js"]


def test_handles_malformed_html_without_raising():
    html = "<script src='/app.js' <<< esto no es HTML valido"
    result = extract_resource_links(html, "ejemplo.onion")
    assert isinstance(result, dict)


def test_no_scripts_returns_empty_list():
    result = extract_resource_links("<html><body>Sin scripts</body></html>", "ejemplo.onion")
    assert result["javascript"] == []
    assert result["css"] == []
    assert result["document"] == []
