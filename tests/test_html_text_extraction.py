from src.html_text_extraction import html_to_plain_text, is_worth_summarizing


def test_strips_scripts_and_styles():
    html = "<script>malicious();</script><style>.a{color:red}</style><p>Hola mundo</p>"
    text = html_to_plain_text(html)
    assert "malicious" not in text
    assert "color:red" not in text
    assert "Hola mundo" in text


def test_collapses_whitespace():
    html = "<p>Hola      \n\n   mundo</p>"
    text = html_to_plain_text(html)
    assert text == "Hola mundo"


def test_truncates_to_max_chars():
    html = "<p>" + ("palabra " * 2000) + "</p>"
    text = html_to_plain_text(html, max_chars=100)
    assert len(text) <= 101  # margen del caracter de elipsis
    assert text.endswith("\u2026")


def test_handles_malformed_html_without_raising():
    html = "<p>Texto sin cerrar <div>anidado mal"
    text = html_to_plain_text(html)
    assert "Texto sin cerrar" in text


def test_empty_html_returns_empty_string():
    assert html_to_plain_text("") == ""


def test_is_worth_summarizing_rejects_short_text():
    assert is_worth_summarizing("") is False
    assert is_worth_summarizing("Error 404") is False


def test_is_worth_summarizing_accepts_real_content():
    text = "Bienvenido a nuestra tienda, vendemos productos variados con envio internacional garantizado."
    assert is_worth_summarizing(text) is True
