from src.jurisdiction_hint import (
    extract_country_from_cert_subject,
    extract_country_hint_from_title,
    resolve_jurisdiction,
)


def test_extract_country_from_cert_subject_real_example():
    """El caso real observado en el dataset: comisaria de policia lituana."""
    subject = (
        "1.2.840.113549.1.9.1=bumbuliukas@protonirockerxow.onion,"
        "CN=6mugs73ir4ae2xqqsfmuvniumyd4dlqzjw6pn2r5t2wnfotw6lodzhad.onion,"
        "O=Jonavos Policijos Komisariatas,L=Jonava,C=LT"
    )
    assert extract_country_from_cert_subject(subject) == "LT"


def test_extract_country_from_cert_subject_simple():
    assert extract_country_from_cert_subject("CN=example.onion,O=Org,C=DE") == "DE"


def test_extract_country_from_cert_subject_country_field_only():
    assert extract_country_from_cert_subject("C=US") == "US"


def test_extract_country_from_cert_subject_none_when_absent():
    assert extract_country_from_cert_subject("CN=example.onion,O=Anarcho-Copy Tor Services") is None


def test_extract_country_from_cert_subject_none_when_input_none():
    assert extract_country_from_cert_subject(None) is None


def test_extract_country_from_cert_subject_unknown_code_returns_none():
    """Un codigo de pais que no esta en COUNTRY_DATA (invalido o poco
    comun) no debe hacer que la funcion falle, simplemente no da pista."""
    assert extract_country_from_cert_subject("CN=example.onion,C=ZZ") is None


def test_extract_country_hint_from_title_matches_keyword():
    assert extract_country_hint_from_title("Jonavos Policijos Komisariatas") == "LT"


def test_extract_country_hint_from_title_case_insensitive():
    assert extract_country_hint_from_title("BUNDESKRIMINALAMT - Achtung") == "DE"


def test_extract_country_hint_from_title_none_when_no_match():
    assert extract_country_hint_from_title("Onion Bitcoin wallets") is None


def test_extract_country_hint_from_title_none_when_input_none():
    assert extract_country_hint_from_title(None) is None


def test_resolve_jurisdiction_prefers_cert_over_title():
    """El certificado tiene prioridad sobre el titulo cuando ambos dan pista."""
    hint = resolve_jurisdiction(
        tls_cert_subject="CN=example.onion,C=FR",
        tls_cert_issuer=None,
        http_title="Polizei Achtung",  # apuntaria a DE si se usara
    )
    assert hint is not None
    assert hint.country_code == "FR"
    assert hint.source == "tls_cert"


def test_resolve_jurisdiction_falls_back_to_issuer():
    hint = resolve_jurisdiction(
        tls_cert_subject="CN=example.onion,O=Org",  # sin C=
        tls_cert_issuer="CN=Internal CA,C=NL",
        http_title=None,
    )
    assert hint is not None
    assert hint.country_code == "NL"
    assert hint.source == "tls_cert"


def test_resolve_jurisdiction_falls_back_to_title_when_no_cert_hint():
    hint = resolve_jurisdiction(
        tls_cert_subject=None,
        tls_cert_issuer=None,
        http_title="Jonavos Policijos Komisariatas",
    )
    assert hint is not None
    assert hint.country_code == "LT"
    assert hint.source == "http_title"


def test_resolve_jurisdiction_none_when_nothing_available():
    hint = resolve_jurisdiction(tls_cert_subject=None, tls_cert_issuer=None, http_title=None)
    assert hint is None


def test_resolve_jurisdiction_none_when_no_signal_recognized():
    hint = resolve_jurisdiction(
        tls_cert_subject="CN=example.onion,O=Anarcho-Copy Tor Services",
        tls_cert_issuer=None,
        http_title="Onion Bitcoin wallets",
    )
    assert hint is None


def test_resolve_jurisdiction_includes_coordinates():
    hint = resolve_jurisdiction(tls_cert_subject="C=ES", tls_cert_issuer=None, http_title=None)
    assert hint is not None
    assert hint.country_name == "España"
    assert isinstance(hint.lat, float)
    assert isinstance(hint.lng, float)
