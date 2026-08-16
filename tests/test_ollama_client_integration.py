"""
Tests de integracion de OllamaClient contra el servidor Ollama SIMULADO
(tests/fake_ollama_server.py). Confirman que el cliente construye bien
las peticiones HTTP y maneja correctamente exito, timeout, JSON
malformado, respuesta vacia, y error 500 - sin necesitar Ollama real
instalado.
"""

import time

import pytest

from src.ollama_client import OllamaClient, OllamaError
from tests.fake_ollama_server import FakeOllamaServer


def test_is_available_true_when_server_up():
    with FakeOllamaServer() as server:
        client = OllamaClient(host=server.url)
        assert client.is_available() is True


def test_is_available_false_when_server_down():
    # Puerto en el que casi con toda seguridad no hay nada escuchando
    client = OllamaClient(host="http://127.0.0.1:1", timeout=1)
    assert client.is_available() is False


def test_summarize_success():
    with FakeOllamaServer() as server:
        server.handler.fixed_summary = "Foro de discusion sobre tecnologia y privacidad."
        client = OllamaClient(host=server.url, model="qwen2.5:1.5b")
        result = client.summarize("Este es un foro donde la gente habla de privacidad.")
        assert result == "Foro de discusion sobre tecnologia y privacidad."


def test_summarize_sends_correct_payload():
    with FakeOllamaServer() as server:
        client = OllamaClient(host=server.url, model="llama3.2:1b", timeout=5)
        client.summarize("contenido de prueba", max_words=40)

        assert len(server.handler.request_log) == 1
        sent = server.handler.request_log[0]
        assert sent["model"] == "llama3.2:1b"
        assert sent["stream"] is False
        assert "contenido de prueba" in sent["prompt"]
        assert "40" in sent["prompt"]  # el limite de palabras se paso en el prompt


def test_summarize_raises_on_empty_response():
    with FakeOllamaServer() as server:
        server.handler.simulate_empty_response = True
        client = OllamaClient(host=server.url)
        with pytest.raises(OllamaError, match="vacia"):
            client.summarize("texto")


def test_summarize_raises_on_malformed_json():
    with FakeOllamaServer() as server:
        server.handler.simulate_malformed_json = True
        client = OllamaClient(host=server.url)
        with pytest.raises(OllamaError, match="JSON"):
            client.summarize("texto")


def test_summarize_raises_on_server_error():
    with FakeOllamaServer() as server:
        server.handler.simulate_server_error = True
        client = OllamaClient(host=server.url)
        with pytest.raises(OllamaError):
            client.summarize("texto")


def test_summarize_raises_on_timeout():
    with FakeOllamaServer() as server:
        server.handler.simulate_timeout = True
        client = OllamaClient(host=server.url, timeout=1)  # el servidor simulado tarda 5s
        t0 = time.monotonic()
        with pytest.raises(OllamaError, match="respondio"):
            client.summarize("texto")
        elapsed = time.monotonic() - t0
        assert elapsed < 4  # confirma que corto por SU timeout, no espero los 5s del servidor


def test_summarize_raises_when_server_unreachable():
    client = OllamaClient(host="http://127.0.0.1:1", timeout=1)
    with pytest.raises(OllamaError, match="conectar"):
        client.summarize("texto")


CATEGORIES = ["marketplace", "foro", "otro"]


def test_classify_returns_exact_category():
    with FakeOllamaServer() as server:
        server.handler.fixed_summary = "marketplace"
        client = OllamaClient(host=server.url)
        assert client.classify("texto de una tienda", CATEGORIES) == "marketplace"


def test_classify_normalizes_noisy_response():
    """
    El modelo puede responder con ruido alrededor de la categoria (ej.
    mayusculas, un punto final, texto extra) - se normaliza buscando
    cual categoria conocida aparece dentro de la respuesta.
    """
    with FakeOllamaServer() as server:
        server.handler.fixed_summary = "La categoria es: Marketplace."
        client = OllamaClient(host=server.url)
        assert client.classify("texto", CATEGORIES) == "marketplace"


def test_classify_falls_back_to_last_category_when_unrecognized():
    with FakeOllamaServer() as server:
        server.handler.fixed_summary = "esto no es ninguna categoria valida"
        client = OllamaClient(host=server.url)
        assert client.classify("texto", CATEGORIES) == "otro"  # ultima de la lista


def test_classify_sends_all_categories_in_prompt():
    with FakeOllamaServer() as server:
        client = OllamaClient(host=server.url)
        client.classify("texto de prueba", CATEGORIES)
        sent = server.handler.request_log[0]
        assert "marketplace" in sent["prompt"]
        assert "foro" in sent["prompt"]
        assert "otro" in sent["prompt"]
        assert "texto de prueba" in sent["prompt"]
