"""
Servidor Ollama SIMULADO, solo para verificar que OllamaClient construye
las peticiones y parsea las respuestas correctamente, sin depender de
tener Ollama de verdad instalado (mi entorno de trabajo no tiene acceso
de red hacia ollama.com). Imita el formato real de respuesta de
`/api/generate` (modo `stream: false`) y `/api/tags`, documentado
publicamente por Ollama.

Esto NO prueba la calidad de los resumenes de un modelo real - eso solo
se puede verificar con Ollama real instalado. Prueba unicamente que el
CODIGO del cliente (peticion HTTP, parseo JSON, manejo de errores/
timeouts) es correcto.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer


class _FakeOllamaHandler(BaseHTTPRequestHandler):
    # Configuracion de comportamiento simulado, ajustable desde los tests
    # via atributos de clase (mas simple que pasar estado por instancia,
    # ya que BaseHTTPRequestHandler crea una instancia nueva por peticion).
    # fixed_summary=None -> se genera un resumen "de mentira" a partir del
    # propio texto de entrada (solo para que las demos se lean con sentido,
    # NO simula inteligencia real). Fijar un valor concreto para los tests
    # que necesitan una salida predecible.
    fixed_summary: str | None = None
    simulate_timeout = False
    simulate_malformed_json = False
    simulate_empty_response = False
    simulate_server_error = False
    request_log: list[dict] = []

    def log_message(self, format, *args):  # silenciar logs por consola
        pass

    def do_GET(self):
        if self.path == "/api/tags":
            self._send_json(200, {"models": [{"name": "qwen2.5:1.5b"}]})
        else:
            self._send_json(404, {"error": "no encontrado"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(length)
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except Exception:
            payload = {}
        _FakeOllamaHandler.request_log.append(payload)

        if self.path != "/api/generate":
            self._send_json(404, {"error": "no encontrado"})
            return

        if self.simulate_timeout:
            time.sleep(5)  # el cliente debe cortar antes por su propio timeout
            return

        if self.simulate_server_error:
            self._send_json(500, {"error": "fallo interno simulado"})
            return

        if self.simulate_malformed_json:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"esto no es json valido {{{")
            return

        response_text = "" if self.simulate_empty_response else self._build_response_text(payload)
        self._send_json(200, {
            "model": payload.get("model", "modelo-desconocido"),
            "response": response_text,
            "done": True,
        })

    def _build_response_text(self, payload: dict) -> str:
        if self.fixed_summary is not None:
            return self.fixed_summary
        # "Resumen" de mentira, solo para que el texto de las demos se
        # lea con sentido: NO simula inteligencia real, solo recorta el
        # texto de entrada (extraido del prompt, entre "TEXTO:" y
        # "RESUMEN:") a un fragmento reconocible.
        prompt = payload.get("prompt", "")
        start = prompt.find("TEXTO:\n")
        end = prompt.find("\n\nRESUMEN:")
        fragment = prompt[start + 7:end].strip() if start >= 0 and end > start else prompt[:80]
        fragment = " ".join(fragment.split())[:90]
        return f"[resumen simulado] {fragment}..."

    def _send_json(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class FakeOllamaServer:
    """Context manager: levanta el servidor simulado en un hilo aparte."""

    def __init__(self, port: int = 0) -> None:
        self.port = port
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "FakeOllamaServer":
        _FakeOllamaHandler.request_log = []
        _FakeOllamaHandler.simulate_timeout = False
        _FakeOllamaHandler.simulate_malformed_json = False
        _FakeOllamaHandler.simulate_empty_response = False
        _FakeOllamaHandler.simulate_server_error = False
        self._httpd = HTTPServer(("127.0.0.1", self.port), _FakeOllamaHandler)
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def handler(self):
        return _FakeOllamaHandler
