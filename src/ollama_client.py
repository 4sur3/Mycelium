"""
Cliente HTTP minimo para Ollama (LLM local), pensado para resumir el
contenido de dominios .onion ya descargado (F4, ampliacion opcional).

Deliberadamente usa solo `urllib` de la libreria estandar, sin añadir
ninguna dependencia nueva - mismo criterio que el resto del proyecto
(evitar dependencias que puedan romper la instalacion, ver el problema
que tuvimos con lxml/pydantic en Python 3.14). Ollama corre en
localhost, no requiere pasar por Tor: es una llamada de red normal a
un servicio en la propia maquina, no al dominio .onion en si.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class OllamaError(Exception):
    """Cualquier fallo al hablar con Ollama: no disponible, timeout,
    respuesta malformada, o respuesta vacia. Se captura como una unica
    excepcion para que quien llame pueda simplemente "saltar este
    dominio y seguir" sin distinguir el motivo exacto."""


class OllamaClient:
    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "qwen2.5:1.5b",
        timeout: float = 30.0,
    ) -> None:
        self.host = host.rstrip("/")
        self.model = model
        self.timeout = timeout

    def is_available(self) -> bool:
        """
        Chequeo barato y rapido (timeout corto) para saber si Ollama
        esta corriendo antes de intentar nada mas costoso. Pensado para
        llamarse UNA vez al principio de un script de relleno, no antes
        de cada dominio.
        """
        try:
            req = urllib.request.Request(f"{self.host}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3):
                return True
        except Exception:
            return False

    def summarize(self, text: str, max_words: int = 60) -> str:
        """
        Pide a Ollama un resumen breve y neutro del texto. Lanza
        OllamaError si algo falla (conexion, timeout, JSON invalido, o
        respuesta vacia) - quien llame decide que hacer (normalmente:
        registrar el fallo y continuar con el siguiente dominio, igual
        que ya hacemos con JARM/PGP/artefactos HTML).
        """
        prompt = self._build_prompt(text, max_words)
        return self._generate(prompt, num_predict=160)

    def classify(self, text: str, categories: list[str]) -> str:
        """
        Clasifica el texto en UNA de las categorias dadas (tarea de
        clasificacion cerrada, no generacion libre - mucho mas fiable
        para un modelo pequeño que resumir texto abierto). Si la
        respuesta del modelo no coincide con ninguna categoria conocida
        (ruido, texto extra, etc.), se normaliza buscando cual de las
        categorias aparece como substring de la respuesta; si ninguna
        aparece, se devuelve la ultima de la lista (pensada para ser el
        cajon de sastre "otro"/equivalente), nunca se lanza error por
        una respuesta ambigua.
        """
        prompt = self._build_classify_prompt(text, categories)
        raw = self._generate(prompt, num_predict=20).strip().lower()
        for category in categories:
            if category.lower() in raw:
                return category
        return categories[-1]

    def _generate(self, prompt: str, num_predict: int) -> str:
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"num_predict": num_predict, "temperature": 0.2},
        }
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.host}/api/generate",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise OllamaError(f"No se pudo conectar con Ollama en {self.host}: {exc}") from exc
        except TimeoutError as exc:
            raise OllamaError(f"Ollama no respondio en {self.timeout}s") from exc

        try:
            body = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaError(f"Respuesta de Ollama no es JSON valido: {exc}") from exc

        summary = (body.get("response") or "").strip()
        if not summary:
            raise OllamaError("Ollama devolvio una respuesta vacia")
        return summary

    @staticmethod
    def _build_prompt(text: str, max_words: int) -> str:
        return (
            f"Resume el siguiente contenido de una pagina web en como maximo {max_words} "
            "palabras, en español, de forma neutra y factual, sin opiniones ni "
            "advertencias. No inventes informacion que no este en el texto. Si el "
            "texto no tiene contenido claro que resumir, responde exactamente: "
            "'Sin contenido suficiente para resumir'.\n\n"
            f"TEXTO:\n{text}\n\nRESUMEN:"
        )

    @staticmethod
    def _build_classify_prompt(text: str, categories: list[str]) -> str:
        options = ", ".join(categories)
        return (
            "Clasifica el siguiente resumen de una pagina web en UNA SOLA de estas "
            f"categorias exactas: {options}.\n\n"
            "Responde EXCLUSIVAMENTE con la palabra exacta de la categoria, sin "
            "explicacion, sin puntuacion, sin comillas.\n\n"
            f"RESUMEN:\n{text}\n\nCATEGORIA:"
        )
