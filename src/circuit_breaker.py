"""
Disyuntor simple para el escenario de relleno masivo: si Ollama deja de
responder a mitad de procesar miles de dominios (se cae el servicio, se
queda sin memoria, etc.), seguir intentando uno a uno significaria
esperar el timeout completo (ej. 30s) en CADA dominio restante. Tras un
numero de fallos consecutivos, se abre el circuito y se deja de
intentar, con un aviso claro - el mismo principio que ya aplicamos en
correlate() para evitar la explosion combinatoria: detectar una
condicion anormal y cortar por lo sano en vez de seguir a ciegas.
"""

from __future__ import annotations


class CircuitOpenError(Exception):
    """Se lanza cuando el disyuntor esta abierto: no lo intentes, falla ya."""


class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5) -> None:
        self.failure_threshold = failure_threshold
        self.consecutive_failures = 0
        self.is_open = False

    def guard(self) -> None:
        """Llamar ANTES de cada intento; lanza si el circuito ya esta abierto."""
        if self.is_open:
            raise CircuitOpenError(
                f"Disyuntor abierto tras {self.failure_threshold} fallos consecutivos. "
                "Revisa que Ollama siga corriendo antes de reintentar."
            )

    def record_success(self) -> None:
        self.consecutive_failures = 0

    def record_failure(self) -> None:
        self.consecutive_failures += 1
        if self.consecutive_failures >= self.failure_threshold:
            self.is_open = True

    def reset(self) -> None:
        self.consecutive_failures = 0
        self.is_open = False
