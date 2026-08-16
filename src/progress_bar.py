"""
Barra de progreso de terminal con estimacion de tiempo restante (ETA),
para scripts de relleno largos (horas). Deliberadamente sin ninguna
dependencia nueva (no se anade `tqdm` ni similar) - mismo criterio que
el resto del proyecto: usar la libreria estandar cuando basta.
"""

from __future__ import annotations

import sys
import time

_LINE_WIDTH = 120  # ancho fijo para machacar restos de una linea anterior mas larga


def format_duration(seconds: float) -> str:
    """Formatea segundos como '3s', '4m12s' o '1h23m', el que corresponda."""
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h{minutes:02d}m"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def render_progress_bar(current: int, total: int, start_time: float, width: int = 30, suffix: str = "") -> str:
    """
    Construye (sin imprimir) la linea de la barra de progreso: fraccion
    completada, porcentaje, contador, tiempo transcurrido, y tiempo
    restante estimado (extrapolando el ritmo medio hasta ahora).
    """
    if total <= 0:
        return ""
    fraction = min(current / total, 1.0)
    filled = int(width * fraction)
    bar = "#" * filled + "-" * (width - filled)

    elapsed = time.monotonic() - start_time
    rate = current / elapsed if elapsed > 0 else 0
    remaining = (total - current) / rate if rate > 0 else 0

    line = (
        f"[{bar}] {fraction * 100:5.1f}% ({current}/{total}) "
        f"transcurrido={format_duration(elapsed)} restante_est={format_duration(remaining)}"
    )
    if suffix:
        line += f" | {suffix}"
    return line


def print_progress(current: int, total: int, start_time: float, suffix: str = "") -> None:
    """Imprime la barra en la MISMA linea (retorno de carro, sin salto)."""
    line = render_progress_bar(current, total, start_time, suffix=suffix)
    sys.stdout.write("\r" + line.ljust(_LINE_WIDTH))
    sys.stdout.flush()


def clear_progress_line() -> None:
    """
    Limpia la linea de la barra antes de imprimir un mensaje normal
    (log de un evento puntual: fallo, bloqueo por safe-mode, etc.) -
    sin esto, el mensaje quedaria pegado visualmente a los restos de la
    barra en la misma linea.
    """
    sys.stdout.write("\r" + " " * _LINE_WIDTH + "\r")
    sys.stdout.flush()
