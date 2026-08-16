"""
Gestion de la conexion a Tor: control del daemon via stem (para forzar
renovacion de circuito) y construccion de sesiones que enrutan a traves
del proxy SOCKS5 local.
"""

from __future__ import annotations

import logging
import re
import time

import aiohttp
from aiohttp_socks import ProxyConnector
from stem import Signal
from stem.control import Controller

import config

logger = logging.getLogger(__name__)

BOOTSTRAP_PROGRESS_RE = re.compile(r"PROGRESS=(\d+)")


class TorCircuitManager:
    """
    Envuelve la conexion de control a Tor. Se usa para pedir un nuevo
    circuito (NEWNYM) cada cierto numero de peticiones, no en cada una:
    cambiar de circuito por peticion es mas lento y aqui no estamos
    evadiendo rate-limiting de un sitio en concreto, solo repartiendo
    carga entre varios nodos de salida a lo largo del crawling.
    """

    def __init__(
        self,
        control_host: str = config.TOR_CONTROL_HOST,
        control_port: int = config.TOR_CONTROL_PORT,
        password: str | None = config.TOR_CONTROL_PASSWORD,
    ) -> None:
        self.control_host = control_host
        self.control_port = control_port
        self.password = password
        self._controller: Controller | None = None
        self._request_count = 0

    def __enter__(self) -> "TorCircuitManager":
        self._controller = Controller.from_port(
            address=self.control_host, port=self.control_port
        )
        if self.password:
            self._controller.authenticate(password=self.password)
        else:
            self._controller.authenticate()  # cookie auth
        logger.info("Conectado al puerto de control de Tor")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._controller is not None:
            self._controller.close()

    def maybe_renew_circuit(self) -> None:
        """
        Incrementa el contador de peticiones y fuerza un nuevo circuito
        si se ha alcanzado el umbral configurado.
        """
        self._request_count += 1
        if self._request_count >= config.CIRCUIT_RENEW_EVERY_N_REQUESTS:
            self.renew_circuit()
            self._request_count = 0

    def renew_circuit(self) -> None:
        if self._controller is None:
            raise RuntimeError("TorCircuitManager no esta inicializado (usar como context manager)")
        self._controller.signal(Signal.NEWNYM)
        # Tor exige un pequeno margen tras NEWNYM antes de que el circuito
        # nuevo este realmente disponible.
        wait_time = self._controller.get_newnym_wait()
        if wait_time > 0:
            time.sleep(wait_time)
        logger.info("Circuito Tor renovado")

    def wait_for_bootstrap(self, timeout: float = 90.0, poll_interval: float = 2.0) -> None:
        """
        Espera activamente a que Tor complete el bootstrap (descarga del
        consensus de la red y construccion de los primeros circuitos)
        antes de permitir cualquier conexion a servicios .onion.

        Sin esto, cualquier intento de conexion justo despues de arrancar
        el contenedor/daemon de Tor falla de forma consistente (no es un
        fallo intermitente de red, es que Tor todavia no esta listo), lo
        cual es facil de confundir con un bug en el codigo de la aplicacion.
        """
        if self._controller is None:
            raise RuntimeError("TorCircuitManager no esta inicializado (usar como context manager)")

        start = time.monotonic()
        last_progress = -1
        while time.monotonic() - start < timeout:
            info = self._controller.get_info("status/bootstrap-phase")
            match = BOOTSTRAP_PROGRESS_RE.search(info)
            progress = int(match.group(1)) if match else 0
            if progress != last_progress:
                logger.info("Bootstrap de Tor: %d%%", progress)
                last_progress = progress
            if progress >= 100:
                return
            time.sleep(poll_interval)

        raise TimeoutError(
            f"Tor no completo el bootstrap en {timeout}s (ultimo progreso: {last_progress}%). "
            "Revisa 'docker logs onion-infra-tor' para ver si hay un problema real de red "
            "(bloqueo de tu ISP/red a los directory servers de Tor, por ejemplo)."
        )


def socks_proxy_url() -> str:
    """
    URL de proxy SOCKS5 lista para usar con aiohttp-socks.

    Nota: aiohttp-socks (basado en python-socks) NO reconoce el esquema
    "socks5h://" (esa "h" es una convencion de curl/requests para forzar
    resolucion de DNS remota). Con python-socks la resolucion de DNS via
    el proxy SOCKS5 ya es el comportamiento por defecto, asi que basta
    con "socks5://": no hay fuga de DNS local con este esquema en esta
    libreria en concreto.
    """
    return f"socks5://{config.TOR_SOCKS_HOST}:{config.TOR_SOCKS_PORT}"


def create_tor_session() -> aiohttp.ClientSession:
    """
    Crea una aiohttp.ClientSession que enruta todas las peticiones a
    traves del proxy SOCKS5 de Tor. Esta es la sesion que deben usar
    todos los adapters de fuentes semilla y, mas adelante, el fetcher
    del crawler.

    Se establece un User-Agent de navegador real por defecto: varios
    hidden services (via nginx u otros front-ends) cortan la conexion
    sin responder si detectan el User-Agent por defecto de aiohttp,
    que se identifica claramente como cliente automatizado.

    Uso:
        async with create_tor_session() as session:
            async with session.get(url) as resp:
                ...
    """
    connector = ProxyConnector.from_url(socks_proxy_url())
    timeout = aiohttp.ClientTimeout(
        total=config.REQUEST_TIMEOUT_SECONDS,
        connect=config.CONNECT_TIMEOUT_SECONDS,
    )
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/115.0",
    }
    return aiohttp.ClientSession(connector=connector, timeout=timeout, headers=headers)


def check_socks_port_reachable(
    host: str = config.TOR_SOCKS_HOST, port: int = config.TOR_SOCKS_PORT, timeout: float = 3.0
) -> bool:
    """Chequeo TCP simple, sin pasar por Tor, solo para confirmar que el
    puerto SOCKS esta escuchando antes de intentar nada mas costoso."""
    import socket

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
