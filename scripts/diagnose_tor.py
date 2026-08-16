"""
Diagnostico aislado de conectividad Tor.

Objetivo: determinar si el fallo persistente contra Ahmia es:
  (a) un problema del stack async (aiohttp-socks) en esta maquina/version
      de Python, comparando contra una llamada SINCRONA con requests+PySocks
  (b) un problema especifico de la direccion de Ahmia, comparando contra
      un onion de referencia muy estable (el de Facebook, usado habitualmente
      solo para tests de conectividad, no forma parte del dataset del TFM)

Ejecutar con Tor ya arrancado y con el bootstrap completo (si acabas de
lanzar `docker compose up -d tor`, espera al menos 30-60s antes de correr
este script).

Uso:
    python3 scripts/diagnose_tor.py
"""

from __future__ import annotations

import sys
import traceback

import requests

# Onion de referencia, muy estable, usado solo para verificar conectividad
# (no es parte de las fuentes semilla del proyecto).
REFERENCE_ONION = "http://facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion/"
AHMIA_ONION = "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/onions/"
TOR_CHECK_CLEARNET = "https://check.torproject.org/api/ip"

PROXIES = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

# Muchos hidden services (via nginx u otros front-ends) cortan la conexion
# sin responder si el User-Agent parece un cliente automatizado (el valor
# por defecto de requests/aiohttp). Usamos un User-Agent de navegador real
# para descartar esto como causa del RemoteDisconnected.
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/115.0",
}


def try_sync_request(label: str, url: str, timeout: int = 30) -> None:
    print(f"\n--- {label} ---")
    print(f"URL: {url}")
    try:
        resp = requests.get(url, proxies=PROXIES, headers=HEADERS, timeout=timeout)
        print(f"OK: status={resp.status_code}, bytes={len(resp.content)}")
        if "check.torproject.org" in url:
            print(f"Respuesta: {resp.text.strip()[:200]}")
    except Exception:
        print("FALLO:")
        traceback.print_exc(limit=3)


def main() -> int:
    print("=" * 70)
    print("DIAGNOSTICO 1: Tor exit hacia clearnet (confirma que Tor en si")
    print("funciona, independientemente de onions)")
    print("=" * 70)
    try_sync_request("Tor -> clearnet (requests + PySocks, sincrono)", TOR_CHECK_CLEARNET)

    print("\n" + "=" * 70)
    print("DIAGNOSTICO 2: onion de referencia estable, via requests sincrono")
    print("=" * 70)
    try_sync_request("Onion de referencia (requests + PySocks, sincrono)", REFERENCE_ONION)

    print("\n" + "=" * 70)
    print("DIAGNOSTICO 3: Ahmia, via requests sincrono (mismo metodo que 1 y 2)")
    print("=" * 70)
    try_sync_request("Ahmia (requests + PySocks, sincrono)", AHMIA_ONION)

    print("\n" + "=" * 70)
    print("Lectura de resultados:")
    print("  - Si 1 falla: Tor no esta funcionando correctamente en si mismo,")
    print("    el problema es de la instalacion/contenedor Tor, no del codigo Python.")
    print("  - Si 1 OK pero 2 y 3 fallan: problema generico conectando a onions")
    print("    (puede ser el contenedor Tor con soporte limitado a hidden services).")
    print("  - Si 1 y 2 OK pero 3 falla: problema especifico de la direccion/servicio")
    print("    de Ahmia en este momento (direccion desactualizada o el servicio")
    print("    esta rechazando conexiones puntualmente).")
    print("  - Si 1, 2 y 3 OK aqui (sincrono) pero el pipeline async seguia fallando:")
    print("    el problema esta en el stack aiohttp-socks/asyncio de esta maquina,")
    print("    y migramos el fetcher a un cliente sincrono con threads en su lugar.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
