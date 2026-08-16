"""
Genera el caso de estudio de desanonimizacion (F7) a partir de datos
reales ya cargados en Neo4j y Elasticsearch (ejecutar run_batch.py antes
si todavia no tienes datos).

Busca el mejor ejemplo disponible en tu grafo (prioriza certificado o
clave SSH compartidos sobre similitud de contenido) y redacta un informe
en Markdown listo para incorporar a la memoria del TFM, con la cadena de
correlacion completa y una consulta Cypher para reproducir la captura
visual en Neo4j Browser.

Uso:
    python3 scripts/generate_case_study.py
"""

from __future__ import annotations

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from src.graph import GraphStore
from src.search_index import SearchIndex

RELATION_LABELS = {
    "shared_tls_cert": "certificado TLS compartido",
    "shared_ssh_key": "clave SSH compartida",
    "shared_pgp_key": "clave PGP compartida",
    "shared_jarm": "JARM compartido (misma pila/configuracion TLS)",
    "shared_crypto_address": "direccion de criptomoneda compartida",
    "similar_content": "contenido casi identico (fuzzy hashing)",
}


def fetch_domain_details(addresses: list[str]) -> dict[str, dict]:
    """Recupera titulo, tecnologia y puertos de cada dominio implicado,
    para enriquecer la narrativa del caso de estudio."""
    details = {}
    with SearchIndex() as index:
        for address in addresses:
            try:
                hits = index.search(address, size=1)
                if hits:
                    details[address] = hits[0]
            except Exception:
                pass
    return details


def render_report(case: dict, details: dict[str, dict]) -> str:
    relation = case["relation"]
    onions = case["onions"]
    degree = case["degree"]
    evidence = case["evidence"]
    detail_a = case.get("detail_a")
    detail_b = case.get("detail_b")
    label = RELATION_LABELS.get(relation, relation)

    lines = []
    lines.append("# Caso de estudio: desanonimizacion de infraestructura compartida")
    lines.append("")
    lines.append(f"*Generado automaticamente el {date.today().isoformat()} a partir del dataset real del proyecto.*")
    lines.append("")
    lines.append("## 1. Resumen del hallazgo")
    lines.append("")
    lines.append(
        f"Se ha identificado un grupo de **{degree} dominios `.onion`** que comparten "
        f"{label}, lo cual constituye una fuga de infraestructura en el sentido de "
        "OnionScan: informacion de configuracion expuesta publicamente que permite "
        "correlacionar servicios que, en principio, deberian ser anonimos e "
        "independientes entre si."
    )
    lines.append("")
    lines.append("## 2. Dominios implicados")
    lines.append("")
    for addr in onions:
        info = details.get(addr, {})
        title = info.get("http_title") or "(sin titulo HTTP detectado)"
        techs = ", ".join(info.get("technologies", [])) or "sin tecnologia detectada"
        ports = ", ".join(info.get("open_ports", [])) or "sin puertos abiertos detectados"
        lines.append(f"- **`{addr}`**")
        lines.append(f"  - Titulo HTTP: {title}")
        lines.append(f"  - Tecnologia: {techs}")
        lines.append(f"  - Puertos abiertos: {ports}")
    lines.append("")
    lines.append("## 3. Evidencia tecnica")
    lines.append("")
    if relation == "shared_tls_cert":
        lines.append(f"- **Fingerprint SHA-256 del certificado:** `{evidence}`")
        if detail_a:
            lines.append(f"- **Subject:** `{detail_a}`")
        if detail_b:
            lines.append(f"- **Issuer:** `{detail_b}`")
        lines.append(
            "\nUn certificado TLS identico entre dominios distintos indica, con muy "
            "alta probabilidad, que ambos servicios estan desplegados en el mismo "
            "servidor fisico o bajo el mismo operador, que ha reutilizado el mismo "
            "material criptografico en lugar de generar un certificado independiente "
            "para cada servicio."
        )
    elif relation == "shared_ssh_key":
        lines.append(f"- **Fingerprint SHA-256 de la clave SSH:** `{evidence}`")
        if detail_a:
            lines.append(f"- **Tipo de clave:** `{detail_a}`")
        lines.append(
            "\nUna clave publica SSH identica es una señal aun mas fuerte que un "
            "certificado compartido: normalmente implica acceso administrativo "
            "compartido a la misma maquina fisica o al mismo conjunto de maquinas "
            "gestionadas centralmente por el mismo operador."
        )
    elif relation == "shared_pgp_key":
        lines.append(f"- **Hash del bloque de clave PGP publicada:** `{evidence}`")
        lines.append(
            "\nUna clave PGP identica publicada en dos dominios distintos es una "
            "señal de identidad muy fuerte, comparable a un certificado o clave SSH "
            "compartidos: a diferencia de estos, una clave PGP esta pensada "
            "especificamente para identificar a una PERSONA u operador concreto "
            "(se usa para firmar/verificar comunicaciones), no a un servidor. Su "
            "reutilizacion entre sitios en teoria independientes es evidencia "
            "directa de que los gestiona la misma persona."
        )
    elif relation == "shared_jarm":
        lines.append(f"- **Hash JARM (pila/configuracion TLS):** `{evidence}`")
        lines.append(
            "\nJARM identifica la pila y configuracion TLS del servidor (version, "
            "orden de cifrados, extensiones), no el certificado. Dos dominios con "
            "certificados totalmente distintos que comparten JARM sugieren el mismo "
            "software desplegado con la misma configuracion (por ejemplo, la misma "
            "imagen de servidor o script de aprovisionamiento). Es una señal algo "
            "menos concluyente que un certificado o clave compartidos: una "
            "configuracion por defecto muy comun podria coincidir entre operadores "
            "sin relacion real entre si, asi que se recomienda buscar corroboracion "
            "adicional antes de tratarla como concluyente por si sola."
        )
    elif relation == "shared_crypto_address":
        currency = detail_a or "desconocida"
        addr_value = detail_b or evidence.split(":", 1)[-1]
        lines.append(f"- **Moneda:** `{currency}`")
        lines.append(f"- **Direccion:** `{addr_value}`")
        lines.append(
            "\nLa misma direccion de criptomoneda mencionada en dos dominios "
            "distintos sugiere que ambos sitios reciben pagos en la misma wallet, "
            "lo cual es evidencia solida de que los gestiona el mismo operador. Es "
            "algo menos concluyente que un certificado, clave SSH o clave PGP "
            "compartidos porque, en casos poco frecuentes, una direccion puede "
            "reutilizarse legitimamente entre sitios independientes (por ejemplo, "
            "una direccion de donacion citada como ejemplo). Se recomienda "
            "corroborar con otra señal antes de darla por concluyente en solitario."
        )
    else:
        lines.append(f"- **Evidencia de similitud (ssdeep/ppdeep):** `{evidence}`")
        lines.append(
            "\nEste es el nivel de evidencia mas debil de todos: sugiere que ambos "
            "dominios comparten plantilla, tema o generador de contenido, lo cual es "
            "compatible con (pero no prueba por si solo) que compartan operador o "
            "infraestructura. Se recomienda buscar corroboracion adicional (fugas de "
            "certificado/SSH/PGP/cripto, mismo ASN, etc.) antes de tratar esto como "
            "concluyente."
        )
    lines.append("")
    lines.append("## 4. Metodologia (nota para la memoria)")
    lines.append("")
    lines.append(
        "Es importante remarcar que esta correlacion es **pasiva**: no se ha "
        "explotado ninguna vulnerabilidad de aplicacion ni se ha accedido a "
        "informacion protegida. Los datos usados (certificado TLS, clave publica "
        "SSH, contenido HTTP) son expuestos voluntariamente por el propio servidor "
        "a cualquier cliente que se conecte; el hallazgo consiste unicamente en "
        "detectar que dos servicios, en teoria independientes, exponen el mismo "
        "artefacto. Esta es la misma metodologia que empleo OnionScan (Lewis, 2016)."
    )
    lines.append("")
    lines.append("## 5. Reproducir la visualizacion para la memoria")
    lines.append("")
    lines.append(
        "Para capturar el grafo visualmente (Neo4j Browser, `http://localhost:7474`), "
        "ejecuta esta consulta con las direcciones de este caso:"
    )
    lines.append("")
    addresses_literal = ", ".join(f'"{a}"' for a in onions)
    lines.append("```cypher")
    lines.append(f"MATCH (o:Onion) WHERE o.address IN [{addresses_literal}]")
    lines.append("OPTIONAL MATCH (o)-[r]-(x)")
    lines.append("RETURN o, r, x")
    lines.append("```")
    lines.append("")
    lines.append(
        "Tambien puedes abrir la ficha de cualquiera de estos dominios en el "
        "dashboard propio (`http://localhost:8000`) para ver el arbol de "
        "infraestructura relacionada generado automaticamente."
    )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    print("Consultando el grafo de Neo4j en busca del mejor caso de estudio disponible...")
    with GraphStore() as graph:
        case = graph.find_best_case_study()

    if case is None:
        print("No se encontro ninguna relacion de infraestructura en el grafo todavia.")
        print("Esto es normal si el dataset es pequeño o si acabas de cargarlo: la")
        print("probabilidad de coincidencia (certificado/SSH/contenido compartido)")
        print("sube con el numero de dominios procesados. Prueba con un --limit mayor")
        print("en scripts/run_batch.py y vuelve a ejecutar este script despues.")
        return 1

    print(f"Mejor caso encontrado: {case['relation']} entre {case['degree']} dominios.")
    print("Recuperando detalles de cada dominio desde Elasticsearch...")
    details = fetch_domain_details(case["onions"])

    report = render_report(case, details)
    out_path = config.DATA_DIR / f"case_study_{date.today().isoformat()}.md"
    out_path.write_text(report, encoding="utf-8")

    print(f"\nCaso de estudio guardado en: {out_path}")
    print("Abrelo y pegalo (o adaptalo) directamente en el capitulo de resultados")
    print("de la memoria del TFM.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
