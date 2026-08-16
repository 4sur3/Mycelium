"""
Grafo de infraestructura (F5).

Modelo de datos:
  Nodos:
    (:Onion {address, status, first_seen, open_ports, technologies,
              http_title, server_header})
    (:Certificate {sha256, subject, issuer, not_valid_after})
    (:SSHKey {fingerprint_sha256, key_type})

  Relaciones:
    (:Onion)-[:USES_CERT]->(:Certificate)
    (:Onion)-[:USES_SSH_KEY]->(:SSHKey)
    (:Onion)-[:SIMILAR_CONTENT {score, evidence}]->(:Onion)

Decision de diseno: los certificados y claves SSH compartidos NO se
modelan como una relacion directa Onion-Onion, sino como dos aristas
USES_CERT/USES_SSH_KEY hacia el MISMO nodo Certificate/SSHKey. Esto es
mas fiel al dominio (el artefacto compartido es una entidad real, no una
propiedad de la relacion) y permite consultas como "cuantos onions
distintos usan este certificado" sin tener que contar aristas N a N.
La similitud de contenido si se modela como relacion directa Onion-Onion
porque el score es propio de cada par, no una entidad compartida.

Este modulo usa el driver SINCRONO oficial de Neo4j (no hace falta async
aqui: la carga al grafo ocurre al final del pipeline, no en el bucle de
red concurrente con Tor).
"""

from __future__ import annotations

import logging
from typing import Optional

from neo4j import GraphDatabase

import config
from src.models import InfrastructureLink, LeakEvidence, OnionRecord, ServiceEnumeration

logger = logging.getLogger(__name__)


class GraphStore:
    def __init__(
        self,
        uri: str = config.NEO4J_URI,
        user: str = config.NEO4J_USER,
        password: str = config.NEO4J_PASSWORD,
    ) -> None:
        self._driver = GraphDatabase.driver(uri, auth=(user, password))

    def close(self) -> None:
        self._driver.close()

    def __enter__(self) -> "GraphStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- setup ----------------------------------------------------------------

    def ensure_constraints(self) -> None:
        """
        Constraints de unicidad. Sin esto, cargar el mismo dataset dos
        veces duplicaria nodos en vez de fusionarlos (MERGE se apoya en
        estas claves para saber que ya existe un nodo).
        """
        statements = [
            "CREATE CONSTRAINT onion_address IF NOT EXISTS "
            "FOR (o:Onion) REQUIRE o.address IS UNIQUE",
            "CREATE CONSTRAINT cert_sha256 IF NOT EXISTS "
            "FOR (c:Certificate) REQUIRE c.sha256 IS UNIQUE",
            "CREATE CONSTRAINT sshkey_fingerprint IF NOT EXISTS "
            "FOR (k:SSHKey) REQUIRE k.fingerprint_sha256 IS UNIQUE",
            "CREATE CONSTRAINT jarm_hash IF NOT EXISTS "
            "FOR (j:JarmFingerprint) REQUIRE j.hash IS UNIQUE",
            "CREATE CONSTRAINT pgpkey_hash IF NOT EXISTS "
            "FOR (p:PGPKey) REQUIRE p.hash IS UNIQUE",
            # Neo4j Community no soporta constraints de unicidad compuestos
            # (multi-propiedad); se usa un id combinado "MONEDA:direccion"
            # como propiedad unica en su lugar.
            "CREATE CONSTRAINT crypto_address_id IF NOT EXISTS "
            "FOR (a:CryptoAddress) REQUIRE a.id IS UNIQUE",
            # Un unico label para JS/CSS/favicon/documento (distinguidos
            # por la propiedad artifact_type), en vez de 4 labels
            # distintos: simplifica constraints/consultas y es coherente
            # con el resto del modelado (un nodo por artefacto compartido).
            "CREATE CONSTRAINT html_artifact_hash IF NOT EXISTS "
            "FOR (h:HtmlArtifact) REQUIRE h.hash IS UNIQUE",
        ]
        with self._driver.session() as session:
            for stmt in statements:
                session.run(stmt)
        logger.info("Constraints de Neo4j verificados/creados")

    # -- carga ------------------------------------------------------------------

    def upsert_onion(
        self, record: OnionRecord, enumeration: Optional[ServiceEnumeration] = None
    ) -> None:
        open_ports = []
        technologies: list[str] = []
        http_title = None
        server_header = None
        if enumeration is not None:
            open_ports = [f"{p.port}/{p.protocol}" for p in enumeration.open_ports]
            technologies = enumeration.technologies
            http_title = enumeration.http_title
            server_header = enumeration.server_header

        query = """
        MERGE (o:Onion {address: $address})
        SET o.status = $status,
            o.first_seen = $first_seen,
            o.open_ports = $open_ports,
            o.technologies = $technologies,
            o.http_title = $http_title,
            o.server_header = $server_header
        """
        params = {
            "address": record.address,
            "status": record.status.value,
            "first_seen": record.first_seen.isoformat(),
            "open_ports": open_ports,
            "technologies": technologies,
            "http_title": http_title,
            "server_header": server_header,
        }
        with self._driver.session() as session:
            session.run(query, params)

    def upsert_leak_evidence(self, evidence: LeakEvidence) -> None:
        with self._driver.session() as session:
            if evidence.tls_cert_sha256:
                session.run(
                    """
                    MERGE (c:Certificate {sha256: $sha256})
                    SET c.subject = $subject,
                        c.issuer = $issuer,
                        c.not_valid_after = $not_valid_after
                    WITH c
                    MATCH (o:Onion {address: $address})
                    MERGE (o)-[:USES_CERT]->(c)
                    """,
                    {
                        "sha256": evidence.tls_cert_sha256,
                        "subject": evidence.tls_cert_subject,
                        "issuer": evidence.tls_cert_issuer,
                        "not_valid_after": (
                            evidence.tls_cert_not_valid_after.isoformat()
                            if evidence.tls_cert_not_valid_after else None
                        ),
                        "address": evidence.address,
                    },
                )
            if evidence.jarm_hash:
                session.run(
                    """
                    MERGE (j:JarmFingerprint {hash: $hash})
                    WITH j
                    MATCH (o:Onion {address: $address})
                    MERGE (o)-[:HAS_JARM]->(j)
                    """,
                    {
                        "hash": evidence.jarm_hash,
                        "address": evidence.address,
                    },
                )
            if evidence.ssh_fingerprint_sha256:
                session.run(
                    """
                    MERGE (k:SSHKey {fingerprint_sha256: $fingerprint})
                    SET k.key_type = $key_type
                    WITH k
                    MATCH (o:Onion {address: $address})
                    MERGE (o)-[:USES_SSH_KEY]->(k)
                    """,
                    {
                        "fingerprint": evidence.ssh_fingerprint_sha256,
                        "key_type": evidence.ssh_key_type,
                        "address": evidence.address,
                    },
                )
            if evidence.pgp_key_hash:
                session.run(
                    """
                    MERGE (p:PGPKey {hash: $hash})
                    WITH p
                    MATCH (o:Onion {address: $address})
                    MERGE (o)-[:PUBLISHES_PGP_KEY]->(p)
                    """,
                    {
                        "hash": evidence.pgp_key_hash,
                        "address": evidence.address,
                    },
                )
            for mention in evidence.crypto_addresses:
                session.run(
                    """
                    MERGE (a:CryptoAddress {id: $id})
                    SET a.currency = $currency, a.address = $addr_value
                    WITH a
                    MATCH (o:Onion {address: $address})
                    MERGE (o)-[:MENTIONS_ADDRESS]->(a)
                    """,
                    {
                        "id": f"{mention.currency}:{mention.address}",
                        "currency": mention.currency,
                        "addr_value": mention.address,
                        "address": evidence.address,
                    },
                )
            for artifact in evidence.html_artifacts:
                session.run(
                    """
                    MERGE (h:HtmlArtifact {hash: $hash})
                    SET h.artifact_type = $artifact_type
                    WITH h
                    MATCH (o:Onion {address: $address})
                    MERGE (o)-[:HAS_HTML_ARTIFACT]->(h)
                    """,
                    {
                        "hash": artifact.hash,
                        "artifact_type": artifact.artifact_type,
                        "address": evidence.address,
                    },
                )

    def upsert_links(self, links: list[InfrastructureLink]) -> None:
        """
        Solo los enlaces de tipo similar_content se cargan como relacion
        directa Onion-Onion. shared_tls_cert y shared_ssh_key ya quedan
        representados implicitamente por dos aristas USES_CERT/USES_SSH_KEY
        hacia el mismo nodo compartido (ver upsert_leak_evidence), asi que
        cargarlos tambien como relacion directa seria informacion redundante.
        """
        with self._driver.session() as session:
            for link in links:
                if link.relation_type != "similar_content":
                    continue
                # Orden canonico para evitar crear (a)-[:SIMILAR_CONTENT]->(b)
                # y (b)-[:SIMILAR_CONTENT]->(a) como aristas distintas.
                a, b = sorted((link.address_a, link.address_b))
                session.run(
                    """
                    MATCH (a:Onion {address: $a}), (b:Onion {address: $b})
                    MERGE (a)-[r:SIMILAR_CONTENT]->(b)
                    SET r.evidence = $evidence, r.confidence = $confidence
                    """,
                    {"a": a, "b": b, "evidence": link.evidence, "confidence": link.confidence},
                )

    # -- consulta -----------------------------------------------------------

    def find_best_case_study(self) -> Optional[dict]:
        """
        Busca el mejor ejemplo real para el caso de estudio de
        desanonimizacion (F7), en cuatro niveles de prioridad:
          1. Certificado TLS, clave SSH o clave PGP compartidos
             (identidad exacta, la señal mas fuerte: material
             criptografico o de identidad personal concreto). Una clave
             PGP se trata al mismo nivel que certificado/SSH porque esta
             pensada especificamente para identificar a una persona u
             operador, no solo a un servidor.
          2. JARM o direccion de criptomoneda compartidos (fuertes, pero
             algo menos concluyentes por si solos: JARM porque dos
             operadores distintos podrian coincidir en una configuracion
             por defecto muy comun, y una wallet porque en raras
             ocasiones se reutiliza legitimamente entre sitios
             independientes, ej. direcciones de donacion).
          3. Similitud de contenido (la señal mas debil, solo como
             ultimo recurso).
        Dentro de cada nivel, se prioriza el artefacto que conecta a MAS
        dominios a la vez (el caso mas contundente: "una sola fuga
        revela N dominios", no solo 2). Entre niveles, el nivel superior
        siempre gana, incluso si un artefacto de nivel inferior conecta
        a mas dominios.

        Devuelve None si el grafo no tiene ninguna relacion todavia
        (dataset demasiado pequeño o recien cargado).
        """
        with self._driver.session() as session:
            cert_result = session.run(
                """
                MATCH (c:Certificate)<-[:USES_CERT]-(o:Onion)
                WITH c, collect(o.address) AS onions, count(o) AS degree
                WHERE degree > 1
                RETURN 'shared_tls_cert' AS relation, c.sha256 AS evidence,
                       c.subject AS detail_a, c.issuer AS detail_b,
                       onions, degree
                ORDER BY degree DESC
                LIMIT 1
                """
            ).single()

            ssh_result = session.run(
                """
                MATCH (k:SSHKey)<-[:USES_SSH_KEY]-(o:Onion)
                WITH k, collect(o.address) AS onions, count(o) AS degree
                WHERE degree > 1
                RETURN 'shared_ssh_key' AS relation, k.fingerprint_sha256 AS evidence,
                       k.key_type AS detail_a, null AS detail_b,
                       onions, degree
                ORDER BY degree DESC
                LIMIT 1
                """
            ).single()

            pgp_result = session.run(
                """
                MATCH (p:PGPKey)<-[:PUBLISHES_PGP_KEY]-(o:Onion)
                WITH p, collect(o.address) AS onions, count(o) AS degree
                WHERE degree > 1
                RETURN 'shared_pgp_key' AS relation, p.hash AS evidence,
                       null AS detail_a, null AS detail_b,
                       onions, degree
                ORDER BY degree DESC
                LIMIT 1
                """
            ).single()

            tier1 = [r for r in (cert_result, ssh_result, pgp_result) if r is not None]
            if tier1:
                best = max(tier1, key=lambda r: r["degree"])
                return dict(best)

            jarm_result = session.run(
                """
                MATCH (j:JarmFingerprint)<-[:HAS_JARM]-(o:Onion)
                WITH j, collect(o.address) AS onions, count(o) AS degree
                WHERE degree > 1
                RETURN 'shared_jarm' AS relation, j.hash AS evidence,
                       null AS detail_a, null AS detail_b,
                       onions, degree
                ORDER BY degree DESC
                LIMIT 1
                """
            ).single()

            crypto_result = session.run(
                """
                MATCH (a:CryptoAddress)<-[:MENTIONS_ADDRESS]-(o:Onion)
                WITH a, collect(o.address) AS onions, count(o) AS degree
                WHERE degree > 1
                RETURN 'shared_crypto_address' AS relation, a.id AS evidence,
                       a.currency AS detail_a, a.address AS detail_b,
                       onions, degree
                ORDER BY degree DESC
                LIMIT 1
                """
            ).single()

            tier2 = [r for r in (jarm_result, crypto_result) if r is not None]
            if tier2:
                best = max(tier2, key=lambda r: r["degree"])
                return dict(best)

            # Fallback: sin coincidencias exactas, usar la relacion de
            # contenido similar con mayor confianza como ultimo recurso.
            content_result = session.run(
                """
                MATCH (a:Onion)-[r:SIMILAR_CONTENT]-(b:Onion)
                RETURN 'similar_content' AS relation, r.evidence AS evidence,
                       null AS detail_a, null AS detail_b,
                       [a.address, b.address] AS onions, 2 AS degree
                ORDER BY r.confidence DESC
                LIMIT 1
                """
            ).single()
            return dict(content_result) if content_result else None

    def artifact_summary(self, top_n: int = 5) -> dict:
        """
        Resumen de artefactos de infraestructura para el dashboard: cuantos
        certificados y claves SSH distintos se han extraido en total, cuantos
        de ellos estan REALMENTE compartidos por mas de un dominio (degree > 1,
        la señal de correlacion en si), y el top N de cada tipo ordenado por
        cuantos dominios conecta (el dato mas util para priorizar que mirar
        primero en el caso de estudio F7).
        """
        with self._driver.session() as session:
            cert_result = session.run(
                """
                MATCH (c:Certificate)
                OPTIONAL MATCH (c)<-[:USES_CERT]-(o:Onion)
                WITH c, count(o) AS degree
                RETURN count(c) AS total,
                       sum(CASE WHEN degree > 1 THEN 1 ELSE 0 END) AS shared_total,
                       collect({sha256: c.sha256, subject: c.subject, degree: degree}) AS items
                """
            ).single()

            ssh_result = session.run(
                """
                MATCH (k:SSHKey)
                OPTIONAL MATCH (k)<-[:USES_SSH_KEY]-(o:Onion)
                WITH k, count(o) AS degree
                RETURN count(k) AS total,
                       sum(CASE WHEN degree > 1 THEN 1 ELSE 0 END) AS shared_total,
                       collect({fingerprint: k.fingerprint_sha256, key_type: k.key_type, degree: degree}) AS items
                """
            ).single()

            jarm_result = session.run(
                """
                MATCH (j:JarmFingerprint)
                OPTIONAL MATCH (j)<-[:HAS_JARM]-(o:Onion)
                WITH j, count(o) AS degree
                RETURN count(j) AS total,
                       sum(CASE WHEN degree > 1 THEN 1 ELSE 0 END) AS shared_total,
                       collect({hash: j.hash, degree: degree}) AS items
                """
            ).single()

            pgp_result = session.run(
                """
                MATCH (p:PGPKey)
                OPTIONAL MATCH (p)<-[:PUBLISHES_PGP_KEY]-(o:Onion)
                WITH p, count(o) AS degree
                RETURN count(p) AS total,
                       sum(CASE WHEN degree > 1 THEN 1 ELSE 0 END) AS shared_total,
                       collect({hash: p.hash, degree: degree}) AS items
                """
            ).single()

            crypto_result = session.run(
                """
                MATCH (a:CryptoAddress)
                OPTIONAL MATCH (a)<-[:MENTIONS_ADDRESS]-(o:Onion)
                WITH a, count(o) AS degree
                RETURN count(a) AS total,
                       sum(CASE WHEN degree > 1 THEN 1 ELSE 0 END) AS shared_total,
                       collect({id: a.id, currency: a.currency, address: a.address, degree: degree}) AS items
                """
            ).single()

        def top_shared(record: Optional[dict]) -> list[dict]:
            if not record:
                return []
            shared = [item for item in record["items"] if item["degree"] > 1]
            shared.sort(key=lambda item: item["degree"], reverse=True)
            return shared[:top_n]

        return {
            "certificates_total": cert_result["total"] if cert_result else 0,
            "certificates_shared": cert_result["shared_total"] if cert_result else 0,
            "top_certificates": top_shared(cert_result),
            "jarm_total": jarm_result["total"] if jarm_result else 0,
            "jarm_shared": jarm_result["shared_total"] if jarm_result else 0,
            "top_jarm": top_shared(jarm_result),
            "ssh_keys_total": ssh_result["total"] if ssh_result else 0,
            "ssh_keys_shared": ssh_result["shared_total"] if ssh_result else 0,
            "top_ssh_keys": top_shared(ssh_result),
            "pgp_keys_total": pgp_result["total"] if pgp_result else 0,
            "pgp_keys_shared": pgp_result["shared_total"] if pgp_result else 0,
            "top_pgp_keys": top_shared(pgp_result),
            "crypto_addresses_total": crypto_result["total"] if crypto_result else 0,
            "crypto_addresses_shared": crypto_result["shared_total"] if crypto_result else 0,
            "top_crypto_addresses": top_shared(crypto_result),
        }

    def find_relation_edges_among(self, addresses: list[str]) -> list[tuple[str, str]]:
        """
        Dado un conjunto acotado de direcciones (pensado para los
        dominios con pista de jurisdiccion resuelta, para las lineas de
        conexion del mapa), devuelve los pares que tienen alguna relacion
        de infraestructura confirmada entre si - via cualquiera de los
        nodos compartidos (certificado, JARM, SSH, PGP, cripto, artefacto
        HTML) o la relacion directa de contenido similar.

        Acotado deliberadamente al conjunto recibido (en vez de devolver
        TODAS las relaciones del grafo): el mapa solo puede dibujar
        lineas entre puntos que existen en el, y esto evita traer datos
        de mas para un caso de uso que no los necesita.
        """
        if not addresses:
            return []

        shared_node_query = """
            MATCH (a:Onion)-[:USES_CERT|HAS_JARM|USES_SSH_KEY|PUBLISHES_PGP_KEY
                              |MENTIONS_ADDRESS|HAS_HTML_ARTIFACT]->(shared)
                  <-[:USES_CERT|HAS_JARM|USES_SSH_KEY|PUBLISHES_PGP_KEY
                     |MENTIONS_ADDRESS|HAS_HTML_ARTIFACT]-(b:Onion)
            WHERE a.address IN $addresses AND b.address IN $addresses AND a.address < b.address
            RETURN DISTINCT a.address AS address_a, b.address AS address_b
        """
        similar_content_query = """
            MATCH (a:Onion)-[:SIMILAR_CONTENT]-(b:Onion)
            WHERE a.address IN $addresses AND b.address IN $addresses AND a.address < b.address
            RETURN DISTINCT a.address AS address_a, b.address AS address_b
        """

        pairs: set[tuple[str, str]] = set()
        with self._driver.session() as session:
            for query in (shared_node_query, similar_content_query):
                records = session.run(query, {"addresses": addresses})
                for r in records:
                    pairs.add((r["address_a"], r["address_b"]))
        return sorted(pairs)

    def find_related_infrastructure(self, address: str) -> dict[str, list[dict]]:
        """
        Dado un dominio (por ejemplo, uno con una fuga confirmada), busca
        todos los demas dominios conectados a el via certificado
        compartido, JARM compartido, clave SSH compartida, clave PGP
        compartida, direccion de cripto compartida, artefacto HTML
        compartido, o contenido similar.
        Esta es la consulta que responde a la pregunta central del TFM:
        partiendo de un onion vulnerado, que otros onions comparten su
        infraestructura.

        Cada relacion incluye ademas group_size: cuantos dominios EN
        TOTAL comparten ese mismo valor (no solo cuantos aparecen
        conectados a `address`). Es el mismo umbral que ya usa
        correlate() para avisar de grupos sospechosamente genericos
        (>50, ver src/correlation.py) - aqui se expone el numero en si,
        para que se pueda juzgar caso por caso si una relacion concreta
        es una señal fuerte (grupo pequeño, ej. 2 dominios comparten una
        clave SSH - practicamente imposible por azar) o ruido probable
        (grupo grande, ej. 71 dominios con el mismo JARM - mas coherente
        con una configuracion TLS por defecto compartida por software,
        no con un operador compartido). similar_content queda fuera de
        esto (group_size=None): es una relacion directa par a par, no
        un grupo con nodo compartido, el concepto no aplica igual.

        Devuelve un dict agrupado por tipo de relacion (no una lista
        plana), para poder mostrar cada tipo en su propio apartado en la
        interfaz: certificado, JARM, SSH, PGP, cripto y contenido son
        señales COMPLEMENTARIAS, nunca deben pisarse entre si.

        Diseño deliberado: se usan consultas independientes (una por
        tipo), no una unica consulta con varios OPTIONAL MATCH
        encadenados. Encadenar muchos OPTIONAL MATCH en la misma
        consulta es un patron conocido en Cypher por generar productos
        cartesianos entre los distintos patrones, dificiles de razonar y
        de depurar; con consultas separadas es imposible que un tipo de
        relacion interfiera con otro.
        """
        queries: dict[str, str] = {
            "shared_tls_cert": """
                MATCH (start:Onion {address: $address})-[:USES_CERT]->(c:Certificate)
                WITH c
                MATCH (c)<-[:USES_CERT]-(o:Onion)
                RETURN c.sha256 AS via, collect(o.address) AS addresses
            """,
            "shared_ssh_key": """
                MATCH (start:Onion {address: $address})-[:USES_SSH_KEY]->(k:SSHKey)
                WITH k
                MATCH (k)<-[:USES_SSH_KEY]-(o:Onion)
                RETURN k.fingerprint_sha256 AS via, collect(o.address) AS addresses
            """,
            "shared_jarm": """
                MATCH (start:Onion {address: $address})-[:HAS_JARM]->(j:JarmFingerprint)
                WITH j
                MATCH (j)<-[:HAS_JARM]-(o:Onion)
                RETURN j.hash AS via, collect(o.address) AS addresses
            """,
            "shared_pgp_key": """
                MATCH (start:Onion {address: $address})-[:PUBLISHES_PGP_KEY]->(p:PGPKey)
                WITH p
                MATCH (p)<-[:PUBLISHES_PGP_KEY]-(o:Onion)
                RETURN p.hash AS via, collect(o.address) AS addresses
            """,
            "shared_crypto_address": """
                MATCH (start:Onion {address: $address})-[:MENTIONS_ADDRESS]->(ca:CryptoAddress)
                WITH ca
                MATCH (ca)<-[:MENTIONS_ADDRESS]-(o:Onion)
                RETURN ca.id AS via, collect(o.address) AS addresses
            """,
            "shared_javascript": """
                MATCH (start:Onion {address: $address})-[:HAS_HTML_ARTIFACT]->(h:HtmlArtifact {artifact_type: 'javascript'})
                WITH h
                MATCH (h)<-[:HAS_HTML_ARTIFACT]-(o:Onion)
                RETURN h.hash AS via, collect(o.address) AS addresses
            """,
            "shared_css": """
                MATCH (start:Onion {address: $address})-[:HAS_HTML_ARTIFACT]->(h:HtmlArtifact {artifact_type: 'css'})
                WITH h
                MATCH (h)<-[:HAS_HTML_ARTIFACT]-(o:Onion)
                RETURN h.hash AS via, collect(o.address) AS addresses
            """,
            "shared_favicon": """
                MATCH (start:Onion {address: $address})-[:HAS_HTML_ARTIFACT]->(h:HtmlArtifact {artifact_type: 'favicon'})
                WITH h
                MATCH (h)<-[:HAS_HTML_ARTIFACT]-(o:Onion)
                RETURN h.hash AS via, collect(o.address) AS addresses
            """,
            "shared_document": """
                MATCH (start:Onion {address: $address})-[:HAS_HTML_ARTIFACT]->(h:HtmlArtifact {artifact_type: 'document'})
                WITH h
                MATCH (h)<-[:HAS_HTML_ARTIFACT]-(o:Onion)
                RETURN h.hash AS via, collect(o.address) AS addresses
            """,
            "similar_content": """
                MATCH (start:Onion {address: $address})-[sc:SIMILAR_CONTENT]-(other:Onion)
                RETURN DISTINCT other.address AS address, sc.evidence AS via
            """,
        }

        results: dict[str, list[dict]] = {}
        with self._driver.session() as session:
            for relation_type, query in queries.items():
                records = session.run(query, {"address": address})
                if relation_type == "similar_content":
                    # Relacion directa par a par, no un grupo con nodo
                    # compartido - group_size no aplica aqui.
                    results[relation_type] = [
                        {"address": r["address"], "relation": relation_type, "via": r["via"], "group_size": None}
                        for r in records
                        if r["address"] is not None
                    ]
                    continue

                items: list[dict] = []
                for r in records:
                    group_addresses = r["addresses"] or []
                    group_size = len(group_addresses)
                    for other_address in group_addresses:
                        if other_address == address:
                            continue
                        items.append({
                            "address": other_address, "relation": relation_type,
                            "via": r["via"], "group_size": group_size,
                        })
                results[relation_type] = items
        return results
