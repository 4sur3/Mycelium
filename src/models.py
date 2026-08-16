"""
Estructuras de datos compartidas por el pipeline.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class OnionStatus(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"
    BLOCKED = "blocked"  # descartado por safe_mode, nunca se llega a indexar


class ServicePort(BaseModel):
    """Resultado de sondear un puerto concreto de un dominio onion."""

    port: int
    protocol: str  # http, https, ftp, ssh, smtp, smtps, submission, irc, other
    open: bool
    banner: Optional[str] = None


class ServiceEnumeration(BaseModel):
    """
    Resultado de enumerar todos los servicios de un dominio (F2). Se
    persiste por separado del OnionRecord de discovery: son fases
    distintas del pipeline con ritmos de actualizacion distintos (un
    dominio puede re-enumerarse sin necesidad de re-descubrirse).
    """

    address: str
    ports: list[ServicePort] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    http_title: Optional[str] = None
    server_header: Optional[str] = None
    # Resumen breve del contenido, generado por un LLM local (Ollama,
    # opcional - ver config.ENABLE_LLM_SUMMARY). Metadato descriptivo,
    # igual que http_title: nunca se persiste el HTML del que se deriva.
    llm_summary: Optional[str] = None
    # Categoria del tipo de servicio (marketplace, foro, exchange...),
    # tambien generada por el LLM local - ver config.LLM_CATEGORY_CHOICES.
    # Se clasifica a partir del RESUMEN ya generado, no del HTML: no
    # requiere ninguna peticion de red adicional (ni Tor ni al LLM dos
    # veces con el mismo contenido).
    llm_category: Optional[str] = None
    # Pista DEBIL de jurisdiccion/pais, derivada de datos ya guardados
    # (certificado TLS o titulo HTTP) - nunca de la ubicacion de red real,
    # que Tor hace indeterminable por diseño. Ver src/jurisdiction_hint.py.
    jurisdiction_country_code: Optional[str] = None
    jurisdiction_source: Optional[str] = None  # "tls_cert" | "http_title"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def open_ports(self) -> list[ServicePort]:
        return [p for p in self.ports if p.open]


class CryptoAddressMention(BaseModel):
    """Una direccion de criptomoneda encontrada en el contenido de un dominio."""

    currency: str  # BTC, XMR, ETH
    address: str


class HtmlArtifactMention(BaseModel):
    """
    Un recurso enlazado desde el HTML de un dominio (JavaScript, CSS,
    favicon o documento) del que se ha calculado el hash. Nunca se
    persiste el contenido del recurso, solo su hash y la URL de origen
    (para referencia).
    """

    artifact_type: str  # javascript, css, favicon, document
    url: str
    hash: str


class LeakEvidence(BaseModel):
    """
    Datos extraidos de un dominio para correlacion de infraestructura
    (F4, estilo OnionScan). Cada campo es opcional porque no todos los
    dominios exponen todos los tipos de fuga (TLS, JARM, SSH, contenido,
    PGP, direcciones de cripto, artefactos HTML).
    """

    address: str
    tls_cert_sha256: Optional[str] = None
    tls_cert_subject: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    tls_cert_not_valid_after: Optional[datetime] = None
    jarm_hash: Optional[str] = None
    ssh_fingerprint_sha256: Optional[str] = None
    ssh_key_type: Optional[str] = None
    content_fuzzy_hash: Optional[str] = None
    pgp_key_hash: Optional[str] = None
    crypto_addresses: list[CryptoAddressMention] = Field(default_factory=list)
    html_artifacts: list[HtmlArtifactMention] = Field(default_factory=list)
    extracted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class InfrastructureLink(BaseModel):
    """
    Una arista de correlacion entre dos dominios: comparten un mismo
    artefacto de infraestructura (certificado, clave SSH o plantilla de
    contenido similar). Es la unidad basica que alimenta el grafo de
    Neo4j en F5.
    """

    address_a: str
    address_b: str
    relation_type: str  # shared_tls_cert, shared_ssh_key, similar_content
    evidence: str  # hash o valor de similitud, nunca el contenido en si
    confidence: float = 1.0  # 1.0 para coincidencia exacta (cert/ssh), <1.0 para similitud de contenido


class OnionRecord(BaseModel):
    """
    Representa un dominio .onion dentro del dataset fechado.

    discovered_via acumula todas las fuentes semilla que han reportado este
    dominio, lo cual permite el analisis de solapamiento entre motores que
    comentamos en la memoria (cuantos onions unicos aporta cada fuente).
    """

    address: str = Field(..., description="Direccion onion normalizada, sin esquema ni slash final")
    discovered_via: list[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_checked: Optional[datetime] = None
    status: OnionStatus = OnionStatus.UNKNOWN
    depth: int = 0  # saltos desde la semilla original
    is_v3: bool = True

    def add_source(self, source_name: str) -> None:
        if source_name not in self.discovered_via:
            self.discovered_via.append(source_name)

    @staticmethod
    def normalize(raw_address: str) -> str:
        """
        Normaliza una direccion onion: minusculas, sin esquema, sin slash
        final, sin query string. Debe aplicarse ANTES de cualquier
        comparacion de duplicados o insercion en el frontier.
        """
        addr = raw_address.strip().lower()
        for prefix in ("http://", "https://"):
            if addr.startswith(prefix):
                addr = addr[len(prefix):]
        addr = addr.split("/")[0]
        addr = addr.split("?")[0]
        return addr
