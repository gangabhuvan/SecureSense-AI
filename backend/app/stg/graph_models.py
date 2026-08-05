"""
graph_models.py

Core data models for the SecureSense AI
Securities Trust Graph (STG).

The STG represents entities and relationships observed across
financial communications without confusing content mentions
with authenticated sender identity.

Security Boundary
-----------------
A graph relationship records what SecureSense has observed.

For example:

    Communication --MENTIONS--> hdfcbank.com

does NOT imply:

    HDFC Bank --SENT--> Communication

Sender authenticity remains the responsibility of the
Authenticity Verification Engine (AVE).

The STG is responsible for:

- entity representation
- relationship representation
- provenance tracking
- reputation intelligence
- relationship-derived contextual intelligence
- graph-derived trust/risk evidence
- auditable graph analysis results

Important Separation
--------------------
Direct entity reputation and relationship-derived context are
different forms of intelligence.

A risky neighbour does NOT automatically make an entity
phishing.

Relationship intelligence therefore remains contextual and
must not silently create direct ENTITY_SECURITY evidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ============================================================
# Utility
# ============================================================

def utc_now() -> datetime:
    """
    Return the current UTC timestamp.
    """

    return datetime.now(
        timezone.utc
    )


# ============================================================
# Node Types
# ============================================================

class NodeType(str, Enum):
    """
    Supported Securities Trust Graph node categories.
    """

    COMMUNICATION = "Communication"

    ORGANISATION = "Organisation"

    DOMAIN = "Domain"

    URL = "URL"

    EMAIL = "Email"

    PHONE = "Phone"

    UPI_ID = "UPI ID"

    BANK_ACCOUNT = "Bank Account"

    IFSC = "IFSC"

    PAN = "PAN"

    AADHAAR = "Aadhaar"

    SEBI_REGISTRATION = "SEBI Registration"

    QR_CODE = "QR Code"

    IP_ADDRESS = "IP Address"

    UNKNOWN = "Unknown"


# ============================================================
# Relationship Types
# ============================================================

class RelationshipType(str, Enum):
    """
    Supported relationships between graph entities.

    Relationships are deliberately explicit so that observed
    content relationships cannot silently become authenticated
    identity relationships.
    """

    # --------------------------------------------------------
    # Content-derived relationships
    # --------------------------------------------------------

    MENTIONS = "MENTIONS"

    CONTAINS = "CONTAINS"

    REFERENCES = "REFERENCES"

    LINKS_TO = "LINKS_TO"

    OBSERVED_WITH = "OBSERVED_WITH"

    # --------------------------------------------------------
    # Claimed relationships
    # --------------------------------------------------------

    CLAIMS_TO_BE = "CLAIMS_TO_BE"

    CLAIMS_ASSOCIATION_WITH = (
        "CLAIMS_ASSOCIATION_WITH"
    )

    # --------------------------------------------------------
    # Verified / trusted relationships
    # --------------------------------------------------------

    VERIFIED_AS = "VERIFIED_AS"

    USES_DOMAIN = "USES_DOMAIN"

    USES_EMAIL = "USES_EMAIL"

    USES_PHONE = "USES_PHONE"

    REGISTERED_TO = "REGISTERED_TO"

    OWNED_BY = "OWNED_BY"

    # --------------------------------------------------------
    # Risk / intelligence relationships
    # --------------------------------------------------------

    ASSOCIATED_WITH = "ASSOCIATED_WITH"

    PREVIOUSLY_OBSERVED_WITH = (
        "PREVIOUSLY_OBSERVED_WITH"
    )

    FLAGGED_WITH = "FLAGGED_WITH"

    UNKNOWN = "UNKNOWN"


# ============================================================
# Evidence / Provenance Types
# ============================================================

class EvidenceSource(str, Enum):
    """
    Origin of a graph observation.
    """

    CONTENT_EXTRACTION = "Content Extraction"

    NLP_SECURITY = "NLP Security Analysis"

    URL_INTELLIGENCE = "URL Intelligence"

    VISUAL_INTELLIGENCE = (
        "Visual Phishing Intelligence"
    )
    QR_INTELLIGENCE = "QR Intelligence"
    RULE_ENGINE = "Rule Engine"

    AUTHENTICITY_ENGINE = (
        "Authenticity Verification Engine"
    )

    EXPLICIT_METADATA = "Explicit Metadata"

    SECURITIES_TRUST_GRAPH = (
        "Securities Trust Graph"
    )

    EXTERNAL_VERIFICATION = (
        "External Verification"
    )

    SYSTEM = "System"

    UNKNOWN = "Unknown"


# ============================================================
# Trust Classification
# ============================================================

class TrustClassification(str, Enum):
    """
    High-level graph reputation classification.

    UNKNOWN is intentionally different from suspicious.

    Absence of graph history is not evidence of maliciousness.
    """

    TRUSTED = "Trusted"

    LOW_RISK = "Low Risk"

    NEUTRAL = "Neutral"

    SUSPICIOUS = "Suspicious"

    HIGH_RISK = "High Risk"

    UNKNOWN = "Unknown"


# ============================================================
# Graph Node
# ============================================================

class GraphNode(BaseModel):
    """
    Individual entity represented in the Securities Trust Graph.
    """

    node_id: str

    node_type: NodeType

    value: str

    normalized_value: str

    display_name: Optional[str] = None

    verified: bool = False

    first_seen: datetime = Field(
        default_factory=utc_now
    )

    last_seen: datetime = Field(
        default_factory=utc_now
    )

    observation_count: int = 1

    attributes: Dict[str, Any] = Field(
        default_factory=dict
    )

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )


# ============================================================
# Graph Edge
# ============================================================

class GraphEdge(BaseModel):
    """
    Directed relationship between two graph nodes.

    `verified` must only be True when the relationship itself
    has been independently authenticated or established from a
    trusted source.

    A relationship extracted from communication content should
    normally have verified=False.
    """

    edge_id: str

    source_node_id: str

    target_node_id: str

    relationship: RelationshipType

    verified: bool = False

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    evidence_source: EvidenceSource = (
        EvidenceSource.UNKNOWN
    )

    first_seen: datetime = Field(
        default_factory=utc_now
    )

    last_seen: datetime = Field(
        default_factory=utc_now
    )

    observation_count: int = 1

    attributes: Dict[str, Any] = Field(
        default_factory=dict
    )

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )


# ============================================================
# Graph Evidence
# ============================================================

class GraphEvidence(BaseModel):
    """
    Explainable graph-derived evidence.

    This object describes why STG produced a particular trust
    or risk observation.
    """

    evidence_type: str

    description: str

    source: EvidenceSource = (
        EvidenceSource.SECURITIES_TRUST_GRAPH
    )

    node_ids: List[str] = Field(
        default_factory=list
    )

    edge_ids: List[str] = Field(
        default_factory=list
    )

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )

    risk_contribution: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    trust_contribution: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    attributes: Dict[str, Any] = Field(
        default_factory=dict
    )


# ============================================================
# Entity Reputation
# ============================================================

class EntityReputation(BaseModel):
    """
    Reputation assessment for one graph entity.

    Reputation is historical/contextual intelligence derived
    from direct entity-specific security observations.

    It is NOT equivalent to sender authentication.

    Relationship-derived neighbour risk is intentionally NOT
    stored in this object. That intelligence is represented by
    RelationshipRiskContext.
    """

    node_id: str

    node_type: NodeType

    value: str

    classification: TrustClassification = (
        TrustClassification.UNKNOWN
    )

    trust_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
    )

    risk_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    total_observations: int = 0

    legitimate_observations: int = 0

    suspicious_observations: int = 0

    phishing_observations: int = 0

    verified_relationships: int = 0

    suspicious_relationships: int = 0

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )

    reasons: List[str] = Field(
        default_factory=list
    )


# ============================================================
# Relationship Risk Signal
# ============================================================

class RelationshipRiskSignal(BaseModel):
    """
    One explainable relationship-derived contextual signal.

    A signal describes how the reputation of a neighbouring
    graph entity may provide bounded context for the subject
    entity.

    This is NOT direct security evidence about the subject.

    Example:

        URL A
            --FLAGGED_WITH-->
        Domain B

    If Domain B has independently established high-risk
    reputation, the relationship may raise contextual concern
    around URL A.

    It must NOT create a synthetic:

        URL A -> Phishing

    ENTITY_SECURITY observation.
    """

    subject_node_id: str

    neighbour_node_id: str

    neighbour_node_type: NodeType

    neighbour_value: str

    edge_id: str

    relationship: RelationshipType

    edge_verified: bool = False

    edge_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    edge_evidence_source: EvidenceSource = (
        EvidenceSource.UNKNOWN
    )

    neighbour_classification: TrustClassification = (
        TrustClassification.UNKNOWN
    )

    neighbour_risk_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
    )

    neighbour_trust_score: float = Field(
        default=50.0,
        ge=0.0,
        le=100.0,
    )

    neighbour_confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    relationship_weight: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    risk_contribution: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    trust_contribution: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )

    explanation: str = ""

    attributes: Dict[str, Any] = Field(
        default_factory=dict
    )


# ============================================================
# Relationship Risk Context
# ============================================================

class RelationshipRiskContext(BaseModel):
    """
    Bounded relationship-derived contextual intelligence for
    one graph entity.

    Relationship context is deliberately separated from direct
    EntityReputation.

    Therefore:

    - direct model/verification evidence remains direct
    - neighbour reputation remains neighbour reputation
    - graph associations remain contextual
    - no propagated signal becomes fake ENTITY_SECURITY
      evidence
    - sender authentication remains an AVE responsibility

    `contextual_risk_score` describes association-derived
    concern only. It must not silently replace the direct
    reputation risk score or the communication-level phishing
    decision.
    """

    subject_node_id: str

    available: bool = False

    signals: List[
        RelationshipRiskSignal
    ] = Field(
        default_factory=list
    )

    contextual_risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    contextual_trust_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    classification: TrustClassification = (
        TrustClassification.UNKNOWN
    )

    relationships_analysed: int = 0

    contributing_relationships: int = 0

    high_risk_neighbours: int = 0

    suspicious_neighbours: int = 0

    trusted_neighbours: int = 0

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )

    reasons: List[str] = Field(
        default_factory=list
    )

    summary: str = (
        "No relationship-derived contextual intelligence "
        "is currently available."
    )


# ============================================================
# Communication Graph Context
# ============================================================

class CommunicationGraphContext(BaseModel):
    """
    Graph context constructed for one analysed communication.

    This represents relationships observed for the current
    communication without claiming sender authenticity.

    Direct entity reputation and relationship-derived context
    are intentionally exposed separately.
    """

    communication_id: Optional[str] = None

    communication_node_id: Optional[str] = None

    nodes: List[GraphNode] = Field(
        default_factory=list
    )

    edges: List[GraphEdge] = Field(
        default_factory=list
    )

    entity_reputations: List[
        EntityReputation
    ] = Field(
        default_factory=list
    )

    relationship_risk: List[
        RelationshipRiskContext
    ] = Field(
        default_factory=list
    )

    evidence: List[GraphEvidence] = Field(
        default_factory=list
    )


# ============================================================
# STG Analysis Result
# ============================================================

class STGAnalysisResult(BaseModel):
    """
    Final result returned by the Securities Trust Graph engine.

    STG risk is intentionally kept separate from the primary
    multimodal phishing decision.

    It may later participate in a carefully designed fusion
    policy, but graph reputation must not silently override
    trained communication-level security models.

    `graph_risk_score` and `graph_trust_score` retain their
    existing direct historical reputation semantics.

    Relationship-derived contextual intelligence is available
    separately through:

        context.relationship_risk

    This prevents graph associations from silently changing
    direct entity-security reputation.
    """

    available: bool = False

    communication_id: Optional[str] = None

    analysed_at: datetime = Field(
        default_factory=utc_now
    )

    nodes_added: int = 0

    edges_added: int = 0

    nodes_updated: int = 0

    edges_updated: int = 0

    entities_analysed: int = 0

    reputation_available: bool = False

    reputation_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    graph_risk_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    graph_trust_score: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=100.0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
    )

    classification: TrustClassification = (
        TrustClassification.UNKNOWN
    )

    context: CommunicationGraphContext = Field(
        default_factory=CommunicationGraphContext
    )

    evidence_ids: List[str] = Field(
        default_factory=list
    )

    ledger_ids: List[str] = Field(
        default_factory=list
    )

    summary: str = (
        "No Securities Trust Graph intelligence "
        "is currently available."
    )


# ============================================================
# Graph Statistics
# ============================================================

class GraphStatistics(BaseModel):
    """
    Lightweight statistics describing the current STG state.
    """

    total_nodes: int = 0

    total_edges: int = 0

    verified_nodes: int = 0

    verified_edges: int = 0

    communication_nodes: int = 0

    organisation_nodes: int = 0

    domain_nodes: int = 0

    url_nodes: int = 0

    email_nodes: int = 0

    phone_nodes: int = 0

    upi_nodes: int = 0

    bank_account_nodes: int = 0

    sebi_registration_nodes: int = 0


# ============================================================
# Public Exports
# ============================================================

__all__ = [
    "NodeType",
    "RelationshipType",
    "EvidenceSource",
    "TrustClassification",
    "GraphNode",
    "GraphEdge",
    "GraphEvidence",
    "EntityReputation",
    "RelationshipRiskSignal",
    "RelationshipRiskContext",
    "CommunicationGraphContext",
    "STGAnalysisResult",
    "GraphStatistics",
]