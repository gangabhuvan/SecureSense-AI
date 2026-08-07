"""
models.py

Database models for SecureSense AI.

Persistent storage includes:

1. Communications
   - Uploaded files
   - Pasted text
   - OCR / extracted text
   - Final multimodal analysis

2. Securities Trust Graph (STG)
   - Persistent graph entities
   - Persistent graph relationships
   - Historical observations
   - Per-communication observation provenance
   - Evidence provenance

The STG stores graph history independently from the
communication analysis table.

Security Design
---------------
An entity being mentioned inside a high-risk communication
does not automatically make that entity high risk.

STGObservation provides communication-aware provenance so
that:

1. Reprocessing the same communication is idempotent.
2. Historical observations represent independent
   communications rather than repeated processing.
3. Entity-specific security observations can be separated
   from communication-level risk.
"""

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)

from app.database.database import Base

# ============================================================
# User
# ============================================================

class User(Base):
    """
    SecureSense AI user account.
    """

    __tablename__ = "users"

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    username = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
    )

    email = Column(
        String,
        unique=True,
        nullable=False,
        index=True,
    )

    hashed_password = Column(
        String,
        nullable=False,
    )

    is_active = Column(
        Boolean,
        default=True,
        nullable=False,
    )

    created_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    last_login = Column(
        DateTime,
        nullable=True,
    )

# ============================================================
# Communication
# ============================================================

class Communication(Base):
    """
    Persisted communication analysed by SecureSense AI.

    A communication may originate from:
    - An uploaded document/image
    - Direct pasted text

    File-specific fields are therefore allowed to be NULL for
    text-only communications.
    """

    __tablename__ = "communications"

    # ========================================================
    # Primary Identity
    # ========================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    communication_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    # ========================================================
    # Input Metadata
    # ========================================================

    filename = Column(
        String,
        nullable=True,
    )

    file_type = Column(
        String,
        nullable=True,
    )

    filepath = Column(
        String,
        nullable=True,
    )

    filesize = Column(
        Integer,
        nullable=True,
    )

    mime_type = Column(
        String,
        nullable=True,
    )

    sha256 = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # Processing State
    # ========================================================

    status = Column(
        String,
        default="Uploaded",
    )

    uploaded_at = Column(
        DateTime,
        default=datetime.utcnow,
    )

    # ========================================================
    # OCR / Extracted Communication Text
    # ========================================================

    extracted_text = Column(
        Text,
        nullable=True,
    )

    ocr_status = Column(
        String,
        default="Pending",
    )

    # ========================================================
    # Final Multimodal Risk Assessment
    # ========================================================

    risk_score = Column(
        Float,
        default=0.0,
    )

    risk_level = Column(
        String,
        nullable=True,
    )

    confidence = Column(
        Float,
        nullable=True,
    )

    # ========================================================
    # Document / Communication Context
    # ========================================================

    document_type = Column(
        String,
        nullable=True,
    )

    document_confidence = Column(
        Float,
        nullable=True,
    )

    # ========================================================
    # Human-Readable Analysis
    # ========================================================

    summary = Column(
        Text,
        nullable=True,
    )

    # ========================================================
    # Structured Analysis Data
    # ========================================================

    entities = Column(
        JSON,
        nullable=True,
    )

    findings = Column(
        JSON,
        nullable=True,
    )
    # ========================================================
    # Rich Analysis Snapshot
    # ========================================================

    nlp_result = Column(
        JSON,
        nullable=True,
    )

    visual_result = Column(
        JSON,
        nullable=True,
    )

    qr_result = Column(
        JSON,
        nullable=True,
    )

    voice_result = Column(
        JSON,
        nullable=True,
    )

    url_results = Column(
        JSON,
        nullable=True,
    )

    domain_verification = Column(JSON, nullable=True)

    multimodal_fusion = Column(
        JSON,
        nullable=True,
    )

    communication_intent = Column(
        JSON,
        nullable=True,
    )

    evidence_references = Column(
        JSON,
        nullable=True,
    )

    passport = Column(
        JSON,
        nullable=True,
    )
    # ========================================================
    # Performance Metadata
    # ========================================================

    processing_time = Column(
        Float,
        nullable=True,
    )


# ============================================================
# Securities Trust Graph Node
# ============================================================

class STGNode(Base):
    """
    Persistent entity in the SecureSense Securities Trust
    Graph.

    Nodes are deduplicated using:

        node_type + normalized_value

    This allows the same entity to accumulate historical
    observations across multiple independent communications.

    Important
    ---------
    observation_count represents independent persisted
    observations, not the number of times the analysis
    pipeline happened to process the same communication.
    """

    __tablename__ = "stg_nodes"

    __table_args__ = (
        UniqueConstraint(
            "node_type",
            "normalized_value",
            name="uq_stg_node_type_value",
        ),
        Index(
            "ix_stg_nodes_type_value",
            "node_type",
            "normalized_value",
        ),
    )

    # ========================================================
    # Database Identity
    # ========================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ========================================================
    # Stable Graph Identity
    # ========================================================

    node_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    # ========================================================
    # Entity Identity
    # ========================================================

    node_type = Column(
        String,
        index=True,
        nullable=False,
    )

    value = Column(
        Text,
        nullable=False,
    )

    normalized_value = Column(
        Text,
        nullable=False,
    )

    display_name = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # Verification State
    # ========================================================

    verified = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    # ========================================================
    # Historical Observation Metadata
    # ========================================================

    first_seen = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    last_seen = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    observation_count = Column(
        Integer,
        default=1,
        nullable=False,
    )

    # ========================================================
    # Historical Entity-Specific Security Observations
    # ========================================================
    #
    # These counters must represent security evidence about
    # the ENTITY itself.
    #
    # They must NOT simply inherit the overall risk level of
    # every communication that mentions the entity.
    # ========================================================

    legitimate_observations = Column(
        Integer,
        default=0,
        nullable=False,
    )

    suspicious_observations = Column(
        Integer,
        default=0,
        nullable=False,
    )

    phishing_observations = Column(
        Integer,
        default=0,
        nullable=False,
    )

    # ========================================================
    # Extensible Metadata
    # ========================================================

    attributes = Column(
        JSON,
        nullable=True,
    )

    evidence_ids = Column(
        JSON,
        nullable=True,
    )

    ledger_ids = Column(
        JSON,
        nullable=True,
    )


# ============================================================
# Securities Trust Graph Edge
# ============================================================

class STGEdge(Base):
    """
    Persistent directed relationship between two STG nodes.

    Example:

        Communication --MENTIONS--> Domain

    Content-derived relationships must not automatically be
    interpreted as authenticated sender relationships.

    The `verified` field explicitly distinguishes trusted
    relationships from observations extracted from content.
    """

    __tablename__ = "stg_edges"

    __table_args__ = (
        UniqueConstraint(
            "source_node_id",
            "target_node_id",
            "relationship",
            name="uq_stg_edge_relationship",
        ),
        Index(
            "ix_stg_edges_source_target",
            "source_node_id",
            "target_node_id",
        ),
    )

    # ========================================================
    # Database Identity
    # ========================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ========================================================
    # Stable Graph Identity
    # ========================================================

    edge_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    # ========================================================
    # Relationship Endpoints
    # ========================================================

    source_node_id = Column(
        String,
        ForeignKey(
            "stg_nodes.node_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    target_node_id = Column(
        String,
        ForeignKey(
            "stg_nodes.node_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    relationship = Column(
        String,
        nullable=False,
        index=True,
    )

    # ========================================================
    # Relationship Verification
    # ========================================================

    verified = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    confidence = Column(
        Float,
        default=0.0,
        nullable=False,
    )

    evidence_source = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # Historical Observation Metadata
    # ========================================================

    first_seen = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    last_seen = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    observation_count = Column(
        Integer,
        default=1,
        nullable=False,
    )

    # ========================================================
    # Extensible Metadata / Provenance
    # ========================================================

    attributes = Column(
        JSON,
        nullable=True,
    )

    evidence_ids = Column(
        JSON,
        nullable=True,
    )

    ledger_ids = Column(
        JSON,
        nullable=True,
    )


# ============================================================
# Securities Trust Graph Observation
# ============================================================

class STGObservation(Base):
    """
    Persistent provenance record representing an independent
    observation made by the Securities Trust Graph.

    Why this table exists
    ---------------------
    STGNode and STGEdge represent persistent graph objects.

    They do not, by themselves, tell us whether a particular
    communication has already contributed an observation.

    Without persistent observation provenance, processing the
    same communication twice could incorrectly increment:

    - observation_count
    - legitimate_observations
    - suspicious_observations
    - phishing_observations
    - relationship observation counts

    STGObservation therefore provides communication-level
    idempotency.

    Security Boundary
    -----------------
    security_observation is optional.

    A content-derived mention such as:

        phishing communication
            --MENTIONS-->
        https://www.hdfcbank.com

    may create an observation proving that the communication
    mentioned the URL.

    It must NOT automatically create:

        security_observation = "High"

    for the URL itself.

    Entity security reputation requires entity-specific
    evidence.
    """

    __tablename__ = "stg_observations"

    __table_args__ = (
        UniqueConstraint(
            "communication_id",
            "subject_type",
            "subject_id",
            "observation_type",
            name="uq_stg_communication_observation",
        ),
        Index(
            "ix_stg_observations_communication",
            "communication_id",
        ),
        Index(
            "ix_stg_observations_subject",
            "subject_type",
            "subject_id",
        ),
    )

    # ========================================================
    # Database Identity
    # ========================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ========================================================
    # Stable Observation Identity
    # ========================================================

    observation_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    # ========================================================
    # Communication Provenance
    # ========================================================

    communication_id = Column(
        String,
        nullable=False,
        index=True,
    )

    # ========================================================
    # Observed Graph Subject
    # ========================================================
    #
    # subject_type:
    #
    #     "node"
    #     "edge"
    #
    # subject_id:
    #
    #     STGN-...
    #     STGE-...
    #
    # We intentionally do not use a single SQL foreign key
    # here because the subject may refer to either table.
    # ========================================================

    subject_type = Column(
        String,
        nullable=False,
    )

    subject_id = Column(
        String,
        nullable=False,
        index=True,
    )

    # ========================================================
    # Observation Semantics
    # ========================================================
    #
    # Examples:
    #
    #     ENTITY_MENTION
    #     DOMAIN_DERIVATION
    #     VERIFIED_RELATIONSHIP
    #     ENTITY_SECURITY
    #
    # This allows one communication to provide different
    # independent forms of evidence about the same subject
    # without allowing repeated processing of the exact same
    # observation to inflate history.
    # ========================================================

    observation_type = Column(
        String,
        nullable=False,
    )

    # ========================================================
    # Entity-Specific Security Observation
    # ========================================================
    #
    # Examples:
    #
    #     Legitimate
    #     Suspicious
    #     High
    #
    # NULL means:
    #
    #     "This observation establishes an association, but
    #      does not classify the subject itself."
    #
    # This distinction prevents communication-level risk from
    # poisoning entity reputation.
    # ========================================================

    security_observation = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # Observation Confidence / Verification
    # ========================================================

    verified = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    confidence = Column(
        Float,
        default=0.0,
        nullable=False,
    )

    evidence_source = Column(
        String,
        nullable=True,
    )

    # ========================================================
    # Time
    # ========================================================

    observed_at = Column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )

    # ========================================================
    # Extensible Metadata / Provenance
    # ========================================================

    attributes = Column(
        JSON,
        nullable=True,
    )

    evidence_ids = Column(
        JSON,
        nullable=True,
    )

    ledger_ids = Column(
        JSON,
        nullable=True,
    )
class EELEntry(Base):
    """
    Persistent Explainable Evidence Ledger entry.

    Stores the complete canonical EvidenceRecord together with
    communication provenance so evidence remains auditable
    across backend restarts.

    The complete evidence payload is stored as JSON because
    different intelligence modules produce different forms of
    explainability:

    - NLP Security Analysis -> Integrated Gradients
    - Visual Phishing Intelligence -> Grad-CAM
    - URL Intelligence -> TreeSHAP
    """

    __tablename__ = "eel_entries"

    __table_args__ = (
        Index(
            "ix_eel_entries_communication",
            "communication_id",
        ),
        Index(
            "ix_eel_entries_module",
            "module",
        ),
    )

    # ========================================================
    # Database Identity
    # ========================================================

    id = Column(
        Integer,
        primary_key=True,
        index=True,
    )

    # ========================================================
    # Stable EEL Identities
    # ========================================================

    ledger_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    evidence_id = Column(
        String,
        unique=True,
        index=True,
        nullable=False,
    )

    # ========================================================
    # Communication Provenance
    # ========================================================

    communication_id = Column(
        String,
        ForeignKey(
            "communications.communication_id",
            ondelete="CASCADE",
        ),
        nullable=False,
    )

    # ========================================================
    # Evidence Classification
    # ========================================================

    module = Column(
        String,
        nullable=False,
    )

    evidence_type = Column(
        String,
        nullable=False,
    )

    prediction = Column(
        String,
        nullable=False,
    )

    confidence = Column(
        Float,
        nullable=False,
    )

    risk_score = Column(
        Float,
        nullable=False,
    )

    # ========================================================
    # Time
    # ========================================================

    recorded_at = Column(
        DateTime,
        nullable=False,
    )

    # ========================================================
    # Canonical Evidence Payload
    # ========================================================

    evidence = Column(
        JSON,
        nullable=False,
    )


# ============================================================
# Public Exports
# ============================================================

__all__ = [
    "User",
    "Communication",
    "STGNode",
    "STGEdge",
    "STGObservation",
    "EELEntry",
]