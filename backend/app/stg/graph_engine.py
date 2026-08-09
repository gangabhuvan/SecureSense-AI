"""
graph_engine.py

Persistent Securities Trust Graph (STG) engine for SecureSense AI.

Responsibilities
----------------
- Normalize graph entities
- Create deterministic graph identities
- Persist graph nodes and edges
- Persist communication-aware graph observations
- Prevent duplicate processing from inflating graph history
- Keep communication risk separate from entity reputation
- Preserve evidence and ledger provenance
- Calculate historical entity reputation
- Construct communication-level graph context
- Produce explainable graph intelligence
- Provide graph statistics

Security Boundary
-----------------
The STG records observations and historical associations.

A content-derived relationship such as:

    Communication --MENTIONS--> hdfcbank.com

does NOT establish:

    HDFC Bank --SENT--> Communication

and does NOT establish:

    hdfcbank.com --IS PHISHING-->

merely because the surrounding communication was classified
as phishing.

Communication-level risk belongs to the communication.

Entity reputation requires entity-specific security evidence.

Sender authentication remains the responsibility of the
Authenticity Verification Engine (AVE).

Graph reputation remains separate from the primary multimodal
phishing decision unless an explicit fusion policy is
introduced elsewhere.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime
from typing import Any, Iterable
from urllib.parse import urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database.models import (
    STGEdge,
    STGNode,
    STGObservation,
)

from app.stg.graph_models import (
    CommunicationGraphContext,
    EntityReputation,
    EvidenceSource,
    GraphEdge,
    GraphEvidence,
    GraphNode,
    GraphStatistics,
    NodeType,
    RelationshipRiskContext,
    RelationshipRiskSignal,
    RelationshipType,
    STGAnalysisResult,
    TrustClassification,
)


# ============================================================
# Securities Trust Graph Engine
# ============================================================

class SecuritiesTrustGraphEngine:
    """
    Persistent graph intelligence engine for SecureSense AI.

    The engine separates:

    1. content observations
    2. entity-specific security observations
    3. historical reputation
    4. authenticated identity

    STG records the first three.

    AVE remains authoritative for authenticated identity.
    """

    # ========================================================
    # Entity Mapping
    # ========================================================

    ENTITY_NODE_TYPES = {
        "urls": NodeType.URL,
        "emails": NodeType.EMAIL,
        "phone_numbers": NodeType.PHONE,
        "upi_ids": NodeType.UPI_ID,
        "bank_accounts": NodeType.BANK_ACCOUNT,
        "ifsc_codes": NodeType.IFSC,
        "pan_numbers": NodeType.PAN,
        "aadhaar_numbers": NodeType.AADHAAR,
        "sebi_numbers": NodeType.SEBI_REGISTRATION,
        "qr_codes": NodeType.QR_CODE,
    }

    # ========================================================
    # Observation Types
    # ========================================================

    OBSERVATION_COMMUNICATION = (
        "COMMUNICATION_ANALYSIS"
    )

    OBSERVATION_ENTITY_MENTION = (
        "ENTITY_MENTION"
    )

    OBSERVATION_DOMAIN_DERIVATION = (
        "DOMAIN_DERIVATION"
    )

    OBSERVATION_ENTITY_SECURITY = (
        "ENTITY_SECURITY"
    )

    OBSERVATION_VERIFIED_RELATIONSHIP = (
        "VERIFIED_RELATIONSHIP"
    )

    # ========================================================
    # Construction
    # ========================================================

    def __init__(self) -> None:
        """
        Create the STG engine.

        Database sessions are supplied explicitly by callers.
        """

        pass

    # ========================================================
    # Public Analysis Entry Point
    # ========================================================

    def analyse(
        self,
        db: Session,
        communication_id: str | None,
        entities: dict[str, Any] | None,
        risk_level: str | None = None,
        risk_score: float | None = None,
        evidence_ids: list[str] | None = None,
        ledger_ids: list[str] | None = None,
        entity_security_observations: (
            dict[str, dict[str, Any]] | None
        ) = None,
    ) -> STGAnalysisResult:
        """
        Analyse and persist graph context for one communication.

        Extracted entities are content observations.

        The communication's risk classification is stored on
        the communication node only.

        It is NOT propagated into entity reputation.

        STGObservation makes processing idempotent for a stable
        communication_id.
        """

        entities = (
            entities
            if isinstance(entities, dict)
            else {}
        )

        evidence_ids = self._unique_strings(
            evidence_ids
        )

        ledger_ids = self._unique_strings(
            ledger_ids
        )

        normalized_communication_id = (
            str(communication_id).strip()
            if communication_id
            else None
        )

        # =====================================================
        # Communication Replay Detection
        # =====================================================
        #
        # A stable communication_id represents one historical
        # communication event.
        #
        # If its communication observation already exists, this
        # analyse() invocation is a replay. Existing persistent
        # graph objects must then be reconstructed without
        # mutating their historical provenance.
        # =====================================================

        communication_replay = False

        if normalized_communication_id:

            predicted_communication_node_id = (
                self._make_node_id(
                    NodeType.COMMUNICATION,
                    self.normalize_value(
                        NodeType.COMMUNICATION,
                        normalized_communication_id,
                    ),
                )
            )

            communication_replay = (
                self._observation_exists(
                    db=db,
                    communication_id=(
                        normalized_communication_id
                    ),
                    subject_type="node",
                    subject_id=(
                        predicted_communication_node_id
                    ),
                    observation_type=(
                        self.OBSERVATION_COMMUNICATION
                    ),
                )
            )

        context = CommunicationGraphContext(
            communication_id=(
                normalized_communication_id
            ),
        )

        result = STGAnalysisResult(
            available=True,
            communication_id=(
                normalized_communication_id
            ),
            context=context,
        )

        try:

            # =================================================
            # Communication Node
            # =================================================

            communication_node = None

            if normalized_communication_id:

                communication_node_id = (
                    self._make_node_id(
                        NodeType.COMMUNICATION,
                        self.normalize_value(
                            NodeType.COMMUNICATION,
                            normalized_communication_id,
                        ),
                    )
                )

                communication_is_new = (
                    not self._observation_exists(
                        db=db,
                        communication_id=(
                            normalized_communication_id
                        ),
                        subject_type="node",
                        subject_id=(
                            communication_node_id
                        ),
                        observation_type=(
                            self.OBSERVATION_COMMUNICATION
                        ),
                    )
                )

                (
                    communication_node,
                    created,
                ) = self.upsert_node(
                    db=db,
                    node_type=NodeType.COMMUNICATION,
                    value=normalized_communication_id,
                    display_name=(
                        normalized_communication_id
                    ),
                    verified=False,
                    attributes=(
                        {}
                        if communication_replay
                        else {
                            "risk_level": risk_level,
                            "risk_score": risk_score,
                        }
                    ),
                    evidence_ids=(
                        []
                        if communication_replay
                        else evidence_ids
                    ),
                    ledger_ids=(
                        []
                        if communication_replay
                        else ledger_ids
                    ),

                    # Communication risk may safely remain on
                    # the communication node itself.
                    security_observation=(
                        risk_level
                        if communication_is_new
                        else None
                    ),

                    increment_observation=(
                        communication_is_new
                    ),
                )

                self._record_observation(
                    db=db,
                    communication_id=(
                        normalized_communication_id
                    ),
                    subject_type="node",
                    subject_id=(
                        communication_node.node_id
                    ),
                    observation_type=(
                        self.OBSERVATION_COMMUNICATION
                    ),
                    security_observation=risk_level,
                    verified=False,
                    confidence=100.0,
                    evidence_source=(
                        EvidenceSource.SECURITIES_TRUST_GRAPH
                    ),
                    attributes={
                        "communication_level": True,
                        "risk_level": risk_level,
                        "risk_score": risk_score,
                        "entity_reputation_evidence": False,
                    },
                    evidence_ids=evidence_ids,
                    ledger_ids=ledger_ids,
                )

                context.communication_node_id = (
                    communication_node.node_id
                )

                context.nodes.append(
                    communication_node
                )

                if created:
                    result.nodes_added += 1

                elif communication_is_new:
                    result.nodes_updated += 1

            # =================================================
            # Extracted Content Entities
            # =================================================



            entity_nodes: list[GraphNode] = []

            seen_entity_subjects: set[
                tuple[str, str]
            ] = set()

            for (
                entity_key,
                node_type,
            ) in self.ENTITY_NODE_TYPES.items():

                if entity_key == "qr_codes":
                    continue

                values = entities.get(
                    entity_key,
                    []
                )

                if not isinstance(
                    values,
                    (list, tuple, set),
                ):
                    continue

                for value in values:

                    if value is None:
                        continue

                    value = str(
                        value
                    ).strip()

                    if not value:
                        continue

                    normalized_value = (
                        self.normalize_value(
                            node_type,
                            value,
                        )
                    )

                    if not normalized_value:
                        continue

                    predicted_node_id = (
                        self._make_node_id(
                            node_type,
                            normalized_value,
                        )
                    )

                    entity_identity = (
                        node_type.value,
                        predicted_node_id,
                    )

                    # Duplicate extraction of the same entity
                    # inside one communication should not count
                    # as multiple historical observations.
                    if (
                        entity_identity
                        in seen_entity_subjects
                    ):
                        continue

                    seen_entity_subjects.add(
                        entity_identity
                    )

                    entity_observation_is_new = True

                    if normalized_communication_id:

                        entity_observation_is_new = (
                            not self._observation_exists(
                                db=db,
                                communication_id=(
                                    normalized_communication_id
                                ),
                                subject_type="node",
                                subject_id=(
                                    predicted_node_id
                                ),
                                observation_type=(
                                    self.OBSERVATION_ENTITY_MENTION
                                ),
                            )
                        )

                    (
                        node,
                        created,
                    ) = self.upsert_node(
                        db=db,
                        node_type=node_type,
                        value=value,
                        verified=False,
                        evidence_ids=(
                            []
                            if communication_replay
                            else evidence_ids
                        ),
                        ledger_ids=(
                            []
                            if communication_replay
                            else ledger_ids
                        ),

                        # SECURITY BOUNDARY:
                        #
                        # Do not pass communication risk here.
                        security_observation=None,

                        increment_observation=(
                            entity_observation_is_new
                        ),
                    )

                    entity_nodes.append(
                        node
                    )

                    context.nodes.append(
                        node
                    )

                    if created:
                        result.nodes_added += 1

                    elif entity_observation_is_new:
                        result.nodes_updated += 1

                    result.entities_analysed += 1

                    # -----------------------------------------
                    # Persistent Entity Mention Observation
                    # -----------------------------------------

                    if normalized_communication_id:

                        self._record_observation(
                            db=db,
                            communication_id=(
                                normalized_communication_id
                            ),
                            subject_type="node",
                            subject_id=node.node_id,
                            observation_type=(
                                self.OBSERVATION_ENTITY_MENTION
                            ),

                            # A mention is not an entity
                            # security verdict.
                            security_observation=None,

                            verified=False,
                            confidence=100.0,
                            evidence_source=(
                                EvidenceSource.CONTENT_EXTRACTION
                            ),
                            attributes={
                                "entity_key": entity_key,
                                "content_derived": True,
                                "authentication_evidence": False,
                                "entity_security_evidence": False,
                            },
                            evidence_ids=evidence_ids,
                            ledger_ids=ledger_ids,
                        )

                    # -----------------------------------------
                    # Communication -> Entity
                    # -----------------------------------------

                    if communication_node:

                        predicted_edge_id = (
                            self._make_edge_id(
                                communication_node.node_id,
                                node.node_id,
                                RelationshipType.MENTIONS,
                            )
                        )

                        edge_observation_is_new = True

                        if normalized_communication_id:

                            edge_observation_is_new = (
                                not self._observation_exists(
                                    db=db,
                                    communication_id=(
                                        normalized_communication_id
                                    ),
                                    subject_type="edge",
                                    subject_id=(
                                        predicted_edge_id
                                    ),
                                    observation_type=(
                                        self.OBSERVATION_ENTITY_MENTION
                                    ),
                                )
                            )

                        (
                            edge,
                            edge_created,
                        ) = self.upsert_edge(
                            db=db,
                            source_node_id=(
                                communication_node.node_id
                            ),
                            target_node_id=node.node_id,
                            relationship=(
                                RelationshipType.MENTIONS
                            ),
                            verified=False,
                            confidence=100.0,
                            evidence_source=(
                                EvidenceSource.CONTENT_EXTRACTION
                            ),
                            evidence_ids=(
                                []
                                if communication_replay
                                else evidence_ids
                            ),
                            ledger_ids=(
                                []
                                if communication_replay
                                else ledger_ids
                            ),
                            attributes={
                                "content_derived": True,
                                "authentication_evidence": False,
                                "entity_security_evidence": False,
                            },
                            increment_observation=(
                                edge_observation_is_new
                            ),
                        )

                        context.edges.append(
                            edge
                        )

                        if edge_created:
                            result.edges_added += 1

                        elif edge_observation_is_new:
                            result.edges_updated += 1

                        if normalized_communication_id:

                            self._record_observation(
                                db=db,
                                communication_id=(
                                    normalized_communication_id
                                ),
                                subject_type="edge",
                                subject_id=edge.edge_id,
                                observation_type=(
                                    self.OBSERVATION_ENTITY_MENTION
                                ),
                                security_observation=None,
                                verified=False,
                                confidence=100.0,
                                evidence_source=(
                                    EvidenceSource.CONTENT_EXTRACTION
                                ),
                                attributes={
                                    "content_derived": True,
                                    "authentication_evidence": False,
                                    "entity_security_evidence": False,
                                },
                                evidence_ids=evidence_ids,
                                ledger_ids=ledger_ids,
                            )

                    # -----------------------------------------
                    # URL -> Domain
                    # -----------------------------------------

                    if node_type == NodeType.URL:

                        domain = self._extract_domain(
                            value
                        )

                        if domain:

                            normalized_domain = (
                                self.normalize_value(
                                    NodeType.DOMAIN,
                                    domain,
                                )
                            )

                            predicted_domain_id = (
                                self._make_node_id(
                                    NodeType.DOMAIN,
                                    normalized_domain,
                                )
                            )

                            domain_observation_is_new = True

                            if normalized_communication_id:

                                domain_observation_is_new = (
                                    not self._observation_exists(
                                        db=db,
                                        communication_id=(
                                            normalized_communication_id
                                        ),
                                        subject_type="node",
                                        subject_id=(
                                            predicted_domain_id
                                        ),
                                        observation_type=(
                                            self.OBSERVATION_DOMAIN_DERIVATION
                                        ),
                                    )
                                )

                            (
                                domain_node,
                                domain_created,
                            ) = self.upsert_node(
                                db=db,
                                node_type=NodeType.DOMAIN,
                                value=domain,
                                display_name=domain,
                                verified=False,
                                evidence_ids=(
                                    []
                                    if communication_replay
                                    else evidence_ids
                                ),
                                ledger_ids=(
                                    []
                                    if communication_replay
                                    else ledger_ids
                                ),

                                # SECURITY BOUNDARY:
                                #
                                # URL-derived domain existence
                                # is not a security verdict.
                                security_observation=None,

                                increment_observation=(
                                    domain_observation_is_new
                                ),
                            )

                            context.nodes.append(
                                domain_node
                            )

                            if domain_created:
                                result.nodes_added += 1

                            elif domain_observation_is_new:
                                result.nodes_updated += 1

                            if normalized_communication_id:

                                self._record_observation(
                                    db=db,
                                    communication_id=(
                                        normalized_communication_id
                                    ),
                                    subject_type="node",
                                    subject_id=(
                                        domain_node.node_id
                                    ),
                                    observation_type=(
                                        self.OBSERVATION_DOMAIN_DERIVATION
                                    ),
                                    security_observation=None,
                                    verified=False,
                                    confidence=100.0,
                                    evidence_source=(
                                        EvidenceSource.CONTENT_EXTRACTION
                                    ),
                                    attributes={
                                        "derived_from_url": (
                                            node.node_id
                                        ),
                                        "authentication_evidence": False,
                                        "entity_security_evidence": False,
                                    },
                                    evidence_ids=evidence_ids,
                                    ledger_ids=ledger_ids,
                                )

                            predicted_domain_edge_id = (
                                self._make_edge_id(
                                    node.node_id,
                                    domain_node.node_id,
                                    RelationshipType.LINKS_TO,
                                )
                            )

                            domain_edge_observation_is_new = True

                            if normalized_communication_id:

                                domain_edge_observation_is_new = (
                                    not self._observation_exists(
                                        db=db,
                                        communication_id=(
                                            normalized_communication_id
                                        ),
                                        subject_type="edge",
                                        subject_id=(
                                            predicted_domain_edge_id
                                        ),
                                        observation_type=(
                                            self.OBSERVATION_DOMAIN_DERIVATION
                                        ),
                                    )
                                )

                            (
                                domain_edge,
                                domain_edge_created,
                            ) = self.upsert_edge(
                                db=db,
                                source_node_id=node.node_id,
                                target_node_id=(
                                    domain_node.node_id
                                ),
                                relationship=(
                                    RelationshipType.LINKS_TO
                                ),
                                verified=False,
                                confidence=100.0,
                                evidence_source=(
                                    EvidenceSource.CONTENT_EXTRACTION
                                ),
                                evidence_ids=(
                                    []
                                    if communication_replay
                                    else evidence_ids
                                ),
                                ledger_ids=(
                                    []
                                    if communication_replay
                                    else ledger_ids
                                ),
                                attributes={
                                    "derived_from_url": True,
                                    "authentication_evidence": False,
                                    "entity_security_evidence": False,
                                },
                                increment_observation=(
                                    domain_edge_observation_is_new
                                ),
                            )

                            context.edges.append(
                                domain_edge
                            )

                            if domain_edge_created:
                                result.edges_added += 1

                            elif domain_edge_observation_is_new:
                                result.edges_updated += 1

                            if normalized_communication_id:

                                self._record_observation(
                                    db=db,
                                    communication_id=(
                                        normalized_communication_id
                                    ),
                                    subject_type="edge",
                                    subject_id=(
                                        domain_edge.edge_id
                                    ),
                                    observation_type=(
                                        self.OBSERVATION_DOMAIN_DERIVATION
                                    ),
                                    security_observation=None,
                                    verified=False,
                                    confidence=100.0,
                                    evidence_source=(
                                        EvidenceSource.CONTENT_EXTRACTION
                                    ),
                                    attributes={
                                        "derived_from_url": True,
                                        "authentication_evidence": False,
                                        "entity_security_evidence": False,
                                    },
                                    evidence_ids=evidence_ids,
                                    ledger_ids=ledger_ids,
                                )
            qr_entities = entities.get("qr_codes", [])
            if (
                communication_node
                and isinstance(qr_entities, list)
            ):
                for qr in qr_entities:
                    if not isinstance(qr, dict):
                        continue

                    qr_id = str(
                        qr.get("qr_id") or ""
                    ).strip()

                    if not qr_id:
                        continue

                    payload = str(
                        qr.get("payload") or qr_id
                    ).strip()

                    decoded_url = str(
                        qr.get("decoded_url") or ""
                    ).strip()
                    predicted_qr_node_id = self._make_node_id(
                        NodeType.QR_CODE,
                        self.normalize_value(
                            NodeType.QR_CODE,
                            qr_id,
                        ),
                    )

                    qr_observation_is_new = True

                    if normalized_communication_id:
                        qr_observation_is_new = (
                            not self._observation_exists(
                                db=db,
                                communication_id=normalized_communication_id,
                                subject_type="node",
                                subject_id=predicted_qr_node_id,
                                observation_type=self.OBSERVATION_ENTITY_MENTION,
                            )
                        )
                    (
                        qr_node,
                        qr_created,
                    ) = self.upsert_node(

                        db=db,

                        node_type=NodeType.QR_CODE,

                        value=qr_id,

                        display_name=payload,

                        verified=False,

                        evidence_ids=self._unique_strings([
                            qr.get("evidence_id")
                        ]),

                        ledger_ids=self._unique_strings([
                            qr.get("ledger_id")
                        ]),

                        security_observation=None,

                        increment_observation=qr_observation_is_new,
                    ) 

                    context.nodes.append(qr_node)

                    if normalized_communication_id:
                        self._record_observation(
                            db=db,
                            communication_id=normalized_communication_id,
                            subject_type="node",
                            subject_id=qr_node.node_id,
                            observation_type=self.OBSERVATION_ENTITY_MENTION,
                            security_observation=None,
                            verified=False,
                            confidence=100.0,
                            evidence_source=EvidenceSource.QR_INTELLIGENCE,
                            attributes={
                                "entity_key": "qr_codes",
                                "content_derived": True,
                                "authentication_evidence": False,
                                "entity_security_evidence": False,
                            },
                            evidence_ids=self._unique_strings([
                                qr.get("evidence_id")
                            ]),
                            ledger_ids=self._unique_strings([
                                qr.get("ledger_id")
                            ]),
                        )

                    entity_nodes.append(qr_node)

                    result.entities_analysed += 1

                    if qr_created:
                        result.nodes_added += 1
                    predicted_qr_edge_id = self._make_edge_id(
                        communication_node.node_id,
                        qr_node.node_id,
                        RelationshipType.CONTAINS,
                    )

                    qr_edge_observation_is_new = True

                    if normalized_communication_id:
                        qr_edge_observation_is_new = (
                            not self._observation_exists(
                                db=db,
                                communication_id=normalized_communication_id,
                                subject_type="edge",
                                subject_id=predicted_qr_edge_id,
                                observation_type=self.OBSERVATION_ENTITY_MENTION,
                            )
                        )
                    (
                        qr_edge,
                        qr_edge_created,
                    ) = self.upsert_edge(

                        db=db,

                        source_node_id=communication_node.node_id,

                        target_node_id=qr_node.node_id,

                        relationship=RelationshipType.CONTAINS,

                        verified=False,

                        confidence=100.0,

                        evidence_source=EvidenceSource.QR_INTELLIGENCE,

                        evidence_ids=self._unique_strings([
                            qr.get("evidence_id")
                        ]),

                        ledger_ids=self._unique_strings([
                            qr.get("ledger_id")
                        ]),

                        attributes={
                            "content_derived": True,
                            "authentication_evidence": False,
                            "entity_security_evidence": False,
                        },

                        increment_observation=qr_edge_observation_is_new,
                    )

                    context.edges.append(qr_edge)

                    if normalized_communication_id:
                        self._record_observation(
                            db=db,
                            communication_id=normalized_communication_id,
                            subject_type="edge",
                            subject_id=qr_edge.edge_id,
                            observation_type=self.OBSERVATION_ENTITY_MENTION,
                            security_observation=None,
                            verified=False,
                            confidence=100.0,
                            evidence_source=EvidenceSource.QR_INTELLIGENCE,
                            attributes={
                                "content_derived": True,
                                "authentication_evidence": False,
                                "entity_security_evidence": False,
                            },
                            evidence_ids=self._unique_strings([
                                qr.get("evidence_id")
                            ]),
                            ledger_ids=self._unique_strings([
                                qr.get("ledger_id")
                            ]),
                        )

                    if qr_edge_created:
                        result.edges_added += 1

                    if not decoded_url:
                        continue

                    (
                        url_node,
                        url_created,
                    ) = self.upsert_node(

                        db=db,

                        node_type=NodeType.URL,

                        value=decoded_url,

                        verified=False,

                        evidence_ids=self._unique_strings([
                            qr.get("url_evidence_id")
                        ]),

                        ledger_ids=self._unique_strings([
                            qr.get("url_ledger_id")
                        ]),

                        security_observation=qr.get("url_label"),

                        increment_observation=True,
                    )

                    context.nodes.append(url_node)

                    domain = self._extract_domain(
                        decoded_url
                    )

                    if domain:
                        (
                            domain_node,
                            _,
                        ) = self.upsert_node(
                            db=db,
                            node_type=NodeType.DOMAIN,
                            value=domain,
                            display_name=domain,
                            verified=False,
                            increment_observation=True,
                        )

                        context.nodes.append(domain_node)
                        (
                            domain_edge,
                            _,
                        ) = self.upsert_edge(
                            db=db,
                            source_node_id=url_node.node_id,
                            target_node_id=domain_node.node_id,
                            relationship=RelationshipType.LINKS_TO,
                            confidence=100.0,
                            evidence_source=EvidenceSource.QR_INTELLIGENCE,
                            increment_observation=True,
                        )

                        context.edges.append(domain_edge)
                    result.nodes_added += int(url_created)

                    (
                        qr_url_edge,
                        qr_url_created,
                    ) = self.upsert_edge(

                        db=db,

                        source_node_id=qr_node.node_id,

                        target_node_id=url_node.node_id,

                        relationship=RelationshipType.LINKS_TO,

                        verified=False,

                        confidence=100.0,

                        evidence_source=EvidenceSource.QR_INTELLIGENCE,

                        evidence_ids=self._unique_strings([
                            qr.get("evidence_id")
                        ]),

                        ledger_ids=self._unique_strings([
                            qr.get("ledger_id")
                        ]),

                        attributes={
                            "decoded_from_qr": True,
                        },

                        increment_observation=True,
                    )

                    context.edges.append(qr_url_edge)

                    if qr_url_created:
                        result.edges_added += 1
            # =================================================
            # Entity-Specific Security Observations
            # =================================================
            #
            # Apply explicit entity intelligence BEFORE
            # calculating reputation. Communication-level risk
            # is deliberately never propagated here.

            if (
                normalized_communication_id
                and isinstance(entity_security_observations, dict)
            ):
                for observation_key, observation_data in (
                    entity_security_observations.items()
                ):
                    if not isinstance(observation_data, dict):
                        continue

                    security_observation = (
                        observation_data.get("security_observation")
                        or observation_data.get("verdict")
                        or observation_data.get("risk_level")
                    )
                    if not security_observation:
                        continue

                    target_node = None
                    target_node_id = observation_data.get("node_id")

                    if target_node_id:
                        target_node = (
                            db.query(STGNode)
                            .filter(
                                STGNode.node_id
                                == str(target_node_id).strip()
                            )
                            .first()
                        )

                    entity_value = (
                        observation_data.get("url")
                        or observation_data.get("value")
                        or observation_data.get("entity_value")
                    )

                    if not target_node and not entity_value:
                        key_text = str(observation_key).strip()
                        if key_text.startswith("STGN-"):
                            target_node = (
                                db.query(STGNode)
                                .filter(STGNode.node_id == key_text)
                                .first()
                            )
                        else:
                            entity_value = key_text

                    if not target_node and entity_value:
                        raw_node_type = observation_data.get("node_type")
                        node_type = None

                        if raw_node_type:
                            try:
                                node_type = NodeType(
                                    raw_node_type.value
                                    if isinstance(raw_node_type, NodeType)
                                    else str(raw_node_type).strip()
                                )
                            except (ValueError, TypeError):
                                node_type = None

                        if node_type is None:
                            node_type = NodeType.URL

                        normalized_entity_value = self.normalize_value(
                            node_type,
                            str(entity_value),
                        )

                        if normalized_entity_value:
                            target_node = (
                                db.query(STGNode)
                                .filter(
                                    STGNode.node_type == node_type.value,
                                    STGNode.normalized_value
                                    == normalized_entity_value,
                                )
                                .first()
                            )

                    if not target_node:
                        continue

                    source_raw = (
                        observation_data.get("evidence_source")
                        or EvidenceSource.SECURITIES_TRUST_GRAPH
                    )

                    if isinstance(source_raw, EvidenceSource):
                        source = source_raw
                    else:
                        try:
                            source = EvidenceSource(
                                str(source_raw).strip()
                            )
                        except (ValueError, TypeError):
                            source = (
                                EvidenceSource.SECURITIES_TRUST_GRAPH
                            )

                    observation_evidence_ids = self._unique_strings(
                        observation_data.get("evidence_ids")
                    )
                    observation_ledger_ids = self._unique_strings(
                        observation_data.get("ledger_ids")
                    )

                    if not observation_evidence_ids:
                        observation_evidence_ids = evidence_ids
                    if not observation_ledger_ids:
                        observation_ledger_ids = ledger_ids

                    observation_attributes = observation_data.get(
                        "attributes"
                    )
                    if not isinstance(observation_attributes, dict):
                        observation_attributes = {}

                    security_is_new = not self._observation_exists(
                        db=db,
                        communication_id=normalized_communication_id,
                        subject_type="node",
                        subject_id=target_node.node_id,
                        observation_type=(
                            self.OBSERVATION_ENTITY_SECURITY
                        ),
                    )

                    _, security_created = self._record_observation(
                        db=db,
                        communication_id=normalized_communication_id,
                        subject_type="node",
                        subject_id=target_node.node_id,
                        observation_type=(
                            self.OBSERVATION_ENTITY_SECURITY
                        ),
                        security_observation=str(
                            security_observation
                        ).strip(),
                        verified=bool(
                            observation_data.get("verified", False)
                        ),
                        confidence=self._clamp_score(
                            observation_data.get("confidence", 0.0)
                        ),
                        evidence_source=source,
                        attributes=self._merge_dicts(
                            observation_attributes,
                            {
                                "entity_specific_security_evidence": True,
                                "communication_level": False,
                            },
                        ),
                        evidence_ids=observation_evidence_ids,
                        ledger_ids=observation_ledger_ids,
                    )

                    if security_is_new and security_created:
                        self._apply_security_observation(
                            target_node,
                            str(security_observation).strip(),
                        )
                        target_node.evidence_ids = (
                            self._merge_string_lists(
                                target_node.evidence_ids,
                                observation_evidence_ids,
                            )
                        )
                        target_node.ledger_ids = (
                            self._merge_string_lists(
                                target_node.ledger_ids,
                                observation_ledger_ids,
                            )
                        )

                        if bool(
                            observation_data.get("verified", False)
                        ):
                            target_node.verified = True

                        target_node.attributes = self._merge_dicts(
                            target_node.attributes,
                            {
                                "has_entity_security_evidence": True,
                            },
                        )

                        db.flush()
                        result.nodes_updated += 1

            # =================================================
            # Reputation
            # =================================================

            unique_entity_nodes = (
                self._deduplicate_graph_nodes(
                    entity_nodes
                )
            )

            reputations = []

            for node in unique_entity_nodes:

                reputation = self.get_reputation(
                    db=db,
                    node_id=node.node_id,
                )

                if reputation:

                    reputations.append(
                        reputation
                    )

            context.entity_reputations = (
                reputations
            )

            # =================================================
            # Relationship-Derived Contextual Intelligence
            # =================================================
            #
            # Relationship context is graph-only intelligence.
            # It NEVER creates ENTITY_SECURITY observations.

            context.relationship_risk = [
                self.get_relationship_risk_context(
                    db=db,
                    node_id=node.node_id,
                )
                for node in unique_entity_nodes
            ]
            # =================================================
            # Communication-Level Graph Intelligence
            # =================================================

            self._build_result_reputation(
                result=result,
                reputations=reputations,
            )

            # =================================================
            # Explainable Graph Evidence
            # =================================================

            graph_evidence = (
                self._build_graph_evidence(
                    reputations
                )
            )

            context.evidence = (
                graph_evidence
            )

            result.evidence_ids = (
                self._unique_strings(
                    evidence_ids
                    + [
                        item
                        for evidence in graph_evidence
                        for item in evidence.evidence_ids
                    ]
                )
            )

            result.ledger_ids = (
                self._unique_strings(
                    ledger_ids
                    + [
                        item
                        for evidence in graph_evidence
                        for item in evidence.ledger_ids
                    ]
                )
            )

            # =================================================
            # Deduplicate Context
            # =================================================

            context.nodes = (
                self._deduplicate_graph_nodes(
                    context.nodes
                )
            )

            context.edges = (
                self._deduplicate_graph_edges(
                    context.edges
                )
            )

            # =================================================
            # Summary
            # =================================================

            result.summary = (
                self._build_summary(
                    result
                )
            )

            db.commit()

            return result

        except Exception:

            db.rollback()

            raise

    # ========================================================
    # Node Upsert
    # ========================================================

    def upsert_node(
        self,
        db: Session,
        node_type: NodeType,
        value: str,
        display_name: str | None = None,
        verified: bool = False,
        attributes: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        ledger_ids: list[str] | None = None,
        security_observation: str | None = None,
        increment_observation: bool = True,
    ) -> tuple[GraphNode, bool]:
        """
        Create or update a persistent STG node.

        increment_observation controls whether this call
        represents a new independent observation.

        Returns:
            (GraphNode, created)
        """

        normalized_value = self.normalize_value(
            node_type,
            value,
        )

        if not normalized_value:

            raise ValueError(
                "STG node value cannot be empty."
            )

        existing = (
            db.query(STGNode)
            .filter(
                STGNode.node_type
                == node_type.value,
                STGNode.normalized_value
                == normalized_value,
            )
            .first()
        )

        now = datetime.utcnow()

        incoming_evidence = (
            self._unique_strings(
                evidence_ids
            )
        )

        incoming_ledgers = (
            self._unique_strings(
                ledger_ids
            )
        )

        incoming_attributes = (
            attributes.copy()
            if isinstance(attributes, dict)
            else {}
        )

        if existing:

            # Only a genuinely new independent observation
            # changes historical counters/timestamps.
            if increment_observation:

                existing.last_seen = now

                existing.observation_count = (
                    int(
                        existing.observation_count
                        or 0
                    )
                    + 1
                )

            if verified:
                existing.verified = True

            if (
                display_name
                and not existing.display_name
            ):
                existing.display_name = (
                    display_name
                )

            existing.attributes = (
                self._merge_dicts(
                    existing.attributes,
                    incoming_attributes,
                )
            )

            existing.evidence_ids = (
                self._merge_string_lists(
                    existing.evidence_ids,
                    incoming_evidence,
                )
            )

            existing.ledger_ids = (
                self._merge_string_lists(
                    existing.ledger_ids,
                    incoming_ledgers,
                )
            )

            if increment_observation:

                self._apply_security_observation(
                    existing,
                    security_observation,
                )

            db.flush()

            return (
                self._node_to_model(
                    existing
                ),
                False,
            )

        node_id = self._make_node_id(
            node_type,
            normalized_value,
        )

        persistent_node = STGNode(
            node_id=node_id,
            node_type=node_type.value,
            value=str(value).strip(),
            normalized_value=normalized_value,
            display_name=display_name,
            verified=bool(verified),
            first_seen=now,
            last_seen=now,

            # A newly created graph node necessarily has at
            # least one observation.
            observation_count=1,

            legitimate_observations=0,
            suspicious_observations=0,
            phishing_observations=0,
            attributes=incoming_attributes,
            evidence_ids=incoming_evidence,
            ledger_ids=incoming_ledgers,
        )

        if increment_observation:

            self._apply_security_observation(
                persistent_node,
                security_observation,
            )

        db.add(
            persistent_node
        )

        db.flush()

        return (
            self._node_to_model(
                persistent_node
            ),
            True,
        )

    # ========================================================
    # Edge Upsert
    # ========================================================

    def upsert_edge(
        self,
        db: Session,
        source_node_id: str,
        target_node_id: str,
        relationship: RelationshipType,
        verified: bool = False,
        confidence: float = 0.0,
        evidence_source: EvidenceSource = (
            EvidenceSource.UNKNOWN
        ),
        attributes: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        ledger_ids: list[str] | None = None,
        increment_observation: bool = True,
    ) -> tuple[GraphEdge, bool]:
        """
        Create or update a persistent graph relationship.

        increment_observation prevents repeated processing of
        one communication from inflating edge history.
        """

        source_node_id = str(
            source_node_id
        ).strip()

        target_node_id = str(
            target_node_id
        ).strip()

        if not source_node_id:
            raise ValueError(
                "Source node ID cannot be empty."
            )

        if not target_node_id:
            raise ValueError(
                "Target node ID cannot be empty."
            )

        confidence = self._clamp_score(
            confidence
        )

        existing = (
            db.query(STGEdge)
            .filter(
                STGEdge.source_node_id
                == source_node_id,
                STGEdge.target_node_id
                == target_node_id,
                STGEdge.relationship
                == relationship.value,
            )
            .first()
        )

        now = datetime.utcnow()

        incoming_attributes = (
            attributes.copy()
            if isinstance(attributes, dict)
            else {}
        )

        incoming_evidence = (
            self._unique_strings(
                evidence_ids
            )
        )

        incoming_ledgers = (
            self._unique_strings(
                ledger_ids
            )
        )

        if existing:

            if increment_observation:

                existing.last_seen = now

                existing.observation_count = (
                    int(
                        existing.observation_count
                        or 0
                    )
                    + 1
                )

            if verified:
                existing.verified = True

            existing.confidence = max(
                float(
                    existing.confidence
                    or 0.0
                ),
                confidence,
            )

            if (
                evidence_source
                != EvidenceSource.UNKNOWN
            ):
                existing.evidence_source = (
                    evidence_source.value
                )

            existing.attributes = (
                self._merge_dicts(
                    existing.attributes,
                    incoming_attributes,
                )
            )

            existing.evidence_ids = (
                self._merge_string_lists(
                    existing.evidence_ids,
                    incoming_evidence,
                )
            )

            existing.ledger_ids = (
                self._merge_string_lists(
                    existing.ledger_ids,
                    incoming_ledgers,
                )
            )

            db.flush()

            return (
                self._edge_to_model(
                    existing
                ),
                False,
            )

        edge_id = self._make_edge_id(
            source_node_id,
            target_node_id,
            relationship,
        )

        persistent_edge = STGEdge(
            edge_id=edge_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship=relationship.value,
            verified=bool(verified),
            confidence=confidence,
            evidence_source=evidence_source.value,
            first_seen=now,
            last_seen=now,
            observation_count=1,
            attributes=incoming_attributes,
            evidence_ids=incoming_evidence,
            ledger_ids=incoming_ledgers,
        )

        db.add(
            persistent_edge
        )

        db.flush()

        return (
            self._edge_to_model(
                persistent_edge
            ),
            True,
        )

    # ========================================================
    # Persistent Observation Recording
    # ========================================================

    def _record_observation(
        self,
        db: Session,
        communication_id: str,
        subject_type: str,
        subject_id: str,
        observation_type: str,
        security_observation: str | None = None,
        verified: bool = False,
        confidence: float = 0.0,
        evidence_source: EvidenceSource = (
            EvidenceSource.UNKNOWN
        ),
        attributes: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        ledger_ids: list[str] | None = None,
    ) -> tuple[STGObservation, bool]:
        """
        Persist one immutable communication-aware graph
        observation.

        Once an observation exists for the same communication,
        subject and observation type, replay returns the
        historical observation unchanged.

        Returns:
            (observation, created)
        """

        communication_id = str(
            communication_id
        ).strip()

        subject_type = str(
            subject_type
        ).strip().lower()

        subject_id = str(
            subject_id
        ).strip()

        observation_type = str(
            observation_type
        ).strip().upper()

        if not communication_id:
            raise ValueError(
                "Observation communication ID cannot be empty."
            )

        if subject_type not in {
            "node",
            "edge",
        }:
            raise ValueError(
                "Observation subject_type must be "
                "'node' or 'edge'."
            )

        if not subject_id:
            raise ValueError(
                "Observation subject ID cannot be empty."
            )

        if not observation_type:
            raise ValueError(
                "Observation type cannot be empty."
            )

        existing = (
            db.query(STGObservation)
            .filter(
                STGObservation.communication_id
                == communication_id,
                STGObservation.subject_type
                == subject_type,
                STGObservation.subject_id
                == subject_id,
                STGObservation.observation_type
                == observation_type,
            )
            .first()
        )

        # ----------------------------------------------------
        # Historical immutability boundary
        # ----------------------------------------------------
        #
        # Reprocessing the same communication must not rewrite
        # an already persisted historical observation.
        # ----------------------------------------------------

        if existing:
            return (
                existing,
                False,
            )

        incoming_evidence = (
            self._unique_strings(
                evidence_ids
            )
        )

        incoming_ledgers = (
            self._unique_strings(
                ledger_ids
            )
        )

        incoming_attributes = (
            attributes.copy()
            if isinstance(attributes, dict)
            else {}
        )

        confidence = self._clamp_score(
            confidence
        )

        source_value = (
            evidence_source.value
            if isinstance(
                evidence_source,
                EvidenceSource,
            )
            else str(
                evidence_source
                or EvidenceSource.UNKNOWN.value
            )
        )

        observation_id = (
            self._make_observation_id(
                communication_id=communication_id,
                subject_type=subject_type,
                subject_id=subject_id,
                observation_type=observation_type,
            )
        )

        persistent_observation = (
            STGObservation(
                observation_id=observation_id,
                communication_id=communication_id,
                subject_type=subject_type,
                subject_id=subject_id,
                observation_type=observation_type,
                security_observation=(
                    str(
                        security_observation
                    ).strip()
                    if security_observation
                    else None
                ),
                verified=bool(
                    verified
                ),
                confidence=confidence,
                evidence_source=source_value,
                observed_at=datetime.utcnow(),
                attributes=incoming_attributes,
                evidence_ids=incoming_evidence,
                ledger_ids=incoming_ledgers,
            )
        )

        db.add(
            persistent_observation
        )

        db.flush()

        return (
            persistent_observation,
            True,
        )

    # ========================================================
    # Observation Existence
    # ========================================================

    @staticmethod
    def _observation_exists(
        db: Session,
        communication_id: str,
        subject_type: str,
        subject_id: str,
        observation_type: str,
    ) -> bool:
        """
        Check whether one communication has already supplied
        this exact graph observation.
        """

        existing = (
            db.query(STGObservation.id)
            .filter(
                STGObservation.communication_id
                == str(
                    communication_id
                ).strip(),
                STGObservation.subject_type
                == str(
                    subject_type
                ).strip().lower(),
                STGObservation.subject_id
                == str(
                    subject_id
                ).strip(),
                STGObservation.observation_type
                == str(
                    observation_type
                ).strip().upper(),
            )
            .first()
        )

        return (
            existing is not None
        )

    # ========================================================
    # Explicit Entity Security Observation
    # ========================================================

    def record_entity_security_observation(
        self,
        db: Session,
        communication_id: str,
        node_id: str,
        security_observation: str,
        confidence: float = 0.0,
        verified: bool = False,
        evidence_source: EvidenceSource = (
            EvidenceSource.SECURITIES_TRUST_GRAPH
        ),
        attributes: dict[str, Any] | None = None,
        evidence_ids: list[str] | None = None,
        ledger_ids: list[str] | None = None,
    ) -> bool:
        """
        Record genuine entity-specific security evidence.

        This method is the explicit public API for recording
        entity-specific evidence outside the main analysis flow.

        analyse() may also consume explicit
        entity_security_observations supplied by upstream
        intelligence engines. Ordinary content mentions remain
        insufficient to classify the entity itself.

        Returns:
            True if a new independent security observation was
            recorded, otherwise False.
        """

        node = (
            db.query(STGNode)
            .filter(
                STGNode.node_id
                == str(
                    node_id
                ).strip()
            )
            .first()
        )

        if not node:
            raise ValueError(
                "STG node does not exist."
            )

        is_new = (
            not self._observation_exists(
                db=db,
                communication_id=communication_id,
                subject_type="node",
                subject_id=node.node_id,
                observation_type=(
                    self.OBSERVATION_ENTITY_SECURITY
                ),
            )
        )

        (
            _,
            created,
        ) = self._record_observation(
            db=db,
            communication_id=communication_id,
            subject_type="node",
            subject_id=node.node_id,
            observation_type=(
                self.OBSERVATION_ENTITY_SECURITY
            ),
            security_observation=(
                security_observation
            ),
            verified=verified,
            confidence=confidence,
            evidence_source=evidence_source,
            attributes=self._merge_dicts(
                attributes,
                {
                    "entity_specific_security_evidence": True,
                },
            ),
            evidence_ids=evidence_ids,
            ledger_ids=ledger_ids,
        )

        if is_new and created:

            self._apply_security_observation(
                node,
                security_observation,
            )

            node.evidence_ids = (
                self._merge_string_lists(
                    node.evidence_ids,
                    evidence_ids,
                )
            )

            node.ledger_ids = (
                self._merge_string_lists(
                    node.ledger_ids,
                    ledger_ids,
                )
            )

            if verified:
                node.verified = True

            db.flush()

        db.commit()

        return bool(
            is_new and created
        )

    # ========================================================
    # Reputation
    # ========================================================

    def get_reputation(
        self,
        db: Session,
        node_id: str,
    ) -> EntityReputation | None:
        """
        Calculate provenance-aware historical reputation for a
        graph entity.

        Reputation is derived from persisted ENTITY_SECURITY
        observations rather than accumulated STGNode security
        counters.

        Core guarantees
        ---------------
        1. Mere entity mentions never become reputation votes.
        2. Repeated executions of the same intelligence source
           contribute only one effective vote.
        3. Independent sources remain independent.
        4. Conflicting independent sources are preserved.
        5. Conflict reduces reputation confidence.
        6. Within one provenance group, the newest valid
           security observation represents that source's
           current assessment.
        7. Older observations remain persisted for audit and
           provenance history.
        """

        node = (
            db.query(STGNode)
            .filter(
                STGNode.node_id
                == node_id
            )
            .first()
        )

        if not node:
            return None

        # ====================================================
        # Load Persisted Entity-Specific Security Evidence
        # ====================================================

        observations = (
            db.query(STGObservation)
            .filter(
                STGObservation.subject_type
                == "node",

                STGObservation.subject_id
                == node.node_id,

                STGObservation.observation_type
                == self.OBSERVATION_ENTITY_SECURITY,

                STGObservation.security_observation.isnot(
                    None
                ),
            )
            .order_by(
                STGObservation.id.asc()
            )
            .all()
        )

        # ====================================================
        # Build Independent Provenance Groups
        # ====================================================

        groups: dict[
            tuple[str, bool, bool],
            list[STGObservation],
        ] = {}

        for observation in observations:

            attributes = (
                observation.attributes
                if isinstance(
                    observation.attributes,
                    dict,
                )
                else {}
            )

            entity_specific = attributes.get(
                "entity_specific_security_evidence",
                True,
            )

            if entity_specific is False:
                continue

            source_module = attributes.get(
                "source_module"
            )

            evidence_source = (
                observation.evidence_source
                or "Unknown"
            )

            source_name = str(
                source_module
                or evidence_source
                or "Unknown"
            ).strip()

            if not source_name:
                source_name = "Unknown"

            model_derived = bool(
                attributes.get(
                    "model_derived",
                    False,
                )
            )

            verified = bool(
                observation.verified
            )

            # Provenance identity intentionally includes the
            # verification/model class.
            #
            # This prevents independently verified evidence
            # from collapsing into an unverified model-derived
            # observation merely because both happen to use a
            # similar source label.

            group_key = (
                source_name.lower(),
                verified,
                model_derived,
            )

            groups.setdefault(
                group_key,
                [],
            ).append(
                observation
            )

        # ====================================================
        # Temporal Provenance Resolution
        # ====================================================

        effective_observations: list[
            STGObservation
        ] = []

        provenance_history: dict[
            tuple[str, bool, bool],
            dict[str, Any],
        ] = {}

        for (
            group_key,
            group_observations,
        ) in groups.items():

            # -----------------------------------------------
            # IMPORTANT:
            #
            # The newest observation from one provenance group
            # represents that source's CURRENT assessment.
            #
            # Confidence is NOT used to choose between an old
            # and new verdict from the same source.
            #
            # Example:
            #
            # old:
            # URL Intelligence -> Legitimate -> 99.99%
            #
            # new:
            # URL Intelligence -> Phishing -> 95%
            #
            # Effective current vote:
            # URL Intelligence -> Phishing
            #
            # The old legitimate observation remains in the
            # database for audit but no longer represents the
            # source's current reputation assessment.
            # -----------------------------------------------

            representative = max(
                group_observations,
                key=lambda item: (
                    (
                        item.observed_at.timestamp()
                        if item.observed_at
                        else 0.0
                    ),
                    int(
                        item.id
                        or 0
                    ),
                ),
            )

            effective_observations.append(
                representative
            )

            ordered_history = sorted(
                group_observations,
                key=lambda item: (
                    (
                        item.observed_at.timestamp()
                        if item.observed_at
                        else 0.0
                    ),
                    int(
                        item.id
                        or 0
                    ),
                ),
            )

            verdict_history = [
                str(
                    item.security_observation
                    or ""
                ).strip()
                for item in ordered_history
                if str(
                    item.security_observation
                    or ""
                ).strip()
            ]

            provenance_history[
                group_key
            ] = {
                "raw_count": len(
                    group_observations
                ),
                "verdict_history":
                    verdict_history,
                "current_verdict": str(
                    representative.security_observation
                    or ""
                ).strip(),
                "current_observation_id":
                    representative.observation_id,
                "current_observed_at":
                    representative.observed_at,
            }

        # ====================================================
        # Interpret Effective Security Votes
        # ====================================================

        legitimate = 0
        suspicious = 0
        phishing = 0

        effective_evidence_ids: list[str] = []
        effective_ledger_ids: list[str] = []

        source_descriptions: list[str] = []

        legitimate_sources: list[str] = []
        suspicious_sources: list[str] = []
        phishing_sources: list[str] = []

        counted_effective_observations = 0

        for observation in effective_observations:

            security_value = str(
                observation.security_observation
                or ""
            ).strip().lower()

            attributes = (
                observation.attributes
                if isinstance(
                    observation.attributes,
                    dict,
                )
                else {}
            )

            source_name = str(
                attributes.get(
                    "source_module"
                )
                or observation.evidence_source
                or "Unknown"
            ).strip()

            if not source_name:
                source_name = "Unknown"

            verdict_type: str | None = None

            if security_value in {
                "legitimate",
                "trusted",
                "safe",
                "low",
                "low risk",
                "low_risk",
            }:

                legitimate += 1
                verdict_type = "legitimate"

                legitimate_sources.append(
                    source_name
                )

            elif security_value in {
                "suspicious",
                "neutral",
                "medium",
                "medium risk",
                "medium_risk",
            }:

                suspicious += 1
                verdict_type = "suspicious"

                suspicious_sources.append(
                    source_name
                )

            elif security_value in {
                "phishing",
                "malicious",
                "high",
                "high risk",
                "high_risk",
                "fraud",
                "fraudulent",
            }:

                phishing += 1
                verdict_type = "phishing"

                phishing_sources.append(
                    source_name
                )

            # Unknown labels remain in the audit history but
            # cannot silently become reputation evidence.

            if verdict_type is None:
                continue

            counted_effective_observations += 1

            effective_evidence_ids.extend(
                self._unique_strings(
                    observation.evidence_ids
                )
            )

            effective_ledger_ids.extend(
                self._unique_strings(
                    observation.ledger_ids
                )
            )

            source_descriptions.append(
                source_name
            )

        effective_evidence_ids = (
            self._unique_strings(
                effective_evidence_ids
            )
        )

        effective_ledger_ids = (
            self._unique_strings(
                effective_ledger_ids
            )
        )

        source_descriptions = (
            self._unique_strings(
                source_descriptions
            )
        )

        legitimate_sources = (
            self._unique_strings(
                legitimate_sources
            )
        )

        suspicious_sources = (
            self._unique_strings(
                suspicious_sources
            )
        )

        phishing_sources = (
            self._unique_strings(
                phishing_sources
            )
        )

        total_security_observations = (
            legitimate
            + suspicious
            + phishing
        )

        raw_security_observations = len(
            observations
        )

        independent_sources = (
            counted_effective_observations
        )

        # ====================================================
        # Detect Temporal Verdict Changes
        # ====================================================

        changed_provenance_sources: list[
            str
        ] = []

        for (
            group_key,
            history,
        ) in provenance_history.items():

            verdict_history = [
                str(
                    value
                ).strip().lower()
                for value in history.get(
                    "verdict_history",
                    []
                )
                if str(
                    value
                ).strip()
            ]

            distinct_verdicts = set(
                verdict_history
            )

            if len(
                distinct_verdicts
            ) <= 1:
                continue

            source_name = (
                group_key[0]
            )

            # Recover display casing from the currently
            # effective observation where possible.

            display_name = None

            for observation in (
                effective_observations
            ):

                attributes = (
                    observation.attributes
                    if isinstance(
                        observation.attributes,
                        dict,
                    )
                    else {}
                )

                candidate = str(
                    attributes.get(
                        "source_module"
                    )
                    or observation.evidence_source
                    or "Unknown"
                ).strip()

                candidate_key = (
                    candidate.lower(),
                    bool(
                        observation.verified
                    ),
                    bool(
                        attributes.get(
                            "model_derived",
                            False,
                        )
                    ),
                )

                if candidate_key == group_key:

                    display_name = (
                        candidate
                    )

                    break

            changed_provenance_sources.append(
                display_name
                or source_name
            )

        changed_provenance_sources = (
            self._unique_strings(
                changed_provenance_sources
            )
        )

        # ====================================================
        # Detect Independent-Source Conflict
        # ====================================================

        verdict_categories_present = sum(
            [
                1 if legitimate > 0 else 0,
                1 if suspicious > 0 else 0,
                1 if phishing > 0 else 0,
            ]
        )

        has_conflict = (
            verdict_categories_present > 1
        )

        has_direct_conflict = (
            legitimate > 0
            and phishing > 0
        )

        # ====================================================
        # Relationship Intelligence
        # ====================================================

        verified_relationships = (
            db.query(
                func.count(
                    STGEdge.id
                )
            )
            .filter(
                (
                    (
                        STGEdge.source_node_id
                        == node.node_id
                    )
                    |
                    (
                        STGEdge.target_node_id
                        == node.node_id
                    )
                ),
                STGEdge.verified.is_(True),
            )
            .scalar()
            or 0
        )

        suspicious_relationships = (
            db.query(
                func.count(
                    STGEdge.id
                )
            )
            .filter(
                (
                    (
                        STGEdge.source_node_id
                        == node.node_id
                    )
                    |
                    (
                        STGEdge.target_node_id
                        == node.node_id
                    )
                ),
                STGEdge.relationship.in_(
                    [
                        RelationshipType.FLAGGED_WITH.value,
                        RelationshipType.ASSOCIATED_WITH.value,
                    ]
                ),
            )
            .scalar()
            or 0
        )

        # ====================================================
        # Reputation Calculation
        # ====================================================

        reasons: list[str] = []

        if total_security_observations <= 0:

            classification = (
                TrustClassification.UNKNOWN
            )

            trust_score = 50.0
            risk_score = 50.0
            confidence = 0.0

            reasons.append(
                "No independent entity-specific historical "
                "security evidence is available for this "
                "entity."
            )

        else:

            legitimate_ratio = (
                legitimate
                / total_security_observations
            )

            suspicious_ratio = (
                suspicious
                / total_security_observations
            )

            phishing_ratio = (
                phishing
                / total_security_observations
            )

            # Existing STG security weighting is preserved.
            #
            # Legitimate -> 5 risk
            # Suspicious -> 60 risk
            # Phishing   -> 100 risk

            risk_score = (
                phishing_ratio * 100.0
                + suspicious_ratio * 60.0
                + legitimate_ratio * 5.0
            )

            risk_score = self._clamp_score(
                risk_score
            )

            trust_score = self._clamp_score(
                100.0
                - risk_score
            )

            # =================================================
            # Base Confidence
            # =================================================

            base_confidence = min(
                95.0,
                20.0
                + (
                    total_security_observations
                    * 10.0
                ),
            )

            # =================================================
            # Conflict-Aware Confidence
            # =================================================

            if has_direct_conflict:

                confidence = max(
                    10.0,
                    base_confidence
                    - 20.0,
                )

            elif has_conflict:

                confidence = max(
                    10.0,
                    base_confidence
                    - 10.0,
                )

            else:

                confidence = (
                    base_confidence
                )

            # =================================================
            # Effective Evidence Reasons
            # =================================================

            if phishing > 0:

                reasons.append(
                    f"{phishing} independent phishing/"
                    "malicious evidence group(s) are "
                    "currently effective."
                )

            if suspicious > 0:

                reasons.append(
                    f"{suspicious} independent suspicious "
                    "evidence group(s) are currently "
                    "effective."
                )

            if legitimate > 0:

                reasons.append(
                    f"{legitimate} independent legitimate "
                    "evidence group(s) are currently "
                    "effective."
                )

            # =================================================
            # Temporal Change Explanation
            # =================================================

            if changed_provenance_sources:

                reasons.append(
                    "Historical verdict changes were detected "
                    "within one or more provenance groups. "
                    "The newest valid observation from each "
                    "group is used as its current reputation "
                    "vote."
                )

                reasons.append(
                    "Source(s) with historical verdict "
                    "changes: "
                    + ", ".join(
                        changed_provenance_sources
                    )
                    + "."
                )

            # =================================================
            # Conflict Explanation
            # =================================================

            if has_direct_conflict:

                reasons.append(
                    "Conflicting independent entity-security "
                    "evidence is present: at least one source "
                    "currently assesses the entity as "
                    "legitimate while another independently "
                    "assesses it as phishing/malicious."
                )

                if legitimate_sources:

                    reasons.append(
                        "Current legitimate assessment "
                        "source(s): "
                        + ", ".join(
                            legitimate_sources
                        )
                        + "."
                    )

                if phishing_sources:

                    reasons.append(
                        "Current phishing/malicious assessment "
                        "source(s): "
                        + ", ".join(
                            phishing_sources
                        )
                        + "."
                    )

                reasons.append(
                    "Reputation confidence was reduced "
                    "because independent current security "
                    "sources directly disagree."
                )

            elif has_conflict:

                reasons.append(
                    "Conflicting independent entity-security "
                    "evidence is present across multiple "
                    "current security assessment categories."
                )

                if legitimate_sources:

                    reasons.append(
                        "Current legitimate assessment "
                        "source(s): "
                        + ", ".join(
                            legitimate_sources
                        )
                        + "."
                    )

                if suspicious_sources:

                    reasons.append(
                        "Current suspicious assessment "
                        "source(s): "
                        + ", ".join(
                            suspicious_sources
                        )
                        + "."
                    )

                if phishing_sources:

                    reasons.append(
                        "Current phishing/malicious assessment "
                        "source(s): "
                        + ", ".join(
                            phishing_sources
                        )
                        + "."
                    )

                reasons.append(
                    "Reputation confidence was reduced "
                    "because independent current security "
                    "sources do not fully agree."
                )

            # =================================================
            # Classification
            # =================================================

            if risk_score >= 80.0:

                classification = (
                    TrustClassification.HIGH_RISK
                )

            elif risk_score >= 60.0:

                classification = (
                    TrustClassification.SUSPICIOUS
                )

            elif risk_score >= 40.0:

                classification = (
                    TrustClassification.NEUTRAL
                )

            elif risk_score >= 20.0:

                classification = (
                    TrustClassification.LOW_RISK
                )

            else:

                classification = (
                    TrustClassification.TRUSTED
                )

        # ====================================================
        # Provenance / Audit Explanation
        # ====================================================

        if raw_security_observations > 0:

            reasons.append(
                f"{raw_security_observations} raw "
                "entity-security observation(s) were reduced "
                f"to {independent_sources} current "
                "independent provenance group(s) for "
                "reputation scoring."
            )

        if source_descriptions:

            reasons.append(
                "Current independent reputation source(s): "
                + ", ".join(
                    source_descriptions
                )
                + "."
            )

        if verified_relationships:

            reasons.append(
                f"{verified_relationships} verified graph "
                "relationship(s) are recorded."
            )

        if suspicious_relationships:

            reasons.append(
                f"{suspicious_relationships} risk-associated "
                "graph relationship(s) are recorded."
            )

        # ====================================================
        # Return Reputation
        # ====================================================

        return EntityReputation(
            node_id=node.node_id,

            node_type=self._safe_node_type(
                node.node_type
            ),

            value=node.value,

            classification=classification,

            trust_score=round(
                trust_score,
                4,
            ),

            risk_score=round(
                risk_score,
                4,
            ),

            confidence=round(
                confidence,
                4,
            ),

            # Retain graph-history semantics for API
            # compatibility.
            total_observations=int(
                node.observation_count
                or 0
            ),

            # Effective CURRENT independent security votes.
            legitimate_observations=legitimate,

            suspicious_observations=suspicious,

            phishing_observations=phishing,

            verified_relationships=int(
                verified_relationships
            ),

            suspicious_relationships=int(
                suspicious_relationships
            ),

            # Only currently effective reputation evidence is
            # surfaced here. Historical evidence remains in
            # STGObservation for audit.
            evidence_ids=(
                effective_evidence_ids
                if effective_evidence_ids
                else self._unique_strings(
                    node.evidence_ids
                )
            ),

            ledger_ids=(
                effective_ledger_ids
                if effective_ledger_ids
                else self._unique_strings(
                    node.ledger_ids
                )
            ),

            reasons=reasons,
        )

    # Graph Statistics
    # ========================================================

    def get_statistics(
        self,
        db: Session,
    ) -> GraphStatistics:
        """
        Return lightweight statistics describing the STG.
        """

        def count_type(
            node_type: NodeType,
        ) -> int:

            return int(
                db.query(
                    func.count(
                        STGNode.id
                    )
                )
                .filter(
                    STGNode.node_type
                    == node_type.value
                )
                .scalar()
                or 0
            )

        return GraphStatistics(
            total_nodes=int(
                db.query(
                    func.count(
                        STGNode.id
                    )
                )
                .scalar()
                or 0
            ),

            total_edges=int(
                db.query(
                    func.count(
                        STGEdge.id
                    )
                )
                .scalar()
                or 0
            ),

            verified_nodes=int(
                db.query(
                    func.count(
                        STGNode.id
                    )
                )
                .filter(
                    STGNode.verified.is_(True)
                )
                .scalar()
                or 0
            ),

            verified_edges=int(
                db.query(
                    func.count(
                        STGEdge.id
                    )
                )
                .filter(
                    STGEdge.verified.is_(True)
                )
                .scalar()
                or 0
            ),

            communication_nodes=count_type(
                NodeType.COMMUNICATION
            ),

            organisation_nodes=count_type(
                NodeType.ORGANISATION
            ),

            domain_nodes=count_type(
                NodeType.DOMAIN
            ),

            url_nodes=count_type(
                NodeType.URL
            ),

            email_nodes=count_type(
                NodeType.EMAIL
            ),

            phone_nodes=count_type(
                NodeType.PHONE
            ),

            upi_nodes=count_type(
                NodeType.UPI_ID
            ),

            bank_account_nodes=count_type(
                NodeType.BANK_ACCOUNT
            ),

            sebi_registration_nodes=count_type(
                NodeType.SEBI_REGISTRATION
            ),
        )

    # ========================================================
    # Node Retrieval
    # ========================================================

    def get_node(
        self,
        db: Session,
        node_id: str,
    ) -> GraphNode | None:
        """
        Retrieve one graph node by stable node ID.
        """

        node = (
            db.query(STGNode)
            .filter(
                STGNode.node_id
                == node_id
            )
            .first()
        )

        if not node:
            return None

        return self._node_to_model(
            node
        )

    # ========================================================
    # Neighbour Retrieval
    # ========================================================

    def get_neighbours(
        self,
        db: Session,
        node_id: str,
    ) -> list[GraphEdge]:
        """
        Return graph edges connected to a node.
        """

        edges = (
            db.query(STGEdge)
            .filter(
                (
                    STGEdge.source_node_id
                    == node_id
                )
                |
                (
                    STGEdge.target_node_id
                    == node_id
                )
            )
            .all()
        )

        return [
            self._edge_to_model(
                edge
            )
            for edge in edges
        ]


    # ========================================================
    # Relationship-Derived Contextual Intelligence
    # ========================================================

    def get_relationship_risk_context(
        self,
        db: Session,
        node_id: str,
    ) -> RelationshipRiskContext:
        """
        Build bounded contextual intelligence from neighbours.

        This method NEVER records ENTITY_SECURITY evidence.
        Direct reputation remains authoritative for entities.
        """

        subject = (
            db.query(STGNode)
            .filter(STGNode.node_id == str(node_id).strip())
            .first()
        )

        if not subject:
            return RelationshipRiskContext(
                subject_node_id=str(node_id).strip(),
                summary="The requested STG subject node does not exist.",
            )

        edges = (
            db.query(STGEdge)
            .filter(
                (STGEdge.source_node_id == subject.node_id)
                |
                (STGEdge.target_node_id == subject.node_id)
            )
            .all()
        )

        signals: list[RelationshipRiskSignal] = []

        # ----------------------------------------------------
        # Neighbour-level anti-amplification
        # ----------------------------------------------------
        #
        # All eligible relationship signals are retained in
        # `signals` for provenance and audit.
        #
        # Aggregate contextual scoring, however, must count a
        # neighbour's direct reputation only once. Otherwise
        # several relationship types pointing to the same
        # neighbour could manufacture apparent independent
        # support from one underlying reputation.
        #
        # For each neighbour, the strongest effective
        # relationship signal is used for aggregate scoring.
        # ----------------------------------------------------

        scoring_signals_by_neighbour: dict[
            str,
            dict[str, Any],
        ] = {}

        analysed = len(edges)
        evidence_ids: list[str] = []
        ledger_ids: list[str] = []
        high_risk = 0
        suspicious = 0
        trusted = 0
        risk_total = 0.0
        trust_total = 0.0
        weight_total = 0.0
        confidence_total = 0.0

        for edge in edges:
            relationship = self._safe_relationship_type(
                edge.relationship
            )
            weight = self._relationship_context_weight(
                relationship,
                bool(edge.verified),
            )

            # Content, claim-only and otherwise ineligible
            # relationships cannot propagate neighbour
            # reputation.
            if weight <= 0.0:
                continue

            subject_is_source = (
                edge.source_node_id
                == subject.node_id
            )

            # Directional relationships must only propagate
            # neighbour reputation in their semantically valid
            # direction.
            #
            # Symmetric relationships are explicitly allowed
            # in both directions by the centralized policy.
            if not self._relationship_allows_context_direction(
                relationship=relationship,
                subject_is_source=subject_is_source,
            ):
                continue

            neighbour_id = (
                edge.target_node_id
                if edge.source_node_id == subject.node_id
                else edge.source_node_id
            )

            neighbour = (
                db.query(STGNode)
                .filter(STGNode.node_id == neighbour_id)
                .first()
            )
            if not neighbour:
                continue

            reputation = self.get_reputation(
                db=db,
                node_id=neighbour.node_id,
            )

            if (
                not reputation
                or reputation.confidence <= 0.0
                or reputation.classification
                == TrustClassification.UNKNOWN
            ):
                continue

            edge_confidence = self._clamp_score(edge.confidence)
            neighbour_confidence = self._clamp_score(
                reputation.confidence
            )

            effective_weight = (
                weight
                * (edge_confidence / 100.0)
                * (neighbour_confidence / 100.0)
            )
            if effective_weight <= 0.0:
                continue

            risk_contribution = (
                reputation.risk_score * effective_weight
            )
            trust_contribution = (
                reputation.trust_score * effective_weight
            )
            signal_confidence = self._clamp_score(
                neighbour_confidence
                * (edge_confidence / 100.0)
            )

            signal_evidence = self._unique_strings(
                list(reputation.evidence_ids)
                + self._unique_strings(edge.evidence_ids)
            )
            signal_ledgers = self._unique_strings(
                list(reputation.ledger_ids)
                + self._unique_strings(edge.ledger_ids)
            )

            signals.append(
                RelationshipRiskSignal(
                    subject_node_id=subject.node_id,
                    neighbour_node_id=neighbour.node_id,
                    neighbour_node_type=self._safe_node_type(
                        neighbour.node_type
                    ),
                    neighbour_value=neighbour.value,
                    edge_id=edge.edge_id,
                    relationship=relationship,
                    edge_verified=bool(edge.verified),
                    edge_confidence=edge_confidence,
                    edge_evidence_source=self._safe_evidence_source(
                        edge.evidence_source
                    ),
                    neighbour_classification=reputation.classification,
                    neighbour_risk_score=reputation.risk_score,
                    neighbour_trust_score=reputation.trust_score,
                    neighbour_confidence=neighbour_confidence,
                    relationship_weight=round(weight, 4),
                    risk_contribution=round(risk_contribution, 4),
                    trust_contribution=round(trust_contribution, 4),
                    confidence=round(signal_confidence, 4),
                    evidence_ids=signal_evidence,
                    ledger_ids=signal_ledgers,
                    explanation=(
                        f"{neighbour.value} has direct "
                        f"{reputation.classification.value} reputation "
                        f"and is connected through {relationship.value}. "
                        f"A bounded contextual weight of {round(weight, 4)} "
                        "is applied. This is not a direct security verdict "
                        "on the subject."
                    ),
                    attributes={
                        "contextual_only": True,
                        "direct_entity_security_evidence": False,
                        "effective_weight": round(effective_weight, 6),
                    },
                )
            )

            # ------------------------------------------------
            # Aggregate scoring candidate
            # ------------------------------------------------
            #
            # Keep every raw signal above for audit, but only
            # the strongest effective relationship for each
            # neighbour may influence aggregate contextual
            # scoring.
            # ------------------------------------------------

            candidate = {
                "effective_weight": effective_weight,
                "risk_contribution": risk_contribution,
                "trust_contribution": trust_contribution,
                "signal_confidence": signal_confidence,
                "classification": reputation.classification,
                "evidence_ids": signal_evidence,
                "ledger_ids": signal_ledgers,
            }

            current = scoring_signals_by_neighbour.get(
                neighbour.node_id
            )

            if (
                current is None
                or effective_weight
                > float(
                    current.get(
                        "effective_weight",
                        0.0,
                    )
                )
            ):
                scoring_signals_by_neighbour[
                    neighbour.node_id
                ] = candidate
        # ----------------------------------------------------
        # Aggregate one effective vote per neighbour
        # ----------------------------------------------------

        for scoring_signal in (
            scoring_signals_by_neighbour.values()
        ):

            risk_total += float(
                scoring_signal[
                    "risk_contribution"
                ]
            )

            trust_total += float(
                scoring_signal[
                    "trust_contribution"
                ]
            )

            weight_total += float(
                scoring_signal[
                    "effective_weight"
                ]
            )

            confidence_total += float(
                scoring_signal[
                    "signal_confidence"
                ]
            )

            evidence_ids.extend(
                scoring_signal[
                    "evidence_ids"
                ]
            )

            ledger_ids.extend(
                scoring_signal[
                    "ledger_ids"
                ]
            )

            classification = scoring_signal[
                "classification"
            ]

            if (
                classification
                == TrustClassification.HIGH_RISK
            ):
                high_risk += 1

            elif (
                classification
                == TrustClassification.SUSPICIOUS
            ):
                suspicious += 1

            elif classification in {
                TrustClassification.TRUSTED,
                TrustClassification.LOW_RISK,
            }:
                trusted += 1

        contextual_conflict = (
            high_risk > 0
            and trusted > 0
        )

        if not signals or weight_total <= 0.0:
            return RelationshipRiskContext(
                subject_node_id=subject.node_id,
                available=False,
                signals=[],
                relationships_analysed=analysed,
                contributing_relationships=0,
                evidence_ids=[],
                ledger_ids=[],
                reasons=[
                    "No eligible relationship had meaningful independent "
                    "neighbour reputation for contextual propagation."
                ],
                summary=(
                    "No relationship-derived contextual intelligence "
                    "is currently available."
                ),
            )

        contextual_risk = self._clamp_score(
            risk_total / weight_total
        )
        contextual_trust = self._clamp_score(
            trust_total / weight_total
        )
        effective_neighbour_count = len(
            scoring_signals_by_neighbour
        )

        contextual_confidence = self._clamp_score(
            confidence_total
            / effective_neighbour_count
        )
        classification = self._classification_from_risk(
            contextual_risk
        )

        return RelationshipRiskContext(
            subject_node_id=subject.node_id,
            available=True,
            signals=signals,
            contextual_risk_score=round(contextual_risk, 4),
            contextual_trust_score=round(contextual_trust, 4),
            confidence=round(contextual_confidence, 4),
            classification=classification,
            relationships_analysed=analysed,
            contributing_relationships=len(signals),
            high_risk_neighbours=high_risk,
            suspicious_neighbours=suspicious,
            trusted_neighbours=trusted,
            evidence_ids=self._unique_strings(evidence_ids),
            ledger_ids=self._unique_strings(ledger_ids),
            reasons=(
                [
                    (
                        f"{len(signals)} of {analysed} connected "
                        "relationship(s) produced eligible contextual "
                        "signals."
                    ),
                    (
                        f"{len(scoring_signals_by_neighbour)} independent "
                        "neighbour(s) contributed to aggregate contextual "
                        "scoring after same-neighbour relationship "
                        "deduplication."
                    ),
                ]
                + (
                    [
                        (
                            "Conflicting independent relationship context "
                            "is present: at least one effective neighbour "
                            "has high-risk reputation while another "
                            "effective neighbour has trusted reputation."
                        ),
                        (
                            f"Effective contextual neighbourhood contains "
                            f"{high_risk} high-risk and {trusted} trusted "
                            "independent neighbour(s)."
                        ),
                    ]
                    if contextual_conflict
                    else []
                )
                + [
                    (
                        "Multiple eligible relationships to the same "
                        "neighbour remain visible for provenance and "
                        "audit, but only the strongest effective "
                        "relationship per neighbour influences aggregate "
                        "contextual scoring."
                    ),
                    (
                        "Relationship-derived context does not create "
                        "direct entity-security observations and does "
                        "not authenticate the sender."
                    ),
                ]
            ),
            summary=(
                (
                    "Conflicting independent relationship-derived "
                    "context was detected. "
                    if contextual_conflict
                    else ""
                )
                + (
                    "Relationship-derived graph context classified "
                    f"{len(scoring_signals_by_neighbour)} independent "
                    f"contributing neighbour(s) as "
                    f"{classification.value} with contextual risk "
                    f"{round(contextual_risk, 4)} and confidence "
                    f"{round(contextual_confidence, 4)}. "
                    f"{len(signals)} eligible relationship signal(s) "
                    "remain available for provenance and audit. "
                    "This is contextual intelligence only."
                )
            ),
        )
    @staticmethod
    def _relationship_allows_context_direction(
        relationship: RelationshipType,
        subject_is_source: bool,
    ) -> bool:
        """
        Determine whether neighbour reputation may propagate
        through a relationship in the requested direction.

        Relationship direction is evaluated from the subject
        node whose contextual reputation is being calculated.

        Security principle
        ------------------
        Directional graph semantics must not be reversed.

        Example:

            URL --OWNED_BY--> Organisation

        The Organisation may provide contextual intelligence
        about the URL.

        The URL must NOT provide OWNED_BY-derived contextual
        intelligence about the Organisation merely because the
        same edge is connected to both nodes.

        Symmetric relationships may propagate in either
        direction.
        """

        # ----------------------------------------------------
        # Non-propagating relationships
        # ----------------------------------------------------

        non_propagating = {
            RelationshipType.MENTIONS,
            RelationshipType.CONTAINS,
            RelationshipType.REFERENCES,
            RelationshipType.CLAIMS_TO_BE,
            RelationshipType.CLAIMS_ASSOCIATION_WITH,
            RelationshipType.UNKNOWN,
        }

        if relationship in non_propagating:
            return False

        # ----------------------------------------------------
        # Symmetric contextual relationships
        # ----------------------------------------------------
        #
        # These relationships describe mutual association
        # rather than ownership/directional dependency.
        # ----------------------------------------------------

        symmetric = {
            RelationshipType.OBSERVED_WITH,
            RelationshipType.PREVIOUSLY_OBSERVED_WITH,
            RelationshipType.ASSOCIATED_WITH,
            RelationshipType.FLAGGED_WITH,
        }

        if relationship in symmetric:
            return True

        # ----------------------------------------------------
        # Forward contextual relationships
        # ----------------------------------------------------
        #
        # For:
        #
        #   subject --RELATIONSHIP--> neighbour
        #
        # neighbour reputation may provide bounded context
        # about subject.
        #
        # The inverse interpretation is not automatically
        # valid.
        # ----------------------------------------------------

        forward_only = {
            RelationshipType.LINKS_TO,
            RelationshipType.VERIFIED_AS,
            RelationshipType.REGISTERED_TO,
            RelationshipType.OWNED_BY,
            RelationshipType.USES_DOMAIN,
            RelationshipType.USES_EMAIL,
            RelationshipType.USES_PHONE,
        }

        if relationship in forward_only:
            return bool(
                subject_is_source
            )

        # ----------------------------------------------------
        # Secure default
        # ----------------------------------------------------
        #
        # New/unknown relationship types must not silently
        # become reputation-propagation channels.
        # ----------------------------------------------------

        return False
    @staticmethod
    def _relationship_context_weight(
        relationship: RelationshipType,
        verified: bool = False,
    ) -> float:
        """
        Conservative bounded relationship propagation policy.
        """

        zero_weight = {
            RelationshipType.MENTIONS,
            RelationshipType.CONTAINS,
            RelationshipType.REFERENCES,
            RelationshipType.CLAIMS_TO_BE,
            RelationshipType.CLAIMS_ASSOCIATION_WITH,
            RelationshipType.UNKNOWN,
        }
        if relationship in zero_weight:
            return 0.0

        weights = {
            RelationshipType.LINKS_TO: 0.15,
            RelationshipType.OBSERVED_WITH: 0.35,
            RelationshipType.PREVIOUSLY_OBSERVED_WITH: 0.40,
            RelationshipType.ASSOCIATED_WITH: 0.60,
            RelationshipType.FLAGGED_WITH: 0.85,
            RelationshipType.VERIFIED_AS: 0.55,
            RelationshipType.REGISTERED_TO: 0.55,
            RelationshipType.OWNED_BY: 0.60,
            RelationshipType.USES_DOMAIN: 0.45,
            RelationshipType.USES_EMAIL: 0.45,
            RelationshipType.USES_PHONE: 0.45,
        }

        verification_required = {
            RelationshipType.VERIFIED_AS,
            RelationshipType.REGISTERED_TO,
            RelationshipType.OWNED_BY,
            RelationshipType.USES_DOMAIN,
            RelationshipType.USES_EMAIL,
            RelationshipType.USES_PHONE,
        }

        if (
            relationship in verification_required
            and not verified
        ):
            return 0.0

        return max(
            0.0,
            min(1.0, float(weights.get(relationship, 0.0))),
        )

    

    @staticmethod
    def _classification_from_risk(
        risk_score: float,
    ) -> TrustClassification:
        if risk_score >= 80.0:
            return TrustClassification.HIGH_RISK
        if risk_score >= 60.0:
            return TrustClassification.SUSPICIOUS
        if risk_score >= 40.0:
            return TrustClassification.NEUTRAL
        if risk_score >= 20.0:
            return TrustClassification.LOW_RISK
        return TrustClassification.TRUSTED

    @staticmethod
    def _safe_evidence_source(
        value: Any,
    ) -> EvidenceSource:
        if isinstance(value, EvidenceSource):
            return value
        try:
            return EvidenceSource(str(value).strip())
        except (ValueError, TypeError):
            return EvidenceSource.UNKNOWN

    # ========================================================
    # Normalization
    # ========================================================

    def normalize_value(
        self,
        node_type: NodeType,
        value: str,
    ) -> str:
        """
        Normalize entity values for graph deduplication.
        """

        value = str(
            value
        ).strip()

        if not value:
            return ""

        if node_type == NodeType.URL:

            return self._normalize_url(
                value
            )

        if node_type == NodeType.DOMAIN:

            return self._normalize_domain(
                value
            )

        if node_type == NodeType.EMAIL:

            return value.lower()

        if node_type == NodeType.PHONE:

            return re.sub(
                r"\D",
                "",
                value,
            )

        if node_type in {
            NodeType.IFSC,
            NodeType.PAN,
            NodeType.SEBI_REGISTRATION,
        }:

            return re.sub(
                r"\s+",
                "",
                value,
            ).upper()

        if node_type in {
            NodeType.AADHAAR,
            NodeType.BANK_ACCOUNT,
        }:

            return re.sub(
                r"\D",
                "",
                value,
            )

        if node_type == NodeType.UPI_ID:

            return value.lower()

        if node_type == NodeType.COMMUNICATION:

            return value.upper()

        return re.sub(
            r"\s+",
            " ",
            value,
        ).strip().lower()

    # ========================================================
    # URL Normalization
    # ========================================================

    def _normalize_url(
        self,
        value: str,
    ) -> str:
        """
        Normalize URL values without treating them as verified.
        """

        value = value.strip()

        candidate = value

        if not re.match(
            r"^[a-z][a-z0-9+.-]*://",
            candidate,
            re.IGNORECASE,
        ):
            candidate = (
                "https://"
                + candidate
            )

        try:

            parsed = urlparse(
                candidate
            )

            hostname = (
                parsed.hostname
                or ""
            ).lower()

            if hostname.startswith(
                "www."
            ):
                hostname = hostname[4:]

            if not hostname:
                return value.lower()

            path = (
                parsed.path
                or ""
            )

            if path == "/":
                path = ""

            normalized = (
                hostname
                + path
            )

            if parsed.query:

                normalized += (
                    "?"
                    + parsed.query
                )

            return normalized.rstrip(
                "/"
            )

        except Exception:

            return value.lower()

    # ========================================================
    # Domain Normalization
    # ========================================================

    def _normalize_domain(
        self,
        value: str,
    ) -> str:

        value = value.strip().lower()

        value = re.sub(
            r"^[a-z][a-z0-9+.-]*://",
            "",
            value,
            flags=re.IGNORECASE,
        )

        value = value.split(
            "/",
            1,
        )[0]

        value = value.split(
            ":",
            1,
        )[0]

        if value.startswith(
            "www."
        ):
            value = value[4:]

        return value.strip(
            "."
        )

    # ========================================================
    # Extract Domain
    # ========================================================

    def _extract_domain(
        self,
        url: str,
    ) -> str | None:

        candidate = str(
            url
        ).strip()

        if not candidate:
            return None

        if not re.match(
            r"^[a-z][a-z0-9+.-]*://",
            candidate,
            re.IGNORECASE,
        ):
            candidate = (
                "https://"
                + candidate
            )

        try:

            parsed = urlparse(
                candidate
            )

            hostname = (
                parsed.hostname
                or ""
            )

            hostname = (
                self._normalize_domain(
                    hostname
                )
            )

            return (
                hostname
                or None
            )

        except Exception:

            return None

    # ========================================================
    # Deterministic IDs
    # ========================================================

    def _make_node_id(
        self,
        node_type: NodeType,
        normalized_value: str,
    ) -> str:

        raw = (
            f"{node_type.value}|"
            f"{normalized_value}"
        )

        digest = hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()[:16].upper()

        return (
            f"STGN-{digest}"
        )

    def _make_edge_id(
        self,
        source_node_id: str,
        target_node_id: str,
        relationship: RelationshipType,
    ) -> str:

        raw = (
            f"{source_node_id}|"
            f"{relationship.value}|"
            f"{target_node_id}"
        )

        digest = hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()[:16].upper()

        return (
            f"STGE-{digest}"
        )

    @staticmethod
    def _make_observation_id(
        communication_id: str,
        subject_type: str,
        subject_id: str,
        observation_type: str,
    ) -> str:
        """
        Create deterministic observation identity.
        """

        raw = (
            f"{communication_id}|"
            f"{subject_type}|"
            f"{subject_id}|"
            f"{observation_type}"
        )

        digest = hashlib.sha256(
            raw.encode(
                "utf-8"
            )
        ).hexdigest()[:16].upper()

        return (
            f"STGO-{digest}"
        )

    # ========================================================
    # Security Observation Tracking
    # ========================================================

    def _apply_security_observation(
        self,
        node: STGNode,
        risk_level: str | None,
    ) -> None:
        """
        Update entity-specific historical security counters.

        IMPORTANT:
        This method must only receive a security classification
        that applies to the node itself.

        Communication-level risk must never be passed here for
        ordinary content entities.
        """

        if not risk_level:
            return

        normalized = str(
            risk_level
        ).strip().lower()

        if normalized in {
            "low",
            "legitimate",
            "safe",
            "trusted",
        }:

            node.legitimate_observations = (
                int(
                    node.legitimate_observations
                    or 0
                )
                + 1
            )

        elif normalized in {
            "medium",
            "suspicious",
            "spam",
        }:

            node.suspicious_observations = (
                int(
                    node.suspicious_observations
                    or 0
                )
                + 1
            )

        elif normalized in {
            "high",
            "phishing",
            "malicious",
        }:

            node.phishing_observations = (
                int(
                    node.phishing_observations
                    or 0
                )
                + 1
            )

    # ========================================================
    # Result Reputation Aggregation
    # ========================================================

    def _build_result_reputation(
        self,
        result: STGAnalysisResult,
        reputations: list[EntityReputation],
    ) -> None:
        """
        Aggregate independent entity reputations into
        communication-level historical graph intelligence.

        Security invariants:

        1. Only meaningful entity-specific historical
           reputation participates.

        2. Independently established high-risk or suspicious
           entity evidence may preserve its security class,
           but only when that evidence has sufficient
           confidence.

        3. Extremely weak malicious evidence must not dominate
           substantially stronger trusted evidence merely
           because of its classification label.

        4. Trusted reputation remains visible in individual
           entity reputations and contributes normally to the
           confidence-weighted baseline.

        5. When a security-preserving floor determines the
           aggregate decision, aggregate confidence reflects
           the evidence responsible for that floor.

        6. This is graph-derived historical context only.
           It does not authenticate the sender and does not
           replace communication-level model decisions.
        """

        # ====================================================
        # Policy
        # ====================================================

        RISK_PRESERVATION_MIN_CONFIDENCE = 20.0

        HIGH_RISK_FLOOR = 80.0
        SUSPICIOUS_FLOOR = 60.0

        # ====================================================
        # No Reputation
        # ====================================================

        if not reputations:

            result.reputation_available = False
            result.reputation_score = None
            result.graph_risk_score = None
            result.graph_trust_score = None
            result.confidence = 0.0
            result.classification = (
                TrustClassification.UNKNOWN
            )

            return

        # ====================================================
        # Meaningful Independent Reputation
        # ====================================================

        meaningful = [
            reputation
            for reputation in reputations
            if (
                self._clamp_score(
                    reputation.confidence
                ) > 0.0
                and reputation.classification
                != TrustClassification.UNKNOWN
            )
        ]

        if not meaningful:

            result.reputation_available = False
            result.reputation_score = None
            result.graph_risk_score = None
            result.graph_trust_score = None
            result.confidence = 0.0
            result.classification = (
                TrustClassification.UNKNOWN
            )

            return

        # ====================================================
        # Confidence-Weighted Baseline
        # ====================================================

        total_weight = sum(
            max(
                self._clamp_score(
                    reputation.confidence
                ),
                1.0,
            )
            for reputation in meaningful
        )

        weighted_risk = sum(
            self._clamp_score(
                reputation.risk_score
            )
            * max(
                self._clamp_score(
                    reputation.confidence
                ),
                1.0,
            )
            for reputation in meaningful
        ) / total_weight

        weighted_trust = sum(
            self._clamp_score(
                reputation.trust_score
            )
            * max(
                self._clamp_score(
                    reputation.confidence
                ),
                1.0,
            )
            for reputation in meaningful
        ) / total_weight

        weighted_risk = self._clamp_score(
            weighted_risk
        )

        weighted_trust = self._clamp_score(
            weighted_trust
        )

        # ====================================================
        # Confidence-Qualified Security Evidence
        # ====================================================
        #
        # A classification label by itself is not sufficient
        # to establish a communication-level graph floor.
        #
        # This prevents extremely weak historical evidence
        # from dominating much stronger independent context.
        # ====================================================

        qualified_high_risk_entities = [
            reputation
            for reputation in meaningful
            if (
                reputation.classification
                == TrustClassification.HIGH_RISK
                and self._clamp_score(
                    reputation.confidence
                )
                >= RISK_PRESERVATION_MIN_CONFIDENCE
            )
        ]

        qualified_suspicious_entities = [
            reputation
            for reputation in meaningful
            if (
                reputation.classification
                == TrustClassification.SUSPICIOUS
                and self._clamp_score(
                    reputation.confidence
                )
                >= RISK_PRESERVATION_MIN_CONFIDENCE
            )
        ]

        # ====================================================
        # Security-Preserving Risk Floor
        # ====================================================

        aggregate_risk = weighted_risk

        floor_applied = False

        floor_confidence: float | None = None

        if qualified_high_risk_entities:

            strongest_high_risk = max(
                qualified_high_risk_entities,
                key=lambda reputation: (
                    self._clamp_score(
                        reputation.risk_score
                    ),
                    self._clamp_score(
                        reputation.confidence
                    ),
                ),
            )

            strongest_high_risk_score = (
                self._clamp_score(
                    strongest_high_risk.risk_score
                )
            )

            preserved_risk = min(
                strongest_high_risk_score,
                HIGH_RISK_FLOOR,
            )

            if preserved_risk > aggregate_risk:

                aggregate_risk = (
                    preserved_risk
                )

                floor_applied = True

                floor_confidence = (
                    self._clamp_score(
                        strongest_high_risk.confidence
                    )
                )

        elif qualified_suspicious_entities:

            strongest_suspicious = max(
                qualified_suspicious_entities,
                key=lambda reputation: (
                    self._clamp_score(
                        reputation.risk_score
                    ),
                    self._clamp_score(
                        reputation.confidence
                    ),
                ),
            )

            strongest_suspicious_score = (
                self._clamp_score(
                    strongest_suspicious.risk_score
                )
            )

            preserved_risk = min(
                strongest_suspicious_score,
                SUSPICIOUS_FLOOR,
            )

            if preserved_risk > aggregate_risk:

                aggregate_risk = (
                    preserved_risk
                )

                floor_applied = True

                floor_confidence = (
                    self._clamp_score(
                        strongest_suspicious.confidence
                    )
                )

        aggregate_risk = self._clamp_score(
            aggregate_risk
        )

        # ====================================================
        # Aggregate Trust
        # ====================================================
        #
        # Risk and trust remain complementary at the compact
        # communication-level STG result.
        #
        # weighted_trust is intentionally calculated above as
        # part of the confidence-weighted baseline. If no
        # security floor changes risk, its complementary form
        # remains consistent with weighted_risk for ordinary
        # entity reputations.
        # ====================================================

        aggregate_trust = self._clamp_score(
            100.0 - aggregate_risk
        )

        # ====================================================
        # Aggregate Confidence
        # ====================================================
        #
        # When ordinary weighted aggregation determines the
        # result, use confidence weighted by the same evidence
        # strengths participating in that aggregation.
        #
        # When a preservation floor determines the result,
        # confidence must describe the evidence responsible
        # for that floor rather than being inflated by
        # unrelated trusted entities.
        # ====================================================

        baseline_confidence = (
            sum(
                self._clamp_score(
                    reputation.confidence
                )
                * max(
                    self._clamp_score(
                        reputation.confidence
                    ),
                    1.0,
                )
                for reputation in meaningful
            )
            / total_weight
        )

        if (
            floor_applied
            and floor_confidence is not None
        ):

            aggregate_confidence = (
                floor_confidence
            )

        else:

            aggregate_confidence = (
                baseline_confidence
            )

        aggregate_confidence = (
            self._clamp_score(
                aggregate_confidence
            )
        )

        # ====================================================
        # Populate Result
        # ====================================================

        result.reputation_available = True

        result.graph_risk_score = round(
            aggregate_risk,
            4,
        )

        result.graph_trust_score = round(
            aggregate_trust,
            4,
        )

        result.reputation_score = (
            result.graph_trust_score
        )

        result.confidence = round(
            aggregate_confidence,
            4,
        )

        # ====================================================
        # Classification
        # ====================================================

        risk = result.graph_risk_score

        if risk >= 80.0:

            result.classification = (
                TrustClassification.HIGH_RISK
            )

        elif risk >= 60.0:

            result.classification = (
                TrustClassification.SUSPICIOUS
            )

        elif risk >= 40.0:

            result.classification = (
                TrustClassification.NEUTRAL
            )

        elif risk >= 20.0:

            result.classification = (
                TrustClassification.LOW_RISK
            )

        else:

            result.classification = (
                TrustClassification.TRUSTED
            )

    # ========================================================
    # Explainable Graph Evidence
    # ========================================================

    def _build_graph_evidence(
        self,
        reputations: list[EntityReputation],
    ) -> list[GraphEvidence]:

        evidence: list[
            GraphEvidence
        ] = []

        for reputation in reputations:

            if (
                reputation.classification
                == TrustClassification.UNKNOWN
            ):
                continue

            if reputation.classification in {
                TrustClassification.SUSPICIOUS,
                TrustClassification.HIGH_RISK,
            }:

                evidence.append(
                    GraphEvidence(
                        evidence_type=(
                            "Historical Risk Association"
                        ),
                        description=(
                            f"{reputation.value} has "
                            "entity-specific historical "
                            "risk evidence in the Securities "
                            "Trust Graph."
                        ),
                        source=(
                            EvidenceSource.SECURITIES_TRUST_GRAPH
                        ),
                        node_ids=[
                            reputation.node_id
                        ],
                        evidence_ids=(
                            reputation.evidence_ids
                        ),
                        ledger_ids=(
                            reputation.ledger_ids
                        ),
                        risk_contribution=(
                            reputation.risk_score
                        ),
                        trust_contribution=0.0,
                        confidence=(
                            reputation.confidence
                        ),
                        attributes={
                            "classification":
                                reputation.classification.value,

                            "total_observations":
                                reputation.total_observations,

                            "phishing_observations":
                                reputation.phishing_observations,

                            "suspicious_observations":
                                reputation.suspicious_observations,

                            "entity_specific": True,
                        },
                    )
                )

            elif reputation.classification in {
                TrustClassification.TRUSTED,
                TrustClassification.LOW_RISK,
            }:

                evidence.append(
                    GraphEvidence(
                        evidence_type=(
                            "Historical Trust Association"
                        ),
                        description=(
                            f"{reputation.value} has "
                            "entity-specific historical "
                            "low-risk evidence in the "
                            "Securities Trust Graph."
                        ),
                        source=(
                            EvidenceSource.SECURITIES_TRUST_GRAPH
                        ),
                        node_ids=[
                            reputation.node_id
                        ],
                        evidence_ids=(
                            reputation.evidence_ids
                        ),
                        ledger_ids=(
                            reputation.ledger_ids
                        ),
                        risk_contribution=0.0,
                        trust_contribution=(
                            reputation.trust_score
                        ),
                        confidence=(
                            reputation.confidence
                        ),
                        attributes={
                            "classification":
                                reputation.classification.value,

                            "total_observations":
                                reputation.total_observations,

                            "legitimate_observations":
                                reputation.legitimate_observations,

                            "entity_specific": True,
                        },
                    )
                )

        return evidence

    # ========================================================
    # Summary
    # ========================================================

    def _build_summary(
        self,
        result: STGAnalysisResult,
    ) -> str:

        if result.entities_analysed == 0:

            return (
                "The communication contained no supported "
                "entities for Securities Trust Graph analysis."
            )

        if not result.reputation_available:

            return (
                f"The Securities Trust Graph recorded "
                f"{result.entities_analysed} supported entity "
                f"observation(s), but no sufficient "
                "entity-specific historical security evidence "
                "is available for a graph-derived trust or "
                "risk classification. Content mentions alone "
                "do not affect entity reputation."
            )

        return (
            f"The Securities Trust Graph analysed "
            f"{result.entities_analysed} supported entity "
            f"observation(s). Entity-specific historical graph "
            f"intelligence classified the observed entity "
            f"context as {result.classification.value} with a "
            f"graph risk score of {result.graph_risk_score} "
            f"and confidence of {result.confidence}. This "
            f"graph intelligence represents historical "
            f"entity-specific evidence and does not "
            f"authenticate the sender."
        )

    # ========================================================
    # ORM -> Pydantic Conversion
    # ========================================================

    def _node_to_model(
        self,
        node: STGNode,
    ) -> GraphNode:

        return GraphNode(
            node_id=node.node_id,
            node_type=self._safe_node_type(
                node.node_type
            ),
            value=node.value,
            normalized_value=node.normalized_value,
            display_name=node.display_name,
            verified=bool(
                node.verified
            ),
            first_seen=node.first_seen,
            last_seen=node.last_seen,
            observation_count=int(
                node.observation_count
                or 0
            ),
            attributes=(
                node.attributes
                if isinstance(
                    node.attributes,
                    dict,
                )
                else {}
            ),
            evidence_ids=self._unique_strings(
                node.evidence_ids
            ),
            ledger_ids=self._unique_strings(
                node.ledger_ids
            ),
        )

    def _edge_to_model(
        self,
        edge: STGEdge,
    ) -> GraphEdge:

        return GraphEdge(
            edge_id=edge.edge_id,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            relationship=(
                self._safe_relationship_type(
                    edge.relationship
                )
            ),
            verified=bool(
                edge.verified
            ),
            confidence=self._clamp_score(
                edge.confidence
            ),
            evidence_source=(
                self._safe_evidence_source(
                    edge.evidence_source
                )
            ),
            first_seen=edge.first_seen,
            last_seen=edge.last_seen,
            observation_count=int(
                edge.observation_count
                or 0
            ),
            attributes=(
                edge.attributes
                if isinstance(
                    edge.attributes,
                    dict,
                )
                else {}
            ),
            evidence_ids=self._unique_strings(
                edge.evidence_ids
            ),
            ledger_ids=self._unique_strings(
                edge.ledger_ids
            ),
        )

    # ========================================================
    # Safe Enum Conversion
    # ========================================================

    @staticmethod
    def _safe_node_type(
        value: str,
    ) -> NodeType:

        try:
            return NodeType(
                value
            )

        except (
            ValueError,
            TypeError,
        ):
            return NodeType.UNKNOWN

    @staticmethod
    def _safe_relationship_type(
        value: str,
    ) -> RelationshipType:

        try:
            return RelationshipType(
                value
            )

        except (
            ValueError,
            TypeError,
        ):
            return RelationshipType.UNKNOWN

    @staticmethod
    def _safe_evidence_source(
        value: str | None,
    ) -> EvidenceSource:

        try:
            return EvidenceSource(
                value
            )

        except (
            ValueError,
            TypeError,
        ):
            return EvidenceSource.UNKNOWN

    # ========================================================
    # Collection Helpers
    # ========================================================

    @staticmethod
    def _unique_strings(
        values: Iterable[Any] | None,
    ) -> list[str]:

        if not values:
            return []

        seen = set()

        result = []

        for value in values:

            if value is None:
                continue

            text = str(
                value
            ).strip()

            if (
                text
                and text not in seen
            ):

                seen.add(
                    text
                )

                result.append(
                    text
                )

        return result

    def _merge_string_lists(
        self,
        existing: Any,
        incoming: Any,
    ) -> list[str]:

        existing_values = (
            existing
            if isinstance(
                existing,
                (list, tuple, set),
            )
            else []
        )

        incoming_values = (
            incoming
            if isinstance(
                incoming,
                (list, tuple, set),
            )
            else []
        )

        return self._unique_strings(
            list(existing_values)
            + list(incoming_values)
        )

    @staticmethod
    def _merge_dicts(
        existing: Any,
        incoming: Any,
    ) -> dict[str, Any]:

        result = {}

        if isinstance(
            existing,
            dict,
        ):
            result.update(
                existing
            )

        if isinstance(
            incoming,
            dict,
        ):
            result.update(
                incoming
            )

        return result

    # ========================================================
    # Context Deduplication
    # ========================================================

    @staticmethod
    def _deduplicate_graph_nodes(
        nodes: list[GraphNode],
    ) -> list[GraphNode]:

        seen = set()

        result = []

        for node in nodes:

            if node.node_id in seen:
                continue

            seen.add(
                node.node_id
            )

            result.append(
                node
            )

        return result

    @staticmethod
    def _deduplicate_graph_edges(
        edges: list[GraphEdge],
    ) -> list[GraphEdge]:

        seen = set()

        result = []

        for edge in edges:

            if edge.edge_id in seen:
                continue

            seen.add(
                edge.edge_id
            )

            result.append(
                edge
            )

        return result

    # ========================================================
    # Numeric Helpers
    # ========================================================

    @staticmethod
    def _clamp_score(
        value: Any,
    ) -> float:

        try:

            number = float(
                value
            )

        except (
            TypeError,
            ValueError,
        ):

            return 0.0

        return max(
            0.0,
            min(
                100.0,
                number,
            ),
        )


# ============================================================
# Singleton
# ============================================================

graph_engine = SecuritiesTrustGraphEngine()


# ============================================================
# Public Exports
# ============================================================

__all__ = [
    "SecuritiesTrustGraphEngine",
    "graph_engine",
]