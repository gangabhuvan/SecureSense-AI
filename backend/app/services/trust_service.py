"""
trust_service.py

SecureSense AI Trust Layer orchestration service.

Responsibilities
----------------
- Accept trusted sender/channel metadata supplied explicitly
  by the communication channel or API
- Run the Authenticity Verification Engine (AVE)
- Generate the Financial Communication Passport (FCP)
- Attach authenticity results to the final passport
- Attach Securities Trust Graph (STG) historical entity context
- Keep content entities separate from sender-authentication
  evidence
- Keep STG reputation separate from communication-level risk
- Produce a final recommendation consistent with communication
  risk, sender verification and historical entity context

Security Boundary
-----------------
SecureSense AI maintains three distinct trust dimensions:

1. Communication Security
   Produced by NLP, URL Intelligence, Visual Intelligence and
   multimodal fusion.

2. Sender Authenticity
   Produced exclusively by the Authenticity Verification
   Engine (AVE) using explicitly supplied sender/channel
   metadata.

3. Historical Entity Reputation
   Produced by the Securities Trust Graph (STG) from
   entity-specific historical security evidence.

These dimensions must not be silently collapsed.

For example:

    "Visit https://www.hdfcbank.com"

may legitimately produce:

    analysis.entities["urls"] =
        ["https://www.hdfcbank.com"]

and STG may have historical evidence indicating that
hdfcbank.com is a trusted entity.

That does NOT establish that HDFC Bank sent the current
communication.

Likewise, a trusted STG entity must not reduce or override a
high-risk phishing decision produced by the communication
security models.

AVE remains authoritative for sender authentication.
"""

from __future__ import annotations

from typing import Any

from app.models.analysis_models import AnalysisResult

from app.models.voice_models import (
    VoiceAuthenticityResult,
)

from app.fcp.generator import passport_generator
from app.fcp.models import (
    FCPRelationshipContext,
    FCPRelationshipContextItem,
    FCPRelationshipSignal,
    FinancialCommunicationPassport,
    SecuritiesTrustGraphContext,
)

from app.stg.graph_models import STGAnalysisResult

from app.trust_engine.authenticity_engine import (
    authenticity_engine,
)


# ============================================================
# Trust Service
# ============================================================

class TrustService:
    """
    Main orchestration service for the SecureSense AI
    Trust Layer.

    Three security dimensions are intentionally preserved.

    Communication intelligence:
        NLP
        URL Intelligence
        Visual Intelligence
        rule-based findings
        multimodal fusion

    Sender authenticity:
        explicit sender email
        explicit sender phone
        explicit originating website/domain

    Historical entity context:
        Securities Trust Graph reputation
        entity-specific security observations
        historical graph associations

    Only explicit sender/channel metadata participates in AVE.

    STG context is exposed independently in the Financial
    Communication Passport and never silently modifies the
    communication-level risk decision.
    """

    # ========================================================
    # Main Processing
    # ========================================================

    def process(
        self,
        analysis: AnalysisResult,
        communication_id: str | None = None,
        communication_type: str = "Unknown",
        sender_email: str | None = None,
        sender_phone: str | None = None,
        sender_website: str | None = None,
        claimed_sender: str | None = None,
        stg_result: STGAnalysisResult | dict[str, Any] | None = None,
        voice_authenticity: (
            VoiceAuthenticityResult | None
        ) = None,
        analysis_available: bool = True,
        trusted_hosting_platform: bool = False,
        hosting_provider: str | None = None,
    ) -> FinancialCommunicationPassport:
        """
        Generate the final Financial Communication Passport.

        Parameters
        ----------
        analysis:
            Final SecureSense communication analysis.

        communication_id:
            Unique communication identifier.

        communication_type:
            Communication/document type.

        sender_email:
            Explicit sender email obtained from trusted
            communication/channel metadata.

            This must NOT be populated automatically from
            email addresses appearing inside message content.

        sender_phone:
            Explicit sender phone number obtained from trusted
            communication/channel metadata.

            This must NOT be populated automatically from
            phone numbers appearing inside message content.

        sender_website:
            Explicit originating sender website/domain when
            independently available from the communication
            channel or trusted metadata.

            URLs merely appearing inside message/document
            content must NOT be passed here.

        claimed_sender:
            Explicitly supplied claimed sender/organisation
            identity.

        stg_result:
            Completed Securities Trust Graph analysis for the
            current communication.

            STG information is treated only as historical
            entity-reputation context.

            It must NOT:
            - authenticate the sender
            - alter AVE verification
            - lower communication risk
            - override multimodal fusion
            - modify the FCP trust score

        Workflow
        --------
        1. Normalize explicit sender metadata
        2. Run Authenticity Verification Engine
        3. Generate Financial Communication Passport
        4. Attach AVE verification result
        5. Determine verified-sender state
        6. Attach STG historical entity context
        7. Generate final context-aware recommendation
        """

        # ====================================================
        # 1. Normalize Explicit Sender Metadata
        # ====================================================

        normalized_email = self._normalize_optional(
            sender_email
        )

        normalized_phone = self._normalize_optional(
            sender_phone
        )

        normalized_website = self._normalize_optional(
            sender_website
        )

        normalized_claimed_sender = (
            self._normalize_optional(
                claimed_sender
            )
        )

        # ====================================================
        # 2. Authenticity Verification
        # ====================================================
        #
        # IMPORTANT:
        #
        # analysis.entities is intentionally NOT passed into
        # AVE here.
        #
        # Extracted content URLs/emails/phone numbers remain
        # content evidence and cannot authenticate the sender.
        #
        # STG reputation is also intentionally NOT passed into
        # AVE.
        #
        # Historical entity reputation cannot authenticate the
        # sender of the current communication.
        # ====================================================

        verification = authenticity_engine.verify(
            sender_email=normalized_email,
            sender_phone=normalized_phone,
            website=normalized_website,
        )

        # ====================================================
        # 3. Generate Financial Communication Passport
        # ====================================================

        passport = passport_generator.generate(
            analysis=analysis,

            communication_id=communication_id,

            communication_type=communication_type,

            claimed_sender=(
                normalized_claimed_sender
                or "Unknown"
            ),
            voice_authenticity=(
                voice_authenticity
            ),
        )

        # ====================================================
        # 4. Attach AVE Result
        # ====================================================

        passport.verification = (
            verification
        )

        # ====================================================
        # 5. Determine Sender Verification State
        # ====================================================
        #
        # A sender is considered verified only when:
        #
        # - AVE explicitly returns Verified
        # - metadata is internally consistent
        # - at least one genuine sender-authentication signal
        #   has been positively verified
        #
        # Content-extracted entities never participate here.
        #
        # STG reputation never participates here.
        # ====================================================

        passport.verified_sender = (
            verification.status == "Verified"
            and verification.metadata_consistent
            and (
                verification.official_email
                or verification.official_phone
                or verification.official_domain
            )
        )

        # ====================================================
        # 6. Attach Securities Trust Graph Context
        # ====================================================
        #
        # STG is attached as an independent contextual
        # dimension.
        #
        # This operation deliberately does NOT modify:
        #
        # - passport.risk_score
        # - passport.risk_level
        # - passport.trust_score
        # - passport.confidence
        # - passport.verified_sender
        # - passport.verification
        #
        # A trusted graph entity therefore cannot make a
        # phishing communication safe and cannot authenticate
        # its sender.
        # ====================================================

        stg_context = self._build_stg_context(
            stg_result
        )

        passport.securities_trust_graph = (
            stg_context
        )

        # ====================================================
        # 7. Final Context-Aware Recommendation
        # ====================================================
        #
        # Communication risk remains authoritative for the
        # security decision.
        #
        # AVE determines sender authenticity.
        #
        # STG may strengthen contextual caution when historical
        # entity-specific risk exists, but trusted STG history
        # never weakens communication-level warnings.
        # ====================================================

        passport.recommended_action = (
            self._get_final_recommendation(
                risk_level=passport.risk_level,
                verified_sender=passport.verified_sender,
                verification_status=(
                    verification.status
                ),
                stg_context=stg_context,
                analysis_available=analysis_available,
                trusted_hosting_platform=trusted_hosting_platform,
                hosting_provider=hosting_provider,
            )
        )

        return passport

    # ========================================================
    # STG Context Builder
    # ========================================================

    @staticmethod
    def _build_stg_context(
        stg_result: (
            STGAnalysisResult
            | dict[str, Any]
            | None
        ),
    ) -> SecuritiesTrustGraphContext | None:
        """
        Convert the completed STG analysis into the compact
        contextual representation stored in the FCP.

        The detailed graph remains available separately in the
        API analysis response.

        Only decision-relevant graph reputation and provenance
        are copied into the passport.
        """

        if stg_result is None:
            return None

        # ----------------------------------------------------
        # Pydantic STG result
        # ----------------------------------------------------

        if isinstance(
            stg_result,
            STGAnalysisResult,
        ):
            return SecuritiesTrustGraphContext(
                available=bool(
                    stg_result.available
                ),

                reputation_available=bool(
                    stg_result.reputation_available
                ),

                classification=(
                    stg_result.classification
                    or "Unknown"
                ),

                graph_risk_score=(
                    stg_result.graph_risk_score
                ),

                graph_trust_score=(
                    stg_result.graph_trust_score
                ),

                confidence=float(
                    stg_result.confidence
                    or 0.0
                ),

                entities_analysed=int(
                    stg_result.entities_analysed
                    or 0
                ),

                nodes=list(
                    getattr(
                        stg_result.context,
                        "nodes",
                        [],
                    )
                    or []
                ),

                edges=list(
                    getattr(
                        stg_result.context,
                        "edges",
                        [],
                    )
                    or []
                ),

                relationship_context=(
                    TrustService._build_relationship_context(
                        getattr(
                            stg_result.context,
                            "relationship_risk",
                            [],
                        )
                    )
                ),
                evidence_ids=list(
                    dict.fromkeys(
                        stg_result.evidence_ids
                        or []
                    )
                ),

                ledger_ids=list(
                    dict.fromkeys(
                        stg_result.ledger_ids
                        or []
                    )
                ),

                summary=(
                    stg_result.summary
                    or ""
                ),
            )

        # ----------------------------------------------------
        # Dictionary STG result
        # ----------------------------------------------------
        #
        # Supporting dictionaries keeps this service reusable
        # when an STG result has already been serialized by an
        # orchestration layer.
        # ----------------------------------------------------

        if isinstance(
            stg_result,
            dict,
        ):
            return SecuritiesTrustGraphContext(
                available=bool(
                    stg_result.get(
                        "available",
                        False,
                    )
                ),

                reputation_available=bool(
                    stg_result.get(
                        "reputation_available",
                        False,
                    )
                ),

                classification=(
                    str(
                        stg_result.get(
                            "classification",
                            "Unknown",
                        )
                        or "Unknown"
                    )
                ),

                graph_risk_score=(
                    TrustService._optional_float(
                        stg_result.get(
                            "graph_risk_score"
                        )
                    )
                ),

                graph_trust_score=(
                    TrustService._optional_float(
                        stg_result.get(
                            "graph_trust_score"
                        )
                    )
                ),

                confidence=(
                    TrustService._safe_float(
                        stg_result.get(
                            "confidence",
                            0.0,
                        )
                    )
                ),

                entities_analysed=(
                    TrustService._safe_int(
                        stg_result.get(
                            "entities_analysed",
                            0,
                        )
                    )
                ),

                nodes=(
                    list(
                        (
                            stg_result.get(
                                "context",
                                {},
                            )
                            or {}
                        ).get(
                            "nodes",
                            [],
                        )
                    )
                    if isinstance(
                        stg_result.get(
                            "context",
                            {},
                        ),
                        dict,
                    )
                    else []
                ),

                edges=(
                    list(
                        (
                            stg_result.get(
                                "context",
                                {},
                            )
                            or {}
                        ).get(
                            "edges",
                            [],
                        )
                    )
                    if isinstance(
                        stg_result.get(
                            "context",
                            {},
                        ),
                        dict,
                    )
                    else []
                ),

                relationship_context=(
                    TrustService._build_relationship_context(
                        (
                            stg_result.get(
                                "context",
                                {},
                            )
                            or {}
                        ).get(
                            "relationship_risk",
                            [],
                        )
                        if isinstance(
                            stg_result.get(
                                "context",
                                {},
                            ),
                            dict,
                        )
                        else []
                    )
                ),

                evidence_ids=(
                    TrustService._unique_strings(
                        stg_result.get(
                            "evidence_ids"
                        )
                    )
                ),

                ledger_ids=(
                    TrustService._unique_strings(
                        stg_result.get(
                            "ledger_ids"
                        )
                    )
                ),

                summary=(
                    str(
                        stg_result.get(
                            "summary",
                            "",
                        )
                        or ""
                    )
                ),
            )

        # ----------------------------------------------------
        # Defensive fallback
        # ----------------------------------------------------

        return None

    # ========================================================
    # STG Relationship Context Builder
    # ========================================================

    @staticmethod
    def _build_relationship_context(
        relationship_contexts: Any,
    ) -> FCPRelationshipContext:
        """
        Convert STG relationship-derived intelligence into the
        compact representation stored in the FCP.

        Security boundary
        -----------------
        Relationship context remains independent from:

        - communication-level risk
        - direct historical entity reputation
        - AVE sender authentication

        Per-subject contexts are preserved separately.

        Contextual risk/trust values belonging to unrelated
        entities are deliberately NOT averaged into a global
        relationship score.
        """

        if relationship_contexts is None:
            relationship_contexts = []

        if not isinstance(
            relationship_contexts,
            (
                list,
                tuple,
            ),
        ):
            relationship_contexts = [
                relationship_contexts
            ]

        contexts: list[
            FCPRelationshipContextItem
        ] = []

        combined_evidence_ids: list[str] = []
        combined_ledger_ids: list[str] = []

        for raw_context in relationship_contexts:

            context_data = (
                TrustService._model_to_dict(
                    raw_context
                )
            )

            if not context_data:
                continue

            raw_signals = (
                context_data.get(
                    "signals",
                    [],
                )
                or []
            )

            if not isinstance(
                raw_signals,
                (
                    list,
                    tuple,
                ),
            ):
                raw_signals = [
                    raw_signals
                ]

            signals: list[
                FCPRelationshipSignal
            ] = []

            for raw_signal in raw_signals:

                signal = (
                    TrustService._build_relationship_signal(
                        raw_signal
                    )
                )

                if signal is None:
                    continue

                signals.append(
                    signal
                )

                combined_evidence_ids.extend(
                    signal.evidence_ids
                )

                combined_ledger_ids.extend(
                    signal.ledger_ids
                )

            context_evidence_ids = (
                TrustService._unique_strings(
                    context_data.get(
                        "evidence_ids"
                    )
                )
            )

            context_ledger_ids = (
                TrustService._unique_strings(
                    context_data.get(
                        "ledger_ids"
                    )
                )
            )

            combined_evidence_ids.extend(
                context_evidence_ids
            )

            combined_ledger_ids.extend(
                context_ledger_ids
            )

            contexts.append(
                FCPRelationshipContextItem(
                    subject_node_id=str(
                        context_data.get(
                            "subject_node_id",
                            "",
                        )
                        or ""
                    ),

                    available=bool(
                        context_data.get(
                            "available",
                            False,
                        )
                    ),

                    contextual_risk_score=(
                        TrustService._optional_float(
                            context_data.get(
                                "contextual_risk_score"
                            )
                        )
                    ),

                    contextual_trust_score=(
                        TrustService._optional_float(
                            context_data.get(
                                "contextual_trust_score"
                            )
                        )
                    ),

                    confidence=(
                        TrustService._safe_float(
                            context_data.get(
                                "confidence",
                                0.0,
                            )
                        )
                    ),

                    classification=(
                        TrustService._enum_value(
                            context_data.get(
                                "classification",
                                "Unknown",
                            ),
                            "Unknown",
                        )
                    ),

                    relationships_analysed=(
                        TrustService._safe_int(
                            context_data.get(
                                "relationships_analysed",
                                0,
                            )
                        )
                    ),

                    contributing_relationships=(
                        TrustService._safe_int(
                            context_data.get(
                                "contributing_relationships",
                                0,
                            )
                        )
                    ),

                    high_risk_neighbours=(
                        TrustService._safe_int(
                            context_data.get(
                                "high_risk_neighbours",
                                0,
                            )
                        )
                    ),

                    suspicious_neighbours=(
                        TrustService._safe_int(
                            context_data.get(
                                "suspicious_neighbours",
                                0,
                            )
                        )
                    ),

                    trusted_neighbours=(
                        TrustService._safe_int(
                            context_data.get(
                                "trusted_neighbours",
                                0,
                            )
                        )
                    ),

                    signals=signals,

                    evidence_ids=(
                        context_evidence_ids
                    ),

                    ledger_ids=(
                        context_ledger_ids
                    ),

                    reasons=(
                        TrustService._unique_strings(
                            context_data.get(
                                "reasons"
                            )
                        )
                    ),

                    summary=str(
                        context_data.get(
                            "summary",
                            "",
                        )
                        or ""
                    ),
                )
            )

        available_contexts = [
            context
            for context in contexts
            if context.available
        ]

        total_signals = sum(
            len(
                context.signals
            )
            for context in contexts
        )

        if available_contexts:

            summary = (
                f"{len(available_contexts)} of "
                f"{len(contexts)} entity relationship "
                "context(s) contain meaningful contextual "
                f"intelligence with {total_signals} "
                "contributing signal(s). Relationship-derived "
                "intelligence remains contextual only."
            )

        elif contexts:

            summary = (
                f"{len(contexts)} entity relationship "
                "context(s) were inspected, but none contained "
                "eligible reputation-propagation signals."
            )

        else:

            summary = (
                "No relationship-derived STG context is "
                "currently available."
            )

        return FCPRelationshipContext(
            available=bool(
                available_contexts
            ),

            contexts_analysed=len(
                contexts
            ),

            contexts_available=len(
                available_contexts
            ),

            total_signals=total_signals,

            contexts=contexts,

            evidence_ids=(
                TrustService._unique_strings(
                    combined_evidence_ids
                )
            ),

            ledger_ids=(
                TrustService._unique_strings(
                    combined_ledger_ids
                )
            ),

            summary=summary,
        )

    @staticmethod
    def _build_relationship_signal(
        raw_signal: Any,
    ) -> FCPRelationshipSignal | None:
        """
        Convert one STG RelationshipRiskSignal into the compact
        FCP relationship-signal model.

        The FCP intentionally exposes only contextual graph
        information. It does not convert this signal into direct
        entity-security evidence.
        """

        signal_data = (
            TrustService._model_to_dict(
                raw_signal
            )
        )

        if not signal_data:
            return None

        # STG currently exposes separate risk and trust
        # contributions. The compact FCP contribution keeps a
        # signed directional value:
        #
        #   positive -> risk contribution
        #   negative -> trust contribution
        #
        # The original risk/trust scores remain available in
        # the detailed STG API response.
        # Preserve STG's original risk and trust contributions
        # independently.
        #
        # These values represent different contextual
        # directions and must not be collapsed into an
        # artificial signed aggregate in the FCP.
        risk_contribution = (
            TrustService._safe_float(
                signal_data.get(
                    "risk_contribution",
                    0.0,
                )
            )
        )

        trust_contribution = (
            TrustService._safe_float(
                signal_data.get(
                    "trust_contribution",
                    0.0,
                )
            )
        )

        return FCPRelationshipSignal(
            relationship_type=(
                TrustService._enum_value(
                    signal_data.get(
                        "relationship",
                        "UNKNOWN",
                    ),
                    "UNKNOWN",
                )
            ),

            neighbour_node_id=str(
                signal_data.get(
                    "neighbour_node_id",
                    "",
                )
                or ""
            ),

            neighbour_type=(
                TrustService._enum_value(
                    signal_data.get(
                        "neighbour_node_type",
                        "Unknown",
                    ),
                    "Unknown",
                )
            ),

            neighbour_value=str(
                signal_data.get(
                    "neighbour_value",
                    "",
                )
                or ""
            ),

            neighbour_classification=(
                TrustService._enum_value(
                    signal_data.get(
                        "neighbour_classification",
                        "Unknown",
                    ),
                    "Unknown",
                )
            ),

            neighbour_risk_score=(
                TrustService._optional_float(
                    signal_data.get(
                        "neighbour_risk_score"
                    )
                )
            ),

            risk_contribution=round(
                risk_contribution,
                4,
            ),

            trust_contribution=round(
                trust_contribution,
                4,
            ),

            confidence=(
                TrustService._safe_float(
                    signal_data.get(
                        "confidence",
                        0.0,
                    )
                )
            ),

            evidence_ids=(
                TrustService._unique_strings(
                    signal_data.get(
                        "evidence_ids"
                    )
                )
            ),

            ledger_ids=(
                TrustService._unique_strings(
                    signal_data.get(
                        "ledger_ids"
                    )
                )
            ),

            reason=str(
                signal_data.get(
                    "explanation",
                    "",
                )
                or ""
            ),
        )

    @staticmethod
    def _model_to_dict(
        value: Any,
    ) -> dict[str, Any]:
        """
        Convert a Pydantic model or dictionary into a plain
        dictionary for defensive STG/FCP context handling.
        """

        if value is None:
            return {}

        if isinstance(
            value,
            dict,
        ):
            return value

        if hasattr(
            value,
            "model_dump",
        ):
            try:
                return value.model_dump(
                    mode="python"
                )
            except TypeError:
                return value.model_dump()

        if hasattr(
            value,
            "dict",
        ):
            return value.dict()

        return {}

    @staticmethod
    def _enum_value(
        value: Any,
        default: str,
    ) -> str:
        """
        Convert enum-backed or plain values into their stable
        string representation.
        """

        if value is None:
            return default

        value = getattr(
            value,
            "value",
            value,
        )

        normalized = str(
            value
        ).strip()

        return (
            normalized
            or default
        )

    # ========================================================
    # Final Recommendation
    # ========================================================

    @staticmethod
    def _get_final_recommendation(
        risk_level: str,
        verified_sender: bool,
        verification_status: str,
        stg_context: (
            SecuritiesTrustGraphContext
            | None
        ) = None,
        analysis_available: bool = True,
        trusted_hosting_platform: bool = False,
        hosting_provider: str | None = None,
    ) -> str:
        """
        Generate the final user-facing recommendation using:

        - communication-level security risk
        - AVE sender-verification state
        - historical STG entity context

        Security policy
        ---------------
        1. Sender authenticity never overrides a high-risk
           communication decision.

        2. Trusted STG history never lowers communication
           caution.

        3. High-risk STG history may strengthen contextual
           caution because it represents entity-specific
           historical security evidence.

        4. STG never authenticates the sender.
        """

        normalized_risk = (
            str(
                risk_level
                or ""
            )
            .strip()
            .lower()
        )

        stg_high_risk = (
            TrustService._stg_indicates_high_risk(
                stg_context
            )
        )

        # ----------------------------------------------------
        # Analysis Unavailable
        # ----------------------------------------------------

        if not analysis_available:

            if stg_high_risk:

                if verified_sender:

                    return (
                        "The supplied sender metadata was verified, "
                        "but a reliable communication-level security "
                        "assessment could not be produced because "
                        "insufficient analysable content or security "
                        "evidence was available. The Securities Trust "
                        "Graph also contains historical entity-specific "
                        "risk evidence. Do not treat sender verification "
                        "alone as confirmation that the communication "
                        "is safe, and independently confirm sensitive "
                        "financial instructions before acting."
                    )

                return (
                    "A reliable communication-level security "
                    "assessment could not be produced because "
                    "insufficient analysable content or security "
                    "evidence was available. The Securities Trust "
                    "Graph also contains historical entity-specific "
                    "risk evidence. Independently verify the sender "
                    "and the communication before taking sensitive "
                    "financial action."
                )

            if verified_sender:

                return (
                    "The supplied sender metadata was verified, but "
                    "a reliable communication-level security "
                    "assessment could not be produced because "
                    "insufficient analysable content or security "
                    "evidence was available. Do not treat sender "
                    "verification alone as confirmation that the "
                    "communication is safe."
                )

            return (
                "A reliable communication-level security assessment "
                "could not be produced because insufficient analysable "
                "content or security evidence was available. "
                "Independently verify the sender and communication "
                "before taking sensitive financial action."
            )

        # ----------------------------------------------------
        # High Risk
        # ----------------------------------------------------

        if normalized_risk == "high":

            if stg_high_risk:

                if verified_sender:

                    return (
                        "The supplied sender metadata was "
                        "verified, but the communication contains "
                        "strong security-risk indicators and the "
                        "Securities Trust Graph also contains "
                        "historical entity-specific risk evidence. "
                        "Do not transfer money, scan QR codes, "
                        "share credentials or take sensitive "
                        "financial action based solely on this "
                        "communication."
                    )

                return (
                    "Do not transfer money, scan QR codes or "
                    "share credentials. The communication "
                    "contains strong security-risk indicators, "
                    "the sender has not been independently "
                    "verified, and the Securities Trust Graph "
                    "also contains historical entity-specific "
                    "risk evidence."
                )

            if verified_sender:

                return (
                    "The supplied sender metadata was verified, "
                    "but the communication contains strong "
                    "security-risk indicators. Do not transfer "
                    "money, scan QR codes, share credentials or "
                    "take sensitive financial action based solely "
                    "on this communication."
                )

            if trusted_hosting_platform:

                provider = hosting_provider or "hosting"

                return (
                    f"The communication is hosted on the official {provider} platform, "
                    "which supports user-generated content. "
                    "Although the hosting infrastructure is trusted, "
                    "the detected content contains strong phishing indicators. "
                    "Do not submit credentials, transfer money or trust the page "
                    "without independently verifying the sender."
                )
            return (
                "Do not transfer money, scan QR codes or share "
                "credentials. The communication contains strong "
                "security-risk indicators and the sender has not "
                "been independently verified."
            )

        # ----------------------------------------------------
        # Medium Risk
        # ----------------------------------------------------

        if normalized_risk == "medium":

            if stg_high_risk:

                if verified_sender:

                    return (
                        "The supplied sender metadata was "
                        "verified, but the communication contains "
                        "moderate security-risk indicators and "
                        "the Securities Trust Graph contains "
                        "historical entity-specific risk evidence. "
                        "Review the request carefully and "
                        "independently confirm sensitive financial "
                        "instructions before acting."
                    )

                return (
                    "Verify the sender independently before "
                    "taking financial action. The communication "
                    "contains moderate security-risk indicators "
                    "and the Securities Trust Graph also contains "
                    "historical entity-specific risk evidence."
                )

            if verified_sender:

                return (
                    "The supplied sender metadata was verified, "
                    "but the communication contains moderate "
                    "security-risk indicators. Review the request "
                    "carefully before taking financial action."
                )

            if trusted_hosting_platform:

                provider = hosting_provider or "hosting"

                return (
                    f"The communication is hosted on the official {provider} platform "
                    "which supports user-generated content. "
                    "Review the hosted content carefully and verify the sender "
                    "before taking financial action."
                )
            return (
                "Verify the sender independently and review the "
                "communication carefully before taking any "
                "financial action."
            )

        # ----------------------------------------------------
        # Low Risk
        # ----------------------------------------------------

        if normalized_risk == "low":

            # Historical high-risk entity evidence is allowed
            # to increase contextual caution even when the
            # current communication models report low risk.
            #
            # The numeric communication risk itself is not
            # modified.
            if stg_high_risk:

                if verified_sender:

                    return (
                        "The current communication has a low "
                        "detected risk and the supplied sender "
                        "metadata was verified, but the "
                        "Securities Trust Graph contains "
                        "historical entity-specific risk evidence. "
                        "Independently confirm sensitive financial "
                        "instructions before acting."
                    )

                return (
                    "The current communication has a low "
                    "detected risk, but the Securities Trust "
                    "Graph contains historical entity-specific "
                    "risk evidence and the sender is not "
                    "independently verified. Verify the sender "
                    "before taking sensitive financial action."
                )

            if verified_sender:

                return (
                    "The communication has a low detected risk "
                    "and the supplied sender metadata was "
                    "verified. Continue with normal financial "
                    "security precautions."
                )

            if (
                verification_status
                == "Insufficient Data"
            ):
                if trusted_hosting_platform:

                    provider = hosting_provider or "hosting"

                    return (
                        f"The communication is hosted on the official {provider} platform, "
                        "which supports user-generated content. "
                        "Infrastructure authenticity has been verified, "
                        "but the hosted content may have been created by any user. "
                        "Verify the sender before submitting personal information, "
                        "opening shared documents or completing forms."
                    )
                return (
                    "This communication shows low detected risk, "
                    "but available evidence was insufficient to "
                    "independently establish its authenticity. "
                    "Continue with normal caution."
                )

            return (
                "The communication has a low detected risk, but "
                "the sender is not verified. Continue with normal "
                "caution and independently confirm sensitive "
                "financial requests."
            )

        # ----------------------------------------------------
        # Defensive Fallback
        # ----------------------------------------------------

        if stg_high_risk:

            if verified_sender:

                return (
                    "The supplied sender metadata was verified, "
                    "but the Securities Trust Graph contains "
                    "historical entity-specific risk evidence. "
                    "Review the communication carefully before "
                    "taking sensitive financial action."
                )

            return (
                "The Securities Trust Graph contains historical "
                "entity-specific risk evidence. Exercise caution "
                "and independently verify the sender before "
                "taking sensitive financial action."
            )

        if verified_sender:

            return (
                "The supplied sender metadata was verified. "
                "Review the communication and exercise normal "
                "financial security precautions."
            )

        return (
            "Exercise caution and independently verify the "
            "sender before taking sensitive financial action."
        )

    # ========================================================
    # STG Risk Interpretation
    # ========================================================

    @staticmethod
    def _stg_indicates_high_risk(
        stg_context: (
            SecuritiesTrustGraphContext
            | None
        ),
    ) -> bool:
        """
        Determine whether STG contains meaningful historical
        entity-specific risk evidence.

        This helper affects only recommendation wording.

        It does NOT alter:
        - risk score
        - trust score
        - sender verification
        - model output
        """

        if stg_context is None:
            return False

        if not stg_context.available:
            return False

        if not stg_context.reputation_available:
            return False

        classification = (
            str(
                stg_context.classification
                or ""
            )
            .strip()
            .lower()
        )

        if classification in {
            "high risk",
            "malicious",
            "phishing",
            "suspicious",
        }:
            return True

        graph_risk_score = (
            stg_context.graph_risk_score
        )

        if (
            graph_risk_score is not None
            and graph_risk_score >= 70.0
        ):
            return True

        return False

    # ========================================================
    # Optional Metadata Normalization
    # ========================================================

    @staticmethod
    def _normalize_optional(
        value: str | None,
    ) -> str | None:
        """
        Normalize optional sender/channel metadata.

        Empty strings and whitespace-only strings become None.
        """

        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            value = str(
                value
            )

        value = value.strip()

        if not value:
            return None

        return value

    # ========================================================
    # Defensive Conversion Helpers
    # ========================================================

    @staticmethod
    def _safe_float(
        value: Any,
    ) -> float:
        """
        Convert a value to float without allowing malformed
        optional STG context to break FCP generation.
        """

        try:
            return float(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0.0

    @staticmethod
    def _optional_float(
        value: Any,
    ) -> float | None:
        """
        Convert an optional value to float.
        """

        if value is None:
            return None

        try:
            return float(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int:
        """
        Convert a value to a non-negative integer.
        """

        try:
            converted = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ):
            return 0

        return max(
            0,
            converted,
        )

    @staticmethod
    def _unique_strings(
        values: Any,
    ) -> list[str]:
        """
        Normalize an optional collection into a de-duplicated
        list of non-empty strings.
        """

        if values is None:
            return []

        if isinstance(
            values,
            str,
        ):
            values = [
                values
            ]

        try:
            iterator = iter(
                values
            )
        except TypeError:
            iterator = iter(
                [
                    values
                ]
            )

        result: list[str] = []

        for value in iterator:

            if value is None:
                continue

            normalized = str(
                value
            ).strip()

            if (
                normalized
                and normalized not in result
            ):
                result.append(
                    normalized
                )

        return result


# ============================================================
# Singleton
# ============================================================

trust_service = TrustService()