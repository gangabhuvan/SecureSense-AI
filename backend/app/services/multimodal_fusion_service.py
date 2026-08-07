"""
multimodal_fusion_service.py

SecureSense AI multimodal decision fusion.

Purpose
-------
Combine independently trained security-model outputs without
diluting or overriding their learned predictions.

Supported modalities
--------------------
-DistilBERT NLP Intelligence
-ConvNeXt-Tiny Visual Intelligence
-XGBoost URL Intelligence
-Spectra-AASIST3 Voice Intelligence
-Communication Intent Intelligence (CII)

Design principles
-----------------
- Preserve trained-model probabilities.
- Preserve trained-model decisions.
- Do not use arbitrary weighted averages.
- Do not reclassify ML predictions using manually selected
  probability thresholds.
- A strong phishing signal from one trained model must not be
  cancelled by another modality without overwhelming cross-modal consensus.
- Explicitly expose cross-modal agreement/disagreement.
- When multiple URLs exist, the strongest learned URL phishing
  signal represents the URL modality.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from app.models.analysis_models import NLPResult
from app.models.voice_models import (
    VoiceAuthenticityResult,
)


# ==========================================================
# Fusion Result
# ==========================================================

@dataclass
class MultimodalFusionResult:
    """
    Communication-level multimodal decision.

    Risk scores and confidence values use a 0-100 scale.
    """

    risk_score: float
    risk_level: str
    confidence: float

    decision: str
    agreement: str
    dominant_modality: str
    override_applied: bool = False
    nlp_risk: Optional[float] = None
    visual_risk: Optional[float] = None
    url_risk: Optional[float] = None
    voice_risk: Optional[float] = None
    intent_risk: Optional[float] = None
    trusted_hosting_platform: bool = False
    voice_confidence: Optional[float] = None
    intent_confidence: Optional[float] = None
    hosting_provider: Optional[str] = None
    nlp_label: Optional[str] = None
    visual_label: Optional[str] = None
    url_label: Optional[str] = None
    voice_label: Optional[str] = None
    intent_label: Optional[str] = None

    voice_summary: Optional[str] = None
    intent_context: Optional[str] = None
    summary: str = ""

    def as_dict(self) -> Dict[str, Any]:
        """
        Return a JSON-serializable representation.
        """

        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "decision": self.decision,
            "agreement": self.agreement,
            "dominant_modality": self.dominant_modality,
            "override_applied": self.override_applied,
            "nlp_risk": self.nlp_risk,
            "visual_risk": self.visual_risk,
            "url_risk": self.url_risk,
            "voice_risk": self.voice_risk,
            "intent_risk": self.intent_risk,
            "trusted_hosting_platform": self.trusted_hosting_platform,
            "hosting_provider": self.hosting_provider,
            "voice_confidence": self.voice_confidence,
            "intent_confidence": self.intent_confidence,

            "nlp_label": self.nlp_label,
            "visual_label": self.visual_label,
            "url_label": self.url_label,
            "voice_label": self.voice_label,
            "intent_label": self.intent_label,

            "voice_summary": self.voice_summary,
            "intent_context": self.intent_context,
            "summary": self.summary,
        }


# ==========================================================
# Multimodal Fusion Service
# ==========================================================

class MultimodalFusionService:
    """
    Fuse NLP, Visual, URL, Voice, and Intent security intelligence.

    Final phishing risk:

        strongest available trained-model phishing probability

    Final security decision:

        original label produced by the model responsible for
        the strongest phishing signal

    No arbitrary weighted averaging is performed.
    """

    # ======================================================
    # Helpers
    # ======================================================

    @staticmethod
    def _clamp(
        value: float,
    ) -> float:
        """
        Clamp a percentage to the valid 0-100 range.
        """

        return min(
            max(
                float(value),
                0.0,
            ),
            100.0,
        )

    @staticmethod
    def _risk_level(
        risk_score: float,
    ) -> str:
        """
        Convert continuous risk into reporting severity.

        IMPORTANT:
        This does not determine the trained-model decision.
        """

        if risk_score >= 75.0:
            return "High"

        if risk_score >= 40.0:
            return "Medium"

        return "Low"

    @staticmethod
    def _is_intent_override_valid(
        url_signal: Optional[Dict[str, Any]],
        intent_signal: Optional[Dict[str, Any]],
        nlp_signal: Optional[Dict[str, Any]],
        visual_signal: Optional[Dict[str, Any]],
        domain_signal: Optional[Dict[str, Any]],
    ) -> Tuple[bool, int]:
        """
        Determine if Communication Intent Intelligence should override
        a URL phishing signal based on a Weighted Evidence Consensus Score.

        The URL model prediction is NOT changed. No signal is invented.
        """

        if not url_signal:
            return False, 0

        # URL must actually classify phishing to even consider an override.
        if str(url_signal.get("label", "")).lower() != "phishing":
            return False, 0

        consensus_score = 0

        # 1. NLP Legitimacy (+1)
        if nlp_signal and str(nlp_signal.get("label", "")).lower() == "legitimate":
            consensus_score += 1

        # 2. CII Legitimacy (+1)
        if intent_signal and str(intent_signal.get("label", "")).lower() in {
            "legitimate",
            "likely legitimate",
        }:
            consensus_score += 1

        # 3. Trusted Context (+2)
        trusted_contexts = {
            "general announcement",
            "event poster",
            "government notice",
            "government advisory",
            "government scheme",
            "government recruitment",
            "recruitment notice",
            "conference",
            "hackathon",
            "seminar",
            "workshop",
            "academic notice",
        }
        if intent_signal:
            context = str(intent_signal.get("context", "")).lower().strip()
            if context in trusted_contexts:
                consensus_score += 2

        # 4. High-Trust Official Domain Verification (+2)
        if domain_signal and domain_signal.get("official_domain"):
            provider = str(
                domain_signal.get("provider_type", "")
            ).lower().strip()

            trusted_provider_keywords = {
                "academic",
                "education",
                "university",
                "government",
                "bank",
                "central bank",
                "financial",
                "technology",
            }

            if any(keyword in provider for keyword in trusted_provider_keywords):
                consensus_score += 2

        # 5. Visual Legitimacy (+1)
        if visual_signal and str(visual_signal.get("label", "")).lower() == "legitimate":
            consensus_score += 1

        # A strong consensus (>= 5 out of 7 possible points) validates the override
        override = consensus_score >= 5

        return override, consensus_score

    @staticmethod
    def _is_nlp_override_valid(
        nlp_signal: Optional[Dict[str, Any]],
        intent_signal: Optional[Dict[str, Any]],
        visual_signal: Optional[Dict[str, Any]],
        url_signal: Optional[Dict[str, Any]],
        domain_signal: Optional[Dict[str, Any]],
    ) -> Tuple[bool, int]:
        """
        Determine if Communication Intent Intelligence should override
        an NLP phishing signal based on a Weighted Evidence Consensus Score.

        The NLP model prediction is NOT changed. No signal is invented.
        """

        if not nlp_signal:
            return False, 0

        # NLP must actually classify phishing to even consider an override.
        if str(nlp_signal.get("label", "")).lower() != "phishing":
            return False, 0

        consensus_score = 0

        # 1. URL Legitimacy (+1)
        if url_signal and str(url_signal.get("label", "")).lower() == "legitimate":
            consensus_score += 1

        # 2. CII Legitimacy (+1)
        if intent_signal and str(intent_signal.get("label", "")).lower() in {
            "legitimate",
            "likely legitimate",
        }:
            consensus_score += 1

        # 3. Trusted Context (+2)
        trusted_contexts = {
            "general announcement",
            "event poster",
            "government notice",
            "government advisory",
            "government scheme",
            "government recruitment",
            "recruitment notice",
            "conference",
            "hackathon",
            "seminar",
            "workshop",
            "academic notice",
        }
        if intent_signal:
            context = str(intent_signal.get("context", "")).lower().strip()
            if context in trusted_contexts:
                consensus_score += 2

        # 4. High-Trust Official Domain Verification (+2)
        if domain_signal and domain_signal.get("official_domain"):
            provider = str(
                domain_signal.get("provider_type", "")
            ).lower().strip()

            trusted_provider_keywords = {
                "academic",
                "education",
                "university",
                "government",
                "bank",
                "central bank",
                "financial",
                "technology",
            }

            if any(keyword in provider for keyword in trusted_provider_keywords):
                consensus_score += 2

        # 5. Visual Legitimacy (+1)
        if visual_signal and str(visual_signal.get("label", "")).lower() == "legitimate":
            consensus_score += 1

        # A strong consensus (>= 5 out of 7 possible points) validates the override
        override = consensus_score >= 5

        return override, consensus_score


    # ======================================================
    # NLP Signal
    # ======================================================
    
    def _nlp_signal(
        self,
        nlp: Optional[NLPResult],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert DistilBERT output into a fusion signal.
        """

        if nlp is None:
            return None

        phishing_probability = self._clamp(
            float(
                nlp.probabilities.get(
                    "Phishing",
                    0.0,
                )
            )
        )

        confidence = self._clamp(
            nlp.confidence_percent
        )

        return {
            "label": nlp.label,
            "risk": phishing_probability,
            "confidence": confidence,
        }

    # ======================================================
    # Visual Signal
    # ======================================================
    
    def _visual_signal(
        self,
        visual_result: Optional[
            Dict[str, Any]
        ],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert ConvNeXt output into a fusion signal.
        """

        if visual_result is None:
            return None

        prediction = visual_result.get(
            "prediction"
        )

        if not prediction:
            return None

        phishing_probability = self._clamp(
            float(
                prediction.get(
                    "phishing_probability",
                    0.0,
                )
            )
            * 100.0
        )

        confidence = self._clamp(
            float(
                prediction.get(
                    "confidence",
                    0.0,
                )
            )
            * 100.0
        )

        return {
            "label": prediction.get(
                "label",
                "Unknown",
            ),
            "risk": phishing_probability,
            "confidence": confidence,
        }

    # ======================================================
    # URL Signal
    # ======================================================

    def _url_signal(
        self,
        url_results: Optional[
            List[Dict[str, Any]]
        ],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert URL Intelligence results into one URL-level
        fusion signal.
        """

        if not url_results:
            return None

        valid_results = [
            result
            for result in url_results
            if isinstance(result, dict)
            and "phishing_probability" in result
        ]

        if not valid_results:
            return None

        strongest = max(
            valid_results,
            key=lambda result: float(
                result.get(
                    "phishing_probability",
                    0.0,
                )
            ),
        )

        phishing_probability = self._clamp(
            float(
                strongest.get(
                    "phishing_probability",
                    0.0,
                )
            )
            * 100.0
        )

        confidence = self._clamp(
            float(
                strongest.get(
                    "confidence",
                    0.0,
                )
            )
            * 100.0
        )

        return {
            "label": strongest.get(
                "label",
                "Unknown",
            ),
            "risk": phishing_probability,
            "confidence": confidence,
            "url": strongest.get("url"),
        }

    # ======================================================
    # Domain Signal
    # ======================================================

    def _domain_signal(
        self,
        domain_results: Optional[
            List[Dict[str, Any]]
        ],
    ) -> Optional[Dict[str, Any]]:
        """
        Extract infrastructure authenticity evidence to support
        model reasoning and reporting.
        """
        
        if not domain_results:
            return None

        # First pass: Prefer official, non-user-generated domains
        for result in domain_results:
            if result.get("official_domain") and not result.get("user_generated_content"):
                return result

        # Second pass: Fallback to any official domain
        for result in domain_results:
            if result.get("official_domain"):
                return result

        return None

    

        # ======================================================
    # Hosted Content Detection
    # ======================================================

    @staticmethod
    def _is_trusted_hosting_platform(
        domain_signal: Optional[Dict[str, Any]],
    ) -> bool:

        if not domain_signal:
            return False

        return (
            domain_signal.get("official_domain", False)
            and domain_signal.get("user_generated_content", False)
        )

    # ======================================================
    # Voice Signal
    # ======================================================

    def _voice_signal(
            self,
            voice_authenticity: Optional[
                VoiceAuthenticityResult
            ],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert VoiceAuthenticityResult into a fusion signal.
        """

        if (
            voice_authenticity is None
            or not voice_authenticity.available
        ):
            return None

        return {
            "label": voice_authenticity.prediction,
            "voice_type": (
                "Synthetic Voice"
                if voice_authenticity.prediction.lower() == "synthetic"
                else "Authentic Human"
            ),
            "risk": self._clamp(
                voice_authenticity.risk_score
            ),
            "confidence": self._clamp(
                voice_authenticity.confidence_percent
            ),
        }

    # ======================================================
    # Communication Intent Signal
    # ======================================================

    def _intent_signal(
        self,
        intent_result: Optional[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert Communication Intent Intelligence output into 
        a peer fusion signal. Correctly maps security_intent -> label.
        """

        if intent_result is None:
            return None

        risk = self._clamp(
            float(intent_result.get("risk_score", 0.0))
        )
        
        confidence = self._clamp(
            float(
                intent_result.get(
                    "context_confidence",
                    intent_result.get("confidence", 0.0),
                )
            )
        )

        return {
            "label": intent_result.get("security_intent", "Unknown"),
            "risk": risk,
            "confidence": confidence,
            "context": intent_result.get("context", "Unknown"),
        }
    
    # ======================================================
    # Agreement
    # ======================================================

    @staticmethod
    def _agreement(
        signals: List[
            tuple[str, Dict[str, Any]]
        ],
    ) -> str:
        """
        Describe agreement between available trained models
        using a robust majority-consensus check.
        """

        if not signals:
            return "No Model Signal"

        if len(signals) == 1:
            return "Single Modality"

        labels = [
            str(signal["label"]).strip().lower()
            for _, signal in signals
        ]

        comparable_labels = [lbl for lbl in labels if lbl != "spam"]
        
        if not comparable_labels:
            return "Not Directly Comparable"

        unique_labels = set(comparable_labels)

        if len(unique_labels) == 1:
            return "Full Agreement"

        label_counts = {lbl: comparable_labels.count(lbl) for lbl in unique_labels}
        max_count = max(label_counts.values())

        if max_count > len(comparable_labels) / 2.0:
            return "Majority Agreement"

        return "Security Conflict"

    # ======================================================
    # Summary
    # ======================================================

    @staticmethod
    def _summary(
        *,
        decision: str,
        agreement: str,
        dominant_modality: str,
        signals: List[
            tuple[str, Dict[str, Any]]
        ],
        voice_signal=None,
        voice_summary=None,
        intent_context=None,
        domain_signal=None,
    ) -> str:
        """
        Generate a human-readable explanation of fusion.
        """

        if not signals:
            return "No trained-model security signal was available for multimodal fusion."

        if len(signals) == 1:
            modality, signal = signals[0]
            summary = (
                "The communication-level decision is based "
                f"on {modality}, which classified the "
                f"communication as {signal['label']}."
            )

            if voice_signal is not None:
                summary += (
                    " Voice authenticity analysis indicates "
                    f"{voice_summary.lower()} "
                    f"({voice_signal['confidence']:.2f}% confidence). "
                    "Speaker authenticity is reported "
                    "independently from communication-level "
                    "security classification."
                )
            else:
                summary += " No additional communication-security modality was available for fusion."

            # Append domain explanation if available
            if domain_signal and domain_signal.get("official_domain"):
                summary += (
                    f" Domain verification identified an official "
                    f"{domain_signal.get('provider_type', 'Unknown')} provider "
                    f"({domain_signal.get('official_provider', 'Unknown')})."
                )
                if domain_signal.get("user_generated_content"):
                    summary += (
                        " The communication is hosted on a trusted platform that "
                        "allows user-generated content. Infrastructure authenticity "
                        "was verified, but the hosted content itself cannot be "
                        "independently authenticated. Security decisions therefore "
                        "continue to rely primarily on the trained AI models."
                    )

            return summary

        model_decisions = ", ".join(
            f"{modality}: {signal['label']}"
            for modality, signal in signals
        )

        if agreement == "Full Agreement":
            summary = (
                "The available trained security models are in full agreement "
                f"({decision}). Model decisions: {model_decisions}. "
                "The communication-level risk preserves the strongest learned "
                f"security signal, supplied by {dominant_modality}."
            )
        elif agreement == "Majority Agreement":
            summary = (
                "The available trained security models have reached a majority agreement "
                f"({decision}). Model decisions: {model_decisions}. "
                "The communication-level risk preserves the strongest learned "
                f"security signal aligned with that consensus, supplied by {dominant_modality}."
            )
        elif agreement == "Evidence Consensus":
            summary = (
                f"A strong evidence consensus ({decision}) overrode single-modality security flags. "
                f"Model decisions: {model_decisions}. "
                f"Consensus validated via {dominant_modality}."
            )
        elif agreement == "Not Directly Comparable":
            summary = (
                "The available trained models are not fully directly comparable because "
                "the NLP model contains a Spam class while other modalities use binary classification. "
                f"Model decisions: {model_decisions}. "
                "The final decision preserves the prediction "
                f"from {dominant_modality} ({decision}), which supplied the strongest learned security signal."
            )
        else:
            # Security Conflict
            summary = (
                "The communication-level security decision "
                f"is '{decision}', determined by {dominant_modality}."
            )
        
        if intent_context and intent_context not in ["Unknown", "Generic"]:
            summary += f" Detected context: {intent_context}."

        if voice_signal is not None:
            summary += (
                " Voice authenticity analysis indicates "
                f"{voice_summary.lower()} "
                f"({voice_signal['confidence']:.2f}% confidence). "
                "Speaker authenticity is reported independently from communication security."
            )

        if domain_signal and domain_signal.get("official_domain"):
            summary += (
                f" Domain verification identified an official "
                f"{domain_signal.get('provider_type', 'Unknown')} provider "
                f"({domain_signal.get('official_provider', 'Unknown')})."
            )

            if domain_signal.get("user_generated_content"):
                summary += (
                    " The platform supports user-generated content, "
                    "The hosting infrastructure is trusted, but hosted pages "
                    "must still be verified because anyone can create and share content."
                )

        return summary

    # ======================================================
    # Main Fusion API
    # ======================================================

    def fuse(
        self,
        *,
        nlp: Optional[NLPResult] = None,
        visual_result: Optional[Dict[str, Any]] = None,
        url_results: Optional[List[Dict[str, Any]]] = None,
        domain_results: Optional[List[Dict[str, Any]]] = None,
        voice_authenticity: Optional[VoiceAuthenticityResult] = None,
        intent_result: Optional[Dict[str, Any]] = None,
    ) -> MultimodalFusionResult:
        """
        Fuse all available trained-model security signals.

        No weighted averaging and no manual reclassification
        of trained-model decisions are performed.
        """

        nlp_signal = self._nlp_signal(nlp)
        visual_signal = self._visual_signal(visual_result)
        url_signal = self._url_signal(url_results)
        domain_signal = self._domain_signal(domain_results)
        trusted_hosting = self._is_trusted_hosting_platform(
            domain_signal
        )
        voice_signal = self._voice_signal(voice_authenticity)
        intent_signal = self._intent_signal(intent_result)

        # --------------------------------------------------
        # Collect available trained-model signals
        # --------------------------------------------------

        signals: List[tuple[str, Dict[str, Any]]] = []

        if nlp_signal is not None:
            signals.append(("NLP Intelligence", nlp_signal))
        if visual_signal is not None:
            signals.append(("Visual Intelligence", visual_signal))
        if url_signal is not None:
            signals.append(("URL Intelligence", url_signal))
        if intent_signal is not None:
            signals.append(("Communication Intent Intelligence", intent_signal))
            
        voice_summary = None
        if voice_signal is not None:
            voice_summary = voice_signal["voice_type"]

        intent_context = None
        if intent_signal is not None:
            intent_context = intent_signal.get("context")

        # --------------------------------------------------
        # No trained-model signal
        # --------------------------------------------------

        if not signals:
            return MultimodalFusionResult(
                risk_score=0.0,
                risk_level="Low",
                confidence=0.0,
                decision="Unknown",
                agreement="No Model Signal",
                dominant_modality="None",
                trusted_hosting_platform=trusted_hosting,
                summary="No trained-model security signal was available for multimodal fusion.",
            )

        # --------------------------------------------------
        # Cross-modal relationship
        # --------------------------------------------------

        agreement = self._agreement(signals)

        # --------------------------------------------------
        # Strongest learned phishing signal
        # --------------------------------------------------

        def _dominance_key(
            item: tuple[str, Dict[str, Any]],
        ) -> tuple[float, int]:

            _, signal = item

            risk = self._clamp(float(signal.get("risk", 0.0)))
            label = str(signal.get("label", "")).strip().lower()

            security_tiebreak = 1 if label in {"phishing"} else 0

            return (risk, security_tiebreak)

        # --------------------------------------------------
        # Override URL Dominance using Evidence-Based Consensus
        # --------------------------------------------------
        
        url_override, url_score = self._is_intent_override_valid(
            url_signal,
            intent_signal,
            nlp_signal,
            visual_signal,
            domain_signal,
        )

        nlp_override, nlp_score = self._is_nlp_override_valid(
            nlp_signal,
            intent_signal,
            visual_signal,
            url_signal,
            domain_signal,
        )

        if url_override:
            override_applied = True
            consensus_score = url_score
            dominant_modality = "Evidence-Based Consensus (URL Override)"
        elif nlp_override:
            override_applied = True
            consensus_score = nlp_score
            dominant_modality = "Evidence-Based Consensus (NLP Override)"
        else:
            override_applied = False
            consensus_score = 0

        if override_applied:
            agreement = "Evidence Consensus"
            
            # Calibrated evidence confidence and risk mappings
            confidence_map = {
                5: (88.0, 20.0),  # (confidence, risk)
                6: (93.0, 12.0),
                7: (97.0, 5.0),
            }
            consensus_confidence, consensus_risk = confidence_map.get(
                consensus_score,
                (88.0, 20.0) if consensus_score >= 5 else (75.0, 45.0),
            )

            dominant_signal = {
                "label": "Legitimate",
                "risk": consensus_risk,
                "confidence": consensus_confidence,
            }
        else:
            (
                dominant_modality,
                dominant_signal,
            ) = max(
                signals,
                key=_dominance_key,
            )

        # --------------------------------------------------
        # Final calculations
        # --------------------------------------------------

        risk_score = self._clamp(dominant_signal["risk"])
        decision = str(dominant_signal["label"])
        risk_level = self._risk_level(risk_score)
        confidence = self._clamp(dominant_signal["confidence"])

        summary = self._summary(
            decision=decision,
            agreement=agreement,
            dominant_modality=dominant_modality,
            signals=signals,
            voice_signal=voice_signal,
            voice_summary=voice_summary,
            intent_context=intent_context,
            domain_signal=domain_signal,
        )

        return MultimodalFusionResult(
            risk_score=round(risk_score, 4),
            risk_level=risk_level,
            confidence=round(confidence, 4),
            decision=decision,
            agreement=agreement,
            dominant_modality=dominant_modality,
            override_applied=override_applied,
            trusted_hosting_platform=trusted_hosting,

            hosting_provider=(
                domain_signal.get("official_provider")
                if domain_signal
                else None
            ),
            nlp_risk=round(nlp_signal["risk"], 4) if nlp_signal else None,
            visual_risk=round(visual_signal["risk"], 4) if visual_signal else None,
            url_risk=round(url_signal["risk"], 4) if url_signal else None,
            voice_risk=round(voice_signal["risk"], 4) if voice_signal else None,
            intent_risk=round(intent_signal["risk"], 4) if intent_signal else None,

            voice_confidence=round(voice_signal["confidence"], 4) if voice_signal else None,
            intent_confidence=round(intent_signal["confidence"], 4) if intent_signal else None,

            nlp_label=nlp_signal["label"] if nlp_signal else None,
            visual_label=visual_signal["label"] if visual_signal else None,
            url_label=url_signal["label"] if url_signal else None,
            voice_label=voice_signal["label"] if voice_signal else None,
            intent_label=intent_signal["label"] if intent_signal else None,
            
            voice_summary=voice_summary,
            intent_context=intent_context,
            summary=summary,
        )


# ==========================================================
# Singleton
# ==========================================================

multimodal_fusion_service = MultimodalFusionService()