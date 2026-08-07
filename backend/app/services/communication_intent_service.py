"""
communication_intent_service.py

Communication Intent Intelligence (CII)

Determines the semantic intent of a communication
independently from phishing classification.

Outputs:
- communication context
- context confidence
- security intent
- confidence
- risk score
- explainable evidence
"""

from __future__ import annotations

from functools import lru_cache
import re
from typing import List, Dict

from app.models.communication_intent_models import (
    CommunicationIntentResult,
    IntentEvidence,
)
import logging

logger = logging.getLogger(__name__)

class CommunicationIntentService:

    # ======================================================
    # Context Priority (1 is highest priority)
    # ======================================================
    
    CONTEXT_PRIORITY = {
        "Government Notice": 1,
        "Bank Advisory": 2,
        "Recruitment Notice": 3,
        "Student Circular": 4,
        "Event Poster": 5,
        "Invoice / Receipt": 6,
        "Certificate": 7,
        "General Announcement": 8,
        "Unknown": 9,
    }

    # ======================================================
    # Multi-Prototype Semantic Context Descriptions
    # ======================================================
    
    CONTEXT_DESCRIPTIONS: Dict[str, List[str]] = {
        "Government Notice": [
            "Official government advisory, regulatory alert, or public interest notification.",
            "Public awareness notice issued by regulatory bodies like RBI, SEBI, or central ministries.",
            "Official security advisory warning citizens or account holders about regulatory guidelines."
        ],
        "Bank Advisory": [
            "Official banking communication regarding account statements, cards, or digital transactions.",
            "Bank alert concerning net banking, debit credit cards, UPI, or financial security warnings.",
            "Notification regarding bank account status, transaction updates, or financial alerts."
        ],
        "Recruitment Notice": [
            "Job vacancy announcement inviting candidates for careers, interviews, or selections.",
            "Official hiring notice, recruitment drive, application deadline, or job offer letter.",
            "Career opportunity circular for hiring engineers, interns, developers, or staff."
        ],
        "Student Circular": [
            "Academic circular, university timetable, examination notice, or department schedule.",
            "Student notice regarding semester exams, internal assessments, or campus guidelines.",
            "Official administrative circular for students, faculty, or academic staff."
        ],
        "Event Poster": [
            "Announcement for a hackathon, workshop, technical conference, symposium, or seminar.",
            "Competition registration details, innovation challenge, venue, and project submission deadlines.",
            "Event poster highlighting cash prizes, awards, certificates, and guest speakers."
        ],
        "Invoice / Receipt": [
            "Billing invoice, tax receipt, payment acknowledgment, or transaction confirmation.",
            "Financial receipt for payment received, GST bill statement, or purchase order.",
            "Proof of payment, payment invoice, or commercial billing document."
        ],
        "Certificate": [
            "Certificate of participation, course completion, or academic excellence award.",
            "Official document proudly presented to a recipient for successfully completing a program.",
            "Recognition certificate awarded for outstanding performance or achievement."
        ],
        "General Announcement": [
            "General administrative news, community update, or public bulletin broadcast.",
            "General newsletter, organizational memo, or public information broadcast.",
            "Standard community circular, announcement bulletin, or general memo."
        ]
    }

    # ======================================================
    # Context Indicator Dictionaries (Keyword Refinement)
    # ======================================================

    EVENT_KEYWORDS = {
        "hackathon": 3, "conference": 3, "symposium": 3, "summit": 3,
        "workshop": 3, "bootcamp": 3, "seminar": 3, "webinar": 3,
        "competition": 3, "contest": 3, "innovation": 2, "theme": 2,
        "organizer": 2, "organized": 2, "chapter": 2, "deadline": 2,
        "registration": 2, "register": 2, "venue": 2, "prize": 2,
        "award": 2, "cash prize": 3, "developer": 2,
        "developers": 2,
        "developer groups": 4,
        "google developer groups": 5,
        "build with ai": 5,
        "gdg": 4,
        "participation": 2,
        "participants": 2,
        "certificate": 2,
        "certificates": 3,
        "speaker": 2,
        "speakers": 2,
        "session": 2,
        "sessions": 2,
        "community": 2,
        "campus": 2,
    }

    GOVERNMENT_KEYWORDS = {
        "reserve bank of india": 6, "rbi": 6, "sebi": 6, "income tax": 5,
        "government": 4, "ministry": 4, "public awareness": 5,
        "issued in public interest": 6, "official notice": 5,
        "official advisory": 5, "customers are advised": 4,
        "never share otp": 5, "never ask": 4,
    }

    BANK_KEYWORDS = {
        "bank": 4, "banking": 3, "account": 2, "statement": 4,
        "transaction": 3, "upi": 3, "imps": 3, "neft": 3,
        "rtgs": 3, "debit card": 3, "credit card": 3, "cvv": 3,
        "atm pin": 3, "internet banking": 3,
    }

    RECRUITMENT_KEYWORDS = {
        "job": 4, "career": 4, "recruitment": 5, "interview": 4,
        "apply": 3, "selection": 3, "offer letter": 5, "joining": 4,
        "shortlisted": 5, "shortlisted for": 5, "selected": 5, 
        "selection list": 5, "joining letter": 5, "appointment": 4, 
        "application": 3, "registration": 3, "registration fee": 4, 
        "exam": 2, "hall ticket": 2, "interview schedule": 4, 
        "document verification": 3,
    }

    ACADEMIC_KEYWORDS = {
        "university": 4, "department": 3, "semester": 3,
        "internal assessment": 4, "examination": 4, "timetable": 4,
        "student": 3, "faculty": 3, "circular": 3,
    }

    FINANCIAL_DOCUMENT_KEYWORDS = {
        "invoice": 5, "receipt": 5, "payment received": 4,
        "tax invoice": 5, "gst": 3, "bill": 3,
    }
    
    CERTIFICATE_KEYWORDS = {
        "certificate of participation": 5, "certificate of completion": 5,
        "certificate of excellence": 5, "awarded to": 5,
        "proudly presented to": 5, "successfully completed": 4,
        "certificate": 3,
    }

    # ======================================================
    # Intent Indicators (Weighted Phishing Signals)
    # ======================================================

    PHISHING_INTENT_KEYWORDS = {
        "verify your account": 3, "verify now": 3, "click here": 2,
        "click below": 2, "login": 2, "log in": 2,
        "confirm your identity": 3, "update your kyc": 3,
        "urgent": 2, "immediately": 2, "within 24 hours": 3,
        "account suspended": 4, "account blocked": 4,
        "your account has been frozen": 4, "reactivate your account": 3,
        "bank account verification": 4, "enter your password": 5,
        "enter your otp": 5, "share your otp": 5, "claim your refund": 4,
        "limited time": 2, "act now": 2, "reset password": 3,
        "verify payment": 3, "unlock account": 4, "confirm bank account": 4,
        "gift card": 4, "reward": 3, "lottery": 5, "investment": 2,
        "double your money": 5, "crypto": 3, "wallet verification": 4,
        "pay registration fee": 6, "registration fee": 5,
        "processing fee": 5, "application fee": 5, "exam fee": 5,
        "interview fee": 5, "security deposit": 5, "pay now": 4,
        "payment required": 4, "congratulations": 2, "shortlisted": 2,
        "offer expires today": 5, "limited seats": 3, "confirm seat": 3,
    }

    ORGANIZATIONS = {
        "acm": 5, "ieee": 5, "isro": 5,
        "google": 4, "microsoft": 4, "amazon": 4,
        "aws": 4, "oracle": 4, "ibm": 4,
        "meta": 4, "nvidia": 4,
        "iit": 4, "nit": 4, "gdg": 4,
        "rbi": 5, "sebi": 5, "sbi": 5, 
        "hdfc": 5, "icici": 5, "axis": 5,
        "uidai": 5, "npci": 5, "income tax": 5, 
        "epfo": 5, "passport seva": 5, "lic": 5, 
        "nta": 5, "ugc": 5, "ssc": 5, 
        "railway": 5, "ibps": 5, "drdo": 5,
    }

    EMAIL_PATTERN = re.compile(
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    )

    URL_PATTERN = re.compile(
        r"""
        (
            https?://[^\s]+
            |
            www\.[^\s]+
            |
            [A-Za-z0-9.-]+\.(com|org|net|edu|gov|in|io|ai|co|ac|uk|us|gle)(/[^\s]*)?
        )
        """,
        re.IGNORECASE | re.VERBOSE,
    )

    def __init__(self):
        self.context_keys = list(self.CONTEXT_DESCRIPTIONS.keys())
        self.semantic_available = False
        self.semantic_model = None
        self.util = None
        self.context_prototype_embeddings = {}

        try:
            from sentence_transformers import SentenceTransformer, util
            self.util = util
            self.semantic_model = SentenceTransformer("all-MiniLM-L6-v2", device="cpu")
            
            for ctx_name, prototype_sentences in self.CONTEXT_DESCRIPTIONS.items():
                self.context_prototype_embeddings[ctx_name] = self.semantic_model.encode(
                    prototype_sentences, 
                    convert_to_tensor=True
                )
            self.semantic_available = True
        except Exception as init_err:
            self.semantic_available = False

    @lru_cache(maxsize=512)
    def _cached_encode(self, text: str):
        return self.semantic_model.encode(text, convert_to_tensor=True)

    # ======================================================

    def analyse(
        self,
        text: str,
    ) -> CommunicationIntentResult:

        lower = text.lower()
        evidence: List[IntentEvidence] = []
        
        context_scores = {ctx: 0.0 for ctx in self.context_keys}
        semantic_sim_map = {ctx: 0.0 for ctx in self.context_keys}
        
        # ----------------------------------------------
        # 1. Semantic Context Layer (Multi-Prototype Averaging)
        # ----------------------------------------------
        
        if self.semantic_available and text.strip():
            try:
                text_embedding = self._cached_encode(text.strip())
                
                for context_name, prototype_tensor in self.context_prototype_embeddings.items():
                    cosine_scores = self.util.cos_sim(text_embedding, prototype_tensor)[0]
                    
                    top_k = min(2, cosine_scores.size(0))
                    max_sim = float(cosine_scores.topk(top_k).values.mean())
                    semantic_sim_map[context_name] = max_sim
                    
                    if max_sim > 0.1:
                        semantic_points = max_sim * 25.0 
                        context_scores[context_name] += semantic_points
                        
                        if max_sim > 0.35:
                            evidence.append(
                                IntentEvidence(
                                    feature=f"Semantic Match: {context_name}",
                                    score=round(semantic_points, 2),
                                    description=f"Top-2 prototype similarity match: {max_sim:.1%}"
                                )
                            )
            except Exception as sem_err:
                logger.warning(
                    "CII semantic inference skipped: %s",
                    sem_err,
                )

        # ----------------------------------------------
        # 2. Keyword Refinement Layer
        # ----------------------------------------------
        
        context_categories = {
            "Event Poster": self.EVENT_KEYWORDS,
            "Government Notice": self.GOVERNMENT_KEYWORDS,
            "Bank Advisory": self.BANK_KEYWORDS,
            "Recruitment Notice": self.RECRUITMENT_KEYWORDS,
            "Student Circular": self.ACADEMIC_KEYWORDS,
            "Invoice / Receipt": self.FINANCIAL_DOCUMENT_KEYWORDS,
            "Certificate": self.CERTIFICATE_KEYWORDS,
        }
        
        detected_keywords_per_context = {ctx: [] for ctx in context_categories}
        
        for context_name, keyword_dict in context_categories.items():
            for keyword, weight in keyword_dict.items():
                if keyword in lower:
                    context_scores[context_name] += weight
                    detected_keywords_per_context[context_name].append(keyword)
        
        # ----------------------------------------------
        # 3. Organizational Scoring & Context Boosting
        # ----------------------------------------------
        org_score = 0.0
        detected_orgs = []
        for organization, weight in self.ORGANIZATIONS.items():
            if organization in lower:
                org_score += weight
                detected_orgs.append(organization)
                
        if detected_orgs:
            evidence.append(
                IntentEvidence(
                    feature="Organization Recognition",
                    score=org_score,
                    description=f"Recognized entities: {', '.join(detected_orgs)}"
                )
            )
            
            context_scores["Event Poster"] += org_score * 0.8
            context_scores["Student Circular"] += org_score * 0.4
            context_scores["Recruitment Notice"] += org_score * 0.3
            
            if context_scores["Government Notice"] > 0:
                context_scores["Government Notice"] += org_score * 0.3

        # ----------------------------------------------
        # 4. Contact Info Detection
        # ----------------------------------------------
        if self.EMAIL_PATTERN.search(text):
            evidence.append(
                IntentEvidence(
                    feature="Contact Information",
                    score=2.0,
                    description="Email address detected in communication."
                )
            )
            context_scores["Recruitment Notice"] += 0.5
            context_scores["Invoice / Receipt"] += 0.5

        if self.URL_PATTERN.search(text):
            evidence.append(
                IntentEvidence(
                    feature="Web Link",
                    score=2.0,
                    description="Hyperlink/URL detected in communication."
                )
            )
            context_scores["Event Poster"] += 0.5

            context_scores["Recruitment Notice"] += 0.3

            if context_scores["Government Notice"] > 0:
                context_scores["Government Notice"] += 0.2
        # ----------------------------------------------
        # 5. Determine Primary Context & Confidence
        # ----------------------------------------------
        
        sorted_contexts = sorted(context_scores.items(), key=lambda x: x[1], reverse=True)
        best_ctx, best_score = sorted_contexts[0]
        
        for ctx, score in sorted_contexts[1:]:
            if (best_score - score) <= 1.5:
                if self.CONTEXT_PRIORITY.get(ctx, 99) < self.CONTEXT_PRIORITY.get(best_ctx, 99):
                    best_ctx = ctx
                    best_score = score 

        for ctx in self.context_keys:
            if ctx in detected_keywords_per_context and detected_keywords_per_context[ctx]:
                reasons = ", ".join(detected_keywords_per_context[ctx])
                evidence.append(
                    IntentEvidence(
                        feature=f"Keyword Match: {ctx}",
                        score=round(sum(context_categories[ctx][k] for k in detected_keywords_per_context[ctx]), 2),
                        description=f"Indicators detected: {reasons}"
                    )
                )

        best_semantic_sim = semantic_sim_map.get(best_ctx, 0.0)
        semantic_conf = max(0.0, best_semantic_sim * 100.0)
        
        kw_points = sum(context_categories.get(best_ctx, {}).get(k, 0) for k in detected_keywords_per_context.get(best_ctx, []))
        kw_conf = min(100.0, (kw_points / 8.0) * 100.0)
        
        if self.semantic_available and text.strip():
     # Strong keyword evidence should dominate
            if kw_points >= 12:
                context_confidence = (0.30 * semantic_conf) + (0.70 * kw_conf)

    # Moderate evidence: balanced
            elif kw_points >= 6:
                context_confidence = (0.50 * semantic_conf) + (0.50 * kw_conf)

    # Weak evidence: rely more on semantic similarity
            else:
                context_confidence = (0.70 * semantic_conf) + (0.30 * kw_conf)

        else:
            context_confidence = kw_conf
            
        context_confidence = min(99.0, max(10.0, context_confidence))

        if context_confidence >= 75.0:
            final_context = best_ctx
        elif context_confidence >= 50.0:
            final_context = "General Announcement"
        else:
            final_context = "Unknown"

        evidence.append(
            IntentEvidence(
                feature="Final Context",
                score=round(context_confidence, 2),
                description=(
                    f"Selected '{final_context}' "
                    f"(Semantic={semantic_conf:.1f}%, "
                    f"Keyword={kw_conf:.1f}%)"
                ),
            )
        )

        # ----------------------------------------------
        # 6. Granular Intent Qualification (Phishing vs Legitimate)
        # ----------------------------------------------
        
        phishing_score = 0.0
        detected_phishing_keywords = []
        
        for keyword, weight in self.PHISHING_INTENT_KEYWORDS.items():
            if keyword in lower:
                phishing_score += weight
                detected_phishing_keywords.append(keyword)
        
        if phishing_score > 0:
            evidence.append(
                IntentEvidence(
                    feature="High-Risk/Urgency Phrase",
                    score=-phishing_score,
                    description=f"Suspicious or urgent phrasing detected: {', '.join(detected_phishing_keywords)}"
                )
            )

        # High-Value Orgs specific tracking (Expanded for Real-World Coverage)
        high_value_orgs = {
            "isro", "rbi", "sebi", "sbi", "hdfc", "icici", "axis",
            "uidai", "npci", "income tax", "epfo", "passport seva",
            "lic", "nta", "ugc", "ssc", "railway", "ibps", "drdo"
        }
        
        detected_high_value_orgs = [org for org in detected_orgs if org in high_value_orgs]
        has_high_value_org = len(detected_high_value_orgs) > 0

        # Behavioral Scam Rule: Recruitment + Fee + High-Value Org
        has_recruitment = len(detected_keywords_per_context.get("Recruitment Notice", [])) > 0
        has_fee = any(fee in lower for fee in ["registration fee", "processing fee", "application fee", "exam fee", "interview fee", "security deposit"])

        if has_recruitment and has_fee and has_high_value_org:
            phishing_score += 8.0
            evidence.append(
                IntentEvidence(
                    feature="Recruitment Advance-Fee Scam",
                    score=-8.0,
                    description=f"Detected recruitment context combined with upfront fee request and high-value target organization ({', '.join(detected_high_value_orgs)})."
                )
            )

        # Brand Impersonation Rule
        if has_high_value_org and phishing_score >= 5.0:
            phishing_score += 8.0
            evidence.append(
                IntentEvidence(
                    feature="Brand Impersonation Risk",
                    score=-8.0,
                    description=f"High-value organization ({', '.join(detected_high_value_orgs)}) mentioned alongside high-risk phishing indicators."
                )
            )

        # ----------------------------------------------
        # 7. Final Security Classification
        # ----------------------------------------------
        if final_context in ["Government Notice", "Bank Advisory", "Invoice / Receipt", "Event Poster", "Recruitment Notice", "Student Circular", "Certificate"]:
            if phishing_score > 6:
                security_intent = "Unknown"
                confidence = min(99.0, 75.0 + (phishing_score * 1.5))
                risk_score = min(99.0, 75.0 + (phishing_score * 2))
            elif phishing_score >= 3: 
                security_intent = "Unknown"
                confidence = min(99.0, 65.0 + (phishing_score * 2.0))
                risk_score = 50.0 + phishing_score
            else: 
                security_intent = "Legitimate"
                confidence = min(99.0, 70.0 + (best_score * 1.5))
                risk_score = max(5.0, phishing_score * 5.0)
                
        elif final_context == "General Announcement":
            if phishing_score > 6:
                security_intent = "Unknown"
                confidence = min(99.0, 70.0 + (phishing_score * 1.5))
                risk_score = min(99.0, 70.0 + (phishing_score * 2))
            elif phishing_score >= 3: 
                security_intent = "Unknown"
                confidence = min(95.0, 60.0 + (phishing_score * 1.5))
                risk_score = 45.0 + phishing_score
            else: 
                security_intent = "Likely Legitimate"
                confidence = min(95.0, 60.0 + (best_score * 1.5))
                risk_score = 20.0 + (phishing_score * 5.0)
                
        else:
            if phishing_score > 6:
                security_intent = "Unknown"
                confidence = min(99.0, 75.0 + (phishing_score * 1.5))
                risk_score = min(99.0, 80.0 + phishing_score)
            elif phishing_score >= 3:
                security_intent = "Unknown"
                confidence = min(90.0, 60.0 + (phishing_score * 1.5))
                risk_score = 60.0
            else:
                security_intent = "Unknown"
                confidence = min(90.0, 50.0 + (best_score * 2.0))
                risk_score = 50.0

        return CommunicationIntentResult(
            context=final_context,
            context_confidence=round(context_confidence, 2),
            security_intent=security_intent,
            confidence=round(confidence, 2),
            risk_score=round(risk_score, 2),
            evidence=evidence,
        )

communication_intent_service = CommunicationIntentService()