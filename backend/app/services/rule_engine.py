import re
from dataclasses import dataclass
from typing import List
from app.services.context_service import context_service
from app.services.entity_extractor import ExtractedEntities
from app.models.analysis_models import (
    Finding,
    DocumentContext
)


# -------------------------------------------------------
# Rule Engine
# -------------------------------------------------------

class RuleEngine:

    def __init__(self):

        self.high_return_pattern = re.compile(
            r"\b(\d{2,3})\s*%",
            re.IGNORECASE
        )

        self.guaranteed_pattern = re.compile(
            r"(guaranteed|assured|risk[- ]?free|fixed\s+return|zero\s+risk)",
            re.IGNORECASE
        )

        self.urgency_pattern = re.compile(
            r"(urgent|act\s+now|today\s+only|limited\s+time|last\s+chance|offer\s+expires)",
            re.IGNORECASE
        )

        self.login_pattern = re.compile(
            r"(otp|password|login|verify\s+your\s+account|pin)",
            re.IGNORECASE
        )

    # ---------------------------------------------------
    # Main Entry
    # ---------------------------------------------------

    def evaluate(

        self,

        text: str,

        entities: ExtractedEntities,

        context: DocumentContext

    ) -> List[Finding]:

        findings = []

        findings.extend(
            self.guaranteed_returns(text)
        )

        findings.extend(
            self.unrealistic_returns(text)
        )

        findings.extend(
            self.payment_requests(
                text,
                entities
            )
        )

        findings.extend(
            self.suspicious_urls(
                entities
            )
        )

        findings.extend(
            self.credential_theft(
                text,
                context
            )
        )

        findings.extend(
            self.personal_information(
                entities
            )
        )

        findings.extend(
            self.missing_sebi(
                text,
                entities,
                context
            )
        )

        return findings

        # ---------------------------------------------------
    # Guaranteed Returns
    # ---------------------------------------------------

    def guaranteed_returns(
        self,
        text: str
    ) -> List[Finding]:

        findings = []

        for match in self.guaranteed_pattern.finditer(text):

            findings.append(

                Finding(
                    category="Guaranteed Returns",
                    severity="High",
                    score=30,
                    matched_text=match.group(0),
                    explanation="Promises of guaranteed returns are a strong fraud indicator."
                )

            )

        return findings

    # ---------------------------------------------------
    # Unrealistic Returns
    # ---------------------------------------------------

    def unrealistic_returns(
        self,
        text: str
    ) -> List[Finding]:

        findings = []

        for match in self.high_return_pattern.finditer(text):

            try:

                value = int(match.group(1))

            except ValueError:

                continue

            if value >= 20:

                findings.append(

                    Finding(
                        category="Unrealistic Returns",
                        severity="High",
                        score=25,
                        matched_text=match.group(0),
                        explanation=f"Return of {value}% appears unusually high."
                    )

                )

        return findings

    # ---------------------------------------------------
    # Payment Request
    # ---------------------------------------------------

    def payment_requests(
        self,
        text: str,
        entities: ExtractedEntities
    ) -> List[Finding]:

        findings = []

        payment_words = [

            "transfer",
            "pay",
            "deposit",
            "send",
            "upi",
            "bank",
            "wire",
            "remit"

        ]

        lower = text.lower()

        if not any(word in lower for word in payment_words):

            return findings

        for amount in entities.money_amounts:

            findings.append(

                Finding(
                    category="Money Transfer",
                    severity="High",
                    score=20,
                    matched_text=amount,
                    explanation="Money transfer request detected."
                )

            )

        for upi in entities.upi_ids:

            findings.append(

                Finding(
                    category="UPI Payment",
                    severity="Medium",
                    score=15,
                    matched_text=upi,
                    explanation="UPI payment identifier detected."
                )

            )

        return findings

    # ---------------------------------------------------
    # Suspicious URLs
    # ---------------------------------------------------

    def suspicious_urls(
        self,
        entities: ExtractedEntities
    ) -> List[Finding]:

        findings = []

        suspicious = [

            "bit.ly",
            "tinyurl",
            "t.me",
            "telegram",
            "joinchat",
            "whatsapp",
            "bonus",
            "profit",
            "investment"

        ]

        for url in entities.urls:

            lower = url.lower()

            if any(word in lower for word in suspicious):

                findings.append(

                    Finding(
                        category="Suspicious URL",
                        severity="Medium",
                        score=15,
                        matched_text=url,
                        explanation="Suspicious or shortened URL detected."
                    )

                )

        return findings

    # ---------------------------------------------------
    # Credential Theft
    # ---------------------------------------------------

    def credential_theft(
        self,
        text: str,
        context: DocumentContext
    ) -> List[Finding]:

        findings = []

        # Ignore educational material

        if context.document_type == "Educational":

            return findings

        for match in self.login_pattern.finditer(text):

            findings.append(

                Finding(
                    category="Credential Theft",
                    severity="High",
                    score=25,
                    matched_text=match.group(0),
                    explanation="Possible credential harvesting attempt."
                )

            )

        return findings

        # ---------------------------------------------------
    # Personal Information Detection
    # ---------------------------------------------------

    def personal_information(
        self,
        entities: ExtractedEntities
    ) -> List[Finding]:

        findings = []

        for pan in entities.pan_numbers:

            findings.append(

                Finding(
                    category="PAN Information",
                    severity="Medium",
                    score=10,
                    matched_text=pan,
                    explanation="PAN number detected. Verify whether sharing this information is necessary."
                )

            )

        for aadhaar in entities.aadhaar_numbers:

            findings.append(

                Finding(
                    category="Aadhaar Information",
                    severity="High",
                    score=20,
                    matched_text=aadhaar,
                    explanation="Aadhaar number detected. Sharing Aadhaar details may expose sensitive personal information."
                )

            )

        for account in entities.bank_accounts:

            findings.append(

                Finding(
                    category="Bank Account",
                    severity="Medium",
                    score=12,
                    matched_text=account,
                    explanation="Bank account number detected."
                )

            )

        for ifsc in entities.ifsc_codes:

            findings.append(

                Finding(
                    category="IFSC Code",
                    severity="Low",
                    score=5,
                    matched_text=ifsc,
                    explanation="IFSC code detected."
                )

            )

        return findings

    # ---------------------------------------------------
    # Missing SEBI Registration
    # ---------------------------------------------------

    def missing_sebi(
        self,
        text: str,
        entities: ExtractedEntities,
        context: DocumentContext
    ) -> List[Finding]:

        findings = []

        if context.document_type != "Investment":

            return findings

        if entities.sebi_numbers:

            return findings

        investment_keywords = [

            "investment",
            "stock",
            "shares",
            "mutual fund",
            "trading",
            "portfolio",
            "returns",
            "profit"

        ]

        lower = text.lower()

        if any(keyword in lower for keyword in investment_keywords):

            findings.append(

                Finding(
                    category="Missing SEBI Registration",
                    severity="Medium",
                    score=20,
                    matched_text="SEBI Registration",
                    explanation="Investment-related communication without a detectable SEBI registration number."
                )

            )

        return findings

    # ---------------------------------------------------
    # Remove Duplicate Findings
    # ---------------------------------------------------

    def remove_duplicates(
        self,
        findings: List[Finding]
    ) -> List[Finding]:

        unique = {}

        for finding in findings:

            key = (
                finding.category.lower(),
                finding.matched_text.lower()
            )

            if key not in unique:

                unique[key] = finding

        return list(unique.values())


# -------------------------------------------------------
# Singleton Instance
# -------------------------------------------------------

rule_engine = RuleEngine()