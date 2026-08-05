import re
from collections import Counter
from typing import Dict, List

from app.models.analysis_models import DocumentContext

from app.services.patterns import (
    EDUCATIONAL_KEYWORDS,
    INVESTMENT_KEYWORDS,
    BANKING_KEYWORDS,
    GOVERNMENT_KEYWORDS
)


# =======================================================
# Document Categories
# =======================================================

DOCUMENT_KEYWORDS: Dict[str, set] = {

    "Educational": EDUCATIONAL_KEYWORDS,

    "Investment": INVESTMENT_KEYWORDS,

    "Banking": BANKING_KEYWORDS,

    "Government": GOVERNMENT_KEYWORDS,

    "Invoice": {

        "invoice",
        "bill",
        "gst",
        "amount due",
        "tax invoice",
        "quantity",
        "unit price",
        "purchase",
        "subtotal",
        "total"

    },

    "Marketing": {

        "offer",
        "discount",
        "sale",
        "coupon",
        "buy now",
        "limited offer",
        "promotion",
        "deal",
        "exclusive"

    },

    "Personal": {

        "dear",
        "regards",
        "hello",
        "thank you",
        "family",
        "friend",
        "birthday",
        "wedding",
        "congratulations"

    }

}


# =======================================================
# Context Detector
# =======================================================

class ContextDetector:

    def _normalize(
        self,
        text: str
    ) -> str:

        text = text.lower()

        text = text.replace("\n", " ")

        text = text.replace("\t", " ")

        text = re.sub(r"\s+", " ", text)

        return text.strip()

    # ---------------------------------------------------

    def _keyword_matches(

        self,

        text: str,

        keywords: set

    ) -> List[str]:

        matches = []

        for keyword in keywords:

            if keyword in text:

                matches.append(keyword)

        return matches

    # ---------------------------------------------------

    def detect(
        self,
        text: str
    ) -> DocumentContext:

        text = self._normalize(text)

        scores = Counter()

        matched = {}

        for document_type, keywords in DOCUMENT_KEYWORDS.items():

            found = self._keyword_matches(

                text,

                keywords

            )

            if found:

                scores[document_type] = len(found)

                matched[document_type] = found

        if not scores:

            return DocumentContext(

                document_type="Unknown",

                confidence=0.0,

                matched_keywords=[]

            )

        document_type = scores.most_common(1)[0][0]

        total = sum(scores.values())

        confidence = (

            scores[document_type]

            / total

        ) * 100

        return DocumentContext(

            document_type=document_type,

            confidence=round(confidence, 2),

            matched_keywords=sorted(

                matched[document_type]

            )

        )


# =======================================================
# Singleton
# =======================================================

context_detector = ContextDetector()