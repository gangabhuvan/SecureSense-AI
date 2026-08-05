"""
context_service.py

Utilities for analysing the textual context surrounding
detected entities before assigning fraud scores.
"""

from __future__ import annotations

import re


class ContextService:
    """
    Provides helper methods to understand the context in
    which an entity appears.

    Instead of blindly scoring regex matches, the scoring
    engine can ask this service whether the entity appears
    inside an academic paper, references section, payment
    request, etc.
    """

    WINDOW_SIZE = 80

    # ---------------------------------------------------------
    # Context Extraction
    # ---------------------------------------------------------

    def get_context(
        self,
        text: str,
        match: str,
        window: int | None = None,
    ) -> str:
        """
        Returns surrounding text around a matched entity.
        """

        if not text or not match:
            return ""

        window = window or self.WINDOW_SIZE

        index = text.lower().find(match.lower())

        if index == -1:
            return ""

        start = max(0, index - window)
        end = min(len(text), index + len(match) + window)

        return text[start:end].lower()

    # ---------------------------------------------------------
    # Generic Keyword Check
    # ---------------------------------------------------------

    @staticmethod
    def contains_keywords(
        context: str,
        keywords: list[str],
    ) -> bool:

        return any(
            keyword in context
            for keyword in keywords
        )

    # ---------------------------------------------------------
    # Academic Context
    # ---------------------------------------------------------

    def is_academic_context(
        self,
        context: str,
    ) -> bool:

        keywords = [

            "accuracy",
            "precision",
            "recall",
            "f1",
            "macro",
            "weighted",
            "auc",
            "roc",
            "confusion matrix",
            "mcc",
            "mean average precision",
            "validation",
            "training",
            "testing",
            "dataset",
            "experiment",
            "epoch",
            "optimizer",
            "model",
            "classification",
            "brain tumor",
            "paper",
            "conference",
            "journal",

        ]

        return self.contains_keywords(
            context,
            keywords,
        )

    # ---------------------------------------------------------
    # Reference Context
    # ---------------------------------------------------------

    def is_reference_context(
        self,
        context: str,
    ) -> bool:

        keywords = [

            "doi",
            "references",
            "reference",
            "vol.",
            "journal",
            "conference",
            "proceedings",
            "kaggle",
            "available:",
            "accessed",

        ]

        return self.contains_keywords(
            context,
            keywords,
        )

    # ---------------------------------------------------------
    # Contact Information
    # ---------------------------------------------------------

    def is_contact_context(
        self,
        context: str,
    ) -> bool:

        keywords = [

            "department",
            "university",
            "institute",
            "author",
            "orcid",
            "email",
            "contact",

        ]

        return self.contains_keywords(
            context,
            keywords,
        )

    # ---------------------------------------------------------
    # Payment Context
    # ---------------------------------------------------------

    def is_payment_context(
        self,
        context: str,
    ) -> bool:

        keywords = [

            "pay",
            "payment",
            "upi",
            "transfer",
            "bank",
            "account",
            "send money",
            "deposit",
            "withdraw",
            "investment",
            "profit",
            "earn",
            "return",
            "guaranteed",
            "double",

        ]

        return self.contains_keywords(
            context,
            keywords,
        )

    # ---------------------------------------------------------
    # Promotion Context
    # ---------------------------------------------------------

    def is_promotional_context(
        self,
        context: str,
    ) -> bool:

        keywords = [

            "limited offer",
            "offer",
            "bonus",
            "free",
            "today only",
            "exclusive",
            "hurry",
            "join now",
            "click here",
            "register now",

        ]

        return self.contains_keywords(
            context,
            keywords,
        )

    # ---------------------------------------------------------
    # DOI Detection
    # ---------------------------------------------------------

    @staticmethod
    def is_doi(
        value: str,
    ) -> bool:

        pattern = r"10\.\d{4,9}/"

        return bool(
            re.search(
                pattern,
                value,
                re.IGNORECASE,
            )
        )

    # ---------------------------------------------------------
    # Academic Percentage
    # ---------------------------------------------------------

    def is_academic_percentage(
        self,
        text: str,
        percentage: str,
    ) -> bool:

        context = self.get_context(
            text,
            percentage,
        )

        return self.is_academic_context(
            context,
        )

    # ---------------------------------------------------------
    # Safe Bank Number
    # ---------------------------------------------------------

    def should_ignore_bank_number(
        self,
        text: str,
        number: str,
    ) -> bool:

        context = self.get_context(
            text,
            number,
        )

        return (

            self.is_reference_context(
                context
            )

            or

            self.is_academic_context(
                context
            )

        )


context_service = ContextService()