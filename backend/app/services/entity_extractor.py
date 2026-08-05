"""
entity_extractor.py

Entity extraction service for SecureSense AI.

Extracts structured security-relevant entities from:
- Direct text
- OCR-extracted document text
- OCR-extracted screenshot text

URL extraction supports:
- https://example.com
- http://example.com/path
- www.example.com
- example.com
- subdomain.example.com

Bare-domain support is important for screenshots because a
browser/page may visually expose only a hostname such as
"surl.li" rather than a complete URL.
"""

from __future__ import annotations

import re
from dataclasses import (
    asdict,
    dataclass,
    field,
)
from typing import Dict, List
from urllib.parse import urlparse


# ============================================================
# Extracted Entities
# ============================================================

@dataclass
class ExtractedEntities:

    urls: List[str] = field(
        default_factory=list
    )

    emails: List[str] = field(
        default_factory=list
    )

    phone_numbers: List[str] = field(
        default_factory=list
    )

    upi_ids: List[str] = field(
        default_factory=list
    )

    bank_accounts: List[str] = field(
        default_factory=list
    )

    ifsc_codes: List[str] = field(
        default_factory=list
    )

    pan_numbers: List[str] = field(
        default_factory=list
    )

    aadhaar_numbers: List[str] = field(
        default_factory=list
    )

    money_amounts: List[str] = field(
        default_factory=list
    )

    percentages: List[str] = field(
        default_factory=list
    )

    sebi_numbers: List[str] = field(
        default_factory=list
    )

    dates: List[str] = field(
        default_factory=list
    )

    def as_dict(
        self,
    ) -> Dict[str, List[str]]:

        return asdict(
            self
        )


# ============================================================
# Entity Extractor
# ============================================================

class EntityExtractor:

    def __init__(
        self,
    ) -> None:

        # ====================================================
        # URL / Domain Patterns
        # ====================================================

        # Explicit URLs:
        #
        # https://example.com
        # http://example.com/path
        # www.example.com
        self.explicit_url_pattern = re.compile(
            r"""
            (?:
                https?://
                |
                www\.
            )
            [A-Za-z0-9]
            [A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*
            """,
            re.IGNORECASE
            | re.VERBOSE,
        )

        # Bare domains:
        #
        # surl.li
        # hdfcbank.com
        # login.example.co.in
        #
        # Requiring alphabetic TLD characters prevents many
        # numeric OCR fragments from becoming domains.
        self.bare_domain_pattern = re.compile(
            r"""
            (?<![@\w])
            (?:
                [A-Za-z0-9]
                (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
                \.
            )+
            [A-Za-z]{2,24}
            (?:
                /[^\s<>"']*
            )?
            """,
            re.IGNORECASE
            | re.VERBOSE,
        )

        # ====================================================
        # Other Entity Patterns
        # ====================================================

        self.email_pattern = re.compile(
            r"\b"
            r"[A-Za-z0-9._%+-]+"
            r"@"
            r"[A-Za-z0-9.-]+"
            r"\.[A-Za-z]{2,}"
            r"\b"
        )

        self.phone_pattern = re.compile(
            r"(?:\+91[- ]?)?[6-9]\d{9}"
        )

        self.upi_pattern = re.compile(
            r"\b"
            r"[A-Za-z0-9.\-_]{2,}"
            r"@"
            r"[A-Za-z]{2,}"
            r"\b"
        )

        self.ifsc_pattern = re.compile(
            r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
        )

        self.pan_pattern = re.compile(
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
        )

        self.aadhaar_pattern = re.compile(
            r"\b\d{4}\s?\d{4}\s?\d{4}\b"
        )

        self.money_pattern = re.compile(
            r"("
            r"₹\s?\d[\d,]*(?:\.\d+)?"
            r"|"
            r"Rs\.?\s?\d[\d,]*(?:\.\d+)?"
            r"|"
            r"INR\s?\d[\d,]*(?:\.\d+)?"
            r")",
            re.IGNORECASE,
        )

        self.percent_pattern = re.compile(
            r"\b\d{1,3}(?:\.\d+)?%"
        )

        self.bank_account_pattern = re.compile(
            r"\b\d{9,18}\b"
        )

        self.sebi_pattern = re.compile(
            r"\b(?:INA|INZ|INS|INH)\d{9}\b",
            re.IGNORECASE,
        )

        self.date_pattern = re.compile(
            r"\b"
            r"\d{1,2}"
            r"[/-]"
            r"\d{1,2}"
            r"[/-]"
            r"\d{2,4}"
            r"\b"
        )

    # ========================================================
    # General Helpers
    # ========================================================

    @staticmethod
    def _unique(
        values: List[str],
    ) -> List[str]:
        """
        Remove duplicates while preserving original order.
        """

        seen = set()

        result = []

        for value in values:

            normalized = (
                value.strip()
            )

            if not normalized:
                continue

            comparison_key = (
                normalized.lower()
            )

            if comparison_key in seen:
                continue

            seen.add(
                comparison_key
            )

            result.append(
                normalized
            )

        return result

    # ========================================================
    # OCR / Text Normalisation
    # ========================================================

    @staticmethod
    def _clean(
        text: str,
    ) -> str:
        """
        Normalise whitespace without aggressively rewriting
        communication content.
        """

        if not text:
            return ""

        text = text.replace(
            "\n",
            " ",
        )

        text = text.replace(
            "\t",
            " ",
        )

        text = re.sub(
            r"\s+",
            " ",
            text,
        )

        return text.strip()

    # ========================================================
    # URL Normalisation
    # ========================================================

    @staticmethod
    def _repair_ocr_urls(
        text: str,
    ) -> str:
        """
        Repair common OCR corruption seen in URLs.

        Examples
        --------
        https : //google.com
            -> https://google.com

        www . google . com
            -> www.google.com

        docs.google.
        com/forms
            -> docs.google.com/forms

        google . com
            -> google.com
        """

        if not text:
            return ""

        # --------------------------------------------
        # Fix spaced protocol
        # --------------------------------------------

        text = re.sub(
            r"https?\s*:\s*/\s*/",
            lambda m: (
                m.group(0)
                .replace(" ", "")
                .replace("/ /", "//")
            ),
            text,
            flags=re.IGNORECASE,
        )

        # --------------------------------------------
        # Fix "www ."
        # --------------------------------------------

        text = re.sub(
            r"www\s*\.\s*",
            "www.",
            text,
            flags=re.IGNORECASE,
        )

        # --------------------------------------------
        # Fix spaces around dots
        # --------------------------------------------

        text = re.sub(
            r"\s*\.\s*",
            ".",
            text,
        )

        # --------------------------------------------
        # Join broken TLDs
        #
        # google.\ncom
        # docs.google.\ncom
        # --------------------------------------------

        text = re.sub(
            r"\.\s+([A-Za-z]{2,24})(?=[/\s]|$)",
            r".\1",
            text,
        )

        # --------------------------------------------
        # Remove spaces immediately after "/"
        # --------------------------------------------

        text = re.sub(
            r"/\s+",
            "/",
            text,
        )

        return text

    @staticmethod
    def _clean_url_candidate(
        candidate: str,
    ) -> str:
        """
        Remove punctuation commonly attached to URLs by
        sentences or OCR output.
        """

        value = (
            candidate
            .strip()
            .strip(
                "\"'<>[]{}()"
            )
        )

        # Sentence punctuation should not become part of the
        # hostname/path.
        value = value.rstrip(
            ".,;:!?)]}'\""
        )

        return value

    @staticmethod
    def _canonical_url_key(
        value: str,
    ) -> str:
        """
        Generate a comparison key so the same domain is not
        returned twice merely because one occurrence includes
        a scheme or www prefix.
        """

        candidate = value.strip()

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

            path = (
                parsed.path
                or ""
            ).rstrip("/")

            query = (
                f"?{parsed.query}"
                if parsed.query
                else ""
            )

            return (
                hostname
                + path
                + query
            )

        except Exception:

            return value.lower()

    # ========================================================
    # URL Extraction
    # ========================================================
    @staticmethod
    def _is_valid_url_candidate(
        candidate: str,
    ) -> bool:
        """
        Reject OCR fragments that are clearly not valid URLs.
        """

        if not candidate:
            return False

        value = candidate.strip().lower()
        if value.endswith("."):
            return False

        try:
            parsed = urlparse(
                value
                if "://" in value
                else "https://" + value
            )
        except Exception:
            return False

        hostname = parsed.hostname
        
        # 1. Reject if parsed.hostname is None (Fixes the split exception bug)
        if not hostname:
            return False
            
        labels = hostname.split(".")
        if labels[0].isdigit():
            return False

        # Require at least one dot
        if "." not in hostname:
            return False

        # Reject incomplete OCR domains
        tld = hostname.rsplit(".", 1)[-1]

        # TLD must be alphabetic
        if not tld.isalpha():
            return False

        # TLD length should be reasonable
        if len(tld) < 2 or len(tld) > 24:
            return False

        return True   

    def extract_urls(
        self,
        text: str,
    ) -> List[str]:
        """
        Extract explicit URLs and bare domains.

        Examples:
            https://example.com
            www.example.com
            example.com
            surl.li

        Email domains are excluded because email addresses are
        handled separately.
        """

        candidates: List[str] = []

        occupied_spans: List[
            tuple[int, int]
        ] = []

        # ----------------------------------------------------
        # Explicit URLs first
        # ----------------------------------------------------

        for match in (
            self.explicit_url_pattern
            .finditer(text)
        ):

            candidate = (
                self._clean_url_candidate(
                    match.group(0)
                )
            )

            if not candidate:
                continue

            candidates.append(
                candidate
            )

            occupied_spans.append(
                match.span()
            )

        # ----------------------------------------------------
        # Bare domains
        # ----------------------------------------------------

        for match in (
            self.bare_domain_pattern
            .finditer(text)
        ):

            start, end = (
                match.span()
            )

            # Do not duplicate a domain already captured as
            # part of an explicit URL.
            overlaps_explicit = any(
                start < existing_end
                and end > existing_start
                for (
                    existing_start,
                    existing_end,
                ) in occupied_spans
            )

            if overlaps_explicit:
                continue

            # Do not treat the domain portion of an email
            # address as a standalone URL.
            if (
                start > 0
                and text[start - 1] == "@"
            ):
                continue

            candidate = (
                self._clean_url_candidate(
                    match.group(0)
                )
            )

            if candidate:
                candidates.append(
                    candidate
                )

        # ----------------------------------------------------
        # Deduplicate canonically
        # ----------------------------------------------------

        result: List[str] = []

        seen = set()

        for candidate in candidates:

            if not self._is_valid_url_candidate(
                candidate
            ):
                continue

            key = self._canonical_url_key(
                candidate
            )

            if not key:
                continue

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                candidate
            )

        return result

    # ========================================================
    # Other Individual Extractors
    # ========================================================

    def extract_emails(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.email_pattern.findall(
                text
            )
        )

    def extract_phone_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.phone_pattern.findall(
                text
            )
        )

    def extract_upi_ids(
        self,
        text: str,
    ) -> List[str]:
        emails = {
            email.lower()
            for email in self.extract_emails(text)
        }

        candidates = self.upi_pattern.findall(
            text
        )

        invalid = {
            "gmail",
            "yahoo",
            "hotmail",
            "outlook",
            "icloud",
        }

        result = []
        for candidate in candidates:
            if candidate.lower() in emails:
                continue

            if "@" not in candidate:
                continue

            handle, provider = candidate.split(
                "@",
                1,
            )

            if provider.lower() in invalid:
                continue

            if len(handle) < 2:
                continue

            result.append(candidate)
        return self._unique(result)

    def extract_ifsc_codes(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.ifsc_pattern.findall(
                text
            )
        )

    def extract_pan_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.pan_pattern.findall(
                text
            )
        )

    def extract_aadhaar_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.aadhaar_pattern.findall(
                text
            )
        )

    def extract_money_amounts(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.money_pattern.findall(
                text
            )
        )

    def extract_percentages(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.percent_pattern.findall(
                text
            )
        )

    def extract_bank_accounts(
        self,
        text: str,
    ) -> List[str]:

        accounts = []

        for number in (
            self.bank_account_pattern
            .findall(text)
        ):

            if len(number) >= 9:

                accounts.append(
                    number
                )

        return self._unique(
            accounts
        )

    def extract_sebi_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.sebi_pattern.findall(
                text
            )
        )

    def extract_dates(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.date_pattern.findall(
                text
            )
        )

    # ========================================================
    # Main Extraction
    # ========================================================

    def extract(
        self,
        text: str,
    ) -> ExtractedEntities:
        """
        Extract all supported entities from communication text.
        """

        text = self._clean(
            text
        )

        text = self._repair_ocr_urls(
            text
        )

        entities = (
            ExtractedEntities()
        )

        entities.urls = (
            self.extract_urls(
                text
            )
        )

        entities.emails = (
            self.extract_emails(
                text
            )
        )

        entities.phone_numbers = (
            self.extract_phone_numbers(
                text
            )
        )

        entities.upi_ids = (
            self.extract_upi_ids(
                text
            )
        )

        entities.ifsc_codes = (
            self.extract_ifsc_codes(
                text
            )
        )

        entities.pan_numbers = (
            self.extract_pan_numbers(
                text
            )
        )

        entities.aadhaar_numbers = (
            self.extract_aadhaar_numbers(
                text
            )
        )

        entities.money_amounts = (
            self.extract_money_amounts(
                text
            )
        )

        entities.percentages = (
            self.extract_percentages(
                text
            )
        )

        entities.bank_accounts = (
            self.extract_bank_accounts(
                text
            )
        )

        entities.sebi_numbers = (
            self.extract_sebi_numbers(
                text
            )
        )

        entities.dates = (
            self.extract_dates(
                text
            )
        )

        return entities


# ============================================================
# Singleton
# ============================================================

entity_extractor = EntityExtractor()