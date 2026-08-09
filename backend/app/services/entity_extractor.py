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
- OCR-repaired URL forms such as:
    https : //example.com
    www . example . com
    example . com

IMPORTANT:
The extractor must NOT convert normal sentence punctuation into URLs.

Examples that must NOT become URLs:
    today. To
    restrictions. Please
    account. Verify
    information. Contact

The URL repair logic is intentionally conservative.
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

    # ========================================================
    # Common / Recognised TLDs
    # ========================================================
    #
    # This list is used ONLY as a validation layer for
    # bare-domain extraction.
    #
    # Explicit URLs such as:
    #     https://something.unknown
    #
    # are NOT restricted by this list.
    #
    # This prevents ordinary words such as:
    #     restrictions.Please
    #
    # from being classified as domains.
    # ========================================================

    VALID_TLDS = {
        # Generic
        "com",
        "org",
        "net",
        "edu",
        "gov",
        "mil",
        "int",
        "info",
        "biz",
        "name",
        "pro",
        "mobi",
        "travel",
        "jobs",

        # Technology / modern
        "io",
        "ai",
        "app",
        "dev",
        "tech",
        "cloud",
        "online",
        "site",
        "store",
        "shop",
        "blog",
        "xyz",
        "live",
        "digital",
        "agency",
        "solutions",
        "software",
        "systems",
        "network",
        "website",
        "space",
        "world",
        "today",
        "email",
        "me",
        "tv",

        # India
        "in",
        "co.in",
        "net.in",
        "org.in",
        "gov.in",
        "ac.in",
        "edu.in",
        "firm.in",
        "gen.in",
        "ind.in",

        # Common country codes
        "uk",
        "us",
        "ca",
        "au",
        "nz",
        "de",
        "fr",
        "it",
        "es",
        "nl",
        "be",
        "ch",
        "se",
        "no",
        "dk",
        "fi",
        "ie",
        "at",
        "pl",
        "pt",
        "gr",
        "cz",
        "ro",
        "hu",
        "ru",

        # Asia
        "sg",
        "jp",
        "cn",
        "hk",
        "kr",
        "my",
        "id",
        "ph",
        "th",
        "vn",
        "pk",
        "bd",
        "lk",
        "np",
        "ae",
        "sa",
        "qa",
        "kw",
        "il",

        # Africa
        "za",
        "ng",
        "ke",
        "eg",

        # Other commonly encountered shorteners
        "ly",
        "li",
        "cc",
        "to",
    }

    # ========================================================
    # Constructor
    # ========================================================

    def __init__(
        self,
    ) -> None:

        # ====================================================
        # Explicit URLs
        # ====================================================
        #
        # Supported:
        #
        # https://example.com
        # http://example.com/path
        # www.example.com
        #
        # These are deliberately handled separately from
        # bare domains.
        # ====================================================

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

        # ====================================================
        # Bare Domains
        # ====================================================
        #
        # Supported:
        #
        # example.com
        # login.example.com
        # login-paypal-support.com
        # surl.li
        #
        # The TLD is deliberately captured separately so that
        # it can be validated later.
        # ====================================================

        self.bare_domain_pattern = re.compile(
            r"""
            (?<![@\w.-])
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
        # Email
        # ====================================================

        self.email_pattern = re.compile(
            r"\b"
            r"[A-Za-z0-9._%+-]+"
            r"@"
            r"[A-Za-z0-9.-]+"
            r"\.[A-Za-z]{2,}"
            r"\b"
        )

        # ====================================================
        # Indian Phone Numbers
        # ====================================================

        self.phone_pattern = re.compile(
            r"(?:\+91[- ]?)?[6-9]\d{9}"
        )

        # ====================================================
        # UPI
        # ====================================================

        self.upi_pattern = re.compile(
            r"\b"
            r"[A-Za-z0-9.\-_]{2,}"
            r"@"
            r"[A-Za-z]{2,}"
            r"\b"
        )

        # ====================================================
        # IFSC
        # ====================================================

        self.ifsc_pattern = re.compile(
            r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
        )

        # ====================================================
        # PAN
        # ====================================================

        self.pan_pattern = re.compile(
            r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
        )

        # ====================================================
        # Aadhaar
        # ====================================================

        self.aadhaar_pattern = re.compile(
            r"\b\d{4}\s?\d{4}\s?\d{4}\b"
        )

        # ====================================================
        # Money
        # ====================================================

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

        # ====================================================
        # Percentage
        # ====================================================

        self.percent_pattern = re.compile(
            r"\b\d{1,3}(?:\.\d+)?%"
        )

        # ====================================================
        # Bank Account
        # ====================================================

        self.bank_account_pattern = re.compile(
            r"\b\d{9,18}\b"
        )

        # ====================================================
        # SEBI
        # ====================================================

        self.sebi_pattern = re.compile(
            r"\b(?:INA|INZ|INS|INH)\d{9}\b",
            re.IGNORECASE,
        )

        # ====================================================
        # Dates
        # ====================================================

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

            normalized = value.strip()

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
        Normalise whitespace without changing punctuation.

        IMPORTANT:
        We intentionally do NOT replace:
            " . "
        with:
            "."
        globally.

        Otherwise:
            "today. To prevent"

        could become:
            "today.To prevent"
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
        Repair common OCR corruption in URL-like structures.

        Supported repairs:

            https : //google.com
                -> https://google.com

            http : //google.com
                -> http://google.com

            www . google . com
                -> www.google.com

            google . com
                -> google.com

            docs . google . com/forms
                -> docs.google.com/forms

        IMPORTANT:
        This function NEVER performs a global replacement of
        spaces around periods.

        Therefore:

            today. To prevent

        remains:

            today. To prevent

        rather than becoming:

            today.To prevent
        """

        if not text:
            return ""

        # ----------------------------------------------------
        # 1. Repair spaced HTTP / HTTPS protocol
        # ----------------------------------------------------
        #
        # Examples:
        #
        # https : //example.com
        # http ://example.com
        # https: // example.com
        #
        # -> https://example.com
        # ----------------------------------------------------

        text = re.sub(
            r"https?\s*:\s*/\s*/",
            lambda match: re.sub(
                r"\s+",
                "",
                match.group(0),
            ),
            text,
            flags=re.IGNORECASE,
        )

        # ----------------------------------------------------
        # 2. Repair www-style OCR URLs
        # ----------------------------------------------------
        #
        # Only runs when "www" is explicitly present.
        #
        # This is safe because normal sentence fragments are
        # not expected to start with "www".
        # ----------------------------------------------------

        text = re.sub(
            r"""
            \b
            www
            \s*\.\s*
            [A-Za-z0-9-]+
            (?:
                \s*\.\s*
                [A-Za-z0-9-]+
            )+
            """,
            lambda match: re.sub(
                r"\s*\.\s*",
                ".",
                match.group(0),
            ),
            text,
            flags=re.IGNORECASE
            | re.VERBOSE,
        )

        # ----------------------------------------------------
        # 3. Repair spaced bare domains conservatively
        # ----------------------------------------------------
        #
        # Examples:
        #
        # google . com
        # docs . google . com
        #
        # We ONLY repair if the final TLD:
        #
        #   - is lowercase
        #   - is a recognised/common TLD
        #
        # This is important for:
        #
        # today. To
        #
        # because "To" starts with an uppercase letter and
        # therefore will NOT be repaired.
        #
        # Likewise:
        #
        # restrictions. Please
        #
        # will NOT be repaired because "Please" is not a
        # recognised TLD.
        # ----------------------------------------------------

        def repair_spaced_domain(
            match: re.Match,
        ) -> str:

            candidate = match.group(
                0
            )

            parts = re.split(
                r"\s*\.\s*",
                candidate,
            )

            if len(parts) < 2:
                return candidate

            tld = parts[-1].lower()

            # Only repair recognised TLDs.
            if tld not in EntityExtractor.VALID_TLDS:
                return candidate

            # If OCR produced a capitalised TLD, it is much
            # more likely to be sentence punctuation:
            #
            # "today. To"
            #
            # rather than a domain.
            original_tld = parts[-1]

            if original_tld != original_tld.lower():
                return candidate

            return ".".join(
                parts
            )

        text = re.sub(
            r"""
            \b
            [A-Za-z0-9-]+
            (?:
                \s*\.\s*
                [A-Za-z0-9-]+
            )+
            \b
            """,
            repair_spaced_domain,
            text,
            flags=re.VERBOSE,
        )

        # ----------------------------------------------------
        # 4. Remove whitespace immediately after URL paths
        # ----------------------------------------------------
        #
        # Example:
        #
        # https://example.com/ verify
        #
        # -> https://example.com/verify
        #
        # This is intentionally conservative.
        # ----------------------------------------------------

        text = re.sub(
            r"(?<=/)\s+",
            "",
            text,
        )

        return text

    # ========================================================
    # URL Candidate Cleaning
    # ========================================================

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

        # Sentence punctuation should not become part of
        # the hostname/path.
        value = value.rstrip(
            ".,;:!?)]}'\""
        )

        return value

    # ========================================================
    # URL Canonicalisation
    # ========================================================

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
    # Bare Domain Validation
    # ========================================================

    def _looks_like_bare_domain(
        self,
        candidate: str,
        text: str,
        start: int,
        end: int,
    ) -> bool:
        """
        Validate a bare-domain candidate.

        This is the second defensive layer after the regex.

        It prevents ordinary sentence fragments from becoming
        URLs while retaining legitimate bare domains.
        """

        value = candidate.strip()

        if not value:
            return False

        # ----------------------------------------------------
        # Must contain a dot.
        # ----------------------------------------------------

        if "." not in value:
            return False

        # ----------------------------------------------------
        # Bare domains must not contain whitespace.
        # ----------------------------------------------------

        if re.search(
            r"\s",
            value,
        ):
            return False

        # ----------------------------------------------------
        # Separate hostname from optional path.
        # ----------------------------------------------------

        hostname = value.split(
            "/",
            1,
        )[0]

        labels = hostname.split(
            "."
        )

        if len(labels) < 2:
            return False

        # ----------------------------------------------------
        # No empty domain labels.
        # ----------------------------------------------------

        if any(
            not label
            for label in labels
        ):
            return False

        # ----------------------------------------------------
        # Domain labels must be valid.
        # ----------------------------------------------------

        for label in labels:

            if not re.fullmatch(
                r"[A-Za-z0-9-]+",
                label,
            ):
                return False

            if label.startswith(
                "-"
            ):
                return False

            if label.endswith(
                "-"
            ):
                return False

        # ----------------------------------------------------
        # Validate TLD.
        # ----------------------------------------------------

        tld = labels[-1]

        if not re.fullmatch(
            r"[A-Za-z]{2,24}",
            tld,
        ):
            return False

        # ----------------------------------------------------
        # Recognised TLD check.
        #
        # Handle multi-part TLDs such as co.in.
        # ----------------------------------------------------

        tld_lower = tld.lower()

        previous_label = (
            labels[-2].lower()
        )

        if (
            tld_lower not in
            self.VALID_TLDS
        ):

            # Allow recognised second-level country domains.
            compound_tld = (
                previous_label
                + "."
                + tld_lower
            )

            if (
                compound_tld
                not in self.VALID_TLDS
            ):
                return False

        # ----------------------------------------------------
        # Sentence-fragment protection.
        #
        # Example:
        #
        # restrictions.Please
        #
        # "Please" is not a valid TLD and has already been
        # rejected above.
        #
        # Example:
        #
        # today.To
        #
        # ".to" is technically a real TLD, but "To" is
        # capitalised like a normal sentence word.
        #
        # If a bare domain has an uppercase TLD while the
        # previous label is an ordinary lowercase word,
        # treat it as sentence punctuation.
        # ----------------------------------------------------

        if (
            tld != tld.lower()
            and labels[-2] == labels[-2].lower()
        ):
            return False

        # ----------------------------------------------------
        # Additional sentence-boundary protection.
        #
        # If the candidate immediately follows normal sentence
        # punctuation, be conservative unless the candidate
        # has a strong domain-like signal.
        # ----------------------------------------------------

        before = text[
            max(0, start - 3):start
        ]

        # Domain-like labels commonly contain:
        #   -
        #   digits
        #
        # This makes things such as:
        #
        # login-paypal-support.com
        #
        # highly reliable.
        # ----------------------------------------------------

        has_domain_signal = (
            "-" in hostname
            or any(
                char.isdigit()
                for char in hostname
            )
        )

        # If this is a normal word.word construct directly
        # following sentence punctuation, be conservative.
        #
        # Do NOT reject normal legitimate domains globally.
        # Only apply the rule when the candidate itself looks
        # like ordinary natural-language words.
        # ----------------------------------------------------

        if (
            before.endswith(".")
            and not has_domain_signal
        ):
            return False

        return True

    # ========================================================
    # URL Extraction
    # ========================================================

    def extract_urls(
        self,
        text: str,
    ) -> List[str]:
        """
        Extract explicit URLs and validated bare domains.

        Examples:

            https://example.com
            http://example.com/path
            www.example.com
            example.com
            login-paypal-support.com
            surl.li

        False positives such as:

            today.To
            restrictions.Please

        are rejected.
        """

        candidates: List[str] = []

        occupied_spans: List[
            tuple[int, int]
        ] = []

        # ----------------------------------------------------
        # Explicit URLs first
        # ----------------------------------------------------

        for match in (
            self.explicit_url_pattern.finditer(
                text
            )
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
            self.bare_domain_pattern.finditer(
                text
            )
        ):

            start, end = (
                match.span()
            )

            # ------------------------------------------------
            # Do not duplicate a domain already captured as
            # part of an explicit URL.
            # ------------------------------------------------

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

            # ------------------------------------------------
            # Do not treat the domain portion of an email
            # address as a standalone URL.
            # ------------------------------------------------

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

            if not candidate:
                continue

            # ------------------------------------------------
            # Validate the candidate.
            # ------------------------------------------------

            if not self._looks_like_bare_domain(
                candidate,
                text,
                start,
                end,
            ):
                continue

            candidates.append(
                candidate
            )

        # ----------------------------------------------------
        # Deduplicate canonically
        # ----------------------------------------------------

        result: List[str] = []

        seen = set()

        for candidate in candidates:

            key = (
                self._canonical_url_key(
                    candidate
                )
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
    # Email Extraction
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

    # ========================================================
    # Phone Extraction
    # ========================================================

    def extract_phone_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.phone_pattern.findall(
                text
            )
        )

    # ========================================================
    # UPI Extraction
    # ========================================================

    def extract_upi_ids(
        self,
        text: str,
    ) -> List[str]:

        emails = {
            email.lower()
            for email in
            self.extract_emails(text)
        }

        candidates = (
            self.upi_pattern.findall(
                text
            )
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

            if (
                candidate.lower()
                in emails
            ):
                continue

            if "@" not in candidate:
                continue

            handle, provider = (
                candidate.split(
                    "@",
                    1,
                )
            )

            if (
                provider.lower()
                in invalid
            ):
                continue

            if len(handle) < 2:
                continue

            result.append(
                candidate
            )

        return self._unique(
            result
        )

    # ========================================================
    # IFSC Extraction
    # ========================================================

    def extract_ifsc_codes(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.ifsc_pattern.findall(
                text
            )
        )

    # ========================================================
    # PAN Extraction
    # ========================================================

    def extract_pan_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.pan_pattern.findall(
                text
            )
        )

    # ========================================================
    # Aadhaar Extraction
    # ========================================================

    def extract_aadhaar_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.aadhaar_pattern.findall(
                text
            )
        )

    # ========================================================
    # Money Extraction
    # ========================================================

    def extract_money_amounts(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.money_pattern.findall(
                text
            )
        )

    # ========================================================
    # Percentage Extraction
    # ========================================================

    def extract_percentages(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.percent_pattern.findall(
                text
            )
        )

    # ========================================================
    # Bank Account Extraction
    # ========================================================

    def extract_bank_accounts(
        self,
        text: str,
    ) -> List[str]:

        accounts = []

        for number in (
            self.bank_account_pattern.findall(
                text
            )
        ):

            if len(number) >= 9:

                accounts.append(
                    number
                )

        return self._unique(
            accounts
        )

    # ========================================================
    # SEBI Extraction
    # ========================================================

    def extract_sebi_numbers(
        self,
        text: str,
    ) -> List[str]:

        return self._unique(
            self.sebi_pattern.findall(
                text
            )
        )

    # ========================================================
    # Date Extraction
    # ========================================================

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

        # ----------------------------------------------------
        # URLs
        # ----------------------------------------------------

        entities.urls = (
            self.extract_urls(
                text
            )
        )

        # ----------------------------------------------------
        # Emails
        # ----------------------------------------------------

        entities.emails = (
            self.extract_emails(
                text
            )
        )

        # ----------------------------------------------------
        # Phone Numbers
        # ----------------------------------------------------

        entities.phone_numbers = (
            self.extract_phone_numbers(
                text
            )
        )

        # ----------------------------------------------------
        # UPI IDs
        # ----------------------------------------------------

        entities.upi_ids = (
            self.extract_upi_ids(
                text
            )
        )

        # ----------------------------------------------------
        # IFSC
        # ----------------------------------------------------

        entities.ifsc_codes = (
            self.extract_ifsc_codes(
                text
            )
        )

        # ----------------------------------------------------
        # PAN
        # ----------------------------------------------------

        entities.pan_numbers = (
            self.extract_pan_numbers(
                text
            )
        )

        # ----------------------------------------------------
        # Aadhaar
        # ----------------------------------------------------

        entities.aadhaar_numbers = (
            self.extract_aadhaar_numbers(
                text
            )
        )

        # ----------------------------------------------------
        # Money
        # ----------------------------------------------------

        entities.money_amounts = (
            self.extract_money_amounts(
                text
            )
        )

        # ----------------------------------------------------
        # Percentages
        # ----------------------------------------------------

        entities.percentages = (
            self.extract_percentages(
                text
            )
        )

        # ----------------------------------------------------
        # Bank Accounts
        # ----------------------------------------------------

        entities.bank_accounts = (
            self.extract_bank_accounts(
                text
            )
        )

        # ----------------------------------------------------
        # SEBI
        # ----------------------------------------------------

        entities.sebi_numbers = (
            self.extract_sebi_numbers(
                text
            )
        )

        # ----------------------------------------------------
        # Dates
        # ----------------------------------------------------

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