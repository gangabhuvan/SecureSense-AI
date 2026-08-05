"""
authenticity_engine.py

Authenticity Verification Engine (AVE)

Purpose
-------
Verify whether available communication metadata appears to
originate from a known legitimate source.

Important
---------
The absence of verifiable metadata is NOT treated as failed
verification.

Likewise, syntactically valid metadata is NOT automatically
treated as official.

Current checks
--------------
- Official domain
- Official email domain
- Known official phone
- Metadata consistency

Prototype verification sources
------------------------------
Known domains and phone numbers are currently maintained in
local allow-lists.

Future production sources may include:
- Bank / institution registries
- SEBI registered entity data
- RBI data
- TRAI / official contact registries
- WHOIS / DNS intelligence
- Digital signatures
- Certificate validation
"""

from urllib.parse import urlparse

from app.fcp.models import (
    VerificationStatus,
)


class AuthenticityEngine:
    """
    Performs authenticity verification on communication
    metadata extracted by SecureSense AI.
    """

    def __init__(self) -> None:

        # -------------------------------------------------
        # Prototype official-domain registry
        # -------------------------------------------------

        self.official_domains = {
            # Technology
            "google.com",
            "microsoft.com",
            "amazon.com",
            "ieee.org",
            "acm.org",

            # Government
            "sebi.gov.in",
            "rbi.org.in",
            "isro.gov.in",
            "uidai.gov.in",

            # Banking
            "onlinesbi.sbi",
            "sbi.co.in",
            "icicibank.com",
            "hdfcbank.com",
            "axisbank.com",
            "kotak.com",
        }

        # -------------------------------------------------
        # Prototype official-phone registry
        #
        # Keep empty until numbers are sourced from a
        # trusted registry/configuration.
        #
        # Never classify a number as official merely
        # because it is syntactically valid.
        # -------------------------------------------------

        self.official_phones: set[str] = set()

    # =====================================================
    # Public API
    # =====================================================

    def verify(
        self,
        sender_email: str | None = None,
        sender_phone: str | None = None,
        website: str | None = None,
    ) -> VerificationStatus:
        """
        Verify available communication metadata.

        Status semantics
        ----------------
        Insufficient Data:
            No verifiable sender metadata was available.

        Verified:
            At least one supplied identity signal matches a
            trusted official registry and no supplied signal
            conflicts with that result.

        Not Verified:
            Metadata was supplied, but none of the supplied
            identity signals could be verified as official.
        """

        status = VerificationStatus()

        # -------------------------------------------------
        # Determine which signals are actually available
        # -------------------------------------------------

        has_domain = bool(
            website
            and website.strip()
        )

        has_email = bool(
            sender_email
            and sender_email.strip()
        )

        has_phone = bool(
            sender_phone
            and sender_phone.strip()
        )

        has_verifiable_metadata = (
            has_domain
            or has_email
            or has_phone
        )

        # -------------------------------------------------
        # No identity metadata
        # -------------------------------------------------

        if not has_verifiable_metadata:

            status.metadata_consistent = True

            status.verification_confidence = 0.0

            status.status = (
                "Insufficient Data"
            )

            return status

        # -------------------------------------------------
        # Individual verification checks
        # -------------------------------------------------

        if has_domain:

            status.official_domain = (
                self._verify_domain(
                    website
                )
            )

        if has_email:

            status.official_email = (
                self._verify_email(
                    sender_email
                )
            )

        if has_phone:

            status.official_phone = (
                self._verify_phone(
                    sender_phone
                )
            )

        # -------------------------------------------------
        # Metadata consistency
        #
        # At present we can meaningfully compare the
        # website domain and email domain.
        # -------------------------------------------------

        status.metadata_consistent = (
            self._metadata_consistent(
                sender_email=(
                    sender_email
                    if has_email
                    else None
                ),
                website=(
                    website
                    if has_domain
                    else None
                ),
            )
        )

        # -------------------------------------------------
        # Verification score
        #
        # Score represents strength of authenticity
        # evidence, NOT fraud probability.
        # -------------------------------------------------

        score = 0.0

        if status.official_domain:
            score += 40.0

        if status.official_email:
            score += 30.0

        if status.official_phone:
            score += 20.0

        if (
            status.metadata_consistent
            and (
                has_domain
                and has_email
            )
        ):
            score += 10.0

        status.verification_confidence = (
            min(
                100.0,
                score,
            )
        )

        # -------------------------------------------------
        # Final AVE status
        # -------------------------------------------------

        verified_signal = (
            status.official_domain
            or status.official_email
            or status.official_phone
        )

        if (
            verified_signal
            and status.metadata_consistent
        ):

            status.status = "Verified"

        else:

            status.status = (
                "Not Verified"
            )

        return status

    # =====================================================
    # Domain Verification
    # =====================================================

    def _verify_domain(
        self,
        website: str,
    ) -> bool:
        """
        Verify a website against the trusted domain registry.
        """

        domain = self._extract_domain(
            website
        )

        if not domain:
            return False

        for official in self.official_domains:
            if domain == official or domain.endswith("." + official):
                return True

        return False

    # =====================================================
    # Email Verification
    # =====================================================

    def _verify_email(
        self,
        email: str,
    ) -> bool:
        """
        Verify the sender email domain against the trusted
        domain registry.
        """

        email = email.strip().lower()

        if "@" not in email:
            return False

        domain = (
            email
            .rsplit("@", 1)[-1]
            .strip()
            .rstrip(".")
        )

        if not domain:
            return False

        return domain in self.official_domains

    # =====================================================
    # Phone Verification
    # =====================================================

    def _verify_phone(
        self,
        phone: str,
    ) -> bool:
        """
        Verify a phone number against the trusted phone
        registry.

        A valid-looking number alone is NOT sufficient to
        establish authenticity.
        """

        normalized = (
            self._normalize_phone(
                phone
            )
        )

        if not normalized:
            return False

        return (
            normalized
            in self.official_phones
        )

    # =====================================================
    # Metadata Consistency
    # =====================================================

    def _metadata_consistent(
        self,
        sender_email: str | None,
        website: str | None,
    ) -> bool:
        """
        Check whether independently supplied identity signals
        agree with one another.

        Currently compares email and website domains.
        """

        # Nothing to compare.
        if not (
            sender_email
            and website
        ):
            return True

        email = (
            sender_email
            .strip()
            .lower()
        )

        if "@" not in email:
            return False

        email_domain = (
            email
            .rsplit("@", 1)[-1]
            .strip()
            .rstrip(".")
        )

        website_domain = (
            self._extract_domain(
                website
            )
        )

        if not (
            email_domain
            and website_domain
        ):
            return False

        return (
            email_domain
            == website_domain
        )

    # =====================================================
    # Helpers
    # =====================================================

    @staticmethod
    def _extract_domain(
        website: str,
    ) -> str | None:
        """
        Normalize a URL/domain into a comparable hostname.

        Supports values both with and without a URL scheme.
        """

        if not website:
            return None

        value = (
            website
            .strip()
            .lower()
        )

        if not value:
            return None

        # urlparse interprets a bare domain as a path.
        if "://" not in value:

            value = (
                "https://"
                + value
            )

        try:

            parsed = urlparse(
                value
            )

            domain = (
                parsed.hostname
                or ""
            ).lower()

        except Exception:

            return None

        if domain.startswith(
            "www."
        ):

            domain = domain[4:]

        domain = domain.rstrip(".")

        return domain or None

    @staticmethod
    def _normalize_phone(
        phone: str,
    ) -> str | None:
        """
        Normalize a phone number for registry comparison.

        This performs normalization only. It does NOT claim
        that the number is authentic.
        """

        digits = "".join(
            character
            for character in phone
            if character.isdigit()
        )

        if not digits:
            return None

        return digits


# ==========================================================
# Singleton
# ==========================================================

authenticity_engine = AuthenticityEngine()