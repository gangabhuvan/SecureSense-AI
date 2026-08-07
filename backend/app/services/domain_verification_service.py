"""
domain_verification_service.py

Official Domain Intelligence for SecureSense AI.

Determines whether a URL belongs to a known official provider or trusted namespace
(e.g., restricted government and academic TLDs).

This service NEVER classifies phishing on its own.
It provides authenticity evidence about the hosting infrastructure,
including trust categories and user-generated content flags,
to be consumed by downstream multimodal fusion.
"""

from urllib.parse import urlparse
import tldextract


class DomainVerificationService:

    # ========================================================
    # Explicit Trusted Providers Database
    # ========================================================

    TRUSTED_DOMAINS = {

        # ---------------- Google ----------------

        "google.com": {
            "provider": "Google",
            "provider_type": "Technology",
            "trust_category": "Technology",
            "user_generated": False,
        },
        "docs.google.com": {
            "provider": "Google",
            "service": "Google Docs / Google Forms",
            "provider_type": "Document & Form Hosting",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "drive.google.com": {
            "provider": "Google Drive",
            "provider_type": "Cloud Storage",
            "trust_category": "Hosting",
            "user_generated": True,
        },

        # ---------------- Microsoft ----------------

        "microsoft.com": {
            "provider": "Microsoft",
            "provider_type": "Technology",
            "trust_category": "Technology",
            "user_generated": False,
        },
        "office.com": {
            "provider": "Microsoft Office",
            "provider_type": "Office Platform",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "office365.com": {
            "provider": "Microsoft 365",
            "provider_type": "Office Platform",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "sharepoint.com": {
            "provider": "SharePoint",
            "provider_type": "Document Hosting",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "onedrive.live.com": {
            "provider": "OneDrive",
            "provider_type": "Cloud Storage",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "live.com": {
            "provider": "Microsoft Live",
            "provider_type": "Identity",
            "trust_category": "Technology",
            "user_generated": False,
        },

        # ---------------- Cloud & File Hosting ----------------

        "dropbox.com": {
            "provider": "Dropbox",
            "provider_type": "Cloud Storage",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "box.com": {
            "provider": "Box",
            "provider_type": "Cloud Storage",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "github.com": {
            "provider": "GitHub",
            "provider_type": "Code Hosting",
            "trust_category": "Hosting",
            "user_generated": True,
        },
        "aws.amazon.com": {
            "provider": "Amazon Web Services",
            "provider_type": "Cloud Platform",
            "trust_category": "Hosting",
            "user_generated": True,
        },

        # ---------------- Tech Giants ----------------

        "amazon.com": {
            "provider": "Amazon",
            "provider_type": "Commerce",
            "trust_category": "Commerce",
            "user_generated": False,
        },
        "apple.com": {
            "provider": "Apple",
            "provider_type": "Technology",
            "trust_category": "Technology",
            "user_generated": False,
        },
        "adobe.com": {
            "provider": "Adobe",
            "provider_type": "Software",
            "trust_category": "Technology",
            "user_generated": False,
        },
        "oracle.com": {
            "provider": "Oracle",
            "provider_type": "Technology",
            "trust_category": "Technology",
            "user_generated": False,
        },

        # ---------------- Government (India Explicit Overrides) ----------------

        "sebi.gov.in": {
            "provider": "SEBI",
            "provider_type": "Regulatory Body",
            "trust_category": "Government",
            "user_generated": False,
        },
        "rbi.org.in": {
            "provider": "Reserve Bank of India",
            "provider_type": "Central Bank",
            "trust_category": "Government",
            "user_generated": False,
        },
        "uidai.gov.in": {
            "provider": "UIDAI",
            "provider_type": "Identity Authority",
            "trust_category": "Government",
            "user_generated": False,
        },
        "digilocker.gov.in": {
            "provider": "DigiLocker",
            "provider_type": "Digital Document Wallet",
            "trust_category": "Government",
            "user_generated": False,
        },

        # ---------------- Academic (Explicit Overrides) ----------------

        "mit.edu": {
            "provider": "MIT",
            "provider_type": "University",
            "trust_category": "Academic",
            "user_generated": False,
        },
        "stanford.edu": {
            "provider": "Stanford University",
            "provider_type": "University",
            "trust_category": "Academic",
            "user_generated": False,
        },

        # ---------------- Financial / Exchanges / Banks / Brokers ----------------

        "nseindia.com": {
            "provider": "National Stock Exchange",
            "provider_type": "Financial Exchange",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "bseindia.com": {
            "provider": "Bombay Stock Exchange",
            "provider_type": "Financial Exchange",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "sbi.co.in": {
            "provider": "State Bank of India",
            "provider_type": "Bank",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "onlinesbi.sbi": {
            "provider": "State Bank of India",
            "provider_type": "Bank",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "icicibank.com": {
            "provider": "ICICI Bank",
            "provider_type": "Bank",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "hdfcbank.com": {
            "provider": "HDFC Bank",
            "provider_type": "Bank",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "zerodha.com": {
            "provider": "Zerodha",
            "provider_type": "Broker",
            "trust_category": "Financial",
            "user_generated": False,
        },
        "groww.in": {
            "provider": "Groww",
            "provider_type": "Broker",
            "trust_category": "Financial",
            "user_generated": False,
        },
    }

    def verify(self, url: str) -> dict:
        """
        Analyzes a URL against explicit trusted infrastructure and generic 
        restricted TLD namespaces (Academic / Government).
        """
        if not url:
            return self._default_response(None)

        if "://" not in url:
            url = "https://" + url

        try:
            parsed = urlparse(url)
            hostname = (parsed.hostname or "").lower()
            extracted = tldextract.extract(hostname)
            registered_domain = extracted.registered_domain.lower()
            suffix = extracted.suffix.lower()
        except Exception:
            return self._default_response(None)

        # 1. Match against explicit domain database (longest domain match)
        matched_metadata = None
        longest_match = 0

        for domain, metadata in self.TRUSTED_DOMAINS.items():
            if (
                hostname == domain
                or hostname.endswith("." + domain)
                or registered_domain == domain
            ):
                if len(domain) > longest_match:
                    matched_metadata = metadata
                    longest_match = len(domain)

        if matched_metadata:
            return {
                "official_domain": True,
                "official_provider": matched_metadata["provider"],
                "provider_type": matched_metadata["provider_type"],
                "trust_category": matched_metadata["trust_category"],
                "official_hosting_platform": matched_metadata["user_generated"],
                "user_generated_content": matched_metadata["user_generated"],
                "registered_domain": registered_domain,
            }

        # 2. Generic Government Namespace Detection
        if (
            suffix == "gov"
            or suffix.startswith("gov.")
            or suffix.endswith(".gov")
            or ".gov." in suffix
            or suffix in ("gob.es", "gouv.fr", "gob.mx")
        ):
            return {
                "official_domain": True,
                "official_provider": registered_domain,
                "provider_type": "Government Entity",
                "trust_category": "Government",
                "official_hosting_platform": False,
                "user_generated_content": False,
                "registered_domain": registered_domain,
            }

        # 3. Generic Academic Namespace Detection
        if (
            suffix == "edu"
            or suffix.startswith("edu.")
            or suffix.endswith(".edu")
            or suffix.startswith("ac.")
            or suffix.endswith(".ac")
            or ".ac." in suffix
            or ".edu." in suffix
        ):
            return {
                "official_domain": True,
                "official_provider": registered_domain,
                "provider_type": "Academic Institution",
                "trust_category": "Academic",
                "official_hosting_platform": False,
                "user_generated_content": False,
                "registered_domain": registered_domain,
            }

        # 4. Fallback for untrusted or general domains
        return self._default_response(registered_domain)

    def _default_response(self, registered_domain: str) -> dict:
        """Helper to return a standardized dictionary when no match is found."""
        return {
            "official_domain": False,
            "official_provider": None,
            "provider_type": None,
            "trust_category": None,
            "official_hosting_platform": False,
            "user_generated_content": False,
            "registered_domain": registered_domain,
        }


# Singleton instance for simple importing
domain_verification_service = DomainVerificationService()