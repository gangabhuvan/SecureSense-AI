"""
url_feature_service.py

Production feature extraction for the SecureSense AI
URL Phishing Intelligence model.

Produces the exact 17-feature contract used during training:
    - 12 lexical URL features
    - 5 network/domain intelligence features
"""

import math
import socket
from collections import Counter
from datetime import datetime, timezone
from typing import Dict
from urllib.parse import urlparse

import dns.resolver
import tldextract
import whois


class URLFeatureService:
    """
    Extract the 17 features required by the frozen
    SecureSense URL phishing model.
    """

    FEATURE_ORDER = [
        "entropy",
        "url_length",
        "num_www",
        "ratio_digits_url",
        "num_subdomains",
        "length_hostname",
        "num_dots",
        "num_hyphens",
        "ratio_digits_host",
        "prefix_suffix",
        "num_question_mark",
        "num_eq",
        "domain_age",
        "dns_resolvable",
        "num_ips",
        "ttl",
        "num_name_servers",
    ]

    def __init__(self) -> None:
        # Use bundled Public Suffix List snapshot.
        # Avoids downloading data every time the backend starts.
        self.tld_extractor = tldextract.TLDExtract(
            suffix_list_urls=None
        )

    # ========================================================
    # Public API
    # ========================================================

    def extract(self, url: str) -> Dict[str, float]:
        """
        Extract all 17 production features from a URL.
        """

        normalized_url = self._normalize_url(url)

        parsed = urlparse(normalized_url)

        hostname = (
            parsed.hostname or ""
        ).lower().strip(".")

        if not hostname:
            raise ValueError(
                "Unable to determine hostname from URL."
            )

        lexical = self._extract_lexical_features(
            normalized_url,
            hostname,
        )

        network = self._extract_network_features(
            hostname
        )

        features = {
            **lexical,
            **network,
        }

        # Enforce exact model feature contract.
        missing = [
            feature
            for feature in self.FEATURE_ORDER
            if feature not in features
        ]

        if missing:
            raise RuntimeError(
                f"Missing URL features: {missing}"
            )

        return {
            feature: features[feature]
            for feature in self.FEATURE_ORDER
        }

    # ========================================================
    # URL normalization
    # ========================================================

    @staticmethod
    def _normalize_url(url: str) -> str:

        if not isinstance(url, str):
            raise ValueError(
                "URL must be a string."
            )

        url = url.strip()

        if not url:
            raise ValueError(
                "URL cannot be empty."
            )

        if "://" not in url:
            url = f"https://{url}"

        return url

    # ========================================================
    # Lexical features
    # ========================================================

    def _extract_lexical_features(
        self,
        url: str,
        hostname: str,
    ) -> Dict[str, float]:

        extracted = self.tld_extractor(
            hostname
        )

        # Verified against dataset semantics:
        #
        # sub.example.com
        # → one subdomain
        #
        # a.b.example.com
        # → two subdomains

        subdomain = (
            extracted.subdomain or ""
        )

        if subdomain:

            num_subdomains = len(
                [
                    part
                    for part in subdomain.split(".")
                    if part
                ]
            )

        else:

            num_subdomains = 0

        # Verified dataset semantics:
        # prefix_suffix is based on the main domain label.

        domain_label = (
            extracted.domain or ""
        )

        prefix_suffix = (
            1
            if "-" in domain_label
            else 0
        )

        url_length = len(url)

        digit_count_url = sum(
            character.isdigit()
            for character in url
        )

        ratio_digits_url = (
            digit_count_url / url_length
            if url_length
            else 0.0
        )

        hostname_length = len(
            hostname
        )

        digit_count_host = sum(
            character.isdigit()
            for character in hostname
        )

        ratio_digits_host = (
            digit_count_host / hostname_length
            if hostname_length
            else 0.0
        )

        return {
            "entropy":
                self._entropy(url),

            "url_length":
                url_length,

            "num_www":
                url.lower().count("www"),

            "ratio_digits_url":
                ratio_digits_url,

            "num_subdomains":
                num_subdomains,

            "length_hostname":
                hostname_length,

            "num_dots":
                url.count("."),

            "num_hyphens":
                url.count("-"),

            "ratio_digits_host":
                ratio_digits_host,

            "prefix_suffix":
                prefix_suffix,

            "num_question_mark":
                url.count("?"),

            "num_eq":
                url.count("="),
        }

    # ========================================================
    # Shannon entropy
    # ========================================================

    @staticmethod
    def _entropy(value: str) -> float:

        if not value:
            return 0.0

        counts = Counter(value)

        length = len(value)

        entropy = 0.0

        for count in counts.values():

            probability = (
                count / length
            )

            entropy -= (
                probability
                *
                math.log2(probability)
            )

        return entropy

    # ========================================================
    # Network features
    # ========================================================

    def _extract_network_features(
        self,
        hostname: str,
    ) -> Dict[str, float]:

        # Defaults match the semantics established
        # from the training dataset.
        dns_resolvable = 0
        num_ips = 0
        ttl = -1
        num_name_servers = 0

        # ----------------------------------------------------
        # DNS A / AAAA lookup
        # ----------------------------------------------------

        try:

            ip_addresses = set()

            ttl_values = []

            for record_type in (
                "A",
                "AAAA",
            ):

                try:

                    answers = dns.resolver.resolve(
                        hostname,
                        record_type,
                        lifetime=3.0,
                    )

                    ttl_values.append(
                        answers.rrset.ttl
                    )

                    for answer in answers:

                        ip_addresses.add(
                            answer.to_text()
                        )

                except Exception:
                    pass

            if ip_addresses:

                dns_resolvable = 1

                num_ips = len(
                    ip_addresses
                )

                if ttl_values:

                    # Use minimum observed TTL as the
                    # conservative DNS lifetime.
                    ttl = min(
                        ttl_values
                    )

                else:
                    ttl = 0

        except Exception:
            pass

        # ----------------------------------------------------
        # Nameserver lookup
        # ----------------------------------------------------

        try:

            extracted = self.tld_extractor(
                hostname
            )

            registered_domain = (
                extracted.top_domain_under_public_suffix
            )

            lookup_domain = (
                registered_domain
                or hostname
            )

            answers = dns.resolver.resolve(
                lookup_domain,
                "NS",
                lifetime=3.0,
            )

            nameservers = {
                answer.to_text()
                .lower()
                .rstrip(".")
                for answer in answers
            }

            num_name_servers = len(
                nameservers
            )

        except Exception:

            num_name_servers = 0

        # ----------------------------------------------------
        # Domain age
        # ----------------------------------------------------

        domain_age = self._get_domain_age(
            hostname
        )

        return {
            "domain_age":
                domain_age,

            "dns_resolvable":
                dns_resolvable,

            "num_ips":
                num_ips,

            "ttl":
                ttl,

            "num_name_servers":
                num_name_servers,
        }

    # ========================================================
    # WHOIS domain age
    # ========================================================

    def _get_domain_age(
        self,
        hostname: str,
    ) -> float:

        try:

            extracted = self.tld_extractor(
                hostname
            )

            registered_domain = (
                extracted.top_domain_under_public_suffix
            )

            if not registered_domain:
                return -1

            information = whois.whois(
                registered_domain
            )

            creation_date = (
                information.creation_date
            )

            # WHOIS libraries sometimes return
            # multiple creation dates.
            if isinstance(
                creation_date,
                list
            ):

                creation_date = next(
                    (
                        date
                        for date in creation_date
                        if date is not None
                    ),
                    None,
                )

            if creation_date is None:
                return -1

            if creation_date.tzinfo is None:

                creation_date = (
                    creation_date.replace(
                        tzinfo=timezone.utc
                    )
                )

            now = datetime.now(
                timezone.utc
            )

            age = (
                now - creation_date
            ).days

            if age < 0:
                return -1

            return float(age)

        except Exception:

            # Training dataset semantics:
            # unavailable domain age = -1
            return -1


# Singleton
url_feature_service = URLFeatureService()