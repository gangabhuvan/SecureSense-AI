"""
web_content_extraction_service.py

SecureSense AI
Web Content Extraction Service.

Downloads a webpage and extracts
communication-oriented text for NLP analysis.
"""

from __future__ import annotations

import re
from typing import Dict

import requests
from bs4 import BeautifulSoup


class WebContentExtractionService:

    USER_AGENT = (
        "Mozilla/5.0 "
        "(Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/138.0 Safari/537.36"
    )

    TIMEOUT = 10

    MAX_TEXT_LENGTH = 4000

    def extract(
        self,
        url: str,
    ) -> Dict:

        if "://" not in url:
            url = "https://" + url

        try:

            response = requests.get(
                url,
                timeout=self.TIMEOUT,
                headers={
                    "User-Agent": self.USER_AGENT,
                },
            )

            response.raise_for_status()

        except Exception as exc:

            return {
                "success": False,
                "reason": str(exc),
                "text": "",
                "character_count": 0,
                "preview": "",
            }

        soup = BeautifulSoup(
            response.text,
            "lxml",
        )

        # ---------------------------------------------------
        # Remove invisible / non-content elements
        # ---------------------------------------------------

        for tag in soup(
            [
                "script",
                "style",
                "noscript",
                "svg",
                "header",
                "fff",
                "footer",
                "nav",
                "iframe",
                "canvas",
                "aside",
            ]
        ):
            tag.decompose()

        extracted_parts = []

        # ---------------------------------------------------
        # Title
        # ---------------------------------------------------

        if soup.title and soup.title.string:

            title = soup.title.string.strip()

            if title:
                extracted_parts.append(title)

        # ---------------------------------------------------
        # Meta Description
        # ---------------------------------------------------

        meta = soup.find(
            "meta",
            attrs={"name": "description"},
        )

        if (
            meta
            and meta.get("content")
        ):

            extracted_parts.append(
                meta["content"].strip()
            )

        # ---------------------------------------------------
        # Important visible text
        # ---------------------------------------------------

        IMPORTANT_TAGS = [

            "h1",
            "h2",
            "h3",

            "p",

            "label",

            "button",

            "legend",

            "li",

            "span",

            "strong",

            "b",
        ]

        seen = set()

        for tag_name in IMPORTANT_TAGS:

            for element in soup.find_all(
                tag_name
            ):

                text = element.get_text(
                    " ",
                    strip=True,
                )

                text = re.sub(
                    r"\s+",
                    " ",
                    text,
                )

                if len(text) < 4:
                    continue

                if text in seen:
                    continue

                seen.add(text)

                extracted_parts.append(text)

        # ---------------------------------------------------
        # Merge
        # ---------------------------------------------------

        text = "\n".join(
            extracted_parts
        )

        # Remove excessive whitespace

        text = re.sub(
            r"\n{3,}",
            "\n\n",
            text,
        )

        text = re.sub(
            r"[ \t]+",
            " ",
            text,
        )

        text = text.strip()

        # ---------------------------------------------------
        # Prevent extremely large NLP inputs
        # ---------------------------------------------------

        if len(text) > self.MAX_TEXT_LENGTH:

            text = text[
                : self.MAX_TEXT_LENGTH
            ]

        return {

            "success": True,

            "reason": None,

            "text": text,

            "character_count": len(text),

            "preview": text[:1000],
        }


web_content_extraction_service = (
    WebContentExtractionService()
)