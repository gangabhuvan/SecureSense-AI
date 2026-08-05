"""
communication_selector.py

SecureSense AI

Selects reader-directed communication from OCR text or webpage text 
before NLP analysis. Uses block-level semantic grouping to reconstruct 
fragmented text (e.g., forms, emails) and evaluate them as cohesive units.

This module DOES NOT perform phishing detection.
Its responsibility is only to reduce non-communicative document noise 
so that DistilBERT receives text closer to its trained distribution.
"""

from __future__ import annotations

import re
from typing import List


class DocumentType:
    EMAIL = "email"
    FORM = "form"
    POSTER = "poster"
    GENERIC = "generic"


class CommunicationSelector:

    MAX_OUTPUT_CHARS = 1400  
    MIN_BLOCK_LENGTH = 10
    SCORE_THRESHOLD = 4

    # =====================================================
    # Tuning Weights (Candidate for external config post-prototype)
    # =====================================================
    CTA_WEIGHT = 4
    EMAIL_WEIGHT = 4
    URL_WEIGHT = 4
    QUESTION_WEIGHT = 3
    FORM_COLON_WEIGHT = 2
    REQUIRED_WEIGHT = 2
    INPUT_LABEL_WEIGHT = 5
    FORM_FIELD_WEIGHT = 3
    AUTH_WEIGHT = 6
    FINANCIAL_WEIGHT = 2
    NOISE_WEIGHT = -5
    POSTER_CONTEXT_WEIGHT = 8  # Strongly boosts core event context over CTAs

    # =====================================================
    # Patterns & Vocabularies
    # =====================================================
    
    _CTA_LIST = [
        r"verify identity", r"verify account", r"verify now", r"one time password",
        r"log in", r"sign in", r"click", r"verify", r"confirm", r"login",
        r"register", r"registration", r"submit", r"continue", r"pay", r"payment", 
        r"scan", r"download", r"install", r"activate", r"reset", r"update", 
        r"complete", r"fill", r"enter", r"upload", r"apply", r"contact", r"call", 
        r"email", r"visit", r"book", r"join", r"start", r"proceed", r"next", 
        r"claim", r"unlock", r"resume", r"authenticate"
    ]
    _CTA_LIST.sort(key=len, reverse=True)
    CTA_PATTERN = re.compile(r"\b(" + "|".join(_CTA_LIST) + r")\b")

    _INFO_LIST = [
        r"all rights reserved", r"committee", r"sponsor", r"chair", r"conference",
        r"workshop", r"proceedings", r"volume", r"issue", r"isbn", r"issn",
        r"organizing", r"technical", r"advisory", r"venue", r"copyright"
    ]
    _INFO_LIST.sort(key=len, reverse=True)
    INFORMATION_PATTERN = re.compile(r"\b(" + "|".join(_INFO_LIST) + r")\b")

    # Compiled regex for faster poster context extraction
    # Removed "deadline" to prevent standard phishing emails from being flagged as posters
    POSTER_PATTERN = re.compile(
        r"\b(hackathon|award|prize|competition|webinar|summit|bootcamp|event)\b",
        re.I
    )
    
    # Event keywords used to unconditionally rescue header/context blocks
    EVENT_KEYWORDS = {
        "hackathon", "conference", "workshop", "symposium", "seminar",
        "innovation", "research", "competition", "contest", "summit",
        "ieee", "acm", "university", "chapter", "theme", "organized"
    }
    
    # Sensitive targets handled purely in scoring, NOT document classification
    AUTH_KEYWORDS = {"otp", "password", "pin", "cvv", "aadhaar", "pan", "upi"}
    FINANCIAL_KEYWORDS = {"account", "transaction", "refund", "bank", "wallet", "beneficiary", "amount", "ifsc"}

    # OCR-Tolerant Patterns
    EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+\s*@\s*[A-Za-z0-9.-]+\s*\.\s*[A-Za-z]{2,}", re.I)
    URL_PATTERN = re.compile(
        r"(https?[\s:/\\]+\S+"
        r"|www\.\S+"
        r"|[A-Za-z0-9.-]+\s*\.\s*(org|com|net|edu|gov|in|co|io|ai)\b)",
        re.I,
    )
    
    INPUT_LABEL_PATTERN = re.compile(r"\b(enter|select|choose|provide)\b")
    FORM_COLON_PATTERN = re.compile(r"\b(name|email|phone|password|otp|upi|amount|cvv|pin)\s*:")
    
    # Structural fields used purely to detect if a document is a form
    FORM_STRUCTURE_PATTERN = re.compile(
        r"\b(name|email|phone|mobile|address|city|state|country|age|gender|dob)\b", 
        re.I
    )
    
    HEADER_PATTERN = re.compile(r"^(from|to|subject|date|cc|bcc)\s*:", re.I)

    # =====================================================
    # Document Type Detection
    # =====================================================

    def _detect_document_type(self, text: str) -> str:
        """
        Uses simple heuristics to categorize the document context, 
        allowing dynamic weight adjustments for edge cases like posters.
        """
        lower = text.lower()
        
        # Email Check
        if re.search(r"^(from|to|subject|date)\s*:", lower, re.M):
            return DocumentType.EMAIL
            
        # Form Check (Robust to OCR missing 'submit')
        form_indicators = sum(1 for _ in self.FORM_STRUCTURE_PATTERN.finditer(lower))
        if form_indicators >= 3 or (form_indicators >= 2 and self.INPUT_LABEL_PATTERN.search(lower)):
            return DocumentType.FORM
            
        # Poster Check using the compiled POSTER_PATTERN
        poster_indicators = sum(1 for _ in self.INFORMATION_PATTERN.finditer(lower))
        if poster_indicators >= 2 or re.search(r"\b(venue|sponsor|register here)\b", lower) or self.POSTER_PATTERN.search(lower):
            return DocumentType.POSTER
            
        return DocumentType.GENERIC

    # =====================================================
    # Block Formatting & Reconstruction
    # =====================================================

    def _reconstruct_blocks(self, text: str, doc_type: str = DocumentType.GENERIC) -> List[str]:
        """
        Merges fragmented OCR lines into cohesive paragraphs/blocks.
        Forces splits on major communication shifts to handle missing newlines.
        """
        lines = [
            re.sub(r"\s+", " ", line).strip()
            for line in text.splitlines()
        ]

        lines = [line for line in lines if line]
        if not lines:
            return []

        blocks = []
        current = []

        def flush():
            nonlocal current
            if current:
                blocks.append(" ".join(current))
                current = []

        for line in lines:
            lower = line.lower()

            # Start a new block before important communication cues.
            if current and (
                "registration deadline" in lower
                or "more information" in lower
                or "information" in lower
                or "scan" in lower
                or "contact" in lower
                or "upi" in lower
                or self.EMAIL_PATTERN.search(line)
                or (
                    self.URL_PATTERN.search(line)
                    and doc_type != DocumentType.POSTER
                )
            ):
                flush()

            current.append(line)

        flush()

        return [
            block for block in blocks 
            if len(block) >= self.MIN_BLOCK_LENGTH
        ]

    # =====================================================
    # Quality Filtering
    # =====================================================

    def _is_low_quality_block(
        self,
        block: str,
    ) -> bool:
        """
        Reject OCR blocks that are mostly garbage before NLP.
        """

        lower = block.lower()

        noise_keywords = (
            "margin",
            "padding",
            "align",
            "font",
            "color",
            "border",
            "shadow",
            "round_",
            "sticky",
            "content",
            "weight",
            "normal",
        )

        noise_hits = sum(
            word in lower
            for word in noise_keywords
        )

        if noise_hits >= 2:
            return True

        words = re.findall(
            r"[A-Za-z]+",
            block,
        )

        if len(words) < 5:
            return True

        long_words = sum(
            len(word) >= 3
            for word in words
        )

        if len(words) > 0 and (long_words / len(words)) < 0.55:
            return True

        return False

    # =====================================================
    # Scoring
    # =====================================================

    def _block_score(self, block: str, doc_type: str) -> int:
        """
        Evaluates an entire reconstructed block.
        """
        url_stripped = self.URL_PATTERN.sub("", block).strip()
        if len(url_stripped) < 3: 
            return 0
            
        score = 0
        lower = block.lower()

        # 1. CTAs - De-weight for posters to prevent isolated actions from dominating
        matches = sum(1 for _ in self.CTA_PATTERN.finditer(lower))
        if doc_type == DocumentType.POSTER:
            score += (matches * 2)
        else:
            score += (matches * self.CTA_WEIGHT)

        # 2. Comm Markers
        if self.EMAIL_PATTERN.search(block):
            score += self.EMAIL_WEIGHT
        if self.URL_PATTERN.search(block):
            score += self.URL_WEIGHT
        if "?" in block:
            score += self.QUESTION_WEIGHT

        # 3. Forms
        if self.FORM_COLON_PATTERN.search(lower):
            score += self.FORM_COLON_WEIGHT
        if "required" in lower:
            score += self.REQUIRED_WEIGHT
        if self.INPUT_LABEL_PATTERN.search(lower):
            score += self.INPUT_LABEL_WEIGHT
        if self.FORM_STRUCTURE_PATTERN.search(lower):
            score += self.FORM_FIELD_WEIGHT

        # 4. Targets (High-value sensitive keywords)
        for kw in self.AUTH_KEYWORDS:
            if kw in lower:
                score += self.AUTH_WEIGHT
        for kw in self.FINANCIAL_KEYWORDS:
            if kw in lower:
                score += self.FINANCIAL_WEIGHT

        # 5. Event Context Rescue (For Posters)
        if doc_type == DocumentType.POSTER:
            poster_matches = sum(1 for _ in self.POSTER_PATTERN.finditer(lower))
            score += (poster_matches * self.POSTER_CONTEXT_WEIGHT)

        # 6. Noise Penalty
        info_matches = sum(1 for _ in self.INFORMATION_PATTERN.finditer(lower))
        score += (info_matches * self.NOISE_WEIGHT) 

        return score
    
    # =====================================================
    # Main Selection
    # =====================================================

    def select(self, text: str) -> str:
        if not text:
            return ""
            
        # 1. STRUCTURAL HEADER RESCUE
        # Accumulate all lines before the first CTA triggers to preserve multi-line titles
        raw_lines = [line.strip() for line in text.splitlines() if line.strip()]
        header_candidates = []
        
        for line in raw_lines:
            lower = line.lower()
            
            # Stop collecting header once actionable communication starts
            if (
                "scan to register" in lower
                or "scan" in lower
            ):
                break
                
            # Filter OCR garbage from the header
            if len(re.findall(r"[A-Za-z]{3,}", line)) < 2:
                continue
                
            header_candidates.append(line)
            
        header_lines = [
            line.strip()
            for line in header_candidates
            if len(line.strip()) >= 3
        ]
        
        header_text = "\n".join(header_lines)
        
        # Only preserve the header if it contains recognized event identity context
        if not any(kw in header_text.lower() for kw in self.EVENT_KEYWORDS):
            header_text = ""
            
        # 2. STANDARD RECONSTRUCTION & SCORING
        doc_type = self._detect_document_type(text)
        blocks = self._reconstruct_blocks(text, doc_type)
        
        if not blocks:
            fallback_text = header_text if header_text else text.strip()
            if len(fallback_text) > self.MAX_OUTPUT_CHARS:
                return self._safe_truncate(fallback_text)
            return fallback_text

        clean_blocks = [
            block
            for block in blocks
            if not self._is_low_quality_block(block)
        ]

        scored_blocks = [
            (
                self._block_score(
                    block,
                    doc_type,
                ),
                block,
            )
            for block in clean_blocks
        ]
        
        seen = set()
        selected_blocks = []
        
        for score, block in scored_blocks:
            key = block.lower()
            
            # Rescue Event/Header Context regardless of the CTA score
            event_hits = sum(1 for kw in self.EVENT_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", key))
            
            if (score >= self.SCORE_THRESHOLD or event_hits >= 1) and key not in seen:
                seen.add(key)
                selected_blocks.append(block)

        if not selected_blocks:
            best_fallback_blocks = sorted(
                enumerate(scored_blocks), 
                key=lambda x: x[1][0], 
                reverse=True
            )[:1]
            
            best_fallback_blocks.sort(key=lambda x: x[0])
            selected_blocks = [item[1][1] for item in best_fallback_blocks]

        # 3. FINAL COMPILATION & CLEANING
        final_text = "\n\n".join(selected_blocks)
        
        # Prepend the rescued header context without duplicating text
        if header_text:
            header_key = header_text.lower()
            if header_key not in final_text.lower():
                final_text = header_text + "\n\n" + final_text
            
        final_text = re.sub(r"\n{3,}", "\n\n", final_text).strip()
        
        # Clean out inline CSS artifacts that poison DistilBERT
        final_text = re.sub(
            r"\b(?:margin|padding|align|shadow|border|font|color)\b.*",
            "",
            final_text,
            flags=re.I,
        ).strip()

        if len(final_text) > self.MAX_OUTPUT_CHARS:
            return self._safe_truncate(final_text)
            
        return final_text

    def _safe_truncate(self, text: str) -> str:
        truncated = text[:self.MAX_OUTPUT_CHARS]
        last_break = max(truncated.rfind("\n"), truncated.rfind(" "))
        
        if last_break > 0:
            truncated = truncated[:last_break]
            
        return truncated + "..."


communication_selector = CommunicationSelector()