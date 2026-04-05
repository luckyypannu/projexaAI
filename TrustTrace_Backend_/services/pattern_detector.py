"""
services/pattern_detector.py

Responsibilities:
1. classify_input()  — detect input type (url, phone, email)
2. detect_patterns() — apply heuristic detection rules

Features:
- Robust regex classification
- Phishing / scam heuristics
- Typosquatting detection
- Safe parsing + debug logging
"""

from __future__ import annotations

import re
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────────
# Input Classification
# ──────────────────────────────────────────────────────────────────────────────

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)
_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,20}$")


def classify_input(raw: str) -> str:
    """
    Classify input into: email, phone, or url.
    """
    try:
        if _EMAIL_RE.match(raw):
            return "email"
        if _PHONE_RE.match(raw):
            return "phone"
    except Exception as e:
        logger.warning("Classification failed: %s", e)

    return "url"


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _extract_domain(raw: str) -> str:
    """Extract domain safely."""
    try:
        if "://" not in raw:
            raw = "http://" + raw
        return urlparse(raw).netloc.lower().lstrip("www.")
    except Exception:
        return raw.lower()


# ──────────────────────────────────────────────────────────────────────────────
# URL Detection
# ──────────────────────────────────────────────────────────────────────────────

_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".online", ".site", ".icu",
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".cc", ".pw", ".ws",
}

_PHISHING_KEYWORDS = {
    "login", "verify", "secure", "update", "confirm",
    "account", "signin", "banking", "password",
}

_BRAND_NAMES = {
    "paypal", "apple", "amazon", "google", "microsoft",
    "netflix", "facebook", "instagram", "twitter",
}

_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "@": "a",
}


def _normalize_domain(domain: str) -> str:
    for fake, real in _HOMOGLYPHS.items():
        domain = domain.replace(fake, real)
    return domain


def _is_typosquat(domain: str) -> bool:
    try:
        base = re.sub(r"\.[^.]+$", "", domain)
        norm = _normalize_domain(base)

        for brand in _BRAND_NAMES:
            if norm == brand or (brand in norm and norm != brand):
                return True
    except Exception:
        pass

    return False


def _detect_url_patterns(raw: str) -> list[str]:
    flags = []

    try:
        domain = _extract_domain(raw)
        full = raw.lower()

        # Suspicious TLD
        if any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS):
            flags.append("Suspicious top-level domain")

        # Too many hyphens
        if any(label.count("-") >= 3 for label in domain.split(".")):
            flags.append("Excessive hyphens in domain")

        # Keywords
        if any(kw in full for kw in _PHISHING_KEYWORDS):
            flags.append("Phishing keyword detected")

        # Typosquatting
        if _is_typosquat(domain):
            flags.append("Possible brand impersonation")

        # Raw IP
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}", domain):
            flags.append("Uses IP address instead of domain")

        # Deep subdomain
        if domain.count(".") >= 5:
            flags.append("Unusual subdomain depth")

        # HTTP + sensitive keywords
        if raw.startswith("http://") and any(
            kw in full for kw in {"login", "secure", "account"}
        ):
            flags.append("Sensitive action over HTTP")

    except Exception as e:
        logger.error("URL detection failed: %s", e)

    return flags


# ──────────────────────────────────────────────────────────────────────────────
# Phone Detection
# ──────────────────────────────────────────────────────────────────────────────

_HIGH_RISK_CODES = {"+234", "+91", "+92", "+880", "+7"}


def _detect_phone_patterns(raw: str) -> list[str]:
    flags = []

    try:
        digits = re.sub(r"[^\d+]", "", raw)
        count = len(re.sub(r"\D", "", digits))

        if count < 7 or count > 15:
            flags.append("Invalid phone length")

        if any(digits.startswith(code) for code in _HIGH_RISK_CODES):
            flags.append("High-risk country code")

        if re.search(r"(\d)\1{6,}", digits):
            flags.append("Repeating digits pattern")

    except Exception as e:
        logger.error("Phone detection failed: %s", e)

    return flags


# ──────────────────────────────────────────────────────────────────────────────
# Email Detection
# ──────────────────────────────────────────────────────────────────────────────

_FREE_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com"
}


def _detect_email_patterns(raw: str) -> list[str]:
    flags = []

    try:
        local, domain = raw.lower().split("@")

        norm = _normalize_domain(domain)

        # Free provider spoof
        if any(p.split(".")[0] in norm for p in _FREE_PROVIDERS):
            if domain not in _FREE_PROVIDERS:
                flags.append("Possible email provider impersonation")

        # Brand impersonation
        if _is_typosquat(domain):
            flags.append("Brand impersonation in email")

        # Suspicious local part
        if any(kw in local for kw in {"admin", "support", "verify"}):
            flags.append("Suspicious email prefix")

        # Obfuscation
        if local.count(".") >= 4 or local.count("-") >= 3:
            flags.append("Obfuscated email format")

    except Exception as e:
        logger.error("Email detection failed: %s", e)
        flags.append("Invalid email format")

    return flags


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def detect_patterns(raw: str, input_type: str) -> list[str]:
    """
    Main dispatcher.
    """
    try:
        if input_type == "url":
            return _detect_url_patterns(raw)

        if input_type == "phone":
            return _detect_phone_patterns(raw)

        if input_type == "email":
            return _detect_email_patterns(raw)

    except Exception as e:
        logger.error("Pattern detection failed: %s", e)

    return []