from __future__ import annotations

import re
from urllib.parse import urlparse


# ── Input classification ───────────────────────────────────────────────────────

# Regex patterns for classification (order matters — URL check last so that
# URLs containing @ are not misidentified as email addresses).
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", re.IGNORECASE)
_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,20}$")


def classify_input(raw: str) -> str:
    """
    Return "email", "phone", or "url" for the given raw input string.
    Defaults to "url" if none of the more specific patterns match.
    """
    if _EMAIL_RE.match(raw):
        return "email"
    if _PHONE_RE.match(raw):
        return "phone"
    return "url"


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _extract_domain(raw: str) -> str:
    """Return the netloc (hostname) portion of a URL or email domain."""
    if "://" not in raw:
        raw = "http://" + raw
    return urlparse(raw).netloc.lower().lstrip("www.")


# ── URL / Domain patterns ──────────────────────────────────────────────────────

# TLDs that are disproportionately abused for phishing/spam
_SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".top", ".club", ".online", ".site", ".icu",
    ".tk", ".ml", ".ga", ".cf", ".gq",      # Free Freenom TLDs
    ".cc", ".pw", ".ws",
}

# Keywords in domains frequently used to impersonate legitimate services
_PHISHING_KEYWORDS: set[str] = {
    "login", "verify", "secure", "update", "confirm", "account",
    "signin", "banking", "password", "support", "help", "service",
    "paypal", "apple", "amazon", "google", "microsoft", "netflix",
    "facebook", "instagram", "twitter",
}

# Common brand names that scammers typosquat
_BRAND_NAMES: set[str] = {
    "paypal", "apple", "amazon", "google", "microsoft",
    "netflix", "facebook", "instagram", "twitter", "ebay",
    "wellsfargo", "chase", "barclays", "hsbc",
}

# Characters used to visually mimic Latin letters (simple homoglyph map)
_HOMOGLYPHS: dict[str, str] = {
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "6": "b", "7": "t", "@": "a",
}


def _normalize_domain(domain: str) -> str:
    """Replace common homoglyphs so that paypa1 → paypal."""
    result = domain
    for fake, real in _HOMOGLYPHS.items():
        result = result.replace(fake, real)
    return result


def _is_typosquat(domain: str) -> bool:
    """
    Heuristic typosquatting check:
    - Normalise homoglyphs, strip TLD, and test against known brand names.
    - Also flag domains that *contain* a brand name but are not the official site.
    """
    base = re.sub(r"\.[^.]+$", "", domain)   # remove TLD
    normalised = _normalize_domain(base)

    for brand in _BRAND_NAMES:
        # Exact match after normalisation (e.g. "paypa1" → "paypal")
        if normalised == brand:
            return True
        # Brand name buried in a longer domain (e.g. "paypal-secure.xyz")
        if brand in normalised and normalised != brand:
            return True
    return False


def _detect_url_patterns(raw: str) -> list[str]:
    flags: list[str] = []
    domain = _extract_domain(raw)

    # Suspicious TLD
    for tld in _SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            flags.append(f"Suspicious top-level domain: {tld}")
            break

    # Excessive hyphens (≥ 3 in the domain label)
    labels = domain.split(".")
    for label in labels:
        if label.count("-") >= 3:
            flags.append("Domain contains excessive hyphens — common in phishing URLs")
            break

    # Suspicious keywords in domain or path
    full_lower = raw.lower()
    for kw in _PHISHING_KEYWORDS:
        if re.search(rf"\b{kw}\b", full_lower):
            flags.append(f"Phishing keyword detected in URL: '{kw}'")
            break   # report only the first match to avoid noise

    # Typosquatting / homoglyph impersonation
    if _is_typosquat(domain):
        flags.append(f"Possible brand impersonation / typosquatting: {domain}")

    # IP address used as hostname (direct-IP phishing)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$", domain):
        flags.append("URL uses a raw IP address instead of a domain name")

    # Extremely long subdomain chains (≥ 5 dots in hostname)
    if domain.count(".") >= 5:
        flags.append("Domain has an unusually deep subdomain structure")

    # HTTP (not HTTPS) for a login/payment-related URL
    scheme = raw.split("://")[0].lower() if "://" in raw else "http"
    if scheme == "http":
        for kw in {"login", "verify", "secure", "account", "banking", "password"}:
            if kw in full_lower:
                flags.append("Sensitive operation over unencrypted HTTP connection")
                break

    return flags


# ── Phone number patterns ──────────────────────────────────────────────────────

# Country codes associated with high volumes of spam / scam calls
_HIGH_RISK_COUNTRY_CODES: set[str] = {
    "+234",  # Nigeria
    "+91",   # India (high scam call volume)
    "+62",   # Indonesia
    "+55",   # Brazil
    "+880",  # Bangladesh
    "+92",   # Pakistan
    "+7",    # Russia
}


def _detect_phone_patterns(raw: str) -> list[str]:
    flags: list[str] = []
    digits_only = re.sub(r"[^\d+]", "", raw)

    # Validate approximate length
    digit_count = len(re.sub(r"\D", "", digits_only))
    if digit_count < 7 or digit_count > 15:
        flags.append("Phone number length is invalid (outside 7–15 digit range)")

    # High-risk country code prefix
    for code in _HIGH_RISK_COUNTRY_CODES:
        if digits_only.startswith(code):
            flags.append(f"Phone number originates from a high-risk country code: {code}")
            break

    # Repeating digit patterns common in fake/test numbers
    if re.search(r"(\d)\1{6,}", digits_only):
        flags.append("Phone number contains a suspicious repeating digit pattern")

    return flags


# ── Email patterns ─────────────────────────────────────────────────────────────

# Free email providers whose domains are commonly spoofed
_FREE_PROVIDERS: set[str] = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "live.com", "icloud.com", "protonmail.com", "mail.com",
}

# Well-known brands that phishers mimic in email domains
_EMAIL_BRAND_DOMAINS: set[str] = {
    "paypal", "apple", "amazon", "google", "microsoft",
    "netflix", "facebook", "twitter", "instagram", "ebay",
    "support", "admin", "noreply", "service",
}


def _detect_email_patterns(raw: str) -> list[str]:
    flags: list[str] = []

    parts = raw.lower().split("@")
    if len(parts) != 2:
        flags.append("Email address format is invalid")
        return flags

    local_part, domain = parts

    # Spoofed free-provider domain (e.g. "gmai1.com" instead of "gmail.com")
    normalised_domain = _normalize_domain(domain)
    for provider in _FREE_PROVIDERS:
        provider_base = provider.split(".")[0]
        if (
            normalised_domain == provider           # exact homoglyph match
            or (provider_base in normalised_domain and normalised_domain != provider)
        ):
            flags.append(
                f"Email domain may be impersonating a free provider: {domain}"
            )
            break

    # Brand name in domain that doesn't match official domain (e.g. apple-support.net)
    if _is_typosquat(domain):
        flags.append(f"Email domain appears to impersonate a well-known brand: {domain}")

    # Suspicious local part keywords
    for kw in {"admin", "support", "noreply", "billing", "verify", "secure"}:
        if kw in local_part:
            flags.append(f"Email local part contains a suspicious keyword: '{kw}'")
            break

    # Excessive dots or hyphens in local part (obfuscation tactic)
    if local_part.count(".") >= 4 or local_part.count("-") >= 3:
        flags.append("Email local part contains unusual punctuation — possible obfuscation")

    return flags


# ── Public API ────────────────────────────────────────────────────────────────

def detect_patterns(raw: str, input_type: str) -> list[str]:
    """
    Dispatch to the appropriate rule-set and return a list of flag strings.
    An empty list means no suspicious patterns were detected.
    """
    if input_type == "url":
        return _detect_url_patterns(raw)
    if input_type == "phone":
        return _detect_phone_patterns(raw)
    if input_type == "email":
        return _detect_email_patterns(raw)
    return []
