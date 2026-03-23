from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

SCORE_LOW_MIN    = 80
SCORE_MEDIUM_MIN = 50
INITIAL_SCORE    = 100


_API_DEDUCTIONS: dict[str, int] = {
    # Google Safe Browsing
    "gsb_flagged": 50,

    # URLhaus (replaces PhishTank)
    "urlhaus_found":   40,   # URL is in the URLhaus malware database
    "urlhaus_online":  10,   # URL is *currently* active — extra penalty

    # VirusTotal
    "vt_malicious_high": 30,
    "vt_malicious_low":  15,
    "vt_suspicious":     10,

    # NumVerify / phone
    "phone_invalid":          60,
    "phone_voip":             20,
    "phone_unknown_carrier":  10,
    "phone_high_risk_country": 20,

    # Known-scams DB hit
    "known_scam": 50,
}

_PATTERN_DEDUCTIONS: dict[str, int] = {
    "suspicious top-level domain": 15,
    "excessive hyphens":           10,
    "phishing keyword":            15,
    "brand impersonation":         20,
    "typosquat":                   20,
    "raw ip address":              15,
    "deep subdomain":              10,
    "unencrypted http":            10,
    "high-risk country code":      20,
    "repeating digit":             10,
    "invalid":                     15,
    "impersonat":                  20,
    "obfuscation":                 10,
    "suspicious keyword":          10,
}


def _score_api_results(
    api_results: dict[str, Any],
    input_type: str,
) -> tuple[int, list[str]]:
    """
    Evaluate external API results and return (total_deduction, triggered_keys).
    """
    deductions = 0
    triggered: list[str] = []

    # ── Google Safe Browsing ───────────────────────────────────────────────────
    gsb = api_results.get("google_safe_browsing", {})
    if gsb.get("flagged"):
        deductions += _API_DEDUCTIONS["gsb_flagged"]
        triggered.append("gsb_flagged")

    # ── URLhaus (replaces PhishTank) ───────────────────────────────────────────
    uh = api_results.get("urlhaus", {})
    if uh.get("found"):
        deductions += _API_DEDUCTIONS["urlhaus_found"]
        triggered.append("urlhaus_found")
        # Extra penalty if URL is currently online (actively serving malware)
        if uh.get("url_status") == "online":
            deductions += _API_DEDUCTIONS["urlhaus_online"]
            triggered.append("urlhaus_online")

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    vt = api_results.get("virustotal", {})
    malicious_count = vt.get("malicious", 0)
    if malicious_count >= 3:
        deductions += _API_DEDUCTIONS["vt_malicious_high"]
        triggered.append("vt_malicious_high")
    elif malicious_count >= 1:
        deductions += _API_DEDUCTIONS["vt_malicious_low"]
        triggered.append("vt_malicious_low")
    if vt.get("suspicious", 0) >= 1:
        deductions += _API_DEDUCTIONS["vt_suspicious"]
        triggered.append("vt_suspicious")

    # ── NumVerify (phone only) ─────────────────────────────────────────────────
    if input_type == "phone":
        nv = api_results.get("numverify", {})
        if not nv.get("valid", True):
            deductions += _API_DEDUCTIONS["phone_invalid"]
            triggered.append("phone_invalid")
        else:
            line_type = (nv.get("line_type") or "").lower()
            carrier   = (nv.get("carrier") or "").lower()

            if line_type == "voip":
                deductions += _API_DEDUCTIONS["phone_voip"]
                triggered.append("phone_voip")
            if not carrier or carrier in ("unknown", ""):
                deductions += _API_DEDUCTIONS["phone_unknown_carrier"]
                triggered.append("phone_unknown_carrier")

    return deductions, triggered


def _score_pattern_flags(pattern_flags: list[str]) -> int:
    """
    Match pattern-flag descriptions against the deduction table.
    Each key is applied at most once.
    """
    deductions = 0
    applied: set[str] = set()

    for flag in pattern_flags:
        flag_lower = flag.lower()
        for keyword, points in _PATTERN_DEDUCTIONS.items():
            if keyword in flag_lower and keyword not in applied:
                deductions += points
                applied.add(keyword)
                break

    return deductions


def _derive_risk_level(score: int) -> str:
    if score >= SCORE_LOW_MIN:
        return "Low"
    if score >= SCORE_MEDIUM_MIN:
        return "Medium"
    return "High"


def calculate_score(
    api_results: dict[str, Any],
    pattern_flags: list[str],
    input_type: str,
    in_known_scams: bool = False,
) -> tuple[int, str]:
    """
    Compute the final trust score and risk level.
    """
    total_deduction = 0

    api_deduction, triggered = _score_api_results(api_results, input_type)
    total_deduction += api_deduction

    if triggered:
        logger.debug("API deductions triggered: %s", triggered)

    pattern_deduction = _score_pattern_flags(pattern_flags)
    total_deduction += pattern_deduction

    if in_known_scams:
        total_deduction += _API_DEDUCTIONS["known_scam"]
        logger.debug("Known-scam deduction applied.")

    final_score = max(0, min(INITIAL_SCORE, INITIAL_SCORE - total_deduction))
    risk_level  = _derive_risk_level(final_score)

    logger.info(
        "Score calculated: %d (%s) | API=%d | Pattern=%d",
        final_score, risk_level, api_deduction, pattern_deduction,
    )

    return final_score, risk_level
