"""
services/trust_score_engine.py

Calculates a 0–100 trust score using weighted deductions.

Risk levels:
80–100 → Low Risk
50–79  → Medium Risk
0–49   → High Risk
"""

from __future__ import annotations

import logging
from typing import Any, Tuple, List

logger = logging.getLogger(__name__)

# ── Score thresholds ──────────────────────────────────────────────────────────
SCORE_LOW_MIN: int = 80
SCORE_MEDIUM_MIN: int = 50
INITIAL_SCORE: int = 100

# ── API-based deductions ──────────────────────────────────────────────────────
_API_DEDUCTIONS: dict[str, int] = {
    # Google Safe Browsing
    "gsb_flagged": 50,

    # URLhaus
    "urlhaus_found": 40,
    "urlhaus_online": 10,

    # VirusTotal
    "vt_malicious_high": 30,
    "vt_malicious_low": 15,
    "vt_suspicious": 10,

    # Phone checks
    "phone_invalid": 60,
    "phone_voip": 20,
    "phone_unknown_carrier": 10,
    "phone_high_risk_country": 20,

    # Known scam DB
    "known_scam": 50,
}

# ── Pattern-based deductions ──────────────────────────────────────────────────
_PATTERN_DEDUCTIONS: dict[str, int] = {
    "suspicious top-level domain": 15,
    "excessive hyphens": 10,
    "phishing keyword": 15,
    "brand impersonation": 20,
    "typosquat": 20,
    "raw ip address": 15,
    "deep subdomain": 10,
    "unencrypted http": 10,
    "high-risk country code": 20,
    "repeating digit": 10,
    "invalid": 15,
    "impersonat": 20,
    "obfuscation": 10,
    "suspicious keyword": 10,
}


# ── API scoring ───────────────────────────────────────────────────────────────
def _score_api_results(
    api_results: dict[str, Any],
    input_type: str,
) -> Tuple[int, List[str]]:
    deductions = 0
    triggered: List[str] = []

    # Google Safe Browsing
    if api_results.get("google_safe_browsing", {}).get("flagged"):
        deductions += _API_DEDUCTIONS["gsb_flagged"]
        triggered.append("gsb_flagged")

    # URLhaus
    uh = api_results.get("urlhaus", {})
    if uh.get("found"):
        deductions += _API_DEDUCTIONS["urlhaus_found"]
        triggered.append("urlhaus_found")

        if uh.get("url_status") == "online":
            deductions += _API_DEDUCTIONS["urlhaus_online"]
            triggered.append("urlhaus_online")

    # VirusTotal
    vt = api_results.get("virustotal", {})
    malicious = vt.get("malicious", 0)

    if malicious >= 3:
        deductions += _API_DEDUCTIONS["vt_malicious_high"]
        triggered.append("vt_malicious_high")
    elif malicious >= 1:
        deductions += _API_DEDUCTIONS["vt_malicious_low"]
        triggered.append("vt_malicious_low")

    if vt.get("suspicious", 0) >= 1:
        deductions += _API_DEDUCTIONS["vt_suspicious"]
        triggered.append("vt_suspicious")

    # Phone checks
    if input_type == "phone":
        nv = api_results.get("numverify", {})

        if not nv.get("valid", True):
            deductions += _API_DEDUCTIONS["phone_invalid"]
            triggered.append("phone_invalid")
        else:
            line_type = (nv.get("line_type") or "").lower()
            carrier = (nv.get("carrier") or "").lower()

            if line_type == "voip":
                deductions += _API_DEDUCTIONS["phone_voip"]
                triggered.append("phone_voip")

            if not carrier or carrier == "unknown":
                deductions += _API_DEDUCTIONS["phone_unknown_carrier"]
                triggered.append("phone_unknown_carrier")

    return deductions, triggered


# ── Pattern scoring ───────────────────────────────────────────────────────────
def _score_pattern_flags(pattern_flags: List[str]) -> int:
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


# ── Risk classification ───────────────────────────────────────────────────────
def _derive_risk_level(score: int) -> str:
    if score >= SCORE_LOW_MIN:
        return "Low"
    elif score >= SCORE_MEDIUM_MIN:
        return "Medium"
    return "High"


# ── Public function ───────────────────────────────────────────────────────────
def calculate_score(
    api_results: dict[str, Any],
    pattern_flags: List[str],
    input_type: str,
    in_known_scams: bool = False,
) -> Tuple[int, str]:

    total_deduction = 0

    # API scoring
    api_deduction, triggered = _score_api_results(api_results, input_type)
    total_deduction += api_deduction

    if triggered:
        logger.debug("API triggers: %s", triggered)

    # Pattern scoring
    pattern_deduction = _score_pattern_flags(pattern_flags)
    total_deduction += pattern_deduction

    # Known scam hit
    if in_known_scams:
        total_deduction += _API_DEDUCTIONS["known_scam"]
        logger.debug("Known scam match detected")

    # Final score clamp
    final_score = max(0, min(INITIAL_SCORE, INITIAL_SCORE - total_deduction))
    risk_level = _derive_risk_level(final_score)

    logger.info(
        "Final Score: %d (%s) | API=%d | Pattern=%d | Total Deduction=%d",
        final_score,
        risk_level,
        api_deduction,
        pattern_deduction,
        total_deduction,
    )

    return final_score, risk_level