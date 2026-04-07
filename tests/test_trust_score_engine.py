"""
tests/test_trust_score_engine.py

Unit tests for services/trust_score_engine.py

CHANGES:
  All PhishTank mock payloads replaced with URLhaus equivalents.
  New URLhaus-specific test cases added for online vs offline URL status.
"""

import pytest
from services.trust_score_engine import calculate_score, SCORE_LOW_MIN, SCORE_MEDIUM_MIN


def _make_clean_api() -> dict:
    """Return API results that represent a completely clean input."""
    return {
        "google_safe_browsing": {"flagged": False, "matches": []},
        # URLhaus replaces PhishTank — no_results = clean
        "urlhaus": {"found": False, "url_status": "", "threat": "", "tags": [], "query_status": "no_results"},
        "virustotal": {"malicious": 0, "suspicious": 0, "harmless": 10},
    }


# ── Clean input ────────────────────────────────────────────────────────────────

class TestCleanInput:
    def test_perfect_score(self):
        score, level = calculate_score(_make_clean_api(), [], "url", False)
        assert score == 100
        assert level == "Low"

    def test_low_risk_band(self):
        score, level = calculate_score(_make_clean_api(), [], "url", False)
        assert score >= SCORE_LOW_MIN
        assert level == "Low"


# ── Single deduction sources ───────────────────────────────────────────────────

class TestSingleDeductions:
    def test_google_safe_browsing_flag(self):
        api = _make_clean_api()
        api["google_safe_browsing"] = {"flagged": True, "matches": [{"threat": "MALWARE"}]}
        score, level = calculate_score(api, [], "url", False)
        assert score == 50   # 100 - 50
        assert level == "Medium"

    def test_urlhaus_found_offline(self):
        """URL in URLhaus DB but no longer active — base deduction only."""
        api = _make_clean_api()
        api["urlhaus"] = {
            "found": True,
            "url_status": "offline",
            "threat": "malware_download",
            "tags": [],
            "query_status": "ok",
        }
        score, level = calculate_score(api, [], "url", False)
        assert score == 60   # 100 - 40
        assert level == "Medium"

    def test_urlhaus_found_online(self):
        """URL in URLhaus DB AND currently serving malware — extra -10."""
        api = _make_clean_api()
        api["urlhaus"] = {
            "found": True,
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["elf"],
            "query_status": "ok",
        }
        score, level = calculate_score(api, [], "url", False)
        assert score == 50   # 100 - 40 (found) - 10 (online)
        assert level == "Medium"

    def test_urlhaus_not_found(self):
        """URL not in URLhaus — no deduction."""
        api = _make_clean_api()
        api["urlhaus"] = {
            "found": False,
            "url_status": "",
            "threat": "",
            "tags": [],
            "query_status": "no_results",
        }
        score, level = calculate_score(api, [], "url", False)
        assert score == 100
        assert level == "Low"

    def test_virustotal_high_malicious(self):
        api = _make_clean_api()
        api["virustotal"] = {"malicious": 5, "suspicious": 0}
        score, level = calculate_score(api, [], "url", False)
        assert score == 70   # 100 - 30
        assert level == "Medium"

    def test_virustotal_low_malicious(self):
        api = _make_clean_api()
        api["virustotal"] = {"malicious": 1, "suspicious": 0}
        score, level = calculate_score(api, [], "url", False)
        assert score == 85   # 100 - 15
        assert level == "Low"

    def test_known_scam_deduction(self):
        score, level = calculate_score(_make_clean_api(), [], "url", True)
        assert score == 50   # 100 - 50
        assert level == "Medium"

    def test_invalid_phone(self):
        api = {"numverify": {"valid": False}}
        score, level = calculate_score(api, [], "phone", False)
        assert score == 40   # 100 - 60
        assert level == "High"

    def test_voip_phone(self):
        api = {"numverify": {"valid": True, "line_type": "voip", "carrier": "Twilio"}}
        score, level = calculate_score(api, [], "phone", False)
        assert score == 80   # 100 - 20
        assert level == "Low"

    def test_unknown_carrier_phone(self):
        api = {"numverify": {"valid": True, "line_type": "mobile", "carrier": ""}}
        score, level = calculate_score(api, [], "phone", False)
        assert score == 90   # 100 - 10
        assert level == "Low"


# ── Pattern flag deductions ────────────────────────────────────────────────────

class TestPatternDeductions:
    def test_suspicious_tld_flag(self):
        flags = ["Suspicious top-level domain: .xyz"]
        score, level = calculate_score(_make_clean_api(), flags, "url", False)
        assert score == 85   # 100 - 15

    def test_brand_impersonation_flag(self):
        flags = ["Possible brand impersonation / typosquatting: paypa1.com"]
        score, level = calculate_score(_make_clean_api(), flags, "url", False)
        assert score == 80   # 100 - 20

    def test_multiple_pattern_flags(self):
        flags = [
            "Suspicious top-level domain: .xyz",
            "Phishing keyword detected in URL: 'login'",
            "Possible brand impersonation / typosquatting: amaz0n-secure.xyz",
        ]
        score, _ = calculate_score(_make_clean_api(), flags, "url", False)
        assert score == 50   # 100 - 15 - 15 - 20

    def test_duplicate_pattern_flags_deducted_once(self):
        flags = [
            "Phishing keyword detected in URL: 'login'",
            "Phishing keyword detected in URL: 'verify'",
        ]
        score1, _ = calculate_score(_make_clean_api(), flags[:1], "url", False)
        score2, _ = calculate_score(_make_clean_api(), flags, "url", False)
        assert score1 == score2


# ── Score clamping ─────────────────────────────────────────────────────────────

class TestScoreClamping:
    def test_score_cannot_go_below_zero(self):
        api = {
            "google_safe_browsing": {"flagged": True, "matches": [{}]},
            "urlhaus": {
                "found": True, "url_status": "online",
                "threat": "malware_download", "tags": [], "query_status": "ok",
            },
            "virustotal": {"malicious": 10, "suspicious": 5},
        }
        flags = [
            "Suspicious top-level domain: .xyz",
            "Possible brand impersonation / typosquatting: paypa1.com",
            "Phishing keyword detected in URL: 'login'",
            "URL uses a raw IP address instead of a domain name",
            "Sensitive operation over unencrypted HTTP connection",
        ]
        score, level = calculate_score(api, flags, "url", in_known_scams=True)
        assert score >= 0
        assert score <= 100
        assert level == "High"

    def test_score_cannot_exceed_100(self):
        score, _ = calculate_score({}, [], "url", False)
        assert score == 100


# ── Risk level bands ───────────────────────────────────────────────────────────

class TestRiskBands:
    def test_low_risk(self):
        score, level = calculate_score(_make_clean_api(), [], "url", False)
        assert level == "Low"

    def test_medium_risk_boundary(self):
        # GSB flag = -50 → score 50 → Medium
        api = _make_clean_api()
        api["google_safe_browsing"] = {"flagged": True, "matches": [{}]}
        score, level = calculate_score(api, [], "url", False)
        assert score == 50
        assert level == "Medium"

    def test_high_risk_boundary(self):
        # GSB -50 + URLhaus found&online -50 = score 0 → High
        api = _make_clean_api()
        api["google_safe_browsing"] = {"flagged": True, "matches": [{}]}
        api["urlhaus"] = {
            "found": True, "url_status": "online",
            "threat": "malware_download", "tags": [], "query_status": "ok",
        }
        score, level = calculate_score(api, [], "url", False)
        assert score == 0
        assert level == "High"
