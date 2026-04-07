"""
tests/test_advice_generator.py

Unit tests for services/advice_generator.py
"""

import pytest
from services.advice_generator import generate_advice


class TestAdviceGenerator:

    # ── Base risk-level advice ────────────────────────────────────────────────

    def test_low_risk_returns_advice(self):
        advice = generate_advice("Low", "url", [])
        assert isinstance(advice, list)
        assert len(advice) > 0

    def test_medium_risk_returns_caution_advice(self):
        advice = generate_advice("Medium", "url", [])
        assert len(advice) > 0
        assert any("caution" in a.lower() for a in advice)

    def test_high_risk_returns_warning_advice(self):
        advice = generate_advice("High", "url", [])
        assert len(advice) > 0
        assert any(
            keyword in a.lower()
            for a in advice
            for keyword in ["scam", "phishing", "danger"]
        )

    # ── Type-specific advice ──────────────────────────────────────────────────

    def test_url_high_risk_includes_close_browser(self):
        advice = generate_advice("High", "url", [])
        assert any("close" in a.lower() for a in advice)

    def test_phone_high_risk_includes_block(self):
        advice = generate_advice("High", "phone", [])
        assert any("block" in a.lower() for a in advice)

    def test_email_high_risk_includes_spam_or_delete(self):
        advice = generate_advice("High", "email", [])
        assert any(
            keyword in a.lower()
            for a in advice
            for keyword in ["spam", "delete"]
        )

    def test_url_medium_risk_includes_https_advice(self):
        advice = generate_advice("Medium", "url", [])
        assert any(
            keyword in a.lower()
            for a in advice
            for keyword in ["https", "padlock"]
        )

    # ── Pattern-specific advice ───────────────────────────────────────────────

    def test_typosquat_flag_adds_brand_advice(self):
        flags = ["Possible brand impersonation / typosquatting: paypa1.com"]
        advice = generate_advice("High", "url", flags)
        assert any(
            keyword in a.lower()
            for a in advice
            for keyword in ["brand", "spelling"]
        )

    def test_ip_address_flag_adds_specific_advice(self):
        flags = ["URL uses a raw IP address instead of a domain name"]
        advice = generate_advice("High", "url", flags)
        assert any("ip" in a.lower() for a in advice)

    def test_voip_flag_adds_voip_advice(self):
        flags = ["VOIP number detected"]
        advice = generate_advice("Medium", "phone", flags)
        assert any(
            keyword in a.lower()
            for a in advice
            for keyword in ["voip", "spoof"]
        )

    # ── Deduplication ─────────────────────────────────────────────────────────

    def test_no_duplicate_advice_strings(self):
        flags = [
            "Possible brand impersonation / typosquatting: paypa1.com",
            "Possible brand impersonation / typosquatting: amaz0n.com",
        ]
        advice = generate_advice("High", "url", flags)

        assert len(advice) == len(set(advice)), "Duplicate advice strings found"

    def test_all_items_are_strings(self):
        advice = generate_advice(
            "High",
            "email",
            ["Email domain may be impersonating a free provider"],
        )
        assert all(isinstance(a, str) for a in advice)

    # ── Edge cases ────────────────────────────────────────────────────────────

    def test_empty_pattern_flags(self):
        advice = generate_advice("Low", "url", [])
        assert len(advice) > 0  # Base advice should always exist

    def test_unknown_risk_level_returns_graceful_output(self):
        advice = generate_advice("Unknown", "url", [])
        assert isinstance(advice, list)

    def test_invalid_input_type(self):
        """Should not crash on unknown input type"""
        advice = generate_advice("High", "unknown_type", [])
        assert isinstance(advice, list)