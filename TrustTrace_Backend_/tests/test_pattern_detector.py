"""
tests/test_pattern_detector.py

Unit tests for services/pattern_detector.py
"""

import pytest
from services.pattern_detector import classify_input, detect_patterns


# ── classify_input ─────────────────────────────────────────────────────────────

class TestClassifyInput:
    def test_email_simple(self):
        assert classify_input("user@example.com") == "email"

    def test_email_subdomains(self):
        assert classify_input("user@mail.company.org") == "email"

    def test_phone_e164(self):
        assert classify_input("+12025551234") == "phone"

    def test_phone_spaces(self):
        assert classify_input("+44 20 7946 0958") == "phone"

    def test_url_with_scheme(self):
        assert classify_input("https://example.com") == "url"

    def test_url_without_scheme(self):
        assert classify_input("example.com") == "url"

    def test_url_with_path(self):
        assert classify_input("http://example.com/login?id=1") == "url"


# ── URL pattern detection ──────────────────────────────────────────────────────

class TestURLPatterns:
    def test_suspicious_tld_xyz(self):
        flags = detect_patterns("http://getfreemoney.xyz", "url")
        assert any("xyz" in f.lower() for f in flags)

    def test_suspicious_tld_tk(self):
        flags = detect_patterns("http://example.tk/login", "url")
        assert any(".tk" in f for f in flags)

    def test_phishing_keyword_login(self):
        flags = detect_patterns("http://secure-login.example.com", "url")
        assert any("login" in f.lower() or "keyword" in f.lower() for f in flags)

    def test_typosquatting_paypal(self):
        flags = detect_patterns("http://paypa1.com/signin", "url")
        assert any("impersonation" in f.lower() or "typosquat" in f.lower() for f in flags)

    def test_typosquatting_amazon(self):
        flags = detect_patterns("http://amaz0n-deals.net", "url")
        assert any("impersonation" in f.lower() or "typosquat" in f.lower() for f in flags)

    def test_ip_address_url(self):
        flags = detect_patterns("http://192.168.1.100/login", "url")
        assert any("ip address" in f.lower() for f in flags)

    def test_excessive_hyphens(self):
        flags = detect_patterns("http://best---deals---online.com", "url")
        assert any("hyphen" in f.lower() for f in flags)

    def test_clean_url_no_flags(self):
        flags = detect_patterns("https://www.bbc.co.uk", "url")
        # BBC is a legitimate domain — should have zero or very few flags
        assert len(flags) == 0

    def test_http_with_secure_keyword(self):
        flags = detect_patterns("http://bank-login.example.com/verify", "url")
        assert any("http" in f.lower() or "unencrypted" in f.lower() for f in flags)


# ── Phone pattern detection ────────────────────────────────────────────────────

class TestPhonePatterns:
    def test_high_risk_country_nigeria(self):
        flags = detect_patterns("+2348012345678", "phone")
        assert any("high-risk" in f.lower() or "+234" in f for f in flags)

    def test_repeating_digits(self):
        flags = detect_patterns("+1 555 111 1111111", "phone")
        # Excessive repeating digits
        assert any("repeat" in f.lower() for f in flags)

    def test_too_short(self):
        flags = detect_patterns("+1234", "phone")
        assert any("invalid" in f.lower() or "length" in f.lower() for f in flags)

    def test_valid_us_number_no_flags(self):
        flags = detect_patterns("+12025551234", "phone")
        # Standard US number — should not trigger country-code warning
        assert not any("+1" in f and "high-risk" in f.lower() for f in flags)


# ── Email pattern detection ────────────────────────────────────────────────────

class TestEmailPatterns:
    def test_spoofed_gmail(self):
        flags = detect_patterns("support@gmai1.com", "email")
        assert any("impersonat" in f.lower() or "provider" in f.lower() for f in flags)

    def test_brand_impersonation_paypal(self):
        flags = detect_patterns("billing@paypal-secure.net", "email")
        assert any("impersonat" in f.lower() or "brand" in f.lower() for f in flags)

    def test_suspicious_local_part(self):
        flags = detect_patterns("noreply@somesite.com", "email")
        assert any("keyword" in f.lower() or "suspicious" in f.lower() for f in flags)

    def test_clean_corporate_email(self):
        flags = detect_patterns("john.smith@company.com", "email")
        assert len(flags) == 0

    def test_invalid_email_format(self):
        flags = detect_patterns("notanemail", "email")
        # classify_input would return url for this, but if forced to email:
        flags = detect_patterns("notanemail@", "email")
        assert any("invalid" in f.lower() for f in flags)
