from __future__ import annotations


# ── Base advice by risk level ──────────────────────────────────────────────────

_BASE_ADVICE: dict[str, list[str]] = {
    "Low": [
        "No major threats detected. Always verify before sharing sensitive information.",
        "Keep your software and browser up to date for the best protection.",
    ],
    "Medium": [
        "This input has suspicious characteristics — proceed with caution.",
        "Do not enter passwords or payment details unless you are certain of the source.",
        "Consider verifying the legitimacy of this contact through official channels.",
    ],
    "High": [
        "This input is likely associated with scams or phishing. Avoid interacting with it.",
        "Do not share personal information, passwords, or financial details.",
        "If you have already interacted, consider changing your passwords and monitoring your accounts.",
        "Report this to your local cybercrime authority or your organisation's security team.",
    ],
}

# ── Type-specific advice additions ────────────────────────────────────────────

_TYPE_ADVICE: dict[str, dict[str, list[str]]] = {
    "url": {
        "Low": [
            "Bookmark important websites to avoid typing URLs manually in future.",
        ],
        "Medium": [
            "Check the browser address bar carefully — look for subtle misspellings.",
            "Ensure the site uses HTTPS (padlock icon) before submitting any data.",
        ],
        "High": [
            "Close this website immediately and do not click any links on the page.",
            "Run a virus scan on your device if you have already visited this URL.",
        ],
    },
    "phone": {
        "Low": [
            "Be cautious of unsolicited calls even from numbers that appear legitimate.",
        ],
        "Medium": [
            "Do not return calls to unknown numbers — look up the official number independently.",
            "Legitimate organisations will never ask for passwords or full card numbers over the phone.",
        ],
        "High": [
            "Block this number immediately on your device.",
            "Do not call back — scammers sometimes use premium-rate call-back numbers.",
            "If the caller claimed to be from a bank or government agency, hang up and call the official number.",
        ],
    },
    "email": {
        "Low": [
            "Check the sender's full email address — display names can be spoofed.",
        ],
        "Medium": [
            "Do not click links or open attachments in this email without verifying the sender.",
            "Hover over links to see the real destination URL before clicking.",
        ],
        "High": [
            "Mark this email as spam and delete it immediately.",
            "If the email requests account credentials, report it to the impersonated organisation.",
            "Do not download any attachments — they may contain malware.",
        ],
    },
}

# ── Pattern-specific advice snippets ──────────────────────────────────────────

_PATTERN_ADVICE: dict[str, str] = {
    "typosquat": "The domain appears to impersonate a known brand — double-check the spelling carefully.",
    "brand impersonation": "The domain appears to impersonate a known brand — double-check the spelling carefully.",
    "phishing keyword": "The URL contains keywords commonly used in phishing pages.",
    "raw ip address": "Legitimate websites rarely use raw IP addresses — this is a strong scam indicator.",
    "voip": "VOIP numbers can be spoofed easily and are frequently used in telephone scams.",
    "high-risk country": "This number originates from a region with elevated scam activity.",
    "phone_invalid": "This phone number format appears invalid.",
    "impersonat": "This email domain may be impersonating a well-known service.",
    "obfuscation": "The email address uses unusual formatting that may indicate obfuscation.",
}


def generate_advice(
    risk_level: str,
    input_type: str,
    pattern_flags: list[str],
) -> list[str]:
    """
    Build and return a de-duplicated list of advice strings.

    Parameters
    ----------
    risk_level    : "Low" | "Medium" | "High"
    input_type    : "url" | "phone" | "email"
    pattern_flags : Flags raised by the pattern detector.
    """
    advice: list[str] = []

    # 1. Base risk-level advice
    advice.extend(_BASE_ADVICE.get(risk_level, []))

    # 2. Type + risk-level specific advice
    type_bucket = _TYPE_ADVICE.get(input_type, {})
    advice.extend(type_bucket.get(risk_level, []))

    # 3. Pattern-specific advice (only add if not already covered)
    for flag in pattern_flags:
        flag_lower = flag.lower()
        for keyword, tip in _PATTERN_ADVICE.items():
            if keyword in flag_lower and tip not in advice:
                advice.append(tip)
                break

    # Remove duplicates while preserving order
    seen: set[str] = set()
    unique_advice: list[str] = []
    for item in advice:
        if item not in seen:
            seen.add(item)
            unique_advice.append(item)

    return unique_advice
