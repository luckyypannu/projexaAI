"""
services/demo_mode.py

Provides mock scan results for frontend testing when MongoDB is unavailable.
Used in development/demo scenarios.
"""

from models.scan_model import ScanResult


def generate_demo_result(raw_input: str, input_type: str) -> ScanResult:
    """
    Generate a mock ScanResult for demonstration.
    Behavior varies based on input content for realistic testing.
    """
    
    # Demo logic: simulate different risk levels based on input keywords
    is_suspicious = any(kw in raw_input.lower() for kw in [
        'phishing', 'malware', 'scam', 'fraud', 'fake', 'click', 'verify', 'confirm'
    ])
    
    is_safe = any(kw in raw_input.lower() for kw in [
        'google', 'amazon', 'microsoft', 'apple', 'verified', 'trusted', 'secure'
    ])
    
    if is_suspicious:
        trust_score = 25
        risk_level = 'High'
        flags = [
            'Phishing keyword detected in input',
            'Potential social engineering pattern',
            'Domain uses suspicious characteristics'
        ]
        advice = [
            'Do not click on any links in suspicious emails.',
            'Contact the organization directly using verified contact info.',
            'Report this to the appropriate authorities.'
        ]
    elif is_safe:
        trust_score = 85
        risk_level = 'Low'
        flags = []
        advice = [
            'This appears to be a legitimate source.',
            'Standard security practices still apply.'
        ]
    else:
        trust_score = 60
        risk_level = 'Medium'
        flags = [
            'Unable to verify with external databases',
            'Limited threat intelligence available'
        ]
        advice = [
            'Exercise caution and verify independently.',
            'Check for HTTPS and valid SSL certificates.',
            'Look for contact information and privacy policy.'
        ]
    
    return ScanResult(
        input=raw_input,
        type=input_type,
        trust_score=trust_score,
        risk_level=risk_level,
        api_results={'demo_mode': True, 'note': 'Using demo data - MongoDB not available'},
        pattern_flags=flags,
        advice=advice,
    )
