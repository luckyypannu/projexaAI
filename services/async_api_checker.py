from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

_API_TIMEOUT = aiohttp.ClientTimeout(total=10)


# ── Orchestrator ───────────────────────────────────────────────────────────────

async def run_api_checks(
    raw_input: str,
    input_type: str,
    config: dict,
) -> dict[str, Any]:
    """
    Entry point — dispatches the appropriate coroutines based on input_type
    and gathers all results concurrently.
    """
    tasks: list = []
    names: list[str] = []

    async with aiohttp.ClientSession(timeout=_API_TIMEOUT) as session:

        if input_type in ("url", "email"):
            if config.get("GOOGLE_SAFE_BROWSING_API_KEY"):
                tasks.append(check_google_safe_browsing(session, raw_input, config))
                names.append("google_safe_browsing")

            # URLhaus replaces PhishTank
            if config.get("URLHAUS_API_KEY"):
                tasks.append(check_urlhaus(session, raw_input, config))
                names.append("urlhaus")

            if config.get("VIRUSTOTAL_API_KEY"):
                tasks.append(check_virustotal(session, raw_input, config))
                names.append("virustotal")

        elif input_type == "phone":
            if config.get("NUMVERIFY_API_KEY"):
                tasks.append(check_numverify(session, raw_input, config))
                names.append("numverify")

        raw_results = await asyncio.gather(*tasks, return_exceptions=True)

    results: dict[str, Any] = {}
    for name, outcome in zip(names, raw_results):
        if isinstance(outcome, Exception):
            logger.warning("API check '%s' failed: %s", name, outcome)
            results[name] = {"error": str(outcome)}
        else:
            results[name] = outcome

    return results


# ── Google Safe Browsing ───────────────────────────────────────────────────────

async def check_google_safe_browsing(
    session: aiohttp.ClientSession,
    url: str,
    config: dict,
) -> dict[str, Any]:
    """
    Queries the Google Safe Browsing Lookup API v4.
    """
    endpoint = (
        f"{config['GOOGLE_SAFE_BROWSING_URL']}"
        f"?key={config['GOOGLE_SAFE_BROWSING_API_KEY']}"
    )
    payload = {
        "client": {"clientId": "cybertrust", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    async with session.post(endpoint, json=payload) as resp:
        data = await resp.json()

    matches = data.get("matches", [])
    return {
        "flagged": bool(matches),
        "matches": matches,
    }


# ── URLhaus (abuse.ch) ────────────────────────────────────────────────────────

async def check_urlhaus(
    session: aiohttp.ClientSession,
    url: str,
    config: dict,
) -> dict[str, Any]:
    """
    Queries the URLhaus URL lookup API (abuse.ch).
    Replaces PhishTank which shut down in 2020.

    Auth:    Auth-Key header (required)
    Method:  POST with JSON body { "url": "<value>" }
    Docs:    https://urlhaus-api.abuse.ch/#lookup-url

    Response fields:
      query_status  "ok"         — URL found in URLhaus database
                    "no_results" — URL not in database (clean)
      url_status    "online"     — currently serving malware (worse)
                    "offline"    — was malicious, now inactive
      threat        e.g. "malware_download"
      tags          list of strings e.g. ["elf", "emotet"]
    """
    headers = {
        "Auth-Key": config["URLHAUS_API_KEY"],
        "Content-Type": "application/json",
    }
    payload = {"url": url}

    async with session.post(
        config["URLHAUS_URL"],
        headers=headers,
        json=payload,
    ) as resp:
        data = await resp.json(content_type=None)

    query_status = data.get("query_status", "no_results")
    found = query_status == "ok"

    return {
        "found":        found,                              # True = in URLhaus DB
        "url_status":   data.get("url_status", ""),         # "online" | "offline"
        "threat":       data.get("threat", ""),             # e.g. "malware_download"
        "tags":         data.get("tags", []) or [],         # list of strings
        "query_status": query_status,
    }


# ── VirusTotal ─────────────────────────────────────────────────────────────────

async def check_virustotal(
    session: aiohttp.ClientSession,
    url: str,
    config: dict,
) -> dict[str, Any]:
    """
    Queries the VirusTotal URL analysis endpoint v3.
    """
    url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
    endpoint = f"{config['VIRUSTOTAL_URL']}/{url_id}"
    headers = {"x-apikey": config["VIRUSTOTAL_API_KEY"]}

    async with session.get(endpoint, headers=headers) as resp:
        if resp.status == 404:
            return {"not_found": True, "malicious": 0, "suspicious": 0}
        data = await resp.json()

    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )
    return {
        "malicious":  stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


# ── NumVerify ──────────────────────────────────────────────────────────────────

async def check_numverify(
    session: aiohttp.ClientSession,
    phone: str,
    config: dict,
) -> dict[str, Any]:
    """
    Validates and enriches a phone number via the NumVerify API.
    """
    params = {
        "access_key": config["NUMVERIFY_API_KEY"],
        "number": phone,
        "format": 1,
    }

    async with session.get(config["NUMVERIFY_URL"], params=params) as resp:
        data = await resp.json()

    return {
        "valid":        data.get("valid", False),
        "line_type":    data.get("line_type", "unknown"),
        "carrier":      data.get("carrier", "unknown"),
        "country_code": data.get("country_code", ""),
        "country_name": data.get("country_name", ""),
        "location":     data.get("location", ""),
    }
