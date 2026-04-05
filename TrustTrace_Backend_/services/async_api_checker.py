"""
services/async_api_checker.py

Executes external reputation API checks concurrently using asyncio + aiohttp.

APIs Used:
- Google Safe Browsing
- URLhaus (abuse.ch)
- VirusTotal
- NumVerify (phone)

Features:
- Async parallel execution
- Timeout + retry handling
- Safe JSON parsing
- Graceful failure handling
"""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

import aiohttp

logger = logging.getLogger(__name__)

_API_TIMEOUT = aiohttp.ClientTimeout(total=10)
_RETRIES = 2


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

async def run_api_checks(
    raw_input: str,
    input_type: str,
    config: dict,
) -> dict[str, Any]:
    """
    Runs all relevant API checks in parallel.
    """

    tasks = []
    names: list[str] = []

    async with aiohttp.ClientSession(timeout=_API_TIMEOUT) as session:

        if input_type in ("url", "email"):

            if config.get("GOOGLE_SAFE_BROWSING_API_KEY"):
                tasks.append(check_google_safe_browsing(session, raw_input, config))
                names.append("google_safe_browsing")

            if config.get("URLHAUS_API_KEY") and input_type == "url":
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
            logger.warning("API '%s' failed: %s", name, outcome)
            results[name] = {"error": str(outcome)}
        else:
            results[name] = outcome

    return results


# ──────────────────────────────────────────────────────────────────────────────
# Helper: Retry Wrapper
# ──────────────────────────────────────────────────────────────────────────────

async def _fetch_with_retry(request_coro):
    """
    Generic retry wrapper for API calls.
    """
    for attempt in range(_RETRIES + 1):
        try:
            return await request_coro()
        except Exception as e:
            logger.warning("Retry %d failed: %s", attempt + 1, e)
            await asyncio.sleep(1)

    raise RuntimeError("All retries failed")


# ──────────────────────────────────────────────────────────────────────────────
# Google Safe Browsing
# ──────────────────────────────────────────────────────────────────────────────

async def check_google_safe_browsing(session, url, config) -> dict[str, Any]:

    async def _request():
        endpoint = (
            f"{config['GOOGLE_SAFE_BROWSING_URL']}?key={config['GOOGLE_SAFE_BROWSING_API_KEY']}"
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
            resp.raise_for_status()
            return await resp.json()

    data = await _fetch_with_retry(_request)

    matches = data.get("matches", [])
    return {"flagged": bool(matches), "matches": matches}


# ──────────────────────────────────────────────────────────────────────────────
# URLhaus
# ──────────────────────────────────────────────────────────────────────────────

async def check_urlhaus(session, url, config) -> dict[str, Any]:

    async def _request():
        headers = {
            "Auth-Key": config["URLHAUS_API_KEY"],
            "Content-Type": "application/json",
        }

        async with session.post(
            config["URLHAUS_URL"],
            headers=headers,
            json={"url": url},
        ) as resp:
            resp.raise_for_status()
            return await resp.json(content_type=None)

    data = await _fetch_with_retry(_request)

    query_status = data.get("query_status", "no_results")

    return {
        "found": query_status == "ok",
        "url_status": data.get("url_status", ""),
        "threat": data.get("threat", ""),
        "tags": data.get("tags", []) or [],
        "query_status": query_status,
    }


# ──────────────────────────────────────────────────────────────────────────────
# VirusTotal
# ──────────────────────────────────────────────────────────────────────────────

async def check_virustotal(session, url, config) -> dict[str, Any]:

    async def _request():
        url_id = base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()
        endpoint = f"{config['VIRUSTOTAL_URL']}/{url_id}"

        async with session.get(
            endpoint,
            headers={"x-apikey": config["VIRUSTOTAL_API_KEY"]},
        ) as resp:

            if resp.status == 404:
                return None

            resp.raise_for_status()
            return await resp.json()

    data = await _fetch_with_retry(_request)

    if not data:
        return {"not_found": True, "malicious": 0, "suspicious": 0}

    stats = (
        data.get("data", {})
        .get("attributes", {})
        .get("last_analysis_stats", {})
    )

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


# ──────────────────────────────────────────────────────────────────────────────
# NumVerify
# ──────────────────────────────────────────────────────────────────────────────

async def check_numverify(session, phone, config) -> dict[str, Any]:

    async def _request():
        params = {
            "access_key": config["NUMVERIFY_API_KEY"],
            "number": phone,
            "format": 1,
        }

        async with session.get(config["NUMVERIFY_URL"], params=params) as resp:
            resp.raise_for_status()
            return await resp.json()

    data = await _fetch_with_retry(_request)

    return {
        "valid": data.get("valid", False),
        "line_type": data.get("line_type", "unknown"),
        "carrier": data.get("carrier", "unknown"),
        "country_code": data.get("country_code", ""),
        "country_name": data.get("country_name", ""),
        "location": data.get("location", ""),
    }