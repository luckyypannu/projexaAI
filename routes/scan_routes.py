"""
routes/scan_routes.py

HTTP endpoints for scanning inputs and handling user reports.

Endpoints
---------
POST /scan    — Analyse a URL, phone number, or email
POST /report  — Submit a user-reported suspicious input
GET  /health  — Liveness probe

Features
--------
- MongoDB cache for fast responses
- Async API checks with safe execution
- Pattern detection + trust scoring
- Clean logging for debugging
"""

import asyncio
import logging
import os
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, current_app

from database.mongo_connection import get_collection
from models.scan_model import ScanResult
from services.async_api_checker import run_api_checks
from services.pattern_detector import detect_patterns, classify_input
from services.trust_score_engine import calculate_score
from services.advice_generator import generate_advice
from services.demo_mode import generate_demo_result

logger = logging.getLogger(__name__)
scan_bp = Blueprint("scan", __name__)


# ──────────────────────────────────────────────────────────────────────────────
# Async Runner (SAFE)
# ──────────────────────────────────────────────────────────────────────────────

def _run_async(coro):
    """
    Safely execute async code inside Flask (sync environment).

    Handles:
    - Normal execution (asyncio.run)
    - RuntimeError (event loop already running)
    """
    try:
        return asyncio.run(coro)
    except RuntimeError as e:
        logger.warning("asyncio.run() failed, using fallback loop: %s", e)

        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            return loop.run_until_complete(coro)
        finally:
            loop.close()


# ──────────────────────────────────────────────────────────────────────────────
# /scan
# ──────────────────────────────────────────────────────────────────────────────

@scan_bp.route("/scan", methods=["POST"])
def scan():
    """
    Main scan endpoint.

    Flow:
    1. Validate input
    2. Check cache
    3. Run async API checks
    4. Pattern detection
    5. Known scam lookup
    6. Trust score + advice
    7. Store result
    """

    payload = request.get_json(silent=True)

    if not payload or "input" not in payload:
        logger.debug("Invalid payload received: %s", payload)
        return jsonify({"error": "Missing required field: 'input'"}), 400

    raw_input = str(payload["input"]).strip()

    if not raw_input:
        return jsonify({"error": "'input' field must not be empty"}), 400

    # 1. Classify input
    input_type = classify_input(raw_input)
    logger.info("Scan started | type=%s | input=%s", input_type, raw_input)

    # Demo mode: Return mock results when database unavailable
    demo_mode = current_app.config.get("DEMO_MODE", False)
    if not demo_mode:
        demo_mode = os.getenv("DEMO_MODE", "false").lower() == "true"
    logger.debug("Demo mode check | config=%s | env=%s", current_app.config.get("DEMO_MODE", False), os.getenv("DEMO_MODE", "false"))

    if demo_mode:
        logger.info("Demo mode enabled — returning generated result")
        result = generate_demo_result(raw_input, input_type)
        return jsonify(result.to_response()), 200

    # 2. Cache lookup
    cache_col = get_collection(current_app.config["COLLECTION_CACHED"])

    if not cache_col:
        logger.error("Database unavailable — cannot perform scan")
        return jsonify({"error": "Database service unavailable. Please try again later."}), 503

    try:
        cached = cache_col.find_one({"input": raw_input})
    except Exception as e:
        logger.error("Cache read failed: %s", e)
        cached = None

    if cached:
        logger.info("Cache HIT | input=%s", raw_input)
        try:
            result = ScanResult.from_mongo(cached)
            return jsonify(result.to_response()), 200
        except Exception as e:
            logger.warning("Cache parse failed, recomputing: %s", e)

    # 3. Async API checks
    try:
        api_results = _run_async(
            run_api_checks(raw_input, input_type, current_app.config)
        )
    except Exception as e:
        logger.error("API checks failed: %s", e)
        api_results = {}

    # 4. Pattern detection
    try:
        pattern_flags = detect_patterns(raw_input, input_type)
    except Exception as e:
        logger.error("Pattern detection failed: %s", e)
        pattern_flags = []

    # 5. Known scams check
    try:
        known_scams_col = get_collection(
            current_app.config["COLLECTION_KNOWN_SCAMS"]
        )
        in_known_scams = (
            known_scams_col.count_documents({"value": raw_input}, limit=1) > 0
        )
    except Exception as e:
        logger.error("Known scams lookup failed: %s", e)
        in_known_scams = False

    # 6. Trust score + advice
    try:
        trust_score, risk_level = calculate_score(
            api_results, pattern_flags, input_type, in_known_scams
        )
    except Exception as e:
        logger.error("Score calculation failed: %s", e)
        trust_score, risk_level = 50, "UNKNOWN"

    try:
        advice = generate_advice(risk_level, input_type, pattern_flags)
    except Exception as e:
        logger.error("Advice generation failed: %s", e)
        advice = []

    # 7. Create result object
    result = ScanResult(
        input=raw_input,
        type=input_type,
        trust_score=trust_score,
        risk_level=risk_level,
        api_results=api_results,
        pattern_flags=pattern_flags,
        advice=advice,
    )

    # 8. Save to cache
    try:
        cache_col.update_one(
            {"input": raw_input},
            {"$set": result.to_dict()},
            upsert=True,
        )
        logger.debug("Cached result saved")
    except Exception as e:
        logger.warning("Cache write failed: %s", e)

    return jsonify(result.to_response()), 200


# ──────────────────────────────────────────────────────────────────────────────
# /report
# ──────────────────────────────────────────────────────────────────────────────

@scan_bp.route("/report", methods=["POST"])
def report():
    """
    Accept user-reported suspicious input.
    Stored for analytics / moderation.
    """

    payload = request.get_json(silent=True)

    if not payload or "input" not in payload:
        return jsonify({"error": "Missing required field: 'input'"}), 400

    raw_input = str(payload["input"]).strip()

    if not raw_input:
        return jsonify({"error": "'input' field must not be empty"}), 400

    report_doc = {
        "input": raw_input,
        "type": classify_input(raw_input),
        "reason": payload.get("reason", ""),
        "reporter_ip": request.remote_addr,
        "timestamp": datetime.now(timezone.utc),
    }

    try:
        reports_col = get_collection(
            current_app.config["COLLECTION_USER_REPORTS"]
        )
        reports_col.insert_one(report_doc)
        logger.info("Report stored | input=%s", raw_input)

    except Exception as e:
        logger.error("Failed to store report: %s", e)
        return jsonify({"error": "Failed to submit report"}), 500

    return jsonify({
        "message": "Report submitted. Thank you for helping keep the web safe."
    }), 201


# ──────────────────────────────────────────────────────────────────────────────
# /health
# ──────────────────────────────────────────────────────────────────────────────

@scan_bp.route("/health", methods=["GET"])
def health():
    """Health check endpoint (used by Docker / load balancer)."""
    return jsonify({"status": "ok"}), 200