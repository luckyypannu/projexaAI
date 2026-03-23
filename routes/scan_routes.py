import asyncio
import logging
from datetime import datetime, timezone

from flask import Blueprint, request, jsonify, current_app

from database.mongo_connection import get_collection
from models.scan_model import ScanResult
from services.async_api_checker import run_api_checks
from services.pattern_detector import detect_patterns, classify_input
from services.trust_score_engine import calculate_score
from services.advice_generator import generate_advice

logger = logging.getLogger(__name__)
scan_bp = Blueprint("scan", __name__)


def _run_async(coro):
    """
    Safely run a coroutine from a synchronous Flask route.
    nest_asyncio (applied in app.py) makes asyncio.run() safe to call
    even when a background event loop is already running.
    """
    try:
        return asyncio.run(coro)
    except RuntimeError:
        # Fallback: create a brand-new event loop if asyncio.run() fails
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()


# ── /scan ──────────────────────────────────────────────────────────────────────

@scan_bp.route("/scan", methods=["POST"])
def scan():
    """
    Main scan endpoint.

    1. Validate the incoming payload.
    2. Check MongoDB cache — return immediately on hit.
    3. Run async external API checks + pattern detection in parallel.
    4. Calculate trust score and generate advice.
    5. Persist result to MongoDB and return to client.
    """
    payload = request.get_json(silent=True)
    if not payload or "input" not in payload:
        return jsonify({"error": "Missing required field: 'input'"}), 400

    raw_input: str = str(payload["input"]).strip()
    if not raw_input:
        return jsonify({"error": "'input' field must not be empty"}), 400

    # ── 1. Classify input type ─────────────────────────────────────────────────
    input_type: str = classify_input(raw_input)
    logger.info("Scan request — type=%s input=%s", input_type, raw_input)

    # ── 2. Cache lookup ────────────────────────────────────────────────────────
    cache_col = get_collection(current_app.config["COLLECTION_CACHED"])
    cached = cache_col.find_one({"input": raw_input})
    if cached:
        logger.info("Cache HIT for input=%s", raw_input)
        result = ScanResult.from_mongo(cached)
        return jsonify(result.to_response()), 200

    # ── 3. External API checks (async, parallel) ───────────────────────────────
    try:
        api_results: dict = _run_async(
            run_api_checks(raw_input, input_type, current_app.config)
        )
    except Exception as exc:
        logger.error("API checks failed for %s: %s", raw_input, exc)
        api_results = {}

    # ── 4. Pattern detection ───────────────────────────────────────────────────
    pattern_flags: list[str] = detect_patterns(raw_input, input_type)

    # ── 5. Check known-scams collection ───────────────────────────────────────
    known_scams_col = get_collection(current_app.config["COLLECTION_KNOWN_SCAMS"])
    in_known_scams: bool = known_scams_col.count_documents(
        {"value": raw_input}, limit=1
    ) > 0

    # ── 6. Trust score + advice ────────────────────────────────────────────────
    trust_score, risk_level = calculate_score(
        api_results, pattern_flags, input_type, in_known_scams
    )
    advice: list[str] = generate_advice(risk_level, input_type, pattern_flags)

    # ── 7. Build result object ─────────────────────────────────────────────────
    result = ScanResult(
        input=raw_input,
        type=input_type,
        trust_score=trust_score,
        risk_level=risk_level,
        api_results=api_results,
        pattern_flags=pattern_flags,
        advice=advice,
    )

    # ── 8. Persist to cache ────────────────────────────────────────────────────
    try:
        cache_col.update_one(
            {"input": raw_input},
            {"$set": result.to_dict()},
            upsert=True,
        )
    except Exception as exc:
        logger.warning("Failed to cache result for %s: %s", raw_input, exc)

    return jsonify(result.to_response()), 200


# ── /report ────────────────────────────────────────────────────────────────────

@scan_bp.route("/report", methods=["POST"])
def report():
    """
    Accept a user-submitted report of a suspicious input.
    Stored in the `user_reports` collection for review / future analysis.
    """
    payload = request.get_json(silent=True)
    if not payload or "input" not in payload:
        return jsonify({"error": "Missing required field: 'input'"}), 400

    raw_input: str = str(payload["input"]).strip()
    if not raw_input:
        return jsonify({"error": "'input' field must not be empty"}), 400

    report_doc = {
        "input": raw_input,
        "type": classify_input(raw_input),
        "reason": payload.get("reason", ""),
        "reporter_ip": request.remote_addr,
        "timestamp": datetime.now(timezone.utc),
    }

    reports_col = get_collection(current_app.config["COLLECTION_USER_REPORTS"])
    reports_col.insert_one(report_doc)

    logger.info("User report received for input=%s", raw_input)
    return jsonify({"message": "Report submitted. Thank you for helping keep the web safe."}), 201


# ── /health ────────────────────────────────────────────────────────────────────

@scan_bp.route("/health", methods=["GET"])
def health():
    """Simple liveness probe used by load-balancers and monitoring tools."""
    return jsonify({"status": "ok"}), 200
