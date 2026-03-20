import asyncio
import logging
from flask import Blueprint, request, jsonify
from database.mongo_connection import get_collection
from models.scan_model import ScanResult
from services.pattern_detector import detect_patterns
from services.async_api_checker import run_api_checks
from services.trust_score_engine import calculate_score
from services.advice_generator import generate_advice
logger = logging.getLogger(__name__)

scan_bp = Blueprint("scan", __name__)

VALID_SCAN_TYPES = ["url", "phone", "email"]


# ── Route 1: Health Check ────────────────────────────────────
@scan_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ── Route 2: Get Past Reports ────────────────────────────────
@scan_bp.route("/report", methods=["GET"])
def get_report():
    try:
        collection = get_collection("scans")
        
        scan_type = request.args.get("scan_type")
        limit = int(request.args.get("limit", 20))
        
        query = {}
        if scan_type:
            if scan_type not in VALID_SCAN_TYPES:
                return jsonify({"error": "Invalid scan_type"}), 400
            query["scan_type"] = scan_type
        
        results = list(
            collection.find(query, {"_id": 0})
            .sort("created_at", -1)
            .limit(limit)
        )
        
        return jsonify({"count": len(results), "results": results}), 200
        
    except Exception as e:
        logger.error(f"Report error: {e}")
        return jsonify({"error": "Failed to fetch report"}), 500


# ── Route 3: Main Scan ───────────────────────────────────────
@scan_bp.route("/scan", methods=["POST"])
def scan():
    try:
        # 1. Get input
        data = request.get_json()
        if not data:
            return jsonify({"error": "Request body must be JSON"}), 400
        
        target = data.get("target", "").strip()
        scan_type = data.get("scan_type", "").strip().lower()
        
        # 2. Validate
        if not target:
            return jsonify({"error": "target is required"}), 400
        if not scan_type:
            return jsonify({"error": "scan_type is required"}), 400
        if scan_type not in VALID_SCAN_TYPES:
            return jsonify({"error": f"scan_type must be one of {VALID_SCAN_TYPES}"}), 400
        
        # 3. Check cache
        collection = get_collection("scans")
        existing = collection.find_one(
            {"target": target, "scan_type": scan_type},
            {"_id": 0}
        )
        if existing:
            return jsonify({"cached": True, "result": existing}), 200
        
        # 4. Run analysis
        patterns = detect_patterns(target, scan_type)
        api_results = asyncio.run(run_api_checks(target, scan_type))
        score, level = calculate_score(patterns, api_results)
        advice = generate_advice(score, patterns, api_results)
        
        # 5. Build result
        result = ScanResult(
            target=target,
            scan_type=scan_type,
            trust_score=score,
            risk_level=level,
            pattern_flags=patterns,  
            advice=advice
            )
        
        
        # 6. Save to MongoDB
        collection.insert_one(result.to_dict())
        
        # 7. Return response
        return jsonify({"cached": False, "result": result.to_dict()}), 201
        
    except Exception as e:
        logger.error(f"Scan error: {e}")
        return jsonify({"error": "Scan failed"}), 500