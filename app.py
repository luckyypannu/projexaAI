from flask import Flask
from flask_cors import CORS
from config import Config
from database.mongo_connection import init_db
from routes.scan_routes import scan_bp
from ingestion.scam_data_fetcher import start_scheduler
import logging
import os

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def create_app(config: Config = None) -> Flask:
    app = Flask(__name__)
    app.config.from_object(config or Config)

    # ── CORS ───────────────────────────────────────────────────────────────────
    cors_origins = app.config["CORS_ORIGINS"]

    if cors_origins == ["*"] or "*" in cors_origins:
        CORS(app)
    else:
        CORS(app, resources={r"/*": {"origins": cors_origins}})

    # ── MongoDB ────────────────────────────────────────────────────────────────
    init_db(app)

    # ── Routes ─────────────────────────────────────────────────────────────────
    app.register_blueprint(scan_bp)

    # ── Health Check (IMPORTANT for Docker) ─────────────────────────────────────
    @app.route("/health")
    def health():
        return {"status": "ok"}, 200

    # ── Start Scheduler ONLY once (FIXED) ──────────────────────────────────────
    if os.environ.get("RUN_MAIN") == "true" or not app.debug:
        start_scheduler(app)
        logger.info("Scheduler started (single instance).")

    logger.info("CyberTrust backend started successfully.")
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=app.config["DEBUG"],
    )