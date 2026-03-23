import nest_asyncio
nest_asyncio.apply()   # must be called before any event loop is created

from flask import Flask
from flask_cors import CORS
from config import Config
from database.mongo_connection import init_db
from routes.scan_routes import scan_bp
from ingestion.scam_data_fetcher import start_scheduler
import logging

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def create_app(config: Config = None) -> Flask:
    """Application factory — creates and configures the Flask app."""
    app = Flask(__name__)
    app.config.from_object(config or Config)

    # ── CORS ───────────────────────────────────────────────────────────────────
    # In development, CORS_ORIGINS can be set to "*" in .env to allow the HTML
    # file to be opened directly (file://) or from any local dev server.
    # In production, set CORS_ORIGINS to your actual frontend domain.
    cors_origins = app.config["CORS_ORIGINS"]
    if cors_origins == ["*"] or "*" in cors_origins:
        CORS(app)   # allow all origins
    else:
        CORS(app, resources={r"/*": {"origins": cors_origins}})

    # Initialise MongoDB connection & indexes
    init_db(app)

    # Register route blueprints
    app.register_blueprint(scan_bp)

    # Start the 24-hour background data-ingestion scheduler
    start_scheduler(app)

    logger.info("CyberTrust backend started successfully.")
    return app


if __name__ == "__main__":
    application = create_app()
    application.run(
        host="0.0.0.0",
        port=5000,
        debug=Config.DEBUG,
    )
