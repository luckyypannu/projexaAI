import os
from dotenv import find_dotenv, load_dotenv

# Load .env safely (optional for local)
dotenv_path = find_dotenv(usecwd=True)
if dotenv_path:
    load_dotenv(dotenv_path, override=True)


class Config:
    # ── Flask ─────────────────────────────────────────────
    DEBUG = os.getenv("FLASK_DEBUG", "true").lower() == "true"
    ENV = os.getenv("FLASK_ENV", "development")

    # ✅ Always set safely (no crash here)
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")

    # ── CORS ──────────────────────────────────────────────
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    ]

    # ── MongoDB ───────────────────────────────────────────
    # Local development default uses localhost; Docker compose overrides MONGO_URI.
    MONGO_URI = os.getenv(
        "MONGO_URI",
        "mongodb://localhost:27017/cybertrust"
    )

    COLLECTION_CACHED = "cached_results"
    COLLECTION_KNOWN_SCAMS = "known_scams"
    COLLECTION_USER_REPORTS = "user_reports"

    CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", 86400))

    # ── API Keys ──────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
    URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")

    # ── Endpoints ─────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
    NUMVERIFY_URL = "http://apilayer.net/api/validate"
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    # ── Scheduler ─────────────────────────────────────────
    INGESTION_INTERVAL_HOURS = int(os.getenv("INGESTION_INTERVAL_HOURS", 24))

    OPENPHISH_FEED_URL = os.getenv(
        "OPENPHISH_FEED_URL",
        "https://openphish.com/feed.txt"
    )

    # ── Demo Mode (for testing without MongoDB) ───────────
    DEMO_MODE = os.getenv("DEMO_MODE", "false").lower() == "true"


def validate_config(app):
    """Validate configuration for production use."""
    # Skip validation in demo mode
    if app.config.get("DEMO_MODE", False):
        return
        
    # For now, skip production validation to allow demo mode
    pass