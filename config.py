import os
from dotenv import load_dotenv

# Load .env safely
if os.path.exists(".env"):
    load_dotenv()


class Config:
    # ── Flask ──────────────────────────────────────────────────────────────────
    DEBUG = os.getenv("FLASK_DEBUG", "false").lower() == "true"

    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key")

    if not DEBUG and SECRET_KEY == "dev-secret-key":
        raise ValueError("❌ SECRET_KEY must be set in production")

    # ── CORS ───────────────────────────────────────────────────────────────────
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    ]

    # ── MongoDB ────────────────────────────────────────────────────────────────
    MONGO_URI = os.getenv(
        "MONGO_URI",
        "mongodb://mongo:27017/cybertrust"  # Docker fallback
    )

    COLLECTION_CACHED = "cached_results"
    COLLECTION_KNOWN_SCAMS = "known_scams"
    COLLECTION_USER_REPORTS = "user_reports"

    CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", 86400))

    # ── API Keys ───────────────────────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY", "")
    URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY", "")

    # ── Endpoints ──────────────────────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/urls"
    NUMVERIFY_URL = "http://apilayer.net/api/validate"
    URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    # ── Scheduler ──────────────────────────────────────────────────────────────
    INGESTION_INTERVAL_HOURS = int(os.getenv("INGESTION_INTERVAL_HOURS", 24))

    OPENPHISH_FEED_URL = os.getenv(
        "OPENPHISH_FEED_URL",
        "https://openphish.com/feed.txt"
    )