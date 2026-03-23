import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    # ── Flask ──────────────────────────────────────────────────────────────────
    DEBUG: bool = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production")

    # ── CORS ───────────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = os.getenv("CORS_ORIGINS", "*").split(",")

    # ── MongoDB ────────────────────────────────────────────────────────────────
    MONGO_URI: str = os.getenv("MONGO_URI","mongodb+srv://shamayadhariwal62_db_user:hJN9vFTkUppGOSCe@cluster0.ad3brhv.mongodb.net/tt_backend?appName=Cluster0" )
    COLLECTION_CACHED: str = "cached_results"
    COLLECTION_KNOWN_SCAMS: str = "known_scams"
    COLLECTION_USER_REPORTS: str = "user_reports"
    CACHE_TTL_SECONDS: int = int(os.getenv("CACHE_TTL_SECONDS", 86400))

    # ── External API Keys ──────────────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_API_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "")
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    NUMVERIFY_API_KEY: str = os.getenv("NUMVERIFY_API_KEY", "")
    # URLhaus (abuse.ch) — replaces PhishTank which closed in 2020
    URLHAUS_API_KEY: str = os.getenv("URLHAUS_API_KEY", "")

    # ── API Endpoints ──────────────────────────────────────────────────────────
    GOOGLE_SAFE_BROWSING_URL: str = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    )
    VIRUSTOTAL_URL: str = "https://www.virustotal.com/api/v3/urls"
    NUMVERIFY_URL: str = "http://apilayer.net/api/validate"
    # URLhaus URL lookup endpoint
    URLHAUS_URL: str = "https://urlhaus-api.abuse.ch/v1/url/"

    # ── Scheduler ──────────────────────────────────────────────────────────────
    INGESTION_INTERVAL_HOURS: int = int(os.getenv("INGESTION_INTERVAL_HOURS", 24))
    OPENPHISH_FEED_URL: str = os.getenv(
        "OPENPHISH_FEED_URL", "https://openphish.com/feed.txt"
    )
