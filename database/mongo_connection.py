"""
database/mongo_connection.py

Manages the MongoDB client lifecycle and ensures indexes are created
once at startup for fast cached-result lookups.
"""

import logging
import time
from flask import Flask
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ServerSelectionTimeoutError

logger = logging.getLogger(__name__)

# Module-level references — populated by init_db()
_client: MongoClient | None = None
_db: Database | None = None


def init_db(app: Flask) -> None:
    """
    Called once during app startup.
    Creates the MongoClient, stores references, and provisions indexes.
    Includes retry logic for Docker container startup timing.
    """
    global _client, _db

    if app.config.get("DEMO_MODE", False):
        logger.info("Demo mode enabled — skipping MongoDB initialization.")
        return

    mongo_uri: str = app.config["MONGO_URI"]
    max_retries = 10
    retry_delay = 3  # seconds

    for attempt in range(max_retries):
        try:
            logger.info(f"Attempting MongoDB connection (attempt {attempt + 1}/{max_retries})...")

            _client = MongoClient(
                mongo_uri,
                serverSelectionTimeoutMS=5000,
            )

            # Force connection check
            _client.admin.command("ping")

            _db = _client.get_default_database()

            if _db is None:
                raise RuntimeError("❌ No default database selected in MONGO_URI")

            _create_indexes(app)

            logger.info("✅ MongoDB connected and indexes ensured.")
            return

        except ServerSelectionTimeoutError as e:
            if attempt < max_retries - 1:
                logger.warning(f"❌ MongoDB connection failed (attempt {attempt + 1}): {e}. Retrying in {retry_delay}s...")
                time.sleep(retry_delay)
            else:
                logger.error(f"❌ MongoDB connection failed after {max_retries} attempts: {e}")
                logger.warning("⚠️  Starting in FALLBACK mode (no database, scanning disabled)")
                # Don't raise — allow Flask to start without MongoDB


def get_db() -> Database:
    """Return the active database instance. Must call init_db() first."""
    if _db is None:
        logger.warning("❌ Database not initialised — returning None in fallback mode")
        return None
    return _db


def get_collection(name: str) -> Collection:
    """Convenience helper — returns a named collection from the active DB. Returns None if DB unavailable."""
    db = get_db()
    if db is None:
        logger.warning(f"Collection '{name}' requested but database is unavailable")
        return None
    return db[name]


def close_db() -> None:
    """Gracefully close MongoDB connection (optional cleanup)."""
    global _client
    if _client:
        _client.close()
        logger.info("MongoDB connection closed.")


def _create_indexes(app: Flask) -> None:
    """
    Create indexes required for performant lookups.
    pymongo's create_index is idempotent — safe to call every startup.
    """
    db = get_db()

    # Cached results collection
    db[app.config["COLLECTION_CACHED"]].create_index(
        [("input", ASCENDING)],
        unique=True,
        name="idx_cached_input",
    )

    # TTL index (auto-delete old cache)
    db[app.config["COLLECTION_CACHED"]].create_index(
        [("timestamp", ASCENDING)],
        expireAfterSeconds=app.config["CACHE_TTL_SECONDS"],
        name="idx_cached_ttl",
    )

    # Known scams collection
    db[app.config["COLLECTION_KNOWN_SCAMS"]].create_index(
        [("value", ASCENDING)],
        unique=True,
        name="idx_known_scams_value",
    )

    # User reports collection
    db[app.config["COLLECTION_USER_REPORTS"]].create_index(
        [("input", ASCENDING)],
        name="idx_user_reports_input",
    )

    logger.debug("MongoDB indexes created / verified.")