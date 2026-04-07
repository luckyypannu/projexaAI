"""
database/mongo_connection.py

Manages the MongoDB client lifecycle and ensures indexes are created
once at startup for fast cached-result lookups.
"""

import logging
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
    """
    global _client, _db

    mongo_uri: str = app.config["MONGO_URI"]

    try:
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

    except ServerSelectionTimeoutError as e:
        logger.error("❌ MongoDB connection failed: %s", e)
        raise RuntimeError("MongoDB is not reachable")


def get_db() -> Database:
    """Return the active database instance. Must call init_db() first."""
    if _db is None:
        raise RuntimeError("❌ Database not initialised. Call init_db() first.")
    return _db


def get_collection(name: str) -> Collection:
    """Convenience helper — returns a named collection from the active DB."""
    return get_db()[name]


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