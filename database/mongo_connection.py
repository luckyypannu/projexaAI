import logging
from datetime import datetime, timezone
from flask import Flask
from pymongo import MongoClient, ASCENDING
from pymongo.collection import Collection
from pymongo.database import Database

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
    _client = MongoClient(mongo_uri, serverSelectionTimeoutMS=5_000)
    _db = _client.get_default_database()

    _create_indexes(app)
    logger.info("MongoDB connected and indexes ensured.")


def get_db() -> Database:
    """Return the active database instance. Must call init_db() first."""
    if _db is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return _db


def get_collection(name: str) -> Collection:
    """Convenience helper — returns a named collection from the active DB."""
    return get_db()[name]


def _create_indexes(app: Flask) -> None:
    """
    Create indexes required for performant lookups.
    pymongo's create_index is idempotent — safe to call every startup.
    """
    db = get_db()

    # Fast lookup by raw input string in the results cache
    db[app.config["COLLECTION_CACHED"]].create_index(
        [("input", ASCENDING)], unique=True, name="idx_cached_input"
    )

    # TTL index: automatically expire cached documents after CACHE_TTL_SECONDS
    db[app.config["COLLECTION_CACHED"]].create_index(
        [("timestamp", ASCENDING)],
        expireAfterSeconds=app.config["CACHE_TTL_SECONDS"],
        name="idx_cached_ttl",
    )

    # Known-scams lookup by value
    db[app.config["COLLECTION_KNOWN_SCAMS"]].create_index(
        [("value", ASCENDING)], unique=True, name="idx_known_scams_value"
    )

    # User reports — index by input for aggregation queries
    db[app.config["COLLECTION_USER_REPORTS"]].create_index(
        [("input", ASCENDING)], name="idx_user_reports_input"
    )

    logger.debug("MongoDB indexes created / verified.")
