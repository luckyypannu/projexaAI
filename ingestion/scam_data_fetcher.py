from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import List

import aiohttp
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask import Flask

logger = logging.getLogger(__name__)

scheduler: BackgroundScheduler | None = None


# ──────────────────────────────────────────────────────────────────────────────
# Scheduler Bootstrap
# ──────────────────────────────────────────────────────────────────────────────

def start_scheduler(app: Flask) -> None:
    """
    Start background scheduler for periodic scam data ingestion.
    """
    global scheduler

    interval_hours: int = app.config.get("INGESTION_INTERVAL_HOURS", 24)

    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(
        func=_run_ingestion_job,
        trigger=IntervalTrigger(hours=interval_hours),
        args=[app],
        id="scam_data_ingestion",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc),  # run immediately
    )

    scheduler.start()
    logger.info("Scheduler started | interval=%dh", interval_hours)


def shutdown_scheduler() -> None:
    """
    Gracefully stop scheduler (used on app shutdown).
    """
    global scheduler

    if scheduler:
        scheduler.shutdown(wait=False)
        logger.info("Scheduler shut down")


# ──────────────────────────────────────────────────────────────────────────────
# Runner (SYNC → ASYNC bridge)
# ──────────────────────────────────────────────────────────────────────────────

def _run_ingestion_job(app: Flask) -> None:
    """
    Entry point for scheduler job.
    Runs async ingestion safely inside sync APScheduler.
    """
    with app.app_context():
        logger.info("Ingestion job started")

        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(_ingest_all_sources(app))

        except Exception as exc:
            logger.error("Ingestion failed: %s", exc, exc_info=True)

        finally:
            if loop and not loop.is_closed():
                loop.close()
                logger.debug("Event loop closed")


# ──────────────────────────────────────────────────────────────────────────────
# Orchestrator
# ──────────────────────────────────────────────────────────────────────────────

async def _ingest_all_sources(app: Flask) -> None:
    """
    Fetch all external threat intelligence sources in parallel
    and store results in MongoDB.
    """
    from database.mongo_connection import get_collection

    feed_url: str = app.config["OPENPHISH_FEED_URL"]
    collection_name: str = app.config["COLLECTION_KNOWN_SCAMS"]

    timeout = aiohttp.ClientTimeout(total=30)

    async with aiohttp.ClientSession(
        timeout=timeout,
        headers={"User-Agent": "CyberTrust/1.0"},
    ) as session:

        results = await asyncio.gather(
            _fetch_openphish(session, feed_url),
            return_exceptions=True,
        )

    col = get_collection(collection_name)

    bulk_ops = []
    total_processed = 0

    for outcome in results:
        if isinstance(outcome, Exception):
            logger.warning("Source fetch failed: %s", outcome)
            continue

        for doc in outcome:
            total_processed += 1
            bulk_ops.append({
                "filter": {"value": doc["value"]},
                "update": {"$set": doc},
                "upsert": True,
            })

    # ── Bulk Write (FAST + scalable) ─────────────────────────────────────────
    if bulk_ops:
        from pymongo import UpdateOne

        operations = [
            UpdateOne(op["filter"], op["update"], upsert=op["upsert"])
            for op in bulk_ops
        ]

        try:
            result = col.bulk_write(operations, ordered=False)

            upserted = result.upserted_count
            modified = result.modified_count

            logger.info(
                "Ingestion complete | processed=%d | upserted=%d | updated=%d",
                total_processed,
                upserted,
                modified,
            )

        except Exception as e:
            logger.error("Bulk write failed: %s", e, exc_info=True)

    else:
        logger.info("No data fetched from sources")


# ──────────────────────────────────────────────────────────────────────────────
# Data Source: OpenPhish
# ──────────────────────────────────────────────────────────────────────────────

async def _fetch_openphish(
    session: aiohttp.ClientSession,
    feed_url: str,
) -> List[dict]:
    """
    Fetch phishing URLs from OpenPhish feed.

    Features:
    - Retry logic (3 attempts)
    - Timeout handling
    - Clean parsing
    """

    text = None

    for attempt in range(3):
        try:
            async with session.get(feed_url) as resp:
                resp.raise_for_status()
                text = await resp.text()

            logger.debug("OpenPhish fetch success (attempt %d)", attempt + 1)
            break

        except Exception as e:
            logger.warning("OpenPhish retry %d failed: %s", attempt + 1, e)
            await asyncio.sleep(2)

    if text is None:
        raise RuntimeError("OpenPhish fetch failed after retries")

    now = datetime.now(timezone.utc)

    docs = [
        {
            "value": line.strip(),
            "type": "url",
            "source": "openphish",
            "last_seen": now,
        }
        for line in text.splitlines()
        if line.strip()
    ]

    logger.debug("Fetched %d OpenPhish URLs", len(docs))
    return docs