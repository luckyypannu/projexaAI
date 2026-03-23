import logging
import requests
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger

logger = logging.getLogger(__name__)
scheduler = BackgroundScheduler(daemon=True)

def start_scheduler(app):
    """Start background scam data ingestion scheduler"""
    try:
        def fetch_scam_data():
            with app.app_context():
                try:
                    from database.mongo_connection import get_collection
                    feed_url = app.config.get(
                        "OPENPHISH_FEED_URL",
                        "https://openphish.com/feed.txt"
                    )
                    response = requests.get(feed_url, timeout=10)
                    response.raise_for_status()
                    collection = get_collection(
                        app.config["COLLECTION_KNOWN_SCAMS"]
                    )
                    count = 0
                    for line in response.text.splitlines():
                        url = line.strip()
                        if url:
                            collection.update_one(
                                {"value": url},
                                {"$set": {"value": url, "source": "openphish"}},
                                upsert=True
                            )
                            count += 1
                    logger.info(f"Ingested {count} scam entries")
                except Exception as e:
                    logger.error(f"Ingestion failed: {e}")

        scheduler.add_job(
            fetch_scam_data,
            trigger=IntervalTrigger(
                hours=app.config.get("INGESTION_INTERVAL_HOURS", 24)
            ),
            next_run_time=datetime.now()
        )
        scheduler.start()
        logger.info("Scheduler started successfully")
    except Exception as e:
        logger.error(f"Failed to start scheduler: {e}")