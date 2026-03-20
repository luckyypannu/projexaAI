import os
import logging
from pymongo import MongoClient, ASCENDING
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

client = None
db = None

def init_db():
    global client, db
    
    try:
        client = MongoClient(os.getenv("MONGO_URI"))
        db = client["scamchecker"]
        
        # Test the connection
        client.admin.command("ping")
        logger.info("MongoDB connected successfully")
        
        # Create indexes
        scans = db["scans"]
        scans.create_index([("target", ASCENDING)])
        scans.create_index([("scan_type", ASCENDING)])
        
        logger.info("Indexes created successfully")
        
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")
        raise RuntimeError(f"Could not connect to MongoDB: {e}")

def get_collection(name):
    if db is None:
        raise RuntimeError("Database not initialised. Call init_db() first.")
    return db[name]