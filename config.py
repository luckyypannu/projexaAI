import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    URLHAUS_API_KEY= os.getenv("URLHAUS_API_KEY")
    NUMVERIFY_API_KEY = os.getenv("NUMVERIFY_API_KEY")
    DEBUG = os.getenv("DEBUG", "False") == "True"
    PORT = int(os.getenv("PORT", 5000))