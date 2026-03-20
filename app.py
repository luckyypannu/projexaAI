import logging
from flask import Flask
from flask_cors import CORS
from config import Config
from database.mongo_connection import init_db

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    CORS(app)
    init_db()
    
    from routes.scan_routes import scan_bp
    app.register_blueprint(scan_bp)
    
    logger.info("App started successfully")
    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)