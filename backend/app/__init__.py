from flask import Flask
from flask_cors import CORS
from app.config import Config
from app.extensions import db, migrate
from app.routes.auth import auth_bp
from app.routes.dashboard import dashboard_bp
from app.routes.scans import scans_bp
from app.services.scheduler_service import start_scheduler

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(app)

    db.init_app(app)
    migrate.init_app(app, db)

    from app import models

    from app.routes.auth import auth_bp
    from app.routes.scans import scans_bp
    from app.routes.alerts import alerts_bp
    from app.routes.settings import settings_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(scans_bp, url_prefix="/api/scans")
    app.register_blueprint(alerts_bp, url_prefix="/api/alerts")
    app.register_blueprint(settings_bp, url_prefix="/api/settings")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    
    with app.app_context():
        start_scheduler(app)

    @app.route("/")
    def home():
        return {"message": "SentinelGate backend is running"}

    return app