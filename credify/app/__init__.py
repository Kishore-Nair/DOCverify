"""Flask application factory."""

import os
import datetime
from flask import Flask, jsonify
from flask.json.provider import DefaultJSONProvider
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_cors import CORS

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
jwt = JWTManager()
bcrypt = Bcrypt()
cors = CORS()

class CustomProvider(DefaultJSONProvider):
    def default(self, o):
        if isinstance(o, (datetime.date, datetime.datetime)):
            return o.isoformat()
        return super().default(o)

def create_app(config_class="config.DevelopmentConfig"):
    """Create and configure the Flask application."""
    app = Flask(__name__)

    app.json_provider_class = CustomProvider
    app.json = CustomProvider(app)

    # Load config
    app.config.from_object(config_class)

    # Ensure upload folders exist
    os.makedirs(app.config.get("UPLOAD_FOLDER", "app/static/uploads"), exist_ok=True)
    os.makedirs(app.config.get("QR_FOLDER", "app/static/qrcodes"), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)
    bcrypt.init_app(app)
    cors.init_app(app)

    # Register blueprints
    from app.routes.auth import auth_bp, auth_api_bp
    from app.routes.documents import documents_bp, documents_api_bp
    from app.routes.verify import verify_bp, verify_api_bp
    from app.routes.admin import admin_bp

    app.register_blueprint(auth_bp)             # Web: /, /login, /register, /logout
    app.register_blueprint(auth_api_bp)         # API: /auth/*
    app.register_blueprint(documents_bp)        # Web: /dashboard, /upload, /report
    app.register_blueprint(documents_api_bp)    # API: /documents/*
    app.register_blueprint(verify_bp)           # Web: /verify
    app.register_blueprint(verify_api_bp)       # API: /verify/*
    app.register_blueprint(admin_bp)            # Web: /admin/*

    # Register error handlers returning JSON
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify(error="Bad Request", message=str(e)), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify(error="Unauthorized", message=str(e)), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify(error="Forbidden", message=str(e)), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify(error="Not Found", message=str(e)), 404

    @app.errorhandler(500)
    def internal_error(e):
        return jsonify(error="Internal Server Error", message=str(e)), 500

    # Create database tables
    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    return app
