"""Flask application factory."""

import os
from datetime import timedelta

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_jwt_extended import JWTManager

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
jwt = JWTManager()


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)

    # Load config
    app.config.from_object("config.Config")

    # Ensure upload folder exists
    os.makedirs(app.config.get("UPLOAD_FOLDER", "uploads"), exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)

    # Register blueprints
    from app.routes.auth import auth_bp, auth_api_bp
    from app.routes.documents import documents_bp, documents_api_bp
    from app.routes.verify import verify_bp, verify_api_bp

    app.register_blueprint(auth_bp)             # Web: /, /login, /register, /logout
    app.register_blueprint(auth_api_bp)         # API: /auth/*
    app.register_blueprint(documents_bp)        # Web: /dashboard, /upload, /report
    app.register_blueprint(documents_api_bp)    # API: /documents/*
    app.register_blueprint(verify_bp)           # Web: /verify
    app.register_blueprint(verify_api_bp)       # API: /verify/*

    # Create database tables
    with app.app_context():
        from app import models  # noqa: F401
        db.create_all()

    return app
