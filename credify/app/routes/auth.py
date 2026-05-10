"""Authentication routes — web (session) + API (JWT)."""

import re
from datetime import timezone

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

from app import db
from app.models import User

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_ROLES = {"citizen", "issuer", "verifier", "admin"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _api_ok(data=None, message="Success", status=200):
    """Return a consistent JSON success envelope."""
    return jsonify({"success": True, "data": data, "message": message}), status


def _api_err(message="Something went wrong", status=400):
    """Return a consistent JSON error envelope."""
    return jsonify({"success": False, "data": None, "message": message}), status


# ===================================================================== #
#  WEB BLUEPRINT — session-based (serves HTML templates)                #
# ===================================================================== #

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/")
def index():
    """Redirect root to dashboard if logged in, else login."""
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """Register a new user account (web form)."""
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "citizen").strip()

        if not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.register"))

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return redirect(url_for("auth.register"))

        user = User(email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash("Account created! Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("login.html", mode="register")


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    """Log in an existing user (web form)."""
    if current_user.is_authenticated:
        return redirect(url_for("documents.dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("documents.dashboard"))

        flash("Invalid email or password.", "error")
        return redirect(url_for("auth.login"))

    return render_template("login.html", mode="login")


@auth_bp.route("/logout")
@login_required
def logout():
    """Log out the current user."""
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("auth.login"))


# ===================================================================== #
#  API BLUEPRINT — JWT-based (returns JSON)                             #
# ===================================================================== #

auth_api_bp = Blueprint("auth_api", __name__, url_prefix="/auth")


@auth_api_bp.route("/register", methods=["POST"])
def api_register():
    """Register a new user and return a JWT.

    Expects JSON body: {email, password, role?}
    Returns: {success, data: {token, user}, message}
    """
    body = request.get_json(silent=True) or {}

    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role = (body.get("role") or "citizen").strip().lower()

    # --- Validation ---
    errors = []
    if not email:
        errors.append("Email is required.")
    elif not EMAIL_RE.match(email):
        errors.append("Invalid email format.")

    if not password:
        errors.append("Password is required.")
    elif len(password) < 6:
        errors.append("Password must be at least 6 characters.")

    if role not in VALID_ROLES:
        errors.append(f"Invalid role. Choose from: {', '.join(sorted(VALID_ROLES))}.")

    if errors:
        return _api_err("; ".join(errors), 422)

    # Check for duplicates
    if User.query.filter_by(email=email).first():
        return _api_err("Email already registered.", 409)

    # Create user
    user = User(email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    # Issue token
    token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "email": user.email},
    )

    return _api_ok(
        data={"token": token, "user": user.to_dict()},
        message="Account created successfully.",
        status=201,
    )


@auth_api_bp.route("/login", methods=["POST"])
def api_login():
    """Authenticate and return a JWT.

    Expects JSON body: {email, password}
    Returns: {success, data: {token, user}, message}
    """
    body = request.get_json(silent=True) or {}

    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return _api_err("Email and password are required.", 422)

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return _api_err("Invalid email or password.", 401)

    token = create_access_token(
        identity=str(user.id),
        additional_claims={"role": user.role, "email": user.email},
    )

    return _api_ok(
        data={"token": token, "user": user.to_dict()},
        message="Login successful.",
    )


@auth_api_bp.route("/me", methods=["GET"])
@jwt_required()
def api_me():
    """Return the current authenticated user's info.

    Requires: Authorization: Bearer <token>
    Returns: {success, data: {user}, message}
    """
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))

    if not user:
        return _api_err("User not found.", 404)

    return _api_ok(data={"user": user.to_dict()}, message="Authenticated user.")
