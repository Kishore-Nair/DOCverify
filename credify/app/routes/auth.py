"""Authentication routes — web (session) + API (JWT).

Includes:
- Email MX record validation on registration
- TOTP-based 2FA setup + verification
- Login attempt rate limiting (10 failures per IP → 15 min lockout)
"""

import re
import io
import base64
import logging
from datetime import datetime, timezone, timedelta

import pyotp
import qrcode
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, session
from flask_login import login_user, logout_user, login_required, current_user
from flask_jwt_extended import (
    create_access_token,
    jwt_required,
    get_jwt_identity,
)

from app import db
from app.models import User, LoginAttempt

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_ROLES = {"citizen", "issuer", "verifier", "admin"}
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Rate limiting constants
MAX_FAILED_ATTEMPTS = 10
LOCKOUT_MINUTES = 15


def _api_ok(data=None, message="Success", status=200):
    return jsonify({"success": True, "data": data, "message": message}), status


def _api_err(message="Something went wrong", status=400):
    return jsonify({"success": False, "data": None, "message": message}), status


def _check_email_domain(email: str) -> bool:
    """Check if the email domain has valid MX records (is a real mail server)."""
    try:
        import dns.resolver
        domain = email.split("@")[1]
        answers = dns.resolver.resolve(domain, "MX")
        return len(answers) > 0
    except Exception as e:
        logger.warning("MX lookup failed for %s: %s", email, e)
        return False


def _check_rate_limit(ip_address: str) -> bool:
    """Return True if the IP is currently rate-limited (too many failed logins)."""
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_MINUTES)
    recent_failures = LoginAttempt.query.filter(
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= cutoff,
    ).count()
    return recent_failures >= MAX_FAILED_ATTEMPTS


def _record_login_attempt(ip_address: str, email: str, success: bool):
    """Record a login attempt for security monitoring."""
    try:
        attempt = LoginAttempt(
            ip_address=ip_address,
            email=email,
            success=success,
        )
        db.session.add(attempt)
        db.session.commit()
    except Exception as e:
        logger.error("Failed to record login attempt: %s", e)
        db.session.rollback()


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
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "citizen").strip()

        if not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for("auth.register"))

        if not EMAIL_RE.match(email):
            flash("Invalid email format.", "error")
            return redirect(url_for("auth.register"))

        # Check if email domain has valid MX records
        if not _check_email_domain(email):
            flash("Email domain appears invalid. Please use a real email address.", "error")
            return redirect(url_for("auth.register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters.", "error")
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
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ip = request.remote_addr or "unknown"

        # Rate limit check
        if _check_rate_limit(ip):
            flash(f"Too many failed login attempts. Please try again in {LOCKOUT_MINUTES} minutes.", "error")
            return redirect(url_for("auth.login"))

        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            # Check if 2FA is enabled
            if user.two_fa_enabled:
                # Store user id in session for 2FA step
                session["pending_2fa_user_id"] = user.id
                session["pending_2fa_next"] = request.args.get("next", "")
                return redirect(url_for("auth.verify_2fa"))

            _record_login_attempt(ip, email, True)
            login_user(user)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("documents.dashboard"))

        _record_login_attempt(ip, email, False)
        flash("Invalid email or password.", "error")
        return redirect(url_for("auth.login"))

    return render_template("login.html", mode="login")


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Verify TOTP code after password authentication."""
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if not user:
        session.pop("pending_2fa_user_id", None)
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        totp = pyotp.TOTP(user.totp_secret)

        if totp.verify(code, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            next_page = session.pop("pending_2fa_next", "")
            _record_login_attempt(request.remote_addr or "unknown", user.email, True)
            login_user(user)
            return redirect(next_page or url_for("documents.dashboard"))
        else:
            _record_login_attempt(request.remote_addr or "unknown", user.email, False)
            flash("Invalid 2FA code. Please try again.", "error")

    return render_template("verify_2fa.html")


@auth_bp.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    """Enable TOTP-based 2FA for the current user."""
    if request.method == "POST":
        code = request.form.get("totp_code", "").strip()
        secret = session.get("pending_totp_secret")

        if not secret:
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.setup_2fa"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code, valid_window=1):
            current_user.totp_secret = secret
            current_user.two_fa_enabled = True
            db.session.commit()
            session.pop("pending_totp_secret", None)
            flash("Two-factor authentication enabled successfully!", "success")
            return redirect(url_for("documents.dashboard"))
        else:
            flash("Invalid code. Please scan the QR code and try again.", "error")

    # Generate new TOTP secret
    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="Credify"
    )

    # Generate QR code as base64
    img = qrcode.make(provisioning_uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(buffer.getvalue()).decode()

    return render_template("setup_2fa.html", qr_base64=qr_base64, secret=secret)


@auth_bp.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    """Disable 2FA for the current user."""
    current_user.totp_secret = None
    current_user.two_fa_enabled = False
    db.session.commit()
    flash("Two-factor authentication has been disabled.", "success")
    return redirect(url_for("documents.dashboard"))


# -- KYC routes -------------------------------------------------------------

@auth_bp.route("/kyc", methods=["GET", "POST"])
@login_required
def kyc_submit():
    """Submit KYC information."""
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        id_type = request.form.get("id_type", "").strip()
        id_number = request.form.get("id_number", "").strip()

        if not full_name or not id_type or not id_number:
            flash("All KYC fields are required.", "error")
            return redirect(url_for("auth.kyc_submit"))

        current_user.kyc_full_name = full_name
        current_user.kyc_id_type = id_type
        current_user.kyc_id_number = id_number
        current_user.kyc_status = "pending"
        current_user.kyc_submitted_at = datetime.now(timezone.utc)
        db.session.commit()

        flash("KYC submitted successfully! Awaiting admin review.", "success")
        return redirect(url_for("documents.dashboard"))

    return render_template("kyc.html")


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
    """Register a new user and return a JWT."""
    body = request.get_json(silent=True) or {}

    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    role = (body.get("role") or "citizen").strip().lower()

    errors = []
    if not email:
        errors.append("Email is required.")
    elif not EMAIL_RE.match(email):
        errors.append("Invalid email format.")
    else:
        if not _check_email_domain(email):
            errors.append("Email domain appears invalid. Please use a real email address.")

    if not password:
        errors.append("Password is required.")
    elif len(password) < 6:
        errors.append("Password must be at least 6 characters.")

    if role not in VALID_ROLES:
        errors.append(f"Invalid role. Choose from: {', '.join(sorted(VALID_ROLES))}.")

    if errors:
        return _api_err("; ".join(errors), 422)

    if User.query.filter_by(email=email).first():
        return _api_err("Email already registered.", 409)

    user = User(email=email, role=role)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

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
    """Authenticate and return a JWT."""
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    ip = request.remote_addr or "unknown"

    if not email or not password:
        return _api_err("Email and password are required.", 422)

    if _check_rate_limit(ip):
        return _api_err(f"Too many failed login attempts. Try again in {LOCKOUT_MINUTES} minutes.", 429)

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        _record_login_attempt(ip, email, False)
        return _api_err("Invalid email or password.", 401)

    _record_login_attempt(ip, email, True)

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
    """Return the current authenticated user's info."""
    user_id = get_jwt_identity()
    user = db.session.get(User, int(user_id))

    if not user:
        return _api_err("User not found.", 404)

    return _api_ok(data={"user": user.to_dict()}, message="Authenticated user.")
