"""Admin routes — session-based, role-restricted to admin users.

Blueprint ``admin_bp``  /admin, /admin/users, /admin/documents, etc.
Includes KYC approval, security monitoring, and threat alerts.
"""

import logging
from datetime import datetime, timezone, timedelta
from functools import wraps

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    abort,
)
from flask_login import login_required, current_user

from app import db
from app.models import User, Document, AuditLog, LoginAttempt

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ---------------------------------------------------------------------------
# Decorator: require admin role
# ---------------------------------------------------------------------------

def admin_required(f):
    """Ensure the current user is authenticated AND has role='admin'."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            flash("Access denied. Admin privileges required.", "error")
            return redirect(url_for("documents.dashboard"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Admin Dashboard — overview
# ---------------------------------------------------------------------------

@admin_bp.route("/")
@admin_required
def dashboard():
    """Admin overview with aggregate stats."""
    total_users = User.query.count()
    total_docs = Document.query.count()
    verified_docs = Document.query.filter_by(status="verified").count()
    flagged_docs = Document.query.filter(
        Document.status.in_(["flagged", "rejected"])
    ).count()
    revoked_docs = Document.query.filter_by(status="revoked").count()
    pending_docs = Document.query.filter_by(status="pending").count()
    total_audits = AuditLog.query.count()

    recent_docs = Document.query.order_by(Document.upload_date.desc()).limit(10).all()
    recent_users = User.query.order_by(User.created_at.desc()).limit(10).all()
    recent_audits = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(15).all()

    stats = {
        "total_users": total_users,
        "total_docs": total_docs,
        "verified": verified_docs,
        "flagged": flagged_docs,
        "revoked": revoked_docs,
        "pending": pending_docs,
        "total_audits": total_audits,
    }

    return render_template(
        "admin.html",
        stats=stats,
        recent_docs=recent_docs,
        recent_users=recent_users,
        recent_audits=recent_audits,
    )


# ---------------------------------------------------------------------------
# Users management
# ---------------------------------------------------------------------------

@admin_bp.route("/users")
@admin_required
def users():
    """List all users with document counts."""
    all_users = User.query.order_by(User.created_at.desc()).all()

    user_data = []
    for u in all_users:
        doc_count = Document.query.filter_by(owner_id=u.id).count()
        user_data.append({"user": u, "doc_count": doc_count})

    return render_template("admin_users.html", users=user_data)


@admin_bp.route("/users/<int:user_id>")
@admin_required
def user_detail(user_id):
    """View a single user's details and their documents."""
    user = User.query.get_or_404(user_id)
    docs = Document.query.filter_by(owner_id=user.id).order_by(
        Document.upload_date.desc()
    ).all()

    return render_template("admin_user_detail.html", user=user, documents=docs)


@admin_bp.route("/users/<int:user_id>/role", methods=["POST"])
@admin_required
def change_role(user_id):
    """Change a user's role."""
    user = User.query.get_or_404(user_id)
    new_role = request.form.get("role", "").strip().lower()

    valid_roles = {"citizen", "issuer", "verifier", "admin"}
    if new_role not in valid_roles:
        flash(f"Invalid role. Choose from: {', '.join(sorted(valid_roles))}", "error")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    if user.id == current_user.id and new_role != "admin":
        flash("You cannot remove your own admin privileges.", "error")
        return redirect(url_for("admin.user_detail", user_id=user_id))

    old_role = user.role
    user.role = new_role
    db.session.commit()

    logger.info("Admin %s changed role of user %d from %s to %s",
                current_user.email, user.id, old_role, new_role)
    flash(f"User {user.email} role changed from {old_role} to {new_role}.", "success")
    return redirect(url_for("admin.user_detail", user_id=user_id))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    """Delete a user (cannot delete self)."""
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin.users"))

    email = user.email
    db.session.delete(user)
    db.session.commit()

    logger.info("Admin %s deleted user %s (id=%d)", current_user.email, email, user_id)
    flash(f"User {email} has been deleted.", "success")
    return redirect(url_for("admin.users"))


# ---------------------------------------------------------------------------
# Documents management
# ---------------------------------------------------------------------------

@admin_bp.route("/documents")
@admin_required
def documents():
    """List all documents with owner info."""
    status_filter = request.args.get("status", "").strip().lower()

    query = Document.query
    if status_filter:
        query = query.filter_by(status=status_filter)

    all_docs = query.order_by(Document.upload_date.desc()).all()

    return render_template(
        "admin_documents.html",
        documents=all_docs,
        current_filter=status_filter,
    )


@admin_bp.route("/documents/<int:doc_id>")
@admin_required
def document_detail(doc_id):
    """View full document details with audit trail."""
    doc = Document.query.get_or_404(doc_id)
    owner = User.query.get(doc.owner_id)
    audits = AuditLog.query.filter_by(document_id=doc_id).order_by(
        AuditLog.timestamp.desc()
    ).all()

    return render_template(
        "admin_doc_detail.html",
        doc=doc,
        owner=owner,
        audits=audits,
    )


@admin_bp.route("/documents/<int:doc_id>/revoke", methods=["POST"])
@admin_required
def revoke_document(doc_id):
    """Admin-force revoke a document."""
    from app.services.blockchain_service import revoke_document as blockchain_revoke

    doc = Document.query.get_or_404(doc_id)

    if doc.status == "revoked":
        flash("Document is already revoked.", "error")
        return redirect(url_for("admin.document_detail", doc_id=doc_id))

    try:
        tx_hash = blockchain_revoke(doc.sha256_hash)
    except Exception as e:
        logger.error("Admin revoke blockchain error: %s", e)
        tx_hash = "admin_revoke_offline"

    doc.status = "revoked"
    audit = AuditLog(
        document_id=doc.id,
        action="admin_revoke",
        performed_by=current_user.email,
        details={"tx_hash": tx_hash, "reason": "Admin revocation"},
    )
    db.session.add(audit)
    db.session.commit()

    flash(f"Document #{doc.id} has been revoked.", "success")
    return redirect(url_for("admin.document_detail", doc_id=doc_id))


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@admin_bp.route("/audit")
@admin_required
def audit_log():
    """View the full audit trail."""
    page = request.args.get("page", 1, type=int)
    per_page = 25

    pagination = AuditLog.query.order_by(
        AuditLog.timestamp.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return render_template(
        "admin_audit.html",
        audits=pagination.items,
        pagination=pagination,
    )


# ---------------------------------------------------------------------------
# KYC Management
# ---------------------------------------------------------------------------

@admin_bp.route("/kyc")
@admin_required
def kyc_list():
    """List all users with pending KYC submissions."""
    pending = User.query.filter_by(kyc_status="pending").filter(
        User.kyc_full_name.isnot(None)
    ).all()
    verified = User.query.filter_by(kyc_status="verified").all()
    rejected = User.query.filter_by(kyc_status="rejected").all()

    return render_template(
        "admin_kyc.html",
        pending=pending,
        verified=verified,
        rejected=rejected,
    )


@admin_bp.route("/kyc/<int:user_id>/approve", methods=["POST"])
@admin_required
def kyc_approve(user_id):
    """Approve a user's KYC submission."""
    user = User.query.get_or_404(user_id)
    user.kyc_status = "verified"
    user.kyc_verified_at = datetime.now(timezone.utc)
    db.session.commit()
    logger.info("Admin %s approved KYC for user %s", current_user.email, user.email)
    flash(f"KYC approved for {user.email}.", "success")
    return redirect(url_for("admin.kyc_list"))


@admin_bp.route("/kyc/<int:user_id>/reject", methods=["POST"])
@admin_required
def kyc_reject(user_id):
    """Reject a user's KYC submission."""
    user = User.query.get_or_404(user_id)
    reason = request.form.get("reason", "No reason provided")
    user.kyc_status = "rejected"
    user.kyc_rejection_reason = reason
    db.session.commit()
    logger.info("Admin %s rejected KYC for user %s. Reason: %s", current_user.email, user.email, reason)
    flash(f"KYC rejected for {user.email}. Reason: {reason}", "error")
    return redirect(url_for("admin.kyc_list"))


# ---------------------------------------------------------------------------
# Security Monitoring
# ---------------------------------------------------------------------------

@admin_bp.route("/security")
@admin_required
def security():
    """Security monitoring dashboard — failed logins, suspicious activity."""
    cutoff_15m = datetime.now(timezone.utc) - timedelta(minutes=15)
    cutoff_1h = datetime.now(timezone.utc) - timedelta(hours=1)
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    # Failed logins in last 15 minutes grouped by IP
    from sqlalchemy import func
    locked_ips = db.session.query(
        LoginAttempt.ip_address,
        func.count(LoginAttempt.id).label("count")
    ).filter(
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= cutoff_15m,
    ).group_by(LoginAttempt.ip_address).having(
        func.count(LoginAttempt.id) >= 5
    ).all()

    # Recent failed login attempts
    recent_failures = LoginAttempt.query.filter(
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= cutoff_1h,
    ).order_by(LoginAttempt.timestamp.desc()).limit(50).all()

    # Admin revocation velocity — flag if >50 revokes in 5 min
    cutoff_5m = datetime.now(timezone.utc) - timedelta(minutes=5)
    recent_revokes = AuditLog.query.filter(
        AuditLog.action.in_(["revoke", "admin_revoke"]),
        AuditLog.timestamp >= cutoff_5m,
    ).count()

    # Total stats
    total_failures_24h = LoginAttempt.query.filter(
        LoginAttempt.success == False,
        LoginAttempt.timestamp >= cutoff_24h,
    ).count()
    total_logins_24h = LoginAttempt.query.filter(
        LoginAttempt.timestamp >= cutoff_24h,
    ).count()

    alerts = []
    if recent_revokes >= 50:
        alerts.append({
            "level": "critical",
            "message": f"ALERT: {recent_revokes} documents revoked in the last 5 minutes! Possible compromise.",
        })
    for ip, count in locked_ips:
        alerts.append({
            "level": "warning",
            "message": f"IP {ip} has {count} failed login attempts in 15 minutes (locked out).",
        })

    return render_template(
        "admin_security.html",
        locked_ips=locked_ips,
        recent_failures=recent_failures,
        recent_revokes=recent_revokes,
        total_failures_24h=total_failures_24h,
        total_logins_24h=total_logins_24h,
        alerts=alerts,
    )
