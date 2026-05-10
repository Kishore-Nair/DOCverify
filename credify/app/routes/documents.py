"""Document routes — web (session) + API (JWT).

Web blueprint  ``documents_bp``       /dashboard, /upload, /report/<id>
API blueprint  ``documents_api_bp``   /documents/upload, /documents/<id>,
                                      /documents/my, /documents/<id>/revoke
"""

import os
import tempfile

from flask import (
    Blueprint,
    render_template,
    redirect,
    url_for,
    flash,
    request,
    jsonify,
    current_app,
)
from flask_login import login_required, current_user
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from werkzeug.utils import secure_filename

from app import db
from app.models import Document, AuditLog, User
from app.services.hasher import hash_file
from app.services.ai_checker import analyze_document, check_document
from app.services.ipfs_service import upload_file as ipfs_upload
from app.services.blockchain_service import (
    store_document as blockchain_store,
    revoke_document as blockchain_revoke,
)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg"}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB


def _allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _ext(filename: str) -> str:
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def _api_ok(data=None, message="Success", status=200):
    return jsonify({"success": True, "data": data, "message": message}), status


def _api_err(message="Something went wrong", status=400):
    return jsonify({"success": False, "data": None, "message": message}), status


def _generate_qr(doc_id: int, sha256_hash: str) -> str:
    """Generate a QR code PNG and return its URL path.

    The QR encodes ``/verify?hash=<sha256>`` and is saved to
    ``static/qrcodes/<doc_id>.png``.
    """
    try:
        import qrcode

        qr_dir = os.path.join(current_app.root_path, "static", "qrcodes")
        os.makedirs(qr_dir, exist_ok=True)

        verify_url = f"/verify?hash={sha256_hash}"
        img = qrcode.make(verify_url)

        filename = f"{doc_id}.png"
        filepath = os.path.join(qr_dir, filename)
        img.save(filepath)

        return f"/static/qrcodes/{filename}"
    except Exception as exc:
        current_app.logger.warning("QR generation failed: %s", exc)
        return ""


def _save_temp_file(file_storage) -> str:
    """Save an uploaded file to a temp location and return the path."""
    ext = _ext(file_storage.filename)
    fd, path = tempfile.mkstemp(suffix=f".{ext}", prefix="credify_")
    os.close(fd)
    file_storage.save(path)
    return path


# ===================================================================== #
#  WEB BLUEPRINT — session-based (serves HTML templates)                #
# ===================================================================== #

documents_bp = Blueprint("documents", __name__)


@documents_bp.route("/dashboard")
@login_required
def dashboard():
    """Show the user dashboard with document stats."""
    if current_user.role == "admin":
        return redirect(url_for("admin.dashboard"))

    docs = Document.query.filter_by(owner_id=current_user.id).order_by(
        Document.upload_date.desc()
    ).all()
    stats = {
        "total": len(docs),
        "verified": sum(1 for d in docs if d.status == "verified"),
        "pending": sum(1 for d in docs if d.status == "pending"),
        "rejected": sum(1 for d in docs if d.status == "rejected"),
    }
    return render_template("dashboard.html", documents=docs, stats=stats)


@documents_bp.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    """Upload a document through the verification pipeline (web form)."""
    if current_user.role in ("verifier", "admin"):
        flash("Admins and Verifiers are not permitted to upload documents.", "error")
        return redirect(url_for("documents.dashboard"))

    if request.method == "POST":
        file = request.files.get("document")
        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(url_for("documents.upload"))

        if not _allowed_file(file.filename):
            flash("File type not allowed.", "error")
            return redirect(url_for("documents.upload"))

        filename = secure_filename(file.filename)
        upload_dir = current_app.config["UPLOAD_FOLDER"]
        filepath = os.path.join(upload_dir, filename)
        file.save(filepath)

        # Pipeline
        sha256 = hash_file(filepath)
        ai_result = check_document(filepath)
        
        verdict = ai_result.get("verdict", "LEGIT")
        details = ai_result.get("details", [])
        rejection_reason = None
        
        if verdict == "LEGIT":
            status = "verified"
            ipfs_result = ipfs_upload(filepath)
            ipfs_cid = ipfs_result["cid"]
            tx_hash = blockchain_store(sha256, ipfs_cid)
        else:
            status = "rejected"
            rejection_reason = "; ".join(details) if details else "AI flagged document as suspicious."
            ipfs_cid = None
            tx_hash = None

        doc = Document(
            filename=filename,
            original_name=file.filename,
            sha256_hash=sha256,
            ipfs_cid=ipfs_cid,
            blockchain_tx_id=tx_hash,
            status=status,
            owner_id=current_user.id,
            doc_type=request.form.get("doc_type", "").strip() or None,
            issuer_name=request.form.get("issuer_name", "").strip() or None,
            rejection_reason=rejection_reason,
        )
        db.session.add(doc)
        db.session.commit()

        if status == "rejected":
            flash(f"Document REJECTED by AI analysis: {rejection_reason}", "error")
        else:
            flash(f"Document processed — status: {status.upper()}", "success")
        return redirect(url_for("documents.report", doc_id=doc.id))

    return render_template("upload.html")


@documents_bp.route("/report/<int:doc_id>")
@login_required
def report(doc_id: int):
    """Show detailed report for a single document."""
    doc = Document.query.get_or_404(doc_id)
    # Owner, verifier, or admin can view
    if doc.owner_id != current_user.id and current_user.role not in ("verifier", "admin"):
        flash("Access denied.", "error")
        return redirect(url_for("documents.dashboard"))
    return render_template("report.html", doc=doc)


@documents_bp.route("/files")
@login_required
def file_browser():
    """View all uploaded files. Only accessible by verifiers and admins."""
    if current_user.role not in ("verifier", "admin"):
        flash("Access denied. Only verifiers and admins can view all files.", "error")
        return redirect(url_for("documents.dashboard"))

    if current_user.role == "verifier" and current_user.kyc_status != "verified":
        flash("KYC Verification Required: You must complete identity verification before accessing the file browser.", "warning")
        return redirect(url_for("auth.kyc_submit"))

    status_filter = request.args.get("status", "").strip().lower()
    query = Document.query
    if status_filter:
        query = query.filter_by(status=status_filter)
    all_docs = query.order_by(Document.upload_date.desc()).all()
    return render_template("file_browser.html", documents=all_docs, current_filter=status_filter)


# ===================================================================== #
#  API BLUEPRINT — JWT-based (returns JSON)                             #
# ===================================================================== #

documents_api_bp = Blueprint("documents_api", __name__, url_prefix="/documents")


@documents_api_bp.route("/upload", methods=["POST"])
@jwt_required()
def api_upload():
    """Upload and verify a document (full pipeline).

    Requires: JWT with role citizen or issuer.
    Accepts:  multipart/form-data  field ``file``  (PDF/PNG/JPG, ≤10 MB).
    Optional form fields: ``doc_type``, ``issuer_name``.

    Pipeline:
        1. Validate file
        2. AI tampering check → reject if suspicious
        3. SHA-256 hash → de-duplicate
        4. IPFS upload
        5. Blockchain store
        6. Save to DB + AuditLog
        7. Generate QR code
    """
    # -- Auth / role check --
    claims = get_jwt()
    role = claims.get("role", "citizen")
    if role not in ("citizen", "issuer"):
        return _api_err("Only citizens and issuers can upload documents.", 403)

    user_id = int(get_jwt_identity())

    # -- File validation --
    file = request.files.get("file")
    if not file or file.filename == "":
        return _api_err("No file provided.", 422)

    if not _allowed_file(file.filename):
        return _api_err(
            f"File type not allowed. Accepted: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
            422,
        )

    # Save to temp location
    tmp_path = _save_temp_file(file)

    try:
        # Check file size
        file_size = os.path.getsize(tmp_path)
        if file_size > MAX_FILE_SIZE:
            return _api_err(
                f"File too large ({file_size:,} bytes). Max is {MAX_FILE_SIZE:,} bytes.",
                413,
            )

        # ── Step 1: AI tampering check ───────────────────────────────
        ai_result = analyze_document(tmp_path)

        if ai_result["is_suspicious"]:
            # Save rejected doc with rejection reason instead of just returning error
            sha256_rej = hash_file(tmp_path)
            rejection_reason = "; ".join(ai_result["flags"]) if ai_result["flags"] else "AI flagged document as suspicious."
            filename_rej = secure_filename(file.filename)
            doc_rej = Document(
                filename=filename_rej,
                original_name=file.filename,
                sha256_hash=sha256_rej,
                status="rejected",
                owner_id=user_id,
                doc_type=request.form.get("doc_type", "").strip() or None,
                issuer_name=request.form.get("issuer_name", "").strip() or None,
                rejection_reason=rejection_reason,
            )
            db.session.add(doc_rej)
            db.session.commit()
            return _api_err(
                f"Document REJECTED (confidence: "
                f"{ai_result['confidence_score']:.1%}). "
                f"Reason: {rejection_reason}",
                400,
            )

        # ── Step 2: SHA-256 hash ─────────────────────────────────────
        sha256 = hash_file(tmp_path)

        # ── Step 3: De-duplicate ─────────────────────────────────────
        existing = Document.query.filter_by(sha256_hash=sha256).first()
        if existing:
            return _api_ok(
                data={"document": existing.to_dict(), "duplicate": True},
                message="Document already registered.",
                status=200,
            )

        # ── Step 4: IPFS upload ──────────────────────────────────────
        ipfs_result = ipfs_upload(tmp_path)
        ipfs_cid = ipfs_result["cid"]

        # ── Step 5: Blockchain store ─────────────────────────────────
        tx_hash = blockchain_store(sha256, ipfs_cid)

        # ── Step 6: Save to DB ───────────────────────────────────────
        filename = secure_filename(file.filename)
        doc = Document(
            filename=filename,
            original_name=file.filename,
            sha256_hash=sha256,
            ipfs_cid=ipfs_cid,
            blockchain_tx_id=tx_hash,
            status="verified",
            owner_id=user_id,
            doc_type=request.form.get("doc_type", "").strip() or None,
            issuer_name=request.form.get("issuer_name", "").strip() or None,
        )
        db.session.add(doc)
        db.session.flush()  # get doc.id before commit

        # Audit log
        audit = AuditLog(
            document_id=doc.id,
            action="upload",
            performed_by=claims.get("email", str(user_id)),
            details={
                "confidence_score": ai_result["confidence_score"],
                "ipfs_cid": ipfs_cid,
                "tx_hash": tx_hash,
                "file_size": file_size,
            },
        )
        db.session.add(audit)
        db.session.commit()

        # ── Step 7: QR code ──────────────────────────────────────────
        qr_url = _generate_qr(doc.id, sha256)

        return _api_ok(
            data={
                "doc_id": doc.id,
                "sha256_hash": sha256,
                "ipfs_cid": ipfs_cid,
                "tx_hash": tx_hash,
                "confidence_score": ai_result["confidence_score"],
                "qr_code_url": qr_url,
                "document": doc.to_dict(),
            },
            message="Document uploaded and verified successfully.",
            status=201,
        )

    finally:
        # Clean up temp file
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)


@documents_api_bp.route("/<int:doc_id>", methods=["GET"])
@jwt_required()
def api_get_document(doc_id: int):
    """Return document details + audit history.

    Requires: JWT (any authenticated user can view).
    """
    doc = Document.query.get(doc_id)
    if not doc:
        return _api_err("Document not found.", 404)

    # Fetch audit trail
    audit_logs = AuditLog.query.filter_by(document_id=doc_id).order_by(
        AuditLog.timestamp.desc()
    ).all()

    return _api_ok(
        data={
            "document": doc.to_dict(),
            "audit_history": [log.to_dict() for log in audit_logs],
        },
        message="Document retrieved.",
    )


@documents_api_bp.route("/my", methods=["GET"])
@jwt_required()
def api_my_documents():
    """Return all documents owned by the current user.

    Requires: JWT.
    """
    user_id = int(get_jwt_identity())

    docs = Document.query.filter_by(owner_id=user_id).order_by(
        Document.upload_date.desc()
    ).all()

    return _api_ok(
        data={
            "documents": [d.to_dict() for d in docs],
            "count": len(docs),
        },
        message=f"Found {len(docs)} document(s).",
    )


@documents_api_bp.route("/<int:doc_id>/revoke", methods=["POST"])
@jwt_required()
def api_revoke_document(doc_id: int):
    """Revoke a document on-chain and in the database.

    Requires: JWT — must be the document owner or an admin.
    """
    user_id = int(get_jwt_identity())
    claims = get_jwt()
    role = claims.get("role", "citizen")

    doc = Document.query.get(doc_id)
    if not doc:
        return _api_err("Document not found.", 404)

    # Authorization: owner or admin
    if doc.owner_id != user_id and role != "admin":
        return _api_err("Only the document owner or an admin can revoke.", 403)

    if doc.status == "revoked":
        return _api_err("Document is already revoked.", 409)

    # Blockchain revocation
    tx_hash = blockchain_revoke(doc.sha256_hash)

    # Update DB
    doc.status = "revoked"

    audit = AuditLog(
        document_id=doc.id,
        action="revoke",
        performed_by=claims.get("email", str(user_id)),
        details={"tx_hash": tx_hash},
    )
    db.session.add(audit)
    db.session.commit()

    return _api_ok(
        data={
            "doc_id": doc.id,
            "tx_hash": tx_hash,
            "status": doc.status,
            "document": doc.to_dict(),
        },
        message="Document revoked successfully.",
    )
