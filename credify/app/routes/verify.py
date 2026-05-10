"""Verification routes — requires login (verifier / admin only).

Web blueprint ``verify_bp``         /verify
API blueprint ``verify_api_bp``     /verify/hash, /verify/upload, /verify/qr/<id>
"""

import os
import tempfile
import logging
from functools import wraps

from flask import (
    Blueprint,
    render_template,
    request,
    flash,
    jsonify,
    send_from_directory,
    current_app,
    redirect,
    url_for,
)
from flask_login import login_required, current_user

from app import db
from app.models import Document, AuditLog, User
from app.services.hasher import hash_file
from app.services.blockchain_service import verify_document as blockchain_verify
from app.services.ipfs_service import get_file_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Role guard — only verifier + admin can access verification
# ---------------------------------------------------------------------------

def verifier_required(f):
    """Ensure the current user is authenticated AND has verifier or admin role."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role not in ("verifier", "admin"):
            flash("Access denied. Only verifiers and admins can access this portal.", "error")
            return redirect(url_for("documents.dashboard"))
        if current_user.role == "verifier" and current_user.kyc_status != "verified":
            flash("KYC Verification Required: You must complete identity verification before accessing the verification portal.", "warning")
            return redirect(url_for("auth.kyc_submit"))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_ok(data=None, message="Success", status=200):
    return jsonify({"success": True, "data": data, "message": message}), status


def _api_err(message="Something went wrong", status=400):
    return jsonify({"success": False, "data": None, "message": message}), status


def _verify_hash_logic(sha256_hash: str, verified_by: str = "system") -> dict:
    """Core verification logic shared by both /hash and /upload endpoints.
    
    IMPORTANT: This now properly checks document status. A document with
    status 'rejected' or 'flagged' will NOT be shown as authenticated.
    """
    
    # 1. Check database defensively
    try:
        doc = Document.query.filter_by(sha256_hash=sha256_hash).first()
    except Exception as e:
        logger.error("DB Query Error: %s", e)
        doc = None

    # 2. Check blockchain defensively
    try:
        bc_result = blockchain_verify(sha256_hash)
    except Exception as e:
        logger.error("Blockchain Query Error: %s", e)
        bc_result = {}

    bc_exists = bc_result.get("exists", False) if isinstance(bc_result, dict) else False
    bc_timestamp = bc_result.get("timestamp", 0) if isinstance(bc_result, dict) else 0
    bc_revoked = bc_result.get("revoked", False) if isinstance(bc_result, dict) else False
    bc_cid = bc_result.get("cid", "") if isinstance(bc_result, dict) else ""

    # --- CASE 1: Not found anywhere ---
    if not doc and not bc_exists:
        return {
            "verified": False,
            "status": "not_found",
            "message": "Document not found on blockchain or local database.",
            "document": None,
            "owner_email": None,
            "blockchain_timestamp": None,
            "ipfs_url": None,
            "rejection_reason": None,
            "source": "none",
        }

    # --- CASE 2: Found in DB — use DB as primary source of truth for status ---
    if doc:
        owner = User.query.get(doc.owner_id)
        owner_email = owner.email if owner else "Unknown"

        # Determine real status: rejected/flagged docs are NOT authenticated
        if doc.status in ("rejected", "flagged"):
            status = doc.status
            is_verified = False
        elif doc.status == "revoked" or bc_revoked:
            status = "revoked"
            is_verified = False
        elif doc.status == "verified":
            status = "verified"
            is_verified = True
        else:
            # pending or other
            status = doc.status
            is_verified = False

        ipfs_url = get_file_url(doc.ipfs_cid) if doc.ipfs_cid else ""

        # Log to AuditLog
        try:
            audit = AuditLog(
                document_id=doc.id,
                action="verify",
                performed_by=verified_by,
                details={
                    "method": "hash",
                    "blockchain_exists": bc_exists,
                    "blockchain_timestamp": bc_timestamp,
                    "result_status": status,
                }
            )
            db.session.add(audit)
            db.session.commit()
        except Exception as e:
            logger.error("AuditLog Insert Error: %s", e)
            db.session.rollback()

        return {
            "verified": is_verified,
            "status": status,
            "document": doc.to_dict(),
            "owner_email": owner_email,
            "blockchain_timestamp": bc_timestamp,
            "ipfs_url": ipfs_url,
            "rejection_reason": doc.rejection_reason,
            "source": "database",
        }

    # --- CASE 3: Not in DB but found on blockchain ---
    if bc_exists:
        if bc_revoked:
            status = "revoked"
            is_verified = False
        else:
            status = "verified"
            is_verified = True

        ipfs_url = get_file_url(bc_cid) if bc_cid else ""

        return {
            "verified": is_verified,
            "status": status,
            "document": None,
            "owner_email": None,
            "blockchain_timestamp": bc_timestamp,
            "ipfs_url": ipfs_url,
            "rejection_reason": None,
            "source": "blockchain",
            "message": (
                "Document was found on the blockchain but not in local database. "
                "This means the local record was deleted but the blockchain proof remains intact."
            ),
        }

    # Fallback
    return {
        "verified": False,
        "status": "not_found",
        "message": "Document not found.",
        "document": None,
        "owner_email": None,
        "blockchain_timestamp": None,
        "ipfs_url": None,
        "rejection_reason": None,
        "source": "none",
    }


# ===================================================================== #
#  WEB BLUEPRINT — serves HTML (login required, verifier/admin only)    #
# ===================================================================== #

verify_bp = Blueprint("verify", __name__)

@verify_bp.route("/verify", methods=["GET", "POST"])
@verifier_required
def verify():
    """Verify a document by its SHA-256 hash (Web UI). Requires verifier/admin role."""
    result = None

    if request.method == "POST":
        hash_input = request.form.get("hash", "").strip()

        if not hash_input or len(hash_input) != 64:
            flash("Please enter a valid 64-character SHA-256 hash.", "error")
        else:
            api_resp = _verify_hash_logic(hash_input, verified_by=current_user.email)
            result = {
                "found": api_resp["status"] != "not_found",
                "status": api_resp["status"],
                "doc": api_resp["document"],
                "owner_email": api_resp.get("owner_email"),
                "blockchain_timestamp": api_resp["blockchain_timestamp"],
                "rejection_reason": api_resp.get("rejection_reason"),
                "source": api_resp.get("source", "unknown"),
                "message": api_resp.get("message"),
            }

    # Also support ?hash=... from QR codes
    elif request.method == "GET" and request.args.get("hash"):
        hash_input = request.args.get("hash").strip()
        if len(hash_input) == 64:
            api_resp = _verify_hash_logic(hash_input, verified_by=current_user.email)
            result = {
                "found": api_resp["status"] != "not_found",
                "status": api_resp["status"],
                "doc": api_resp["document"],
                "owner_email": api_resp.get("owner_email"),
                "blockchain_timestamp": api_resp["blockchain_timestamp"],
                "rejection_reason": api_resp.get("rejection_reason"),
                "source": api_resp.get("source", "unknown"),
                "message": api_resp.get("message"),
            }

    return render_template("verify.html", result=result)


# ===================================================================== #
#  API BLUEPRINT — JSON endpoints (login required)                      #
# ===================================================================== #

verify_api_bp = Blueprint("verify_api", __name__, url_prefix="/verify")


@verify_api_bp.route("/hash", methods=["POST"])
@login_required
def api_verify_hash():
    """Verify a document by providing its SHA-256 hash.

    Expects JSON body: {sha256_hash: str}
    """
    if current_user.role not in ("verifier", "admin"):
        return _api_err("Access denied. Verifier or admin role required.", 403)

    body = request.get_json(silent=True) or {}
    sha256_hash = body.get("sha256_hash", "").strip().lower()

    if not sha256_hash or len(sha256_hash) != 64:
        return _api_err("Please provide a valid 64-character SHA-256 hash.", 400)

    try:
        result = _verify_hash_logic(sha256_hash, verified_by=current_user.email)
        
        if result["status"] == "not_found":
            msg = result.pop("message", "Document not found.")
            return _api_err(msg, 404)
            
        return _api_ok(data=result, message=f"Document is {result['status']}.")
    except Exception as e:
        logger.error("Verify Hash Endpoint Error: %s", e)
        return _api_err("Internal Server Error during verification", 500)


@verify_api_bp.route("/upload", methods=["POST"])
@login_required
def api_verify_upload():
    """Verify a document by uploading the file itself.

    Accepts: multipart/form-data field ``file``
    """
    if current_user.role not in ("verifier", "admin"):
        return _api_err("Access denied. Verifier or admin role required.", 403)

    file = request.files.get("file")
    if not file or file.filename == "":
        return _api_err("No file provided.", 422)

    fd, path = tempfile.mkstemp(prefix="credify_verify_")
    os.close(fd)
    try:
        file.save(path)
        sha256_hash = hash_file(path)
    except Exception as e:
        logger.error("File Save Error: %s", e)
        if os.path.exists(path):
            os.unlink(path)
        return _api_err("Failed to process file.", 500)

    # Now verify the hash
    try:
        result = _verify_hash_logic(sha256_hash, verified_by=current_user.email)
    except Exception as e:
        logger.error("Verify Logic Error: %s", e)
        if os.path.exists(path):
            os.unlink(path)
        return _api_err("Internal Server Error during verification", 500)
    finally:
        if os.path.exists(path):
            os.unlink(path)
            
    if result["status"] == "not_found":
        msg = result.pop("message", "Document not found.")
        return _api_err(msg, 404)
        
    return _api_ok(data=result, message=f"Document is {result['status']}.")


@verify_api_bp.route("/qr/<int:doc_id>", methods=["GET"])
def api_get_qr(doc_id: int):
    """Return the generated QR code for a given document."""
    try:
        qr_dir = os.path.join(current_app.root_path, "static", "qrcodes")
        filename = f"{doc_id}.png"
        
        if not os.path.exists(os.path.join(qr_dir, filename)):
            return _api_err("QR code not found.", 404)
            
        return send_from_directory(qr_dir, filename)
    except Exception as e:
        logger.error("QR Code Endpoint Error: %s", e)
        return _api_err("Failed to retrieve QR code", 500)
