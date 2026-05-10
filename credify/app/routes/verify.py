"""Verification routes — web (session) + API (public).

Web blueprint ``verify_bp``         /verify
API blueprint ``verify_api_bp``     /verify/hash, /verify/upload, /verify/qr/<id>
"""

import os
import tempfile
import logging
from flask import (
    Blueprint,
    render_template,
    request,
    flash,
    jsonify,
    send_from_directory,
    current_app,
)

from app import db
from app.models import Document, AuditLog
from app.services.hasher import hash_file
from app.services.blockchain_service import verify_document as blockchain_verify
from app.services.ipfs_service import get_file_url

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _api_ok(data=None, message="Success", status=200):
    return jsonify({"success": True, "data": data, "message": message}), status


def _api_err(message="Something went wrong", status=400):
    return jsonify({"success": False, "data": None, "message": message}), status


def _verify_hash_logic(sha256_hash: str) -> dict:
    """Core verification logic shared by both /hash and /upload endpoints."""
    
    # 1. Check database defensively
    try:
        doc = Document.query.filter_by(sha256_hash=sha256_hash).first()
    except Exception as e:
        logger.error("DB Query Error: %s", e)
        # Database unavailable, we'll just act as if not found locally
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

    if not doc and not bc_exists:
        return {
            "verified": False,
            "status": "not_found",
            "message": "Document not found on blockchain or local database.",
            "document": None,
            "blockchain_timestamp": None,
            "ipfs_url": None
        }

    status = "verified"
    if doc and doc.status == "revoked":
        status = "revoked"
    elif bc_revoked:
        status = "revoked"

    ipfs_url = ""
    if doc and doc.ipfs_cid:
        ipfs_url = get_file_url(doc.ipfs_cid)
    elif bc_cid:
        ipfs_url = get_file_url(bc_cid)

    # 3. Log to AuditLog if it's found in DB
    if doc:
        try:
            audit = AuditLog(
                document_id=doc.id,
                action="verify",
                performed_by="public_verification",
                details={
                    "method": "hash",
                    "blockchain_timestamp": bc_timestamp,
                }
            )
            db.session.add(audit)
            db.session.commit()
        except Exception as e:
            logger.error("AuditLog Insert Error: %s", e)
            db.session.rollback()

    return {
        "verified": (status == "verified"),
        "status": status,
        "document": doc.to_dict() if doc else None,
        "blockchain_timestamp": bc_timestamp,
        "ipfs_url": ipfs_url,
    }


# ===================================================================== #
#  WEB BLUEPRINT — serves HTML                                          #
# ===================================================================== #

verify_bp = Blueprint("verify", __name__)

@verify_bp.route("/verify", methods=["GET", "POST"])
def verify():
    """Verify a document by its SHA-256 hash (Web UI)."""
    result = None

    if request.method == "POST":
        hash_input = request.form.get("hash", "").strip()

        if not hash_input or len(hash_input) != 64:
            flash("Please enter a valid 64-character SHA-256 hash.", "error")
        else:
            api_resp = _verify_hash_logic(hash_input)
            result = {
                "found": api_resp["status"] != "not_found",
                "status": api_resp["status"],
                "doc": api_resp["document"],
                "blockchain_timestamp": api_resp["blockchain_timestamp"]
            }

    # Also support ?hash=... from QR codes
    elif request.method == "GET" and request.args.get("hash"):
        hash_input = request.args.get("hash").strip()
        if len(hash_input) == 64:
            api_resp = _verify_hash_logic(hash_input)
            result = {
                "found": api_resp["status"] != "not_found",
                "status": api_resp["status"],
                "doc": api_resp["document"],
                "blockchain_timestamp": api_resp["blockchain_timestamp"]
            }

    return render_template("verify.html", result=result)


# ===================================================================== #
#  API BLUEPRINT — public JSON endpoints                                #
# ===================================================================== #

verify_api_bp = Blueprint("verify_api", __name__, url_prefix="/verify")


@verify_api_bp.route("/hash", methods=["POST"])
def api_verify_hash():
    """Verify a document by providing its SHA-256 hash.

    Expects JSON body: {sha256_hash: str}
    """
    body = request.get_json(silent=True) or {}
    sha256_hash = body.get("sha256_hash", "").strip().lower()

    if not sha256_hash or len(sha256_hash) != 64:
        return _api_err("Please provide a valid 64-character SHA-256 hash.", 400)

    try:
        result = _verify_hash_logic(sha256_hash)
        
        if result["status"] == "not_found":
            return _api_err(result.pop("message"), 404)
            
        return _api_ok(data=result, message=f"Document is {result['status']}.")
    except Exception as e:
        logger.error("Verify Hash Endpoint Error: %s", e)
        return _api_err("Internal Server Error during verification", 500)


@verify_api_bp.route("/upload", methods=["POST"])
def api_verify_upload():
    """Verify a document by uploading the file itself.

    Accepts: multipart/form-data field ``file``
    """
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
        result = _verify_hash_logic(sha256_hash)
    except Exception as e:
        logger.error("Verify Logic Error: %s", e)
        if os.path.exists(path):
            os.unlink(path)
        return _api_err("Internal Server Error during verification", 500)
    finally:
        if os.path.exists(path):
            os.unlink(path)
            
    if result["status"] == "not_found":
        return _api_err(result.pop("message"), 404)
        
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
