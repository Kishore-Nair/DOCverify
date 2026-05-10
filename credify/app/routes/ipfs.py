"""IPFS Access Module"""

import os
from flask import Blueprint, send_from_directory, current_app, abort, redirect
from app.models import Document

ipfs_bp = Blueprint("ipfs", __name__, url_prefix="/ipfs")

@ipfs_bp.route("/<path:cid>")
def get_ipfs_file(cid):
    """Serve a file by its IPFS CID, ensuring it exists in our DB."""
    # Ensure the file is registered in the database
    if cid.startswith("local:"):
        # Browsers normalize `../..` in URLs, which breaks exact string matching.
        basename = os.path.basename(cid)
        doc = Document.query.filter(Document.ipfs_cid.endswith(basename)).first()
    else:
        doc = Document.query.filter_by(ipfs_cid=cid).first()
    
    if not doc:
        # Block access to any CID not explicitly tracked in our database
        abort(404, description="File not found in the Credify registry.")
        
    upload_dir = current_app.config.get("UPLOAD_FOLDER", "app/static/uploads")
    filename = doc.filename
    
    # If it's a local fallback CID, serve directly from its recorded absolute path
    if cid.startswith("local:"):
        # Use doc.ipfs_cid instead of cid to recover any original ../.. paths
        local_path = os.path.abspath(doc.ipfs_cid.replace("local:", ""))
        if os.path.exists(local_path):
            return send_from_directory(os.path.dirname(local_path), os.path.basename(local_path))
    
    # Try to serve the file directly from our standard upload storage for speed
    if filename and os.path.exists(os.path.join(upload_dir, filename)):
        return send_from_directory(upload_dir, filename)
        
    # Fallback to public IPFS gateway if the local file was moved/deleted
    return redirect(f"https://ipfs.io/ipfs/{cid}")
