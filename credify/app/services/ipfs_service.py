"""IPFS storage service for Credify documents.

Provides upload, retrieval URL generation, pinning, and existence
checks via the IPFS HTTP API.  When the IPFS daemon is unreachable the
service falls back to storing the file locally under ``uploads/`` and
returns a CID prefixed with ``local:`` so the rest of the pipeline can
continue to run offline.

Configuration is read from the environment variable ``IPFS_API_URL``
(loaded via python-dotenv in config.py).
"""

import os
import shutil
import logging

logger = logging.getLogger(__name__)

# Public IPFS gateway used to build user-facing URLs
IPFS_GATEWAY = "https://ipfs.io/ipfs"

# Fallback directory when IPFS is not available
LOCAL_UPLOADS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "uploads")


def _api_url() -> str:
    """Return the configured IPFS HTTP API base URL."""
    return os.getenv("IPFS_API_URL", "http://127.0.0.1:5001/api/v0")


# ---------------------------------------------------------------------------
# Core API
# ---------------------------------------------------------------------------


def upload_file(file_path: str) -> dict:
    """Upload a file to IPFS and return metadata.

    Args:
        file_path: Absolute or relative path to the file on disk.

    Returns:
        dict with keys:
            - cid  (str):  IPFS content identifier, or ``local:<path>``
            - size (int):  File size in bytes
            - name (str):  Original filename

    Raises:
        FileNotFoundError: If *file_path* does not exist.
    """
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    filename = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    # --- Attempt real IPFS upload via HTTP API ---
    try:
        import requests

        with open(file_path, "rb") as f:
            resp = requests.post(
                f"{_api_url()}/add",
                files={"file": (filename, f)},
                timeout=30,
            )
        resp.raise_for_status()
        data = resp.json()
        cid = data["Hash"]
        size = int(data.get("Size", file_size))

        logger.info("IPFS upload OK  cid=%s  size=%d  name=%s", cid, size, filename)
        return {"cid": cid, "size": size, "name": filename}

    except Exception as exc:
        logger.warning("IPFS unavailable (%s) — falling back to local storage", exc)
        return _fallback_local(file_path, filename, file_size)


def get_file_url(cid: str) -> str:
    """Return a public gateway URL for a given CID.

    If the CID is a local fallback (``local:…``), the raw local path is
    returned instead.

    Args:
        cid: IPFS content identifier or local fallback string.

    Returns:
        Full URL string.
    """
    if cid.startswith("local:"):
        path = cid[len("local:"):]
        logger.debug("get_file_url: local path %s", path)
        return path

    url = f"{IPFS_GATEWAY}/{cid}"
    logger.debug("get_file_url: %s", url)
    return url


def pin_file(cid: str) -> bool:
    """Pin a CID so the IPFS node keeps it available.

    Args:
        cid: IPFS content identifier.

    Returns:
        True if the pin succeeded (or CID is local), False otherwise.
    """
    if cid.startswith("local:"):
        logger.debug("pin_file: local CID — no-op")
        return True

    try:
        import requests

        resp = requests.post(
            f"{_api_url()}/pin/add",
            params={"arg": cid},
            timeout=30,
        )
        resp.raise_for_status()
        logger.info("Pinned CID: %s", cid)
        return True
    except Exception as exc:
        logger.error("pin_file failed for %s: %s", cid, exc)
        return False


def check_exists(cid: str) -> bool:
    """Check whether a CID exists / is retrievable.

    For local fallback CIDs the function checks the local filesystem.

    Args:
        cid: IPFS content identifier or ``local:…`` path.

    Returns:
        True if the content is reachable.
    """
    if cid.startswith("local:"):
        path = cid[len("local:"):]
        exists = os.path.isfile(path)
        logger.debug("check_exists (local): %s -> %s", path, exists)
        return exists

    try:
        import requests

        resp = requests.post(
            f"{_api_url()}/object/stat",
            params={"arg": cid},
            timeout=15,
        )
        exists = resp.status_code == 200
        logger.debug("check_exists (IPFS): %s -> %s", cid, exists)
        return exists
    except Exception as exc:
        logger.warning("check_exists failed for %s: %s", cid, exc)
        return False


# ---------------------------------------------------------------------------
# Local fallback
# ---------------------------------------------------------------------------


def _fallback_local(file_path: str, filename: str, file_size: int) -> dict:
    """Copy the file into ``uploads/`` and return a local pseudo-CID."""
    os.makedirs(LOCAL_UPLOADS_DIR, exist_ok=True)
    dest = os.path.join(LOCAL_UPLOADS_DIR, filename)

    # Avoid overwriting — append a short hash if the file already exists
    if os.path.exists(dest) and not os.path.samefile(file_path, dest):
        from app.services.hasher import hash_file

        short_hash = hash_file(file_path)[:8]
        name, ext = os.path.splitext(filename)
        dest = os.path.join(LOCAL_UPLOADS_DIR, f"{name}_{short_hash}{ext}")

    if not os.path.exists(dest):
        shutil.copy2(file_path, dest)

    local_cid = f"local:{dest}"
    logger.info(
        "Local fallback  cid=%s  size=%d  name=%s", local_cid, file_size, filename
    )
    return {"cid": local_cid, "size": file_size, "name": filename}
