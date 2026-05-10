"""SHA-256 hashing service for document integrity.

Uses only the Python standard library (`hashlib`).
All functions return lowercase hex digests (64 characters).
"""

import hashlib
import logging

logger = logging.getLogger(__name__)

CHUNK_SIZE = 8192  # bytes per read when streaming a file


def hash_file(file_path: str) -> str:
    """Read a file in chunks and return its SHA-256 hex digest.

    Args:
        file_path: Absolute or relative path to the file.

    Returns:
        64-character lowercase hex string.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
        IsADirectoryError: If *file_path* points to a directory.
    """
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                sha256.update(chunk)
        digest = sha256.hexdigest()
        logger.debug("hash_file(%s) -> %s", file_path, digest)
        return digest
    except FileNotFoundError:
        logger.error("File not found: %s", file_path)
        raise
    except IsADirectoryError:
        logger.error("Path is a directory, not a file: %s", file_path)
        raise


def hash_bytes(data: bytes) -> str:
    """Hash raw bytes and return the SHA-256 hex digest.

    Args:
        data: Arbitrary byte sequence to hash.

    Returns:
        64-character lowercase hex string.
    """
    digest = hashlib.sha256(data).hexdigest()
    logger.debug("hash_bytes(%d bytes) -> %s", len(data), digest)
    return digest


def verify_hash(file_path: str, expected_hash: str) -> bool:
    """Check whether a file's SHA-256 matches an expected value.

    The comparison is case-insensitive.

    Args:
        file_path:     Path to the file to verify.
        expected_hash: The hex digest to compare against.

    Returns:
        True if the hashes match, False otherwise.

    Raises:
        FileNotFoundError: If *file_path* does not exist.
    """
    actual = hash_file(file_path)
    match = actual == expected_hash.lower().strip()
    logger.info(
        "verify_hash(%s): %s (actual=%s, expected=%s)",
        file_path,
        "MATCH" if match else "MISMATCH",
        actual,
        expected_hash,
    )
    return match
