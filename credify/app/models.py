"""Database models for the Credify application."""

from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db, login_manager


# ---------------------------------------------------------------------------
# User
# ---------------------------------------------------------------------------

class User(UserMixin, db.Model):
    """Registered user account with role-based access."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(
        db.String(20),
        nullable=False,
        default="citizen",
    )  # citizen | issuer | verifier | admin
    created_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )

    # Relationships
    documents = db.relationship(
        "Document", backref="owner", lazy=True, foreign_keys="Document.owner_id"
    )
    verification_records = db.relationship(
        "VerificationRecord", backref="verifier", lazy=True
    )

    # -- password helpers ----------------------------------------------------

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "email": self.email,
            "role": self.role,
            "created_at": (
                self.created_at.isoformat() if self.created_at else None
            ),
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email!r} role={self.role!r}>"


@login_manager.user_loader
def load_user(user_id: str):
    return db.session.get(User, int(user_id))


# ---------------------------------------------------------------------------
# Document
# ---------------------------------------------------------------------------

class Document(db.Model):
    """Uploaded document with verification and blockchain metadata."""

    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255), nullable=False)
    sha256_hash = db.Column(db.String(64), nullable=False, index=True)
    ipfs_cid = db.Column(db.String(128), nullable=True)
    blockchain_tx_id = db.Column(db.String(128), nullable=True)
    upload_date = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    doc_type = db.Column(db.String(50), nullable=True)  # e.g. certificate, transcript
    issuer_name = db.Column(db.String(255), nullable=True)
    issue_date = db.Column(db.Date, nullable=True)
    status = db.Column(
        db.String(20), nullable=False, default="pending"
    )  # pending | verified | flagged | revoked

    # Relationships
    audit_logs = db.relationship("AuditLog", backref="document", lazy=True)
    verification_records = db.relationship(
        "VerificationRecord", backref="document", lazy=True
    )

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "owner_id": self.owner_id,
            "filename": self.filename,
            "original_name": self.original_name,
            "sha256_hash": self.sha256_hash,
            "ipfs_cid": self.ipfs_cid,
            "blockchain_tx_id": self.blockchain_tx_id,
            "upload_date": (
                self.upload_date.isoformat() if self.upload_date else None
            ),
            "doc_type": self.doc_type,
            "issuer_name": self.issuer_name,
            "issue_date": (
                self.issue_date.isoformat() if self.issue_date else None
            ),
            "status": self.status,
        }

    def __repr__(self) -> str:
        return (
            f"<Document id={self.id} original_name={self.original_name!r} "
            f"status={self.status!r}>"
        )


# ---------------------------------------------------------------------------
# AuditLog
# ---------------------------------------------------------------------------

class AuditLog(db.Model):
    """Immutable audit trail entry for document lifecycle events."""

    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id"), nullable=False, index=True
    )
    action = db.Column(db.String(50), nullable=False)  # e.g. upload, verify, revoke
    performed_by = db.Column(db.String(120), nullable=False)  # email or system id
    timestamp = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    details = db.Column(db.JSON, nullable=True)  # free-form metadata

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "document_id": self.document_id,
            "action": self.action,
            "performed_by": self.performed_by,
            "timestamp": (
                self.timestamp.isoformat() if self.timestamp else None
            ),
            "details": self.details,
        }

    def __repr__(self) -> str:
        return (
            f"<AuditLog id={self.id} document_id={self.document_id} "
            f"action={self.action!r}>"
        )


# ---------------------------------------------------------------------------
# VerificationRecord
# ---------------------------------------------------------------------------

class VerificationRecord(db.Model):
    """Result of a single verification attempt against a document."""

    __tablename__ = "verification_records"

    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(
        db.Integer, db.ForeignKey("documents.id"), nullable=False, index=True
    )
    verifier_id = db.Column(
        db.Integer, db.ForeignKey("users.id"), nullable=False, index=True
    )
    result = db.Column(
        db.String(20), nullable=False
    )  # e.g. authentic, forged, inconclusive
    confidence_score = db.Column(db.Float, nullable=True)
    verified_at = db.Column(
        db.DateTime, default=lambda: datetime.now(timezone.utc)
    )
    method = db.Column(
        db.String(10), nullable=False
    )  # hash | qr

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "document_id": self.document_id,
            "verifier_id": self.verifier_id,
            "result": self.result,
            "confidence_score": self.confidence_score,
            "verified_at": (
                self.verified_at.isoformat() if self.verified_at else None
            ),
            "method": self.method,
        }

    def __repr__(self) -> str:
        return (
            f"<VerificationRecord id={self.id} document_id={self.document_id} "
            f"result={self.result!r} method={self.method!r}>"
        )
