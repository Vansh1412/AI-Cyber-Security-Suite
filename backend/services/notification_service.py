"""
backend/services/notification_service.py
────────────────────────────────────────
Sprint 5 Phase 5D: In-App Notifications, AES-256-GCM Secret Management,
HMAC Signing, Transactional Outbox Enqueueing, and Preference Administration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
    select,
    update,
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from backend.core.config import settings
from backend.core.security_network import (
    SSRFSecurityError,
    resolve_and_validate_host,
    validate_target_url,
)
from backend.database.models import (
    Alert,
    AuditEvent,
    Base,
    Notification,
    NotificationPreference,
    SOCEventStream,
    User,
)
from backend.schemas.notification import (
    NotificationListResponse,
    NotificationPreferenceResponse,
    NotificationPreferenceUpdate,
    NotificationResponse,
)
from backend.services.event_broadcaster import event_broadcaster
from src.utils.logger import logger


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid_str() -> str:
    return str(uuid.uuid4())


SEVERITY_RANKS: dict[str, int] = {
    "INFO": 1,
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
    "CRITICAL": 5,
}


def _get_severity_rank(sev: str) -> int:
    return SEVERITY_RANKS.get(sev.upper(), 1)


# ── ORM Model: NotificationOutbox ─────────────────────────────────────────────

class NotificationOutbox(Base):
    __tablename__ = "notification_outbox"

    __table_args__ = (
        Index("idx_outbox_claim", "status", "next_attempt_at"),
        Index("idx_outbox_stale_lock", "status", "locked_at"),
    )

    id              = Column(Integer, primary_key=True, index=True)
    outbox_uuid     = Column(String(36), default=_uuid_str, unique=True, index=True, nullable=False)
    user_id         = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    channel         = Column(String(32), default="WEBHOOK", nullable=False)
    destination_url = Column(Text, nullable=False)
    payload_json    = Column(JSON, nullable=False)
    idempotency_key = Column(String(128), unique=True, index=True, nullable=False)
    status          = Column(String(32), default="PENDING", index=True, nullable=False)
    attempt_count   = Column(Integer, default=0, nullable=False)
    max_attempts    = Column(Integer, default=3, nullable=False)
    next_attempt_at = Column(DateTime(timezone=True), default=_utcnow, index=True, nullable=False)
    locked_at       = Column(DateTime(timezone=True), nullable=True)
    locked_by       = Column(String(64), nullable=True)
    delivered_at    = Column(DateTime(timezone=True), nullable=True)
    last_error      = Column(String(512), nullable=True)
    created_at      = Column(DateTime(timezone=True), default=_utcnow, nullable=False)


# ── Dynamic Model Extensions on NotificationPreference ────────────────────────
if not hasattr(NotificationPreference, "consecutive_failures"):
    NotificationPreference.consecutive_failures = Column(Integer, default=0, nullable=False)
if not hasattr(NotificationPreference, "circuit_broken"):
    NotificationPreference.circuit_broken = Column(Boolean, default=False, nullable=False)
if not hasattr(NotificationPreference, "circuit_broken_at"):
    NotificationPreference.circuit_broken_at = Column(DateTime(timezone=True), nullable=True)
if not hasattr(NotificationPreference, "encrypted_webhook_secret"):
    NotificationPreference.encrypted_webhook_secret = Column(Text, nullable=True)


# ── Exceptions ────────────────────────────────────────────────────────────────

class NotificationServiceError(Exception):
    """Base exception for notification service errors."""
    pass


class NotificationNotFoundError(NotificationServiceError):
    """Raised when a notification is not found or not owned by user."""
    pass


class DecryptionError(NotificationServiceError):
    """Raised when ciphertext authentication or decryption fails."""
    pass


class SecretValidationError(NotificationServiceError):
    """Raised when secret entropy or length fails validation."""
    pass


# ── Session Execution Helpers ─────────────────────────────────────────────────

async def _execute(session: Session | AsyncSession, stmt: Any) -> Any:
    if isinstance(session, AsyncSession):
        return await session.execute(stmt)
    return session.execute(stmt)


async def _commit(session: Session | AsyncSession) -> None:
    if isinstance(session, AsyncSession):
        await session.commit()
    else:
        session.commit()


async def _flush(session: Session | AsyncSession) -> None:
    if isinstance(session, AsyncSession):
        await session.flush()
    else:
        session.flush()


async def _rollback(session: Session | AsyncSession) -> None:
    if isinstance(session, AsyncSession):
        await session.rollback()
    else:
        session.rollback()


async def _refresh(session: Session | AsyncSession, obj: Any) -> None:
    if isinstance(session, AsyncSession):
        await session.refresh(obj)
    else:
        session.refresh(obj)


# ── Cryptographic Key & AES-256-GCM Implementation ────────────────────────────

def _get_root_encryption_key() -> str:
    """Retrieve and validate master encryption key."""
    root_key = (
        os.environ.get("WEBHOOK_ENCRYPTION_KEY")
        or getattr(settings, "WEBHOOK_ENCRYPTION_KEY", None)
        or settings.SECRET_KEY
    )
    if not root_key or len(root_key.encode("utf-8")) < 32:
        raise ValueError(
            "WEBHOOK_ENCRYPTION_KEY (or fallback SECRET_KEY) must contain at least 32 bytes."
        )
    return root_key


def encrypt_webhook_secret(plaintext: str) -> str:
    """
    Encrypt plaintext secret using AES-256-GCM with PBKDF2-HMAC-SHA256 (600,000 iterations).
    Format: v1${salt_b64}${nonce_b64}${ciphertext_tag_b64}
    """
    if not plaintext:
        raise ValueError("Cannot encrypt empty secret.")

    root_key = _get_root_encryption_key()
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)  # NIST recommended 96-bit nonce for GCM

    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        root_key.encode("utf-8"),
        salt,
        iterations=600000,
        dklen=32,
    )
    aesgcm = AESGCM(derived_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    salt_b64 = base64.b64encode(salt).decode("ascii")
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    ct_b64 = base64.b64encode(ciphertext_with_tag).decode("ascii")

    return f"v1${salt_b64}${nonce_b64}${ct_b64}"


def decrypt_webhook_secret(envelope: str) -> str:
    """
    Decrypt versioned envelope v1$ using AES-256-GCM.
    Raises DecryptionError on tampering or corruption without leaking key or plaintext.
    """
    if not envelope or not envelope.startswith("v1$"):
        raise DecryptionError("Unsupported or missing encryption envelope format.")

    parts = envelope.split("$")
    if len(parts) != 4:
        raise DecryptionError("Malformed ciphertext envelope.")

    _, salt_b64, nonce_b64, ct_b64 = parts

    try:
        salt = base64.b64decode(salt_b64)
        nonce = base64.b64decode(nonce_b64)
        ciphertext_with_tag = base64.b64decode(ct_b64)
    except Exception as exc:
        raise DecryptionError(f"Base64 decoding failed for ciphertext: {exc}") from exc

    root_key = _get_root_encryption_key()
    derived_key = hashlib.pbkdf2_hmac(
        "sha256",
        root_key.encode("utf-8"),
        salt,
        iterations=600000,
        dklen=32,
    )

    try:
        aesgcm = AESGCM(derived_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        return plaintext_bytes.decode("utf-8")
    except InvalidTag as exc:
        logger.warning("[CRYPTO] AES-GCM decryption failed: authentication tag verification error.")
        raise DecryptionError("Webhook secret authentication tag mismatch or corrupted ciphertext.") from exc
    except Exception as exc:
        logger.warning("[CRYPTO] Decryption failed: %s", exc)
        raise DecryptionError(f"Decryption failed: {exc}") from exc


def generate_webhook_secret() -> str:
    """Generate 32 cryptographically random bytes represented as 64 hex characters (256-bit entropy)."""
    return secrets.token_hex(32)


def get_secret_preview(secret: str | None) -> str | None:
    """Return masked preview of secret, e.g. wh_sec_...f4a1."""
    if not secret:
        return None
    trimmed = secret.strip()
    suffix = trimmed[-4:] if len(trimmed) >= 4 else trimmed
    return f"wh_sec_...{suffix}"


# ── Canonical HMAC-SHA256 Signing ─────────────────────────────────────────────

def compute_hmac_signature(secret: str, timestamp: int | str, raw_body_bytes: bytes) -> str:
    """
    Compute canonical HMAC-SHA256 signature:
    canonical_string = f"{timestamp}." + raw_body_bytes
    """
    canonical = f"{timestamp}.".encode() + raw_body_bytes
    return hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()


def verify_hmac_signature(
    secret: str,
    timestamp: int | str,
    raw_body_bytes: bytes,
    provided_signature: str,
    tolerance_seconds: float = 300.0,
) -> bool:
    """
    Verify canonical HMAC-SHA256 signature with constant-time comparison and 300s replay window.
    """
    try:
        ts_float = float(timestamp)
    except (ValueError, TypeError):
        return False

    if abs(time.time() - ts_float) > tolerance_seconds:
        return False

    expected_sig = compute_hmac_signature(secret, timestamp, raw_body_bytes)
    return hmac.compare_digest(provided_signature.strip(), expected_sig)


# ── Notification Service ──────────────────────────────────────────────────────

class NotificationService:
    """
    Core service managing In-App Notifications, User Preferences,
    and Transactional Outbox Job Enqueueing.
    """

    MAX_UNREAD_NOTIFICATIONS: int = 1000

    # ── Preference Operations ─────────────────────────────────────────────────

    async def get_or_create_preferences(
        self,
        session: Session | AsyncSession,
        user_id: int,
    ) -> NotificationPreference:
        """Fetch or initialize default NotificationPreference for a user."""
        stmt = select(NotificationPreference).where(NotificationPreference.user_id == user_id)
        res = await _execute(session, stmt)
        pref = res.scalars().first()
        if not pref:
            pref = NotificationPreference(
                user_id=user_id,
                in_app_enabled=True,
                email_enabled=False,
                webhook_enabled=False,
                webhook_url=None,
                webhook_secret=None,
                min_severity="HIGH",
                consecutive_failures=0,
                circuit_broken=False,
                circuit_broken_at=None,
                updated_at=_utcnow(),
            )
            session.add(pref)
            await _commit(session)
            await _refresh(session, pref)
        return pref

    async def get_preferences(
        self,
        session: Session | AsyncSession,
        current_user: User,
    ) -> NotificationPreferenceResponse:
        """Retrieve user notification preferences with masked secret preview."""
        pref = await self.get_or_create_preferences(session, current_user.id)
        raw_secret_preview = None
        has_secret = False

        stored_secret = getattr(pref, "encrypted_webhook_secret", None) or pref.webhook_secret
        if stored_secret:
            has_secret = True
            try:
                # If encrypted in envelope
                if stored_secret.startswith("v1$"):
                    decrypted = decrypt_webhook_secret(stored_secret)
                    raw_secret_preview = get_secret_preview(decrypted)
                else:
                    raw_secret_preview = get_secret_preview(stored_secret)
            except Exception:
                raw_secret_preview = "wh_sec_...[encrypted]"

        return NotificationPreferenceResponse(
            in_app_enabled=pref.in_app_enabled,
            email_enabled=pref.email_enabled,
            webhook_enabled=pref.webhook_enabled,
            webhook_url=pref.webhook_url,
            has_webhook_secret=has_secret,
            webhook_secret_preview=raw_secret_preview,
            min_severity=pref.min_severity,
            circuit_broken=getattr(pref, "circuit_broken", False),
            circuit_broken_at=getattr(pref, "circuit_broken_at", None),
            updated_at=pref.updated_at,
        )

    async def update_preferences(
        self,
        session: Session | AsyncSession,
        current_user: User,
        payload: NotificationPreferenceUpdate,
        ip_address: str | None = None,
    ) -> NotificationPreferenceResponse:
        """
        Update user notification preferences with validation and encryption.
        Never returns or logs plaintext secrets.
        """
        pref = await self.get_or_create_preferences(session, current_user.id)
        now = _utcnow()

        if payload.in_app_enabled is not None:
            pref.in_app_enabled = payload.in_app_enabled
        if payload.email_enabled is not None:
            pref.email_enabled = payload.email_enabled
        if payload.min_severity is not None:
            pref.min_severity = payload.min_severity

        # ── Secret Management ─────────────────────────────────────────────────
        if payload.clear_webhook_secret:
            pref.webhook_secret = None
            if hasattr(pref, "encrypted_webhook_secret"):
                pref.encrypted_webhook_secret = None
            pref.webhook_enabled = False
        elif payload.rotate_secret:
            new_secret = generate_webhook_secret()
            encrypted = encrypt_webhook_secret(new_secret)
            pref.webhook_secret = encrypted
            if hasattr(pref, "encrypted_webhook_secret"):
                pref.encrypted_webhook_secret = encrypted
        elif payload.webhook_secret is not None:
            # User supplied secret
            encrypted = encrypt_webhook_secret(payload.webhook_secret)
            pref.webhook_secret = encrypted
            if hasattr(pref, "encrypted_webhook_secret"):
                pref.encrypted_webhook_secret = encrypted

        # ── Webhook URL & SSRF Pre-flight Validation ──────────────────────────
        if payload.webhook_url is not None:
            clean_url = payload.webhook_url.strip()
            if clean_url:
                try:
                    scheme, hostname, port, _ = validate_target_url(clean_url)
                    # Resolve and inspect all A/AAAA records
                    await resolve_and_validate_host(hostname)
                except SSRFSecurityError as exc:
                    raise ValueError(f"Webhook URL SSRF validation failed: {exc}") from exc
                pref.webhook_url = clean_url
            else:
                pref.webhook_url = None
                pref.webhook_enabled = False

        if payload.webhook_enabled is not None:
            if payload.webhook_enabled and not pref.webhook_url:
                raise ValueError("Cannot enable webhook without a valid webhook_url.")
            pref.webhook_enabled = payload.webhook_enabled

            # Explicit re-enable clears circuit breaker
            if payload.webhook_enabled:
                pref.circuit_broken = False
                pref.consecutive_failures = 0
                pref.circuit_broken_at = None

        pref.updated_at = now
        await _commit(session)
        await _refresh(session, pref)

        # Emit audit event (zero plaintext secret)
        audit = AuditEvent(
            action="NOTIFICATION_PREFERENCES_UPDATED",
            actor_user_id=current_user.id,
            target_resource="notification_preferences",
            resource_id=str(pref.id),
            details={
                "in_app_enabled": pref.in_app_enabled,
                "webhook_enabled": pref.webhook_enabled,
                "has_webhook_url": bool(pref.webhook_url),
                "has_webhook_secret": bool(pref.webhook_secret),
                "min_severity": pref.min_severity,
                "circuit_broken": getattr(pref, "circuit_broken", False),
            },
            ip_address=ip_address,
            created_at=now,
        )
        session.add(audit)
        await _commit(session)

        return await self.get_preferences(session, current_user)

    # ── In-App Notification Operations ────────────────────────────────────────

    async def list_notifications(
        self,
        session: Session | AsyncSession,
        current_user: User,
        page: int = 1,
        page_size: int = 20,
        is_read: bool | None = None,
        severity: str | None = None,
    ) -> NotificationListResponse:
        """List notifications strictly scoped to current tenant, ordered by created_at DESC."""
        page = max(1, page)
        page_size = min(100, max(1, page_size))
        offset = (page - 1) * page_size

        query = select(Notification).where(Notification.user_id == current_user.id)
        if is_read is not None:
            query = query.where(Notification.is_read == is_read)
        if severity is not None:
            query = query.where(Notification.severity == severity.upper().strip())

        # Total count
        total_stmt = select(func.count()).select_from(query.subquery())
        total_res = await _execute(session, total_stmt)
        total = total_res.scalar() or 0

        # Unread count
        unread_stmt = select(func.count()).select_from(
            select(Notification).where(
                Notification.user_id == current_user.id,
                Notification.is_read == False,  # noqa: E712
            ).subquery()
        )
        unread_res = await _execute(session, unread_stmt)
        unread_count = unread_res.scalar() or 0

        # Items
        items_stmt = query.order_by(Notification.created_at.desc()).offset(offset).limit(page_size)
        items_res = await _execute(session, items_stmt)
        items = list(items_res.scalars().all())

        return NotificationListResponse(
            items=[NotificationResponse.model_validate(item) for item in items],
            total=total,
            unread_count=unread_count,
            page=page,
            page_size=page_size,
            has_next=(offset + page_size) < total,
        )

    async def get_unread_count(
        self,
        session: Session | AsyncSession,
        current_user: User,
    ) -> int:
        """Get total unread notifications for tenant."""
        stmt = select(func.count()).select_from(
            select(Notification).where(
                Notification.user_id == current_user.id,
                Notification.is_read == False,  # noqa: E712
            ).subquery()
        )
        res = await _execute(session, stmt)
        return res.scalar() or 0

    async def mark_as_read(
        self,
        session: Session | AsyncSession,
        notification_uuid: str,
        current_user: User,
    ) -> NotificationResponse:
        """Mark single notification as read. Anti-enumeration: returns 404 for foreign tenant."""
        stmt = select(Notification).where(
            Notification.notification_uuid == notification_uuid.strip(),
            Notification.user_id == current_user.id,
        )
        res = await _execute(session, stmt)
        notif = res.scalars().first()
        if not notif:
            raise NotificationNotFoundError(f"Notification '{notification_uuid}' not found.")

        if not notif.is_read:
            notif.is_read = True
            unread_count = await self.get_unread_count(session, current_user)
            soc_event_payload = {
                "id": notif.notification_uuid,
                "is_read": True,
                "unread_count": max(0, unread_count - 1),
            }
            soc_event = SOCEventStream(
                event_id=_uuid_str(),
                tenant_id=current_user.id,
                channel="notifications",
                event_type="unread_count_updated",
                aggregate_id=notif.notification_uuid,
                payload_json=soc_event_payload,
                created_at=_utcnow(),
            )
            session.add(soc_event)
            await _flush(session)
            soc_cursor_id = soc_event.cursor_id or 0
            await _commit(session)
            await _refresh(session, notif)
            event_broadcaster.publish_event_nowait(
                event_type="unread_count_updated",
                channel="notifications",
                tenant_id=current_user.id,
                payload=soc_event_payload,
                aggregate_id=notif.notification_uuid,
                cursor_id=soc_cursor_id,
            )

        return NotificationResponse.model_validate(notif)

    async def mark_all_as_read(
        self,
        session: Session | AsyncSession,
        current_user: User,
    ) -> int:
        """Mark all unread notifications as read for tenant."""
        stmt = (
            update(Notification)
            .where(
                Notification.user_id == current_user.id,
                Notification.is_read == False,  # noqa: E712
            )
            .values(is_read=True)
        )
        res = await _execute(session, stmt)
        soc_event_payload = {
            "all_read": True,
            "unread_count": 0,
        }
        soc_event = SOCEventStream(
            event_id=_uuid_str(),
            tenant_id=current_user.id,
            channel="notifications",
            event_type="unread_count_updated",
            aggregate_id=f"user_{current_user.id}",
            payload_json=soc_event_payload,
            created_at=_utcnow(),
        )
        session.add(soc_event)
        await _flush(session)
        soc_cursor_id = soc_event.cursor_id or 0
        await _commit(session)
        event_broadcaster.publish_event_nowait(
            event_type="unread_count_updated",
            channel="notifications",
            tenant_id=current_user.id,
            payload=soc_event_payload,
            aggregate_id=f"user_{current_user.id}",
            cursor_id=soc_cursor_id,
        )
        return res.rowcount or 0

    # ── Transactional Outbox & In-App Enqueueing ──────────────────────────────

    def create_in_app_and_outbox_for_alert(
        self,
        session: Session | AsyncSession,
        alert: Alert,
        is_escalation: bool = False,
        old_severity: str | None = None,
    ) -> None:
        """
        Synchronously enqueue In-App notification and Outbox job inside
        the ORIGINATING ALERT DATABASE TRANSACTION.
        Zero fire-and-forget; commits durably with the Alert.
        """
        if not alert.user_id:
            return  # System alerts without user scope do not generate tenant notifications

        # Load preference within active transaction
        stmt = select(NotificationPreference).where(NotificationPreference.user_id == alert.user_id)
        if isinstance(session, AsyncSession):
            # If in async session, caller handles async or runs query
            # We provide a synchronous helper for sync session and async for async
            return
        pref = session.scalars(stmt).first()

        now = _utcnow()
        alert_sev_rank = _get_severity_rank(alert.severity)
        pref_min_sev = pref.min_severity if pref else "HIGH"
        pref_min_rank = _get_severity_rank(pref_min_sev)

        notif_soc_event: SOCEventStream | None = None
        # 1. In-App Notification Enqueue
        if pref is None or pref.in_app_enabled:
            # Check unread cap
            unread_count = session.query(func.count(Notification.id)).filter(
                Notification.user_id == alert.user_id,
                Notification.is_read == False,  # noqa: E712
            ).scalar() or 0

            if unread_count < self.MAX_UNREAD_NOTIFICATIONS:
                title = (
                    f"[{alert.severity}] Alert Escalated: {alert.title}"
                    if is_escalation
                    else f"[{alert.severity}] Security Alert: {alert.title}"
                )
                msg = (
                    f"Threat severity escalated from {old_severity} to {alert.severity}. Rule: {alert.rule_name}."
                    if is_escalation
                    else alert.description or f"Rule {alert.rule_name} triggered on {alert.indicator_value}."
                )
                notif = Notification(
                    notification_uuid=_uuid_str(),
                    user_id=alert.user_id,
                    title=title[:255],
                    message=msg,
                    severity=alert.severity,
                    is_read=False,
                    link_url=f"/alerts/{alert.alert_uuid}",
                    created_at=now,
                )
                session.add(notif)
                soc_event_payload = {
                    "id": notif.notification_uuid,
                    "title": notif.title,
                    "severity": notif.severity,
                    "alert_uuid": alert.alert_uuid,
                    "unread_count": (unread_count + 1),
                }
                notif_soc_event = SOCEventStream(
                    event_id=_uuid_str(),
                    tenant_id=alert.user_id,
                    channel="notifications",
                    event_type="notification_dispatched",
                    aggregate_id=notif.notification_uuid,
                    payload_json=soc_event_payload,
                    created_at=now,
                )
                session.add(notif_soc_event)

        # 2. Webhook Outbox Enqueue
        if (
            pref
            and pref.webhook_enabled
            and not getattr(pref, "circuit_broken", False)
            and pref.webhook_url
            and alert_sev_rank >= pref_min_rank
        ):
            event_type = "ALERT_ESCALATED" if is_escalation else "ALERT_TRIGGERED"
            idempotency_key = (
                f"wh:{alert.alert_uuid}:ESCALATED:{alert.severity}:{alert.occurrence_count}"
                if is_escalation
                else f"wh:{alert.alert_uuid}:OPEN:{alert.severity}:{alert.occurrence_count}"
            )

            # Check if outbox row with idempotency key already exists
            existing_outbox = session.query(NotificationOutbox).filter(
                NotificationOutbox.idempotency_key == idempotency_key
            ).first()

            if not existing_outbox:
                payload = {
                    "event": event_type,
                    "alert_uuid": alert.alert_uuid,
                    "title": alert.title,
                    "description": alert.description,
                    "severity": alert.severity,
                    "status": alert.status,
                    "rule_name": alert.rule_name,
                    "indicator_type": alert.indicator_type,
                    "indicator_value": alert.indicator_value,
                    "occurrence_count": alert.occurrence_count,
                    "first_seen_at": alert.first_seen_at.isoformat() if alert.first_seen_at else now.isoformat(),
                    "last_seen_at": alert.last_seen_at.isoformat() if alert.last_seen_at else now.isoformat(),
                }
                outbox_job = NotificationOutbox(
                    outbox_uuid=_uuid_str(),
                    user_id=alert.user_id,
                    channel="WEBHOOK",
                    destination_url=pref.webhook_url,
                    payload_json=payload,
                    idempotency_key=idempotency_key,
                    status="PENDING",
                    attempt_count=0,
                    max_attempts=3,
                    next_attempt_at=now,
                    created_at=now,
                )
                session.add(outbox_job)

        return notif_soc_event

    def create_target_suspension_notification(
        self,
        session: Session,
        target: Any,
        subtype: str,
        is_ssrf: bool = False,
    ) -> None:
        """Enqueue In-App notification and Outbox job when a target is suspended or SSRF aborted."""
        if not target.user_id:
            return

        stmt = select(NotificationPreference).where(NotificationPreference.user_id == target.user_id)
        pref = session.scalars(stmt).first()
        now = _utcnow()

        severity = "CRITICAL" if is_ssrf else "MEDIUM"
        title = (
            f"[CRITICAL] SSRF Probe Aborted: {target.normalized_domain}"
            if is_ssrf
            else f"[MEDIUM] Target Suspended: {target.normalized_domain}"
        )
        msg = (
            f"Autonomous monitoring probe aborted due to restricted IP resolution on {target.url}."
            if is_ssrf
            else f"Monitoring target {target.normalized_domain} was auto-suspended after 5 consecutive failed checks."
        )

        target_soc_event: SOCEventStream | None = None
        # In-App
        if pref is None or pref.in_app_enabled:
            notif = Notification(
                notification_uuid=_uuid_str(),
                user_id=target.user_id,
                title=title[:255],
                message=msg,
                severity=severity,
                is_read=False,
                link_url=f"/monitor?target={target.target_uuid}",
                created_at=now,
            )
            session.add(notif)
            target_soc_event = SOCEventStream(
                event_id=_uuid_str(),
                tenant_id=target.user_id,
                channel="monitor",
                event_type="target_status_changed",
                aggregate_id=target.target_uuid,
                payload_json={
                    "id": target.target_uuid,
                    "url": target.url,
                    "normalized_domain": getattr(target, "normalized_domain", None),
                    "status": "SUSPENDED",
                    "subtype": subtype,
                    "severity": severity,
                },
                created_at=now,
            )
            session.add(target_soc_event)

        # Webhook
        if (
            pref
            and pref.webhook_enabled
            and not getattr(pref, "circuit_broken", False)
            and pref.webhook_url
        ):
            idempotency_key = f"wh:target:{target.target_uuid}:{subtype}:{now.strftime('%Y%m%d%H%M')}"
            existing = session.query(NotificationOutbox).filter(
                NotificationOutbox.idempotency_key == idempotency_key
            ).first()
            if not existing:
                payload = {
                    "event": subtype,
                    "target_uuid": target.target_uuid,
                    "url": target.url,
                    "normalized_domain": target.normalized_domain,
                    "severity": severity,
                    "timestamp": now.isoformat(),
                    "reason": msg,
                }
                outbox_job = NotificationOutbox(
                    outbox_uuid=_uuid_str(),
                    user_id=target.user_id,
                    channel="WEBHOOK",
                    destination_url=pref.webhook_url,
                    payload_json=payload,
                    idempotency_key=idempotency_key,
                    status="PENDING",
                    attempt_count=0,
                    max_attempts=3,
                    next_attempt_at=now,
                    created_at=now,
                )
                session.add(outbox_job)

        return target_soc_event


notification_service = NotificationService()
