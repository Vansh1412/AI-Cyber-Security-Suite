"""
backend/database/models.py
───────────────────────────
SQLAlchemy ORM models.

Tables
------
users        — registered accounts
scan_results — every persisted scan (linked to user or anonymous)
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow():
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True)
    email         = Column(String(255), unique=True, index=True, nullable=False)
    hashed_pw     = Column(String(255), nullable=False)
    role          = Column(String(50), default="user", nullable=False)
    is_active     = Column(Boolean, default=True, nullable=False)
    created_at    = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    scans         = relationship("ScanResult", back_populates="user", lazy="selectin")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id            = Column(Integer, primary_key=True, index=True)
    url           = Column(Text, nullable=False)
    prediction    = Column(String(64), nullable=False)
    confidence    = Column(Float, nullable=False)
    latency_ms    = Column(Float, nullable=True)
    cache_hit     = Column(Boolean, default=False, nullable=False)

    # SHAP top-reasons stored as JSON; populated by background task
    top_reasons   = Column(JSON, nullable=True)

    # ── Sprint 2: Zero-Day Ingestion Fields ───────────────────────────────────
    # is_zero_day: True when the URL was not found in local cache/blacklist/feeds
    is_zero_day   = Column(Boolean, default=False, nullable=False)
    # feature_vector: raw extracted feature dict for active learning / retraining
    feature_vector = Column(JSON, nullable=True)
    # source_feed: which layer caught this — "ml", "heuristic", "virustotal", etc.
    source_feed   = Column(String(64), nullable=True)

    # ── Sprint 3: Active Learning & Retraining Tracking ──────────────────────
    is_retrained     = Column(Boolean, default=False, nullable=False, index=True)
    verified_label   = Column(String(64), nullable=True)
    label_provenance = Column(String(128), nullable=True)
    retrain_status   = Column(String(32), default="UNVERIFIED", nullable=False, index=True)
    retrain_attempt_count = Column(Integer, default=0, nullable=False)
    last_retrain_attempt  = Column(DateTime(timezone=True), nullable=True)
    retrained_at     = Column(DateTime(timezone=True), nullable=True)

    user_id       = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user          = relationship("User", back_populates="scans")
