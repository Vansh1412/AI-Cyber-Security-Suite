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

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey,
    Integer, String, Text, JSON,
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

    user_id       = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at    = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    user          = relationship("User", back_populates="scans")
