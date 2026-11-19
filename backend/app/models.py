"""SQLAlchemy ORM models (PostgreSQL in production, SQLite in unit tests)."""

import enum
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base

JsonType = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Role(str, enum.Enum):
    viewer = "viewer"
    responder = "responder"
    admin = "admin"


class Severity(str, enum.Enum):
    sev1 = "sev1"
    sev2 = "sev2"
    sev3 = "sev3"
    sev4 = "sev4"


class IncidentStatus(str, enum.Enum):
    open = "open"
    triaged = "triaged"
    awaiting_approval = "awaiting_approval"
    mitigating = "mitigating"
    resolved = "resolved"


class Category(str, enum.Enum):
    database = "database"
    network = "network"
    memory = "memory"
    cpu = "cpu"
    disk = "disk"
    deployment = "deployment"
    security = "security"
    dependency = "dependency"
    unknown = "unknown"


class Risk(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"


class ActionStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
    executed = "executed"
    failed = "failed"


def _enum(e: type[enum.Enum], name: str) -> Enum:
    return Enum(e, name=name, native_enum=False, length=32, validate_strings=True)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    hashed_password: Mapped[str] = mapped_column(String(100))
    role: Mapped[Role] = mapped_column(_enum(Role, "role"), default=Role.viewer)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (Index("ix_incidents_status_severity", "status", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    service: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"), default=Severity.sev3)
    status: Mapped[IncidentStatus] = mapped_column(_enum(IncidentStatus, "incident_status"), default=IncidentStatus.open)
    category: Mapped[Category] = mapped_column(_enum(Category, "category"), default=Category.unknown)
    source: Mapped[str] = mapped_column(String(32), default="manual")
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    assignee_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    events: Mapped[list["IncidentEvent"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentEvent.id"
    )
    triage_results: Mapped[list["TriageResult"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="TriageResult.id"
    )
    actions: Mapped[list["ProposedAction"]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="ProposedAction.id"
    )


class IncidentEvent(Base):
    __tablename__ = "incident_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    message: Mapped[str] = mapped_column(Text)
    actor: Mapped[str] = mapped_column(String(120), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="events")


class Runbook(Base):
    __tablename__ = "runbooks"

    id: Mapped[int] = mapped_column(primary_key=True)
    title: Mapped[str] = mapped_column(String(200), unique=True)
    category: Mapped[Category] = mapped_column(_enum(Category, "category"), default=Category.unknown)
    tags: Mapped[str] = mapped_column(String(300), default="")
    content: Mapped[str] = mapped_column(Text)
    recommended_actions: Mapped[list] = mapped_column(JsonType, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TriageResult(Base):
    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    category: Mapped[Category] = mapped_column(_enum(Category, "category"))
    severity: Mapped[Severity] = mapped_column(_enum(Severity, "severity"))
    summary: Mapped[str] = mapped_column(Text)
    root_cause_hypothesis: Mapped[str] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float)
    provider: Mapped[str] = mapped_column(String(32))  # openai | heuristic
    used_fallback: Mapped[bool] = mapped_column(default=False)
    retrieved_runbooks: Mapped[list] = mapped_column(JsonType, default=list)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="triage_results")


class ProposedAction(Base):
    __tablename__ = "proposed_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), index=True)
    triage_id: Mapped[int | None] = mapped_column(ForeignKey("triage_results.id"), nullable=True)
    action_type: Mapped[str] = mapped_column(String(48))
    target: Mapped[str] = mapped_column(String(64))
    rationale: Mapped[str] = mapped_column(Text, default="")
    risk: Mapped[Risk] = mapped_column(_enum(Risk, "risk"))
    status: Mapped[ActionStatus] = mapped_column(_enum(ActionStatus, "action_status"), default=ActionStatus.pending)
    decided_by: Mapped[str | None] = mapped_column(String(120), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    result: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="actions")
