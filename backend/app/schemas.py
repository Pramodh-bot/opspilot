"""Pydantic request/response models with strict input validation."""

import re
from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints, field_validator

from app.models import ActionStatus, Category, IncidentStatus, Risk, Role, Severity

SERVICE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

ShortText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


def _clean(value: str) -> str:
    return _CONTROL_CHARS.sub("", value)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------- auth / users ----------
class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: EmailStr
    name: ShortText
    password: str = Field(min_length=10, max_length=128)
    role: Role = Role.viewer

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not (re.search(r"[a-zA-Z]", v) and re.search(r"\d", v)):
            raise ValueError("password must contain letters and digits")
        return v


class UserOut(ORMModel):
    id: int
    email: str
    name: str
    role: Role
    is_active: bool


# ---------- incidents ----------
class IncidentCreate(BaseModel):
    title: ShortText
    description: str = Field(default="", max_length=8000)
    service: str
    severity: Severity = Severity.sev3
    detected_at: datetime | None = None

    @field_validator("service")
    @classmethod
    def valid_service(cls, v: str) -> str:
        v = v.strip()
        if not SERVICE_RE.match(v):
            raise ValueError("service must be 1-64 chars of letters, digits, '.', '_' or '-'")
        return v

    @field_validator("title", "description")
    @classmethod
    def strip_control(cls, v: str) -> str:
        return _clean(v)


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    severity: Severity | None = None
    assignee_id: int | None = None


class CommentCreate(BaseModel):
    message: str = Field(min_length=1, max_length=2000)

    @field_validator("message")
    @classmethod
    def strip_control(cls, v: str) -> str:
        v = _clean(v).strip()
        if not v:
            raise ValueError("message must not be blank")
        return v


class EventOut(ORMModel):
    id: int
    kind: str
    message: str
    actor: str
    created_at: datetime


class TriageOut(ORMModel):
    id: int
    category: Category
    severity: Severity
    summary: str
    root_cause_hypothesis: str
    confidence: float
    provider: str
    used_fallback: bool
    retrieved_runbooks: list
    duration_ms: int
    created_at: datetime


class ActionOut(ORMModel):
    id: int
    incident_id: int
    action_type: str
    target: str
    rationale: str
    risk: Risk
    status: ActionStatus
    decided_by: str | None
    decided_at: datetime | None
    result: str | None
    created_at: datetime


class IncidentOut(ORMModel):
    id: int
    title: str
    description: str
    service: str
    severity: Severity
    status: IncidentStatus
    category: Category
    source: str
    assignee_id: int | None
    detected_at: datetime
    created_at: datetime
    updated_at: datetime
    triaged_at: datetime | None
    resolved_at: datetime | None


class IncidentDetail(IncidentOut):
    events: list[EventOut]
    triage_results: list[TriageOut]
    actions: list[ActionOut]


class IncidentPage(BaseModel):
    items: list[IncidentOut]
    total: int
    limit: int
    offset: int


class ActionDecision(BaseModel):
    approve: bool
    comment: str | None = Field(default=None, max_length=500)


# ---------- runbooks ----------
class RunbookCreate(BaseModel):
    title: ShortText
    category: Category = Category.unknown
    tags: str = Field(default="", max_length=300)
    content: str = Field(min_length=1, max_length=20000)
    recommended_actions: list[str] = Field(default_factory=list, max_length=8)


class RunbookOut(ORMModel):
    id: int
    title: str
    category: Category
    tags: str
    content: str
    recommended_actions: list[str]


# ---------- webhook ----------
class AlertLabels(BaseModel):
    model_config = ConfigDict(extra="allow")
    alertname: str = Field(max_length=200)
    service: str | None = Field(default=None, max_length=64)
    job: str | None = Field(default=None, max_length=64)
    severity: str | None = Field(default=None, max_length=16)


class AlertItem(BaseModel):
    model_config = ConfigDict(extra="allow")
    status: str = "firing"
    labels: AlertLabels
    annotations: dict[str, str] = Field(default_factory=dict)
    startsAt: datetime | None = None


class AlertmanagerPayload(BaseModel):
    model_config = ConfigDict(extra="allow")
    alerts: list[AlertItem] = Field(max_length=50)
