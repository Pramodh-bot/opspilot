from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.agent.service import ApprovalError, InsufficientRole, NotPending, add_event, decide_action, run_triage
from app.db import get_db
from app.deps import require_responder, require_viewer
from app.metrics import INCIDENTS_CREATED, TIME_TO_DETECT, refresh_incident_gauge
from app.models import ActionStatus, Incident, IncidentStatus, ProposedAction, Severity, User
from app.schemas import (
    ActionDecision,
    ActionOut,
    CommentCreate,
    EventOut,
    IncidentCreate,
    IncidentDetail,
    IncidentOut,
    IncidentPage,
    IncidentUpdate,
    TriageOut,
)

router = APIRouter(prefix="/api", tags=["incidents"])


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def create_incident_record(db: Session, body: IncidentCreate, actor: str, source: str, user_id: int | None) -> Incident:
    now = datetime.now(timezone.utc)
    detected = _aware(body.detected_at) if body.detected_at else now
    if detected > now:
        detected = now
    incident = Incident(
        title=body.title,
        description=body.description,
        service=body.service,
        severity=body.severity,
        source=source,
        created_by_id=user_id,
        detected_at=detected,
        created_at=now,
    )
    db.add(incident)
    db.flush()
    add_event(db, incident, "created", f"Incident created via {source}", actor)
    db.commit()
    INCIDENTS_CREATED.labels(incident.severity.value, source).inc()
    TIME_TO_DETECT.observe(max(0.0, (now - detected).total_seconds()))
    refresh_incident_gauge(db)
    return incident


def _get_or_404(db: Session, incident_id: int) -> Incident:
    incident = db.scalar(
        select(Incident)
        .where(Incident.id == incident_id)
        .options(selectinload(Incident.events), selectinload(Incident.triage_results), selectinload(Incident.actions))
    )
    if incident is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Incident not found")
    return incident


@router.post("/incidents", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def create_incident(body: IncidentCreate, user: User = Depends(require_responder), db: Session = Depends(get_db)):
    return create_incident_record(db, body, user.email, "manual", user.id)


@router.get("/incidents", response_model=IncidentPage)
def list_incidents(
    status_filter: IncidentStatus | None = Query(default=None, alias="status"),
    severity: Severity | None = None,
    service: str | None = Query(default=None, max_length=64),
    q: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=25, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    _: User = Depends(require_viewer),
    db: Session = Depends(get_db),
):
    stmt = select(Incident)
    if status_filter:
        stmt = stmt.where(Incident.status == status_filter)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if service:
        stmt = stmt.where(Incident.service == service)
    if q:
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")  # treat wildcards literally
        like = f"%{escaped}%"
        stmt = stmt.where(Incident.title.ilike(like, escape="\\") | Incident.description.ilike(like, escape="\\"))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(Incident.id.desc()).limit(limit).offset(offset)).all()
    return IncidentPage(items=items, total=total, limit=limit, offset=offset)


@router.get("/incidents/{incident_id}", response_model=IncidentDetail)
def get_incident(incident_id: int, _: User = Depends(require_viewer), db: Session = Depends(get_db)):
    return _get_or_404(db, incident_id)


@router.patch("/incidents/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: int, body: IncidentUpdate, user: User = Depends(require_responder), db: Session = Depends(get_db)
):
    incident = _get_or_404(db, incident_id)
    changes = body.model_dump(exclude_unset=True)
    if "assignee_id" in changes and changes["assignee_id"] is not None and not db.get(User, changes["assignee_id"]):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "assignee_id does not exist")
    if body.severity and body.severity != incident.severity:
        add_event(db, incident, "severity_changed", f"Severity {incident.severity.value} -> {body.severity.value}", user.email)
        incident.severity = body.severity
    if "assignee_id" in changes:
        incident.assignee_id = changes["assignee_id"]
        add_event(db, incident, "assigned", f"Assignee set to {changes['assignee_id']}", user.email)
    if body.status and body.status != incident.status:
        add_event(db, incident, "status_changed", f"Status {incident.status.value} -> {body.status.value}", user.email)
        incident.status = body.status
        incident.resolved_at = datetime.now(timezone.utc) if body.status is IncidentStatus.resolved else None
    db.commit()
    refresh_incident_gauge(db)
    return incident


@router.post("/incidents/{incident_id}/comments", response_model=EventOut, status_code=status.HTTP_201_CREATED)
def add_comment(incident_id: int, body: CommentCreate, user: User = Depends(require_responder), db: Session = Depends(get_db)):
    incident = _get_or_404(db, incident_id)
    event = add_event(db, incident, "comment", body.message, user.email)
    db.commit()
    return event


@router.post("/incidents/{incident_id}/triage", response_model=TriageOut)
def triage(incident_id: int, user: User = Depends(require_responder), db: Session = Depends(get_db)):
    incident = _get_or_404(db, incident_id)
    if incident.status is IncidentStatus.resolved:
        raise HTTPException(status.HTTP_409_CONFLICT, "Incident is resolved")
    return run_triage(db, incident, user.email)


@router.post("/actions/{action_id}/decision", response_model=ActionOut)
def decide(action_id: int, body: ActionDecision, user: User = Depends(require_responder), db: Session = Depends(get_db)):
    if db.get(ProposedAction, action_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Action not found")
    try:
        return decide_action(db, action_id, user, body.approve, body.comment)
    except NotPending as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    except InsufficientRole as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
    except ApprovalError as exc:  # pragma: no cover - defensive
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from None


@router.get("/actions", response_model=list[ActionOut])
def pending_actions(_: User = Depends(require_viewer), db: Session = Depends(get_db)):
    return db.scalars(
        select(ProposedAction).where(ProposedAction.status == ActionStatus.pending).order_by(ProposedAction.id.desc()).limit(200)
    ).all()
