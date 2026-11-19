"""Alertmanager webhook: turns firing alerts into incidents and triages them automatically."""

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.service import run_triage
from app.config import get_settings
from app.db import SessionLocal, get_db
from app.models import Incident, IncidentStatus, Severity
from app.routers.incidents import create_incident_record
from app.schemas import AlertItem, AlertmanagerPayload, IncidentCreate
from app.security import constant_time_equals

log = logging.getLogger("opspilot.webhook")
router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])

_SEVERITY_MAP = {
    "critical": Severity.sev1,
    "page": Severity.sev1,
    "high": Severity.sev2,
    "error": Severity.sev2,
    "warning": Severity.sev3,
    "info": Severity.sev4,
}


def _auto_triage(incident_id: int) -> None:
    try:
        with SessionLocal() as db:
            incident = db.get(Incident, incident_id)
            if incident:
                run_triage(db, incident, "alertmanager")
    except Exception:  # never let a background failure disappear silently
        log.exception("auto-triage failed", extra={"incident_id": incident_id})


def _to_incident(alert: AlertItem) -> IncidentCreate:
    labels = alert.labels
    service = labels.service or labels.job or "unknown"
    clean = "".join(c if c.isalnum() or c in "._-" else "-" for c in service)[:64].strip("-._") or "unknown"
    summary = alert.annotations.get("summary") or labels.alertname
    description = alert.annotations.get("description") or summary
    return IncidentCreate(
        title=f"{labels.alertname}: {summary}"[:200],
        description=description[:8000],
        service=clean,
        severity=_SEVERITY_MAP.get((labels.severity or "").lower(), Severity.sev3),
        detected_at=alert.startsAt,
    )


@router.post("/alertmanager", status_code=status.HTTP_202_ACCEPTED)
def alertmanager(
    payload: AlertmanagerPayload,
    background: BackgroundTasks,
    x_webhook_token: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    supplied = x_webhook_token
    if supplied is None and authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()  # Alertmanager http_config.authorization sends this form
    if not constant_time_equals(supplied, get_settings().webhook_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid webhook token")
    created: list[int] = []
    for alert in payload.alerts:
        if alert.status != "firing":
            continue
        data = _to_incident(alert)
        duplicate = db.scalar(
            select(Incident.id).where(
                Incident.title == data.title, Incident.service == data.service, Incident.status != IncidentStatus.resolved
            )
        )
        if duplicate:  # de-duplicate repeated notifications for the same open alert
            continue
        incident = create_incident_record(db, data, "alertmanager", "alertmanager", None)
        created.append(incident.id)
        background.add_task(_auto_triage, incident.id)
    return {"created": created}
