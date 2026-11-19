"""Triage orchestration and the human-in-the-loop approval workflow (all DB side effects)."""

import logging
import time
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.actions import ACTION_CATALOG, APPROVER_ROLE, execute_action
from app.agent.factory import get_llm, retriever_from_db
from app.agent.graph import run_graph
from app.agent.llm import IncidentInput, ResilientLLM, more_severe
from app.config import get_settings
from app.deps import ROLE_RANK
from app.metrics import (
    ACTIONS_TOTAL,
    TIME_TO_TRIAGE,
    TRIAGE_DURATION,
    TRIAGE_TOTAL,
    refresh_incident_gauge,
)
from app.models import (
    ActionStatus,
    Incident,
    IncidentEvent,
    IncidentStatus,
    ProposedAction,
    TriageResult,
    User,
)

log = logging.getLogger("opspilot.agent")


class ApprovalError(Exception):
    """Base class for approval workflow errors."""


class NotPending(ApprovalError):
    pass


class InsufficientRole(ApprovalError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def add_event(db: Session, incident: Incident, kind: str, message: str, actor: str = "system") -> IncidentEvent:
    event = IncidentEvent(incident_id=incident.id, kind=kind, message=message[:2000], actor=actor)
    db.add(event)
    return event


def _run_action(db: Session, incident: Incident, action: ProposedAction, actor: str) -> None:
    ok, result = execute_action(action.action_type, action.target, get_settings().executor_mode)
    action.status = ActionStatus.executed if ok else ActionStatus.failed
    action.result = result
    ACTIONS_TOTAL.labels(action.status.value, action.risk.value).inc()
    add_event(db, incident, "action_executed" if ok else "action_failed", f"{action.action_type}: {result}", actor)


def _sync_status(incident: Incident) -> None:
    """Derive incident status from its action states (never touches resolved incidents)."""
    if incident.status is IncidentStatus.resolved:
        return
    actions = incident.actions
    if any(a.status is ActionStatus.pending for a in actions):
        incident.status = IncidentStatus.awaiting_approval
    elif any(a.status is ActionStatus.executed and a.risk.value != "low" for a in actions):
        incident.status = IncidentStatus.mitigating
    else:
        incident.status = IncidentStatus.triaged


def run_triage(db: Session, incident: Incident, actor: str, llm: ResilientLLM | None = None) -> TriageResult:
    started = time.perf_counter()
    llm = llm or get_llm()
    settings = get_settings()
    outcome = run_graph(
        llm,
        retriever_from_db(db),
        IncidentInput(incident.title, incident.description, incident.service, incident.severity),
        top_k=settings.rag_top_k,
    )
    out = outcome.analysis.output
    duration = time.perf_counter() - started

    # a re-triage supersedes any still-pending proposals so stale actions cannot be approved
    for old in incident.actions:
        if old.status is ActionStatus.pending:
            old.status = ActionStatus.rejected
            old.decided_by, old.decided_at = "system:superseded", _now()
            old.result = "Superseded by a newer triage run"

    triage = TriageResult(
        incident_id=incident.id,
        category=out.category,
        severity=out.severity,
        summary=out.summary,
        root_cause_hypothesis=out.root_cause_hypothesis,
        confidence=out.confidence,
        provider=outcome.analysis.provider,
        used_fallback=outcome.analysis.used_fallback,
        retrieved_runbooks=[r.as_dict() for r in outcome.runbooks],
        duration_ms=int(duration * 1000),
    )
    db.add(triage)
    db.flush()

    first_triage = incident.triaged_at is None
    incident.category = out.category
    new_severity = more_severe(incident.severity, out.severity)  # never silently downgrade the reporter
    if new_severity != incident.severity:
        add_event(
            db,
            incident,
            "severity_changed",
            f"Severity raised {incident.severity.value} -> {new_severity.value} by triage",
            "opspilot-agent",
        )
        incident.severity = new_severity
    incident.triaged_at = _now()

    add_event(
        db,
        incident,
        "triage",
        f"Triaged as {out.category.value}/{out.severity.value} (confidence {out.confidence:.0%}, provider={triage.provider}"
        + (f", fallback={outcome.analysis.fallback_reason}" if triage.used_fallback else "")
        + ")",
        "opspilot-agent",
    )

    for planned in outcome.plan:
        action = ProposedAction(
            incident_id=incident.id,
            triage_id=triage.id,
            action_type=planned.action_type,
            target=planned.target,
            rationale=planned.rationale[:500],
            risk=planned.risk,
            status=ActionStatus.pending,
        )
        db.add(action)
        incident.actions.append(action)
        if planned.auto_approve:
            action.status = ActionStatus.approved
            action.decided_by, action.decided_at = "policy:auto-low-risk", _now()
            _run_action(db, incident, action, "policy:auto-low-risk")
        else:
            add_event(
                db,
                incident,
                "action_proposed",
                f"{planned.action_type} ({planned.risk.value} risk) awaiting approval",
                "opspilot-agent",
            )

    _sync_status(incident)
    db.commit()

    TRIAGE_TOTAL.labels(triage.provider, out.category.value, str(triage.used_fallback).lower()).inc()
    TRIAGE_DURATION.observe(duration)
    if first_triage:
        created = incident.created_at if incident.created_at.tzinfo else incident.created_at.replace(tzinfo=timezone.utc)
        triaged = incident.triaged_at if incident.triaged_at.tzinfo else incident.triaged_at.replace(tzinfo=timezone.utc)
        TIME_TO_TRIAGE.observe(max(0.0, (triaged - created).total_seconds()))
    refresh_incident_gauge(db)
    log.info("triage complete", extra={"incident_id": incident.id, "category": out.category.value, "provider": triage.provider})
    return triage


def decide_action(db: Session, action_id: int, user: User, approve: bool, comment: str | None) -> ProposedAction:
    # lock the row so two approvers cannot both execute the same action
    action = db.execute(select(ProposedAction).where(ProposedAction.id == action_id).with_for_update()).scalar_one()
    if action.status is not ActionStatus.pending:
        raise NotPending(f"Action is already {action.status.value}")
    required = APPROVER_ROLE[action.risk]
    if ROLE_RANK[user.role] < ROLE_RANK[required]:
        raise InsufficientRole(f"{action.risk.value}-risk actions require role '{required.value}'")
    incident = action.incident
    action.decided_by, action.decided_at = user.email, _now()
    note = f" ({comment})" if comment else ""
    if approve:
        action.status = ActionStatus.approved
        add_event(db, incident, "action_approved", f"{action.action_type} approved{note}", user.email)
        _run_action(db, incident, action, user.email)
    else:
        action.status = ActionStatus.rejected
        action.result = comment or "Rejected by operator"
        ACTIONS_TOTAL.labels("rejected", action.risk.value).inc()
        add_event(db, incident, "action_rejected", f"{action.action_type} rejected{note}", user.email)
    _sync_status(incident)
    db.commit()
    refresh_incident_gauge(db)
    return action


__all__ = ["ACTION_CATALOG", "ApprovalError", "InsufficientRole", "NotPending", "decide_action", "run_triage"]
