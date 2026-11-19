"""Prometheus metrics (HTTP + business + LLM health)."""

from prometheus_client import Counter, Gauge, Histogram
from sqlalchemy import func, select
from sqlalchemy.orm import Session

HTTP_REQUESTS = Counter("opspilot_http_requests_total", "HTTP requests", ["method", "route", "status"])
HTTP_LATENCY = Histogram(
    "opspilot_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "route"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)
INCIDENTS_CREATED = Counter("opspilot_incidents_created_total", "Incidents created", ["severity", "source"])
INCIDENTS_BY_STATUS = Gauge("opspilot_incidents", "Incidents by status", ["status"])
TIME_TO_DETECT = Histogram(
    "opspilot_incident_detection_seconds",
    "Seconds between the underlying event (detected_at) and the incident being recorded",
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600),
)
TIME_TO_TRIAGE = Histogram(
    "opspilot_incident_time_to_triage_seconds",
    "Seconds from incident creation to completed triage",
    buckets=(1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600),
)
TRIAGE_TOTAL = Counter("opspilot_triage_total", "Triage runs", ["provider", "category", "fallback"])
TRIAGE_DURATION = Histogram(
    "opspilot_triage_duration_seconds",
    "Agent triage latency",
    buckets=(0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30),
)
LLM_FALLBACKS = Counter("opspilot_llm_fallback_total", "LLM calls served by the heuristic fallback", ["reason"])
LLM_BREAKER_STATE = Gauge("opspilot_llm_circuit_state", "LLM circuit breaker: 0=closed 1=half-open 2=open")
ACTIONS_TOTAL = Counter("opspilot_actions_total", "Remediation actions by outcome", ["status", "risk"])
LOGIN_FAILURES = Counter("opspilot_login_failures_total", "Failed login attempts")


def refresh_incident_gauge(db: Session) -> None:
    from app.models import Incident, IncidentStatus

    counts = dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
    for status in IncidentStatus:
        INCIDENTS_BY_STATUS.labels(status.value).set(counts.get(status, 0))
