import logging
from datetime import datetime, timedelta, timezone

import pytest

from app.agent import service
from app.agent.llm import HeuristicLLM, OpenAILLM, ResilientLLM
from app.circuit_breaker import CircuitBreaker
from app.models import ActionStatus, Incident, IncidentStatus, Role
from tests.conftest import auth, make_user

DEPLOY = {
    "title": "Errors spiked after deploy",
    "description": "Error rate jumped right after the 2.14 release rolled out.",
    "service": "checkout-api",
    "severity": "sev3",
}


def create(client, headers, **over):
    r = client.post("/api/incidents", json={**DEPLOY, **over}, headers=headers)
    assert r.status_code == 201, r.text
    return r.json()


# ---------------- auth ----------------
def test_login_success_me_and_failures(client, db):
    make_user(db, Role.responder, "r@example.com", "Password12345")
    r = client.post("/api/auth/login", json={"email": "R@Example.com", "password": "Password12345"})
    assert r.status_code == 200
    tok = r.json()["access_token"]
    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {tok}"})
    assert me.json()["email"] == "r@example.com" and "hashed_password" not in me.text
    assert client.post("/api/auth/login", json={"email": "r@example.com", "password": "nope"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "ghost@example.com", "password": "x"}).status_code == 401
    assert client.post("/api/auth/login", json={"email": "not-an-email", "password": "x"}).status_code == 422


def test_login_lockout(client, db):
    make_user(db, Role.viewer, "v@example.com", "Password12345")
    for _ in range(5):
        assert client.post("/api/auth/login", json={"email": "v@example.com", "password": "bad"}).status_code == 401
    r = client.post("/api/auth/login", json={"email": "v@example.com", "password": "Password12345"})
    assert r.status_code == 429


def test_inactive_user_cannot_login_or_use_token(client, db, viewer):
    viewer.is_active = False
    db.commit()
    assert client.post("/api/auth/login", json={"email": viewer.email, "password": "Password12345"}).status_code == 401
    assert client.get("/api/auth/me", headers=auth(viewer)).status_code == 401


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer garbage"}, {"Authorization": "Basic abc"}])
def test_unauthenticated_rejected(client, headers):
    assert client.get("/api/incidents", headers=headers).status_code == 401


def test_token_for_deleted_user_rejected(client, db, viewer):
    h = auth(viewer)
    db.delete(viewer)
    db.commit()
    assert client.get("/api/incidents", headers=h).status_code == 401


def test_user_admin_endpoints(client, h_admin, h_responder):
    body = {"email": "New@Example.com", "name": "New", "password": "LongEnough123", "role": "viewer"}
    assert client.post("/api/users", json=body, headers=h_responder).status_code == 403
    assert client.post("/api/users", json=body, headers=h_admin).status_code == 201
    assert client.post("/api/users", json=body, headers=h_admin).status_code == 409
    weak = {**body, "email": "w@example.com", "password": "alllettersonly"}
    assert client.post("/api/users", json=weak, headers=h_admin).status_code == 422
    short = {**body, "email": "s@example.com", "password": "a1"}
    assert client.post("/api/users", json=short, headers=h_admin).status_code == 422
    users = client.get("/api/users", headers=h_admin).json()
    assert {u["email"] for u in users} >= {"new@example.com"}
    assert client.get("/api/users", headers=h_responder).status_code == 403


# ---------------- RBAC + validation ----------------
def test_rbac_matrix(client, h_viewer, h_responder):
    assert client.post("/api/incidents", json=DEPLOY, headers=h_viewer).status_code == 403
    inc = create(client, h_responder)
    assert client.get("/api/incidents", headers=h_viewer).status_code == 200
    assert client.get(f"/api/incidents/{inc['id']}", headers=h_viewer).status_code == 200
    assert client.post(f"/api/incidents/{inc['id']}/triage", headers=h_viewer).status_code == 403
    assert client.patch(f"/api/incidents/{inc['id']}", json={"status": "resolved"}, headers=h_viewer).status_code == 403
    assert client.post(f"/api/incidents/{inc['id']}/comments", json={"message": "x"}, headers=h_viewer).status_code == 403


@pytest.mark.parametrize(
    "over",
    [
        {"title": ""},
        {"title": "x" * 201},
        {"service": "bad service; DROP TABLE"},
        {"service": ""},
        {"severity": "sev9"},
        {"description": "x" * 8001},
        {"service": "../etc/passwd"},
    ],
)
def test_incident_validation(client, h_responder, over):
    assert client.post("/api/incidents", json={**DEPLOY, **over}, headers=h_responder).status_code == 422


def test_control_chars_stripped_and_sql_text_is_inert(client, h_responder):
    inc = create(client, h_responder, title="Bad\x00title'; DROP TABLE incidents;--", description="a\x07b")
    assert "\x00" not in inc["title"] and inc["description"] == "ab"
    assert client.get("/api/incidents", headers=h_responder).json()["total"] == 1


def test_list_filter_search_paginate(client, h_responder):
    create(client, h_responder, title="Disk full on node", service="node-a", severity="sev1")
    create(client, h_responder, title="DNS failures", service="platform")
    create(client, h_responder, title="Third", service="platform")
    r = client.get("/api/incidents?limit=2", headers=h_responder).json()
    assert r["total"] == 3 and len(r["items"]) == 2 and r["items"][0]["title"] == "Third"
    assert client.get("/api/incidents?service=node-a", headers=h_responder).json()["total"] == 1
    assert client.get("/api/incidents?severity=sev1", headers=h_responder).json()["total"] == 1
    assert client.get("/api/incidents?q=dns", headers=h_responder).json()["total"] == 1
    assert client.get("/api/incidents?q=%25_", headers=h_responder).json()["total"] == 0
    assert client.get("/api/incidents?status=open", headers=h_responder).json()["total"] == 3
    assert client.get("/api/incidents?limit=1000", headers=h_responder).status_code == 422
    assert client.get("/api/incidents?status=bogus", headers=h_responder).status_code == 422


def test_get_404_and_update(client, h_responder, responder):
    assert client.get("/api/incidents/999", headers=h_responder).status_code == 404
    inc = create(client, h_responder)
    r = client.patch(f"/api/incidents/{inc['id']}", json={"severity": "sev1", "assignee_id": responder.id}, headers=h_responder)
    assert r.json()["severity"] == "sev1" and r.json()["assignee_id"] == responder.id
    assert client.patch(f"/api/incidents/{inc['id']}", json={"assignee_id": 9999}, headers=h_responder).status_code == 422
    r = client.patch(f"/api/incidents/{inc['id']}", json={"status": "resolved"}, headers=h_responder).json()
    assert r["status"] == "resolved" and r["resolved_at"]
    r = client.patch(f"/api/incidents/{inc['id']}", json={"status": "open", "assignee_id": None}, headers=h_responder).json()
    assert r["resolved_at"] is None and r["assignee_id"] is None
    assert client.patch("/api/incidents/999", json={"status": "open"}, headers=h_responder).status_code == 404
    assert client.patch(f"/api/incidents/{inc['id']}", json={"status": "weird"}, headers=h_responder).status_code == 422


def test_future_detected_at_is_clamped_and_detection_recorded(client, h_responder, db):
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    inc = create(client, h_responder, detected_at=future)
    assert datetime.fromisoformat(inc["detected_at"]).replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc)
    past = (datetime.now(timezone.utc) - timedelta(minutes=5)).replace(tzinfo=None).isoformat()  # naive -> treated as UTC
    create(client, h_responder, detected_at=past)


def test_comments(client, h_responder):
    inc = create(client, h_responder)
    r = client.post(f"/api/incidents/{inc['id']}/comments", json={"message": "  looking now  "}, headers=h_responder)
    assert r.status_code == 201 and r.json()["kind"] == "comment" and r.json()["message"] == "looking now"
    assert client.post(f"/api/incidents/{inc['id']}/comments", json={"message": "\x00 "}, headers=h_responder).status_code == 422
    assert client.post("/api/incidents/999/comments", json={"message": "x"}, headers=h_responder).status_code == 404
    detail = client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()
    assert [e["kind"] for e in detail["events"]] == ["created", "comment"]


# ---------------- triage + approvals ----------------
def test_full_triage_and_approval_flow(client, h_responder, h_admin, h_viewer, db):
    inc = create(client, h_responder)
    t = client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
    assert t.status_code == 200
    triage = t.json()
    assert triage["category"] == "deployment" and triage["provider"] == "heuristic" and not triage["used_fallback"]
    assert triage["retrieved_runbooks"][0]["title"] == "Bad deployment rollback procedure"

    detail = client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()
    by_type = {a["action_type"]: a for a in detail["actions"]}
    assert by_type["collect_diagnostics"]["status"] == "executed"  # low risk auto-approved by policy
    assert by_type["collect_diagnostics"]["decided_by"] == "policy:auto-low-risk"
    rollback = by_type["rollback_deployment"]
    assert rollback["status"] == "pending" and rollback["risk"] == "high"  # human must approve
    assert detail["status"] == "awaiting_approval" and detail["category"] == "deployment"
    assert detail["triaged_at"] is not None

    assert client.get("/api/actions", headers=h_viewer).json()[0]["id"] == rollback["id"]
    # responders cannot approve high-risk actions, admins can
    r = client.post(f"/api/actions/{rollback['id']}/decision", json={"approve": True}, headers=h_responder)
    assert r.status_code == 403
    r = client.post(f"/api/actions/{rollback['id']}/decision", json={"approve": True, "comment": "go"}, headers=h_admin)
    assert r.status_code == 200 and r.json()["status"] == "executed" and "simulated" in r.json()["result"]
    assert client.post(f"/api/actions/{rollback['id']}/decision", json={"approve": True}, headers=h_admin).status_code == 409
    assert client.post("/api/actions/9999/decision", json={"approve": True}, headers=h_admin).status_code == 404
    detail = client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()
    assert detail["status"] == "mitigating"
    kinds = [e["kind"] for e in detail["events"]]
    assert {"triage", "action_approved", "action_executed"} <= set(kinds)
    assert client.get("/api/actions", headers=h_viewer).json() == []


def test_reject_action_and_medium_risk_by_responder(client, h_responder):
    inc = create(
        client, h_responder, title="Pods OOMKilled", description="payments-worker OOMKilled every 20 minutes memory leak"
    )
    client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
    acts = {a["action_type"]: a for a in client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()["actions"]}
    assert acts["restart_service"]["risk"] == "medium"
    r = client.post(
        f"/api/actions/{acts['restart_service']['id']}/decision", json={"approve": False, "comment": "wait"}, headers=h_responder
    )
    assert r.json()["status"] == "rejected" and r.json()["result"] == "wait"
    r = client.post(f"/api/actions/{acts['scale_out']['id']}/decision", json={"approve": True}, headers=h_responder)
    assert r.status_code == 200 and r.json()["status"] == "executed"


def test_retriage_supersedes_pending_and_never_downgrades(client, h_responder):
    inc = create(client, h_responder, severity="sev1", description="release regression after rollout")
    client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
    client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
    detail = client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()
    assert detail["severity"] == "sev1" and len(detail["triage_results"]) == 2
    statuses = [a["status"] for a in detail["actions"] if a["action_type"] == "rollback_deployment"]
    assert statuses == ["rejected", "pending"]
    assert any(a["decided_by"] == "system:superseded" for a in detail["actions"])


def test_triage_raises_severity(client, h_responder):
    inc = create(
        client, h_responder, title="Total outage", description="all users cannot reach the postgres database", severity="sev3"
    )
    client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
    detail = client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()
    assert detail["severity"] == "sev1"
    assert any(e["kind"] == "severity_changed" for e in detail["events"])


def test_triage_resolved_incident_conflict_and_404(client, h_responder):
    inc = create(client, h_responder)
    client.patch(f"/api/incidents/{inc['id']}", json={"status": "resolved"}, headers=h_responder)
    assert client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder).status_code == 409
    assert client.post("/api/incidents/999/triage", headers=h_responder).status_code == 404


def test_executor_disabled_marks_failed(client, h_responder, monkeypatch):
    monkeypatch.setenv("EXECUTOR_MODE", "disabled")
    from app.config import get_settings

    get_settings.cache_clear()
    try:
        inc = create(client, h_responder)
        client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
        detail = client.get(f"/api/incidents/{inc['id']}", headers=h_responder).json()
        diag = next(a for a in detail["actions"] if a["action_type"] == "collect_diagnostics")
        assert diag["status"] == "failed" and "disabled" in diag["result"]
        assert any(e["kind"] == "action_failed" for e in detail["events"])
    finally:
        get_settings.cache_clear()


def test_llm_outage_degrades_gracefully_through_api(client, h_responder, monkeypatch):
    class Down:
        name = "openai"

        def analyze(self, *_a):
            raise ConnectionError("provider down")

    llm = ResilientLLM(Down(), HeuristicLLM(), CircuitBreaker(2, 60))
    monkeypatch.setattr(service, "get_llm", lambda: llm)
    for _ in range(3):
        inc = create(client, h_responder)
        r = client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
        assert r.status_code == 200 and r.json()["used_fallback"] is True
        assert r.json()["category"] == "deployment"
    ready = client.get("/readyz").json()
    assert ready["status"] == "ready"
    monkeypatch.setattr("app.routers.health.get_llm", lambda: llm)
    assert client.get("/readyz").json()["llm_circuit"] == "open"
    assert "opspilot_llm_circuit_state 2.0" in client.get("/metrics").text


def test_openai_success_through_api(client, h_responder, monkeypatch):
    from tests.test_agent import FakeOpenAI, good_json

    llm = ResilientLLM(OpenAILLM(FakeOpenAI(good_json(category="deployment")), "m", 5), HeuristicLLM(), CircuitBreaker())
    monkeypatch.setattr(service, "get_llm", lambda: llm)
    inc = create(client, h_responder)
    r = client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder).json()
    assert r["provider"] == "openai" and not r["used_fallback"]


def test_status_sync_edge_cases(client, h_responder, db):
    inc = create(client, h_responder, title="Unknown weirdness", description="something odd happened")
    client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder)
    row = db.get(Incident, inc["id"])
    assert row.status is IncidentStatus.triaged  # only the auto-approved diagnostics action exists
    assert [a.status for a in row.actions] == [ActionStatus.executed]


# ---------------- runbooks ----------------
def test_runbooks_crud_and_rbac(client, h_admin, h_responder, h_viewer):
    assert len(client.get("/api/runbooks", headers=h_viewer).json()) == 10  # seeded at startup
    body = {
        "title": "Custom runbook",
        "category": "network",
        "tags": "x",
        "content": "do things",
        "recommended_actions": ["restart_service"],
    }
    assert client.post("/api/runbooks", json=body, headers=h_responder).status_code == 403
    r = client.post("/api/runbooks", json=body, headers=h_admin)
    assert r.status_code == 201
    assert client.post("/api/runbooks", json=body, headers=h_admin).status_code == 409
    bad = {**body, "title": "Other", "recommended_actions": ["drop_database"]}
    assert client.post("/api/runbooks", json=bad, headers=h_admin).status_code == 422
    assert client.delete(f"/api/runbooks/{r.json()['id']}", headers=h_responder).status_code == 403
    assert client.delete(f"/api/runbooks/{r.json()['id']}", headers=h_admin).status_code == 204
    assert client.delete("/api/runbooks/9999", headers=h_admin).status_code == 404


def test_new_runbook_is_used_by_rag(client, h_admin, h_responder):
    body = {
        "title": "Quantum flux capacitor recovery",
        "category": "unknown",
        "tags": "flux capacitor",
        "content": "recalibrate the flux capacitor",
        "recommended_actions": [],
    }
    client.post("/api/runbooks", json=body, headers=h_admin)
    inc = create(client, h_responder, title="Flux capacitor failing", description="flux capacitor drifting")
    t = client.post(f"/api/incidents/{inc['id']}/triage", headers=h_responder).json()
    assert t["retrieved_runbooks"][0]["title"] == "Quantum flux capacitor recovery"


# ---------------- webhook ----------------
ALERT = {
    "alerts": [
        {
            "status": "firing",
            "labels": {"alertname": "HighErrorRate", "service": "checkout-api", "severity": "critical"},
            "annotations": {"summary": "5xx after deploy", "description": "Error rate jumped after the new release rollout"},
            "startsAt": (datetime.now(timezone.utc) - timedelta(seconds=90)).isoformat(),
        }
    ]
}


def test_webhook_auth(client):
    assert client.post("/api/webhooks/alertmanager", json=ALERT).status_code == 401
    assert client.post("/api/webhooks/alertmanager", json=ALERT, headers={"X-Webhook-Token": "wrong"}).status_code == 401


def test_webhook_creates_dedupes_and_triages(client, h_viewer):
    h = {"X-Webhook-Token": "hook-token-for-tests"}
    r = client.post("/api/webhooks/alertmanager", json=ALERT, headers=h)
    assert r.status_code == 202 and len(r.json()["created"]) == 1
    again = client.post("/api/webhooks/alertmanager", json=ALERT, headers=h)
    assert again.json()["created"] == []  # duplicate suppressed while still open
    resolved = {"alerts": [{**ALERT["alerts"][0], "status": "resolved"}]}
    assert client.post("/api/webhooks/alertmanager", json=resolved, headers=h).json()["created"] == []
    inc = client.get(f"/api/incidents/{r.json()['created'][0]}", headers=h_viewer).json()
    assert inc["source"] == "alertmanager" and inc["severity"] == "sev1"
    assert inc["category"] == "deployment" and inc["triaged_at"] is not None  # background triage ran
    assert len(inc["triage_results"]) == 1


def test_webhook_accepts_bearer_auth(client):
    r = client.post("/api/webhooks/alertmanager", json=ALERT, headers={"Authorization": "Bearer hook-token-for-tests"})
    assert r.status_code == 202
    assert client.post("/api/webhooks/alertmanager", json=ALERT, headers={"Authorization": "Bearer nope"}).status_code == 401


def test_webhook_odd_labels_and_validation(client):
    h = {"X-Webhook-Token": "hook-token-for-tests"}
    odd = {"alerts": [{"labels": {"alertname": "Weird", "job": "my job/1"}, "annotations": {}}]}
    assert len(client.post("/api/webhooks/alertmanager", json=odd, headers=h).json()["created"]) == 1
    noservice = {"alerts": [{"labels": {"alertname": "NoSvc"}}]}
    assert len(client.post("/api/webhooks/alertmanager", json=noservice, headers=h).json()["created"]) == 1
    assert client.post("/api/webhooks/alertmanager", json={"alerts": [{"labels": {}}]}, headers=h).status_code == 422
    assert (
        client.post("/api/webhooks/alertmanager", json={"alerts": [{"labels": {"alertname": "x"}}] * 51}, headers=h).status_code
        == 422
    )


def test_webhook_disabled_when_no_token_configured(client, monkeypatch):
    from app.config import get_settings

    monkeypatch.delenv("WEBHOOK_TOKEN")
    get_settings.cache_clear()
    try:
        assert client.post("/api/webhooks/alertmanager", json=ALERT, headers={"X-Webhook-Token": ""}).status_code == 401
    finally:
        monkeypatch.setenv("WEBHOOK_TOKEN", "hook-token-for-tests")
        get_settings.cache_clear()


def test_auto_triage_failure_is_logged_not_raised(client, monkeypatch, caplog):
    from app.routers import webhooks

    def boom(*_a, **_k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(webhooks, "run_triage", boom)
    with caplog.at_level(logging.ERROR):
        r = client.post("/api/webhooks/alertmanager", json=ALERT, headers={"X-Webhook-Token": "hook-token-for-tests"})
    assert r.status_code == 202
    assert any("auto-triage failed" in rec.message for rec in caplog.records)
    webhooks._auto_triage(99999)  # missing incident is a no-op
