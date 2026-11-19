import pytest
from sqlalchemy import select

from app import seed
from app.config import get_settings
from app.main import create_app
from app.models import Role, Runbook, User


def test_health_ready_metrics_and_headers(client, h_responder):
    assert client.get("/healthz").json() == {"status": "ok"}
    r = client.get("/readyz")
    assert r.status_code == 200 and r.json()["llm"] == "heuristic-only"
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Request-ID"]
    assert client.get("/healthz", headers={"X-Request-ID": "abc-123"}).headers["X-Request-ID"] == "abc-123"
    client.post(
        "/api/incidents", headers=h_responder, json={"title": "t", "service": "svc-a", "description": "disk full no space left"}
    )
    text = client.get("/metrics").text
    for name in (
        "opspilot_http_requests_total",
        "opspilot_incidents_created_total",
        "opspilot_incident_detection_seconds",
        'opspilot_incidents{status="open"}',
        "opspilot_llm_circuit_state",
    ):
        assert name in text
    assert 'route="/api/incidents"' in text  # route template, not raw path (bounded cardinality)


def test_readyz_db_down(client):
    from app.db import get_db
    from app.main import app

    class Broken:
        def execute(self, *_a):
            raise RuntimeError("db down")

    app.dependency_overrides[get_db] = lambda: Broken()
    try:
        assert client.get("/readyz").status_code == 503
    finally:
        app.dependency_overrides.clear()


def test_unhandled_error_returns_500_json(client):
    from app.main import app

    @app.get("/boom-test")
    def boom():
        raise RuntimeError("secret internals")

    r = client.get("/boom-test")
    assert r.status_code == 500 and r.json() == {"detail": "Internal server error"}
    assert "secret" not in r.text
    app.router.routes.pop()


def test_production_guards(monkeypatch, fresh_settings):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("JWT_SECRET", "dev-only-change-me-dev-only-change-me")
    with pytest.raises(RuntimeError):
        get_settings()
    get_settings.cache_clear()
    monkeypatch.setenv("JWT_SECRET", "x" * 40)
    app = create_app()
    assert app.docs_url is None and app.openapi_url is None


def test_short_jwt_secret_rejected(monkeypatch, fresh_settings):
    monkeypatch.setenv("JWT_SECRET", "short")
    with pytest.raises(ValueError):
        get_settings()


def test_seed_functions(db, monkeypatch, fresh_settings, capsys):
    assert seed.seed_runbooks(db) == 10
    assert seed.seed_runbooks(db) == 0
    assert db.scalar(select(Runbook).limit(1)) is not None
    assert seed.bootstrap_admin(db) is False  # not configured
    monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", "Root@Example.com")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "RootPassword123")
    get_settings.cache_clear()
    assert seed.bootstrap_admin(db) is True
    assert seed.bootstrap_admin(db) is False  # only when the users table is empty
    assert db.scalar(select(User)).role is Role.admin
    seed.seed_demo(db, "DemoPassword123")
    seed.seed_demo(db, "DemoPassword123")  # idempotent
    assert len(db.scalars(select(User)).all()) == 4

    monkeypatch.setattr("sys.argv", ["seed", "--demo"])
    seed.main()
    assert "Demo users created" in capsys.readouterr().out


def test_migrate_helpers(monkeypatch):
    from app import migrate

    migrate.wait_for_db(attempts=1, delay=0)
    if migrate.engine.dialect.name != "postgresql":
        migrate.grant_runtime_privileges("opspilot_app")  # no-op on SQLite
    monkeypatch.setattr(migrate.engine.dialect, "name", "postgresql", raising=False)
    with pytest.raises(ValueError):
        migrate.grant_runtime_privileges("x; DROP TABLE users")
    monkeypatch.setattr("app.migrate.wait_for_db", lambda: None)
    monkeypatch.setattr("app.migrate.grant_runtime_privileges", lambda role: None)
    migrate.main()


def test_lifespan_skips_ddl_when_disabled(monkeypatch, fresh_settings):
    from fastapi.testclient import TestClient

    called = []
    monkeypatch.setenv("AUTO_CREATE_SCHEMA", "false")
    monkeypatch.setattr("app.main.init_db", lambda: called.append(1))
    with TestClient(create_app()) as c:
        assert c.get("/healthz").status_code == 200
    assert called == []
