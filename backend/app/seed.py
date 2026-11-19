"""Seed data: runbooks (always), bootstrap admin (opt-in via env) and demo data (explicit CLI)."""

import argparse
import json
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.agent.factory import SEED_FILE
from app.config import get_settings
from app.db import SessionLocal, init_db
from app.models import Category, Incident, IncidentEvent, Role, Runbook, Severity, User
from app.security import hash_password

log = logging.getLogger("opspilot.seed")


def seed_runbooks(db: Session) -> int:
    if db.scalar(select(func.count()).select_from(Runbook)):
        return 0
    items = json.loads(SEED_FILE.read_text(encoding="utf-8"))
    for r in items:
        db.add(
            Runbook(
                title=r["title"],
                category=Category(r["category"]),
                tags=r["tags"],
                content=r["content"],
                recommended_actions=r["recommended_actions"],
            )
        )
    db.commit()
    return len(items)


def bootstrap_admin(db: Session) -> bool:
    s = get_settings()
    if not (s.bootstrap_admin_email and s.bootstrap_admin_password):
        return False
    if db.scalar(select(func.count()).select_from(User)):
        return False
    db.add(
        User(
            email=s.bootstrap_admin_email.lower(),
            name="Administrator",
            hashed_password=hash_password(s.bootstrap_admin_password),
            role=Role.admin,
        )
    )
    db.commit()
    return True


def seed_demo(db: Session, password: str) -> None:
    """Create one user per role plus a few sample incidents. Intended for local demos only."""
    for email, name, role in [
        ("admin@opspilot.local", "Ada Admin", Role.admin),
        ("responder@opspilot.local", "Riley Responder", Role.responder),
        ("viewer@opspilot.local", "Vic Viewer", Role.viewer),
    ]:
        if not db.scalar(select(User).where(User.email == email)):
            db.add(User(email=email, name=name, hashed_password=hash_password(password), role=role))
    db.commit()
    if db.scalar(select(func.count()).select_from(Incident)):
        return
    now = datetime.now(timezone.utc)
    samples = [
        (
            "Checkout API returning 5xx after release 2.14",
            "Error rate jumped to 40% right after the 2.14 rollout finished.",
            "checkout-api",
            Severity.sev2,
        ),
        (
            "Postgres replica lag over 10 minutes",
            "Replica replication lag keeps growing; dashboards show stale reads.",
            "orders-db",
            Severity.sev3,
        ),
        (
            "Disk usage at 98% on log volume",
            "No space left on device errors appearing in the ingest workers.",
            "log-ingest",
            Severity.sev3,
        ),
    ]
    for i, (title, desc, svc, sev) in enumerate(samples):
        inc = Incident(
            title=title, description=desc, service=svc, severity=sev, detected_at=now - timedelta(minutes=10 + i), source="demo"
        )
        db.add(inc)
        db.flush()
        db.add(IncidentEvent(incident_id=inc.id, kind="created", message="Incident created (demo data)", actor="seed"))
    db.commit()


def main() -> None:
    parser = argparse.ArgumentParser(description="OpsPilot seed utility")
    parser.add_argument("--demo", action="store_true", help="create demo users and incidents (local use only)")
    parser.add_argument("--demo-password", default="OpsPilot-Demo-2026", help="password for the demo users")
    args = parser.parse_args()
    init_db()
    with SessionLocal() as db:
        seed_runbooks(db)
        bootstrap_admin(db)
        if args.demo:
            seed_demo(db, args.demo_password)
            print(f"Demo users created (password: {args.demo_password}): admin@/responder@/viewer@opspilot.local")


if __name__ == "__main__":
    main()
