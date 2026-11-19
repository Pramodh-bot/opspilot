"""One-shot schema bootstrap, run with the schema OWNER role (not the runtime app role).

    python -m app.migrate

Creates tables and grants the runtime role (APP_DB_ROLE, default opspilot_app) data-only privileges, so the
long-running API process never needs DDL rights (least privilege).
"""

import logging
import os
import re
import sys
import time

from sqlalchemy import text
from sqlalchemy.exc import OperationalError

from app.db import engine, init_db
from app.logging_config import configure_logging

log = logging.getLogger("opspilot.migrate")


def grant_runtime_privileges(role: str) -> None:
    if engine.dialect.name != "postgresql":
        return
    if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", role):
        raise ValueError(f"unsafe role name: {role!r}")
    with engine.begin() as conn:
        conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
        conn.execute(text(f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {role}"))
        conn.execute(text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {role}"))
        conn.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {role}"))
        conn.execute(text(f"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {role}"))


def wait_for_db(attempts: int = 30, delay: float = 2.0) -> None:
    for i in range(attempts):
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            return
        except OperationalError:
            log.info("waiting for database (%s/%s)", i + 1, attempts)
            time.sleep(delay)
    raise RuntimeError("database did not become available")


def main() -> None:
    configure_logging("INFO")
    wait_for_db()
    init_db()
    grant_runtime_privileges(os.environ.get("APP_DB_ROLE", "opspilot_app"))
    log.info("schema ready")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("migration failed")
        sys.exit(1)
