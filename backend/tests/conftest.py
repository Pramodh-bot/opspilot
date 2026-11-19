import os

# Must be set before any `app` import: settings and the DB engine are created at import time.
os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite://")  # set TEST_DATABASE_URL to run against PostgreSQL
os.environ["JWT_SECRET"] = "test-secret-test-secret-test-secret-123"
os.environ["WEBHOOK_TOKEN"] = "hook-token-for-tests"
os.environ["BCRYPT_ROUNDS"] = "4"
os.environ["ENVIRONMENT"] = "test"
os.environ.pop("OPENAI_API_KEY", None)
os.environ.pop("BOOTSTRAP_ADMIN_EMAIL", None)
os.environ.pop("BOOTSTRAP_ADMIN_PASSWORD", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Role, User  # noqa: E402
from app.security import create_access_token, hash_password, login_throttle  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_state():
    from app import models  # noqa: F401

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    login_throttle.reset()
    yield


@pytest.fixture
def client(_reset_state):
    with TestClient(app) as c:  # runs lifespan: seeds runbooks
        yield c


@pytest.fixture
def db():
    with SessionLocal() as session:
        yield session


def make_user(db, role: Role, email: str | None = None, password: str = "Password12345") -> User:
    user = User(
        email=email or f"{role.value}@example.com", name=role.value.title(), hashed_password=hash_password(password), role=role
    )
    db.add(user)
    db.commit()
    return user


def auth(user: User) -> dict:
    return {"Authorization": f"Bearer {create_access_token(user.id, user.role.value)}"}


@pytest.fixture
def admin(db):
    return make_user(db, Role.admin)


@pytest.fixture
def responder(db):
    return make_user(db, Role.responder)


@pytest.fixture
def viewer(db):
    return make_user(db, Role.viewer)


@pytest.fixture
def h_admin(admin):
    return auth(admin)


@pytest.fixture
def h_responder(responder):
    return auth(responder)


@pytest.fixture
def h_viewer(viewer):
    return auth(viewer)


@pytest.fixture
def fresh_settings():
    from app.agent.factory import get_llm
    from app.config import get_settings

    get_settings.cache_clear()
    get_llm.cache_clear()
    yield
    get_settings.cache_clear()
    get_llm.cache_clear()
