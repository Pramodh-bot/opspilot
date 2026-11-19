import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.deps import get_current_user, require_admin
from app.metrics import LOGIN_FAILURES
from app.models import User
from app.schemas import LoginRequest, TokenResponse, UserCreate, UserOut
from app.security import create_access_token, hash_password, login_throttle, verify_password

log = logging.getLogger("opspilot.auth")
router = APIRouter(prefix="/api", tags=["auth"])

# verifying against a dummy hash keeps response time similar for unknown users (no user enumeration)
_DUMMY_HASH = hash_password("not-a-real-password-0")


@router.post("/auth/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = body.email.lower()
    key = f"{email}|{request.client.host if request.client else '-'}"
    if login_throttle.is_locked(key):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again later.")
    user = db.scalar(select(User).where(User.email == email))
    ok = verify_password(body.password, user.hashed_password if user else _DUMMY_HASH)
    if not (user and ok and user.is_active):
        login_throttle.record_failure(key)
        LOGIN_FAILURES.inc()
        log.warning("login failed", extra={"client": request.client.host if request.client else "-"})
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    login_throttle.reset(key)
    return TokenResponse(access_token=create_access_token(user.id, user.role.value))


@router.get("/auth/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)):
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)):
    return db.scalars(select(User).order_by(User.id)).all()


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "A user with this email already exists")
    user = User(email=email, name=body.name, hashed_password=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    return user
