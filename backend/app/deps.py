"""FastAPI dependencies: authentication and role-based access control."""

from collections.abc import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Role, User
from app.security import decode_access_token

bearer = HTTPBearer(auto_error=False)

# Higher number = more privilege. Least privilege: every endpoint declares the minimum role.
ROLE_RANK = {Role.viewer: 1, Role.responder: 2, Role.admin: 3}


def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    unauthorized = HTTPException(
        status.HTTP_401_UNAUTHORIZED, "Invalid or missing credentials", headers={"WWW-Authenticate": "Bearer"}
    )
    if creds is None:
        raise unauthorized
    try:
        claims = decode_access_token(creds.credentials)
        user = db.get(User, int(claims["sub"]))
    except (jwt.PyJWTError, ValueError):
        raise unauthorized from None
    if user is None or not user.is_active:
        raise unauthorized
    return user


def require_role(minimum: Role) -> Callable[[User], User]:
    def checker(user: User = Depends(get_current_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role '{minimum.value}' or higher")
        return user

    return checker


require_viewer = require_role(Role.viewer)
require_responder = require_role(Role.responder)
require_admin = require_role(Role.admin)
