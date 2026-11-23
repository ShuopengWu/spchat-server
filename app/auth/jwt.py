import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import jwt
from pwdlib import PasswordHash

from app.auth.session_store import Session, put
from app.common.types import TokenPayload

password_hash = PasswordHash.recommended()
ALGORITHM = "HS256"
# Override AUTH_SECRET_KEY in every non-development environment.
SECRET_KEY = __import__("os").getenv("AUTH_SECRET_KEY", "dev-only-change-this-secret-before-deployment")
ACCESS_TOKEN_MINUTES = 30
REFRESH_TOKEN_DAYS = 7


def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    try:
        return password_hash.verify(password, hashed)
    except Exception:
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def decode_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


def create_token_pair(uid: str, scope: str = "read") -> tuple[str, str, str]:
    now = datetime.now(timezone.utc)
    session_id = str(uuid4())
    refresh_exp = now + timedelta(days=REFRESH_TOKEN_DAYS)
    refresh_token = secrets.token_urlsafe(48)
    access_token = jwt.encode(
        {"sub": uid, "sid": session_id, "type": "access", "scope": scope,
         "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES)},
        SECRET_KEY, algorithm=ALGORITHM,
    )
    put(session_id, Session(uid=uid, hashed_refresh_token=hash_token(refresh_token), exp=refresh_exp, scope=scope))
    return access_token, refresh_token, session_id


def create_access_token(uid: str, session_id: str, scope: str = "read") -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode(
        {"sub": uid, "sid": session_id, "type": "access",
         "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_MINUTES)},
        SECRET_KEY, algorithm=ALGORITHM,
    )


def token_exp(token: str) -> datetime:
    payload = decode_token(token)
    return datetime.fromtimestamp(payload["exp"], timezone.utc)
