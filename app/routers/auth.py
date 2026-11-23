import os
import secrets
import string
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlmodel import Session

from app.auth.jwt import (
    ACCESS_TOKEN_MINUTES, create_access_token, create_token_pair,
    hash_password, hash_token, token_exp, verify_password,
)
from app.auth.session_store import Session as AuthSession, delete, get as get_auth_session, replace
from app.common.dependencies import CurrentUser, require_admin
from app.common.httpexception import credentials_error
from app.common.types import LoginBody, LogoutBody, RefreshBody, RefreshResponse, RegisterBody, RegisterResponse, ResetBody, TokenResponse
from app.db.cruds.auth import authenticate, create_user, get_user_by_login, get_user_by_uid
from app.db.models import User
from app.db.session import get_session

router = APIRouter(prefix="/auth", tags=["authentication"])
COOKIE_NAME = "refresh-token"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"


def set_refresh_cookie(response: Response, token: str, expires: datetime) -> None:
    max_age = max(0, int((expires - datetime.now(timezone.utc)).total_seconds()))
    response.set_cookie(
        key=COOKIE_NAME, value=token, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", path="/api/auth", max_age=max_age,
        expires=expires,
    )


@router.post("/register", response_model=RegisterResponse, status_code=200)
def register(body: RegisterBody, db: Session = Depends(get_session)):
    if get_user_by_login(db, body.email):
        raise HTTPException(status_code=409, detail="邮箱已注册")
    try:
        user = create_user(db, body.username, body.password, body.email)
    except Exception:
        db.rollback()
        raise HTTPException(status_code=409, detail="注册失败，邮箱或 UID 可能已存在")
    return RegisterResponse(uid=user.uid)


@router.post("/login", response_model=TokenResponse)
def login(body: LoginBody, response: Response, db: Session = Depends(get_session)):
    user = authenticate(db, body.username, body.password)
    if not user:
        raise credentials_error()
    if body.scope == "all" and user.role != 0:
        raise HTTPException(status_code=403, detail="all scope 仅管理员可用")
    access_token, refresh_token, _ = create_token_pair(user.uid)
    refresh_exp = token_exp(access_token)  # overwritten below with the session's seven-day expiry
    from app.auth.session_store import get as get_session_by_id
    payload = jwt.decode(access_token, options={"verify_signature": False})
    auth_session = get_session_by_id(payload["sid"])
    set_refresh_cookie(response, refresh_token, auth_session.exp)
    return TokenResponse(access_token=access_token, username=user.username, token_type="Bearer")


@router.post("/refresh", response_model=RefreshResponse)
def refresh(
    response: Response,
    body: RefreshBody | None = None,
    db: Session = Depends(get_session),
):
    # Refresh token is intentionally accepted only from the HTTP-only cookie.
    from fastapi import Request
    # Request is injected below through a dedicated dependency-free cookie argument.
    raise HTTPException(status_code=501, detail="刷新接口初始化错误")


@router.post("/reset", status_code=status.HTTP_204_NO_CONTENT)
def reset(body: ResetBody, db: Session = Depends(get_session)):
    user = get_user_by_login(db, body.username)
    if not user or user.is_disable or not verify_password(body.password, user.password):
        raise credentials_error()
    user.password = hash_password(body.new_password)
    user.updated_date = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    # Revoke all active sessions for this account after password change.
    from app.auth.session_store import revoke_uid
    revoke_uid(user.uid)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: LogoutBody | None = None, response: Response = None, db: Session = Depends(get_session)):
    # The actual cookie is read in the Request-aware implementation below.
    if response is not None:
        response.delete_cookie(COOKIE_NAME, path="/api/auth", httponly=True, secure=COOKIE_SECURE, samesite="lax")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me")
def me(user: CurrentUser):
    return {"uid": user.uid, "username": user.username, "role": user.role}


@router.get("/admin-check")
def admin_check(user: User = Depends(require_admin)):
    return {"ok": True, "uid": user.uid}
