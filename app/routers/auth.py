import os
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlmodel import Session

from app.auth.jwt import (
    create_access_token, create_token_pair, hash_password, hash_token, verify_password,
)
from app.auth.session_store import (
    Session as AuthSession, delete, get as get_auth_session, replace,
    revoke_refresh_token, revoke_uid,
)
from app.common.dependencies import CurrentUser, require_admin
from app.common.httpexception import credentials_error
from app.common.types import (
    LoginBody, RefreshResponse, RegisterBody, RegisterResponse, ResetBody, TokenResponse,
)
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
        samesite="lax", path="/api/auth", max_age=max_age, expires=expires,
    )


@router.post("/register", response_model=RegisterResponse)
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
    access_token, refresh_token, session_id = create_token_pair(user.uid)
    auth_session = get_auth_session(session_id)
    set_refresh_cookie(response, refresh_token, auth_session.exp)
    return TokenResponse(access_token=access_token, username=user.username, token_type="Bearer")


@router.post("/refresh", response_model=RefreshResponse)
def refresh(request: Request, response: Response, db: Session = Depends(get_session)):
    old_token = request.cookies.get(COOKIE_NAME)
    if not old_token:
        raise HTTPException(status_code=401, detail="缺少 refresh-token Cookie")
    old_hash = hash_token(old_token)
    import hmac
    from app.auth.session_store import _sessions, _lock
    with _lock:
        matched = next(
            ((sid, item) for sid, item in _sessions.items()
             if hmac.compare_digest(item.hashed_refresh_token, old_hash)),
            None,
        )
    if not matched:
        response.delete_cookie(COOKIE_NAME, path="/api/auth")
        raise HTTPException(status_code=401, detail="Refresh token 无效或已使用")
    session_id, current = matched
    if current.exp <= datetime.now(timezone.utc):
        delete(session_id)
        raise HTTPException(status_code=401, detail="Refresh token 已过期")
    user = get_user_by_uid(db, current.uid)
    if not user or user.is_disable:
        delete(session_id)
        raise HTTPException(status_code=403, detail="用户不存在或已被禁用")
    new_refresh = secrets.token_urlsafe(48)
    rotated = AuthSession(uid=current.uid, hashed_refresh_token=hash_token(new_refresh), exp=current.exp)
    if not replace(session_id, old_hash, rotated):
        raise HTTPException(status_code=401, detail="Refresh token 已被轮换，请重新登录")
    new_access = create_access_token(current.uid, session_id)
    set_refresh_cookie(response, new_refresh, current.exp)
    return RefreshResponse(access_token=new_access, token_type="Bearer")


@router.post("/reset", status_code=status.HTTP_204_NO_CONTENT)
def reset(body: ResetBody, db: Session = Depends(get_session)):
    user = get_user_by_login(db, body.username)
    if not user or user.is_disable or not verify_password(body.password, user.password):
        raise credentials_error()
    user.password = hash_password(body.new_password)
    user.updated_date = datetime.now(timezone.utc)
    db.add(user)
    db.commit()
    revoke_uid(user.uid)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response):
    refresh_token = request.cookies.get(COOKIE_NAME)
    if refresh_token:
        revoke_refresh_token(hash_token(refresh_token))
    response.delete_cookie(
        COOKIE_NAME, path="/api/auth", httponly=True,
        secure=COOKIE_SECURE, samesite="lax",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/me")
def me(user: CurrentUser):
    return {"uid": user.uid, "username": user.username, "role": user.role}


@router.get("/admin-check")
def admin_check(user: User = Depends(require_admin)):
    return {"ok": True, "uid": user.uid}
