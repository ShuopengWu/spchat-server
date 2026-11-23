from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, status
from sqlmodel import Session

from app.auth.jwt import decode_token
from app.auth.session_store import get as get_auth_session
from app.db.cruds.auth import get_user_by_uid
from app.db.models import User
from app.db.session import get_session


def get_current_user(
    authorization: Annotated[str | None, Header()] = None,
    db: Session = Depends(get_session),
) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="缺少 Bearer access token")
    token = authorization[7:]
    try:
        payload = decode_token(token)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Access token 已过期，请调用刷新接口")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Access token 无效")
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail="Token 类型错误")
    auth_session = get_auth_session(payload.get("sid", ""))
    if not auth_session or auth_session.uid != payload.get("sub"):
        raise HTTPException(status_code=401, detail="登录会话已失效")
    user = get_user_by_uid(db, payload["sub"])
    if not user or user.is_disable:
        raise HTTPException(status_code=403, detail="用户不存在或已被禁用")
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(user: CurrentUser) -> User:
    if user.role != 0:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要管理员权限")
    return user
