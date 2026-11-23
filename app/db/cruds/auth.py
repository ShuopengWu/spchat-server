import secrets
import string
from datetime import datetime, timezone

from sqlmodel import Session, select

from app.auth.jwt import hash_password, verify_password
from app.db.models import User


def get_user_by_login(session: Session, login: str) -> User | None:
    return session.exec(select(User).where((User.uid == login) | (User.email == login))).first()


def get_user_by_uid(session: Session, uid: str) -> User | None:
    return session.exec(select(User).where(User.uid == uid)).first()


def create_user(session: Session, username: str, password: str, email: str) -> User:
    alphabet = string.ascii_uppercase + string.digits
    for _ in range(20):
        uid = "".join(secrets.choice(alphabet) for _ in range(8))
        if not get_user_by_uid(session, uid):
            break
    else:
        raise RuntimeError("无法分配唯一 UID")
    user = User(
        uid=uid, username=username, password=hash_password(password),
        email=email, role=1, avatar_color="#6C8EF5",
        updated_date=datetime.now(timezone.utc), is_disable=False,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def authenticate(session: Session, login: str, password: str) -> User | None:
    user = get_user_by_login(session, login)
    if not user or user.is_disable or not verify_password(password, user.password):
        return None
    return user
