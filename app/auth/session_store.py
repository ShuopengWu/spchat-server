"""In-memory refresh sessions. Replace this module with Redis in production."""
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock


@dataclass
class Session:
    uid: str
    hashed_refresh_token: str
    exp: datetime
    scope: str = "read"


_sessions: dict[str, Session] = {}
_lock = RLock()


def put(session_id: str, session: Session) -> None:
    with _lock:
        _sessions[session_id] = session


def get(session_id: str) -> Session | None:
    with _lock:
        session = _sessions.get(session_id)
        if session and session.exp <= datetime.now(timezone.utc):
            _sessions.pop(session_id, None)
            return None
        return session


def delete(session_id: str) -> None:
    with _lock:
        _sessions.pop(session_id, None)


def replace(session_id: str, expected_hash: str, session: Session) -> bool:
    """Atomic refresh-token rotation; prevents concurrent replay."""
    with _lock:
        current = _sessions.get(session_id)
        if not current or current.hashed_refresh_token != expected_hash:
            return False
        if current.exp <= datetime.now(timezone.utc):
            _sessions.pop(session_id, None)
            return False
        _sessions[session_id] = session
        return True


def revoke_uid(uid: str) -> None:
    with _lock:
        for session_id, session in list(_sessions.items()):
            if session.uid == uid:
                _sessions.pop(session_id, None)


def revoke_refresh_token(token_hash: str) -> None:
    import hmac
    with _lock:
        for session_id, session in list(_sessions.items()):
            if hmac.compare_digest(session.hashed_refresh_token, token_hash):
                _sessions.pop(session_id, None)
