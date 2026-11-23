# SPChat Server

FastAPI + SQLModel + SQLite authentication service.

## Run locally

```bash
uv sync
uv run uvicorn main:app --reload
```

OpenAPI docs: http://127.0.0.1:8000/docs

Set a strong `AUTH_SECRET_KEY` and `COOKIE_SECURE=true` behind HTTPS in production.
The refresh token is stored in an HTTP-only cookie; JavaScript cannot read it.
The in-memory session store is process-local and is intended only as a temporary
development implementation. Use Redis for multi-worker or production deployments.

## Authentication API

- `POST /api/auth/register`: create an account; returns an 8-character UID.
- `POST /api/auth/login`: send `grant_type=password`, `username` (UID or email),
  `password`, and `scope` (`read` or admin-only `all`). Returns access token
  and username; refresh token is set as an HTTP-only cookie.
- `POST /api/auth/refresh`: rotate the refresh cookie and issue a new access token.
- `POST /api/auth/reset`: verify the old password and set `new-password`.
- `POST /api/auth/logout`: revoke the refresh session and clear the cookie.
- `GET /api/auth/me`: example protected endpoint.
- `GET /api/auth/admin-check`: example administrator-only endpoint.

The user table is created automatically on application startup. Newly registered
users receive role 1 (user), a generated UID, and an enabled account.
