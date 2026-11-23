from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class RegisterBody(BaseModel):
    username: str = Field(min_length=3, max_length=12, description="显示名称")
    password: str = Field(min_length=8, max_length=128)
    email: EmailStr


class LoginBody(BaseModel):
    grant_type: Literal["password"] = "password"
    username: str = Field(min_length=1)
    password: str
    scope: Literal["read", "all"] = "read"


class ResetBody(BaseModel):
    username: str
    password: str
    new_password: str = Field(alias="new-password", min_length=8, max_length=128)


class RefreshBody(BaseModel):
    grant_type: Literal["refresh_token"] = "refresh_token"
    refresh_token: str = Field(alias="refresh-token")


class LogoutBody(BaseModel):
    refresh_token: str = Field(alias="refresh-token")


class TokenResponse(BaseModel):
    access_token: str = Field(serialization_alias="access-token")
    username: str | None = None
    token_type: str = "Bearer"


class RefreshResponse(BaseModel):
    access_token: str = Field(serialization_alias="access-token")
    token_type: str = "Bearer"


class RegisterResponse(BaseModel):
    uid: str


class TokenPayload(BaseModel):
    sub: str
    sid: str
    type: str
    exp: int
