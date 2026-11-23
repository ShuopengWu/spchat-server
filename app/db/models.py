from datetime import date, datetime, timezone

from sqlmodel import Field, SQLModel


class User(SQLModel, table=True):
    __tablename__ = "user"

    id: int | None = Field(default=None, primary_key=True)
    uid: str = Field(index=True, unique=True, min_length=8, max_length=8)
    username: str = Field(min_length=3, max_length=12)
    password: str
    role: int = Field(default=1, ge=0, le=1)
    email: str = Field(unique=True, index=True)
    gender: str | None = Field(default=None, max_length=6)
    birthday: date | None = None
    location: str | None = Field(default=None, max_length=30)
    bio: str | None = Field(default=None, max_length=200)
    avatar_color: str = Field(default="#6C8EF5")
    updated_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_disable: bool = Field(default=True)
