"""ORM models for the built-in users directory."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """Stores datetimes as aware UTC, regardless of what the dialect returns.

    SQLite always returns naive datetimes; PostgreSQL returns aware ones.
    Normalizing both ends here keeps ``UserRecord`` identical across backends.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("naive datetime is not allowed; pass an aware UTC datetime")
        return value.astimezone(UTC)

    def process_result_value(self, value: Any, dialect: Dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class Base(DeclarativeBase):
    """Declarative base for the users directory."""


class UserRow(Base):
    """A platform user account."""

    __tablename__ = "keystone_user"

    email: Mapped[str] = mapped_column(String(320), primary_key=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(320), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    roles: Mapped[list[UserRoleRow]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class UserRoleRow(Base):
    """A single role assignment for a user (multi-role model)."""

    __tablename__ = "keystone_user_role"
    __table_args__ = (UniqueConstraint("email", "role", name="uq_keystone_user_role_email_role"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(
        String(320),
        ForeignKey("keystone_user.email", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False)

    user: Mapped[UserRow] = relationship(back_populates="roles")


class ServiceAccountRow(Base):
    """A machine identity (service account)."""

    __tablename__ = "keystone_service_account"

    name: Mapped[str] = mapped_column(String(63), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_blocked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by: Mapped[str | None] = mapped_column(String(330), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)

    roles: Mapped[list[ServiceAccountRoleRow]] = relationship(
        back_populates="account",
        cascade="all, delete-orphan",
        lazy="selectin",
    )


class ServiceAccountRoleRow(Base):
    """A single role assignment for a service account."""

    __tablename__ = "keystone_service_account_role"
    __table_args__ = (UniqueConstraint("name", "role", name="uq_keystone_service_account_role"),)

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(
        String(63),
        ForeignKey("keystone_service_account.name", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    role: Mapped[str] = mapped_column(String(64), nullable=False)

    account: Mapped[ServiceAccountRow] = relationship(back_populates="roles")


class ApiKeyRow(Base):
    """A hashed API key bound to a human or service-account subject."""

    __tablename__ = "keystone_api_key"

    key_id: Mapped[str] = mapped_column(String(12), primary_key=True)
    subject: Mapped[str] = mapped_column(String(330), nullable=False, index=True)
    secret_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    label: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(330), nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    revoked_by: Mapped[str | None] = mapped_column(String(330), nullable=True)
