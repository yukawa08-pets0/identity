from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy import Uuid, ForeignKey, String, DateTime
from uuid import UUID, uuid4
from datetime import datetime
from base import Base
from typing import Optional


class UUIDMixin:
    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid4
    )


class UserORM(Base, UUIDMixin):
    __tablename__ = "users"
    username: Mapped[str] = mapped_column(nullable=False)
    email: Mapped[str] = mapped_column(unique=True, nullable=False)
    credentials: Mapped["CredentialsORM"] = relationship(
        lazy="raise",
        cascade="all, delete-orphan",
        single_parent=True,
        back_populates="user",
        uselist=False,
    )


class CredentialsORM(Base, UUIDMixin):
    __tablename__ = "user_credentials"
    password_hash: Mapped[str] = mapped_column(nullable=False)
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    user: Mapped[UserORM] = relationship(
        lazy="raise",
        back_populates="credentials",
        uselist=False,
    )


class RefreshToken(Base, UUIDMixin):
    __tablename__ = "refresh_tokens"
    token_hash: Mapped[str] = mapped_column(String, unique=True)
    expire_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        default=None,
    )
    session_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("user_sessions.id", ondelete="CASCADE"),
        nullable=False,
    )
    session: Mapped["UserSessionORM"] = relationship(
        lazy="raise",
        back_populates="refresh_tokens",
        uselist=False,
    )


class UserSessionORM(Base, UUIDMixin):
    __tablename__ = "user_sessions"
    expire_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        server_default=None,
        nullable=True,
        default=None,
    )
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        lazy="raise",
        uselist=True,
        cascade="all, delete-orphan",
        back_populates="session",
    )


class PasswordResetORM(Base):
    __tablename__ = "password_resets_tokens"
    token_hash: Mapped[str] = mapped_column(String, primary_key=True)
    expire_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    user_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
