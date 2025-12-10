from domain import (
    User as User,
    UserSession as UserSession,
    UserRepo as UserRepoProtocol,
    UserSessionRepo as UserSessionProtocol,
    PasswordResetRepo as PasswordResetProtocol,
)
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional
from mappers import (
    user_session_to_domain,
    user_session_to_orm,
    user_to_orm,
    user_to_domain,
)
from datetime import datetime
from orm_models import (
    UserORM as UserORM,
    UserSessionORM as UserSessionORM,
    RefreshToken as RefreshTokenORM,
    PasswordResetORM as PasswordResetORM,
)
from uuid import UUID
from exceptions import AppException


class UserRepo(UserRepoProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, user: User) -> User:
        orm = user_to_orm(user)
        self._session.add(orm)
        return user_to_domain(orm)

    async def get_by_id(self, id: UUID) -> Optional[User]:
        stmt = (
            select(UserORM)
            .where(UserORM.id == id)
            .options(selectinload(UserORM.credentials))
        )
        orm = (await self._session.scalars(stmt)).first()
        if orm is None:
            return None

        return user_to_domain(orm)

    async def get_by_email_for_authenticate(self, email: str) -> Optional[User]:
        stmt = (
            select(UserORM)
            .options(selectinload(UserORM.credentials))
            .where(UserORM.email == email)
        )
        user = (await self._session.scalars(stmt)).first()

        if user is None:
            return None

        return user_to_domain(user)

    async def save(self, domain: User) -> None:
        stmt = (
            select(UserORM)
            .where(UserORM.id == domain.id)
            .options(selectinload(UserORM.credentials))
        )

        orm = (await self._session.scalars(stmt)).first()
        if orm is None:
            raise AppException("User not exists")

        orm.username = domain.username
        orm.email = domain.email
        orm.credentials.password_hash = domain.credentials.password_hash


from mappers import refresh_token_to_orm


class UserSessionRepo(UserSessionProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, user_session: UserSession) -> UserSession:
        orm = user_session_to_orm(user_session)
        self._session.add(orm)
        await self._session.flush()
        return user_session_to_domain(orm)

    async def get_by_id(self, id: UUID) -> Optional[UserSession]:
        stmt = (
            select(UserSessionORM)
            .join(RefreshTokenORM, RefreshTokenORM.session_id == UserSessionORM.id)
            .options(selectinload(UserSessionORM.refresh_tokens))
            .where(UserSessionORM.id == id)
        )
        orm = (await self._session.scalars(stmt)).first()
        if orm is None:
            return None

        return user_session_to_domain(orm)

    async def get_by_token_hash(
        self,
        token_hash: str,
    ) -> Optional[UserSession]:
        stmt = (
            select(UserSessionORM)
            .options(selectinload(UserSessionORM.refresh_tokens))
            .join(RefreshTokenORM, RefreshTokenORM.session_id == UserSessionORM.id)
            .where(RefreshTokenORM.token_hash == token_hash)
        )
        orm = (await self._session.scalars(stmt)).first()
        if orm is None:
            return None

        return user_session_to_domain(orm)

    async def get_by_user_id(
        self, user_id: UUID, active_only: bool, now: datetime
    ) -> list[UserSession]:
        stmt = select(UserSessionORM).where(UserSessionORM.user_id == user_id)

        if active_only:
            stmt = stmt.where(
                UserSessionORM.expire_at > now, UserSessionORM.revoked_at.is_(None)
            )

        stmt = stmt.options(selectinload(UserSessionORM.refresh_tokens))
        # .order_by(UserSessionORM.refresh_tokens.desc())

        sessions = (await self._session.scalars(stmt)).all()

        return [user_session_to_domain(s) for s in sessions]

    async def save(self, domain: UserSession) -> None:
        stmt = (
            select(UserSessionORM)
            .options(selectinload(UserSessionORM.refresh_tokens))
            .where(UserSessionORM.id == domain.id)
        )

        orm = (await self._session.scalars(stmt)).first()
        if orm is None:
            raise Exception("UserSession not exists")

        orm.expire_at = domain.expire_at
        orm.user_id = domain.user_id
        orm.revoked_at = domain.revoked_at

        exting_by_id = {t.id: t for t in orm.refresh_tokens}

        for td in domain.refresh_tokens:
            t = exting_by_id.get(td.id)
            if t is None:
                orm.refresh_tokens.append(refresh_token_to_orm(td))
            else:
                t.token_hash = td.hash
                t.revoked_at = td.revoked_at
                t.expire_at = td.expire_at
                t.used_at = td.used_at


from domain import PasswordReset
from mappers import password_reset_tokens_to_domain, password_reset_tokens_to_orm


class PasswordResetRepo(PasswordResetProtocol):
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, domain: PasswordReset) -> PasswordReset:
        orm = password_reset_tokens_to_orm(domain)
        self._session.add(orm)
        await self._session.flush()
        return password_reset_tokens_to_domain(orm)

    async def get_by_token_hash(self, token_hash: str) -> Optional[PasswordReset]:
        stmt = select(PasswordResetORM).where(PasswordResetORM.token_hash == token_hash)

        orm = (await self._session.scalars(stmt)).first()

        if orm is None:
            return None

        return password_reset_tokens_to_domain(orm)

    async def save(self, domain: PasswordReset) -> None:
        stmt = select(PasswordResetORM).where(
            PasswordResetORM.token_hash == domain.token_hash
        )

        orm = (await self._session.scalars(stmt)).first()
        if orm is None:
            raise AppException(detail="PasswordResetTokens not exists")

        orm.expire_at = domain.expire_at
        orm.used_at = domain.used_at
        orm.token_hash = domain.token_hash
        orm.user_id = domain.user_id
