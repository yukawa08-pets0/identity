from sqlalchemy.ext.asyncio import AsyncSession
from domain import UserRepo, UserSessionRepo, PasswordResetRepo
from exceptions import AppException
from anotations import (
    UserRepoFactory,
    UserSessionRepoFactory,
    PasswordResetRepoFactory,
    SessionFactory,
)


class UnitOfWork:
    def __init__(
        self,
        session_factory: SessionFactory,
        user_repo_factory: UserRepoFactory,
        user_session_repo_factory: UserSessionRepoFactory,
        password_reset_repo_factory: PasswordResetRepoFactory,
    ) -> None:
        self._user_repo_factory = user_repo_factory
        self._user_session_repo_factory = user_session_repo_factory
        self._password_reset_repo_factory = password_reset_repo_factory

        self._sf = session_factory
        self._session: AsyncSession | None = None
        self._committed: bool = False

        self._users: UserRepo | None = None
        self._user_sessions: UserSessionRepo | None = None
        self._password_resets: PasswordResetRepo | None = None

    async def __aenter__(self) -> "UnitOfWork":
        self._committed = False
        self._session = self._sf()
        self._users = self._user_repo_factory(self._session)
        self._user_sessions = self._user_session_repo_factory(self._session)
        self._password_resets = self._password_reset_repo_factory(self._session)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:  # type:ignore
        if not self._session:
            raise RuntimeError("UoW used outside of context")
        try:
            if exc_type:
                await self._session.rollback()
            elif not self._committed:
                await self._session.commit()
                self._committed = True
        finally:
            await self._session.close()
            self._session = None

    @property
    def users(self) -> UserRepo:
        if self._users is None:
            raise AppException(detail="UoW used outside of context")
        return self._users

    @property
    def user_sessions(self) -> UserSessionRepo:
        if self._user_sessions is None:
            raise AppException(detail="UoW used outside of context")
        return self._user_sessions

    @property
    def password_resets(self) -> PasswordResetRepo:
        if self._password_resets is None:
            raise AppException(detail="UoW used outside of context")
        return self._password_resets

    @property
    def session(self) -> AsyncSession:
        if self._session is None:
            raise AppException(detail="UoW used outside of context")
        return self._session

    async def commit(self) -> None:
        if not self._session:
            raise RuntimeError("UoW used outside of context")
        elif not self._committed:
            await self._session.commit()
            self._committed = True

    async def rollback(self) -> None:
        if not self._session:
            raise RuntimeError("UoW used outside of context")
        await self._session.rollback()
