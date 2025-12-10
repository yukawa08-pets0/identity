from uow import UnitOfWork

from uow import UnitOfWork
from repositories import UserRepo, UserSessionRepo, PasswordResetRepo
from base import LocalSession
from anotations import (
    UserRepoFactory,
    UserSessionRepoFactory,
    PasswordResetRepoFactory,
    SessionFactory,
)


async def get_uow() -> UnitOfWork:
    return UnitOfWork(
        session_factory=LocalSession,
        user_repo_factory=UserRepo,
        user_session_repo_factory=UserSessionRepo,
        password_reset_repo_factory=PasswordResetRepo,
    )


def get_session():
    return LocalSession


async def get_uow_custom(
    user_repo_factory: UserRepoFactory = UserRepo,
    user_session_repo_factory: UserSessionRepoFactory = UserSessionRepo,
    password_reset_repo: PasswordResetRepoFactory = PasswordResetRepo,
) -> UnitOfWork:
    session_factory: SessionFactory = LocalSession
    return UnitOfWork(
        session_factory=session_factory,
        user_repo_factory=user_repo_factory,
        user_session_repo_factory=user_session_repo_factory,
        password_reset_repo_factory=password_reset_repo,
    )


async def get_uow_opened():
    async with UnitOfWork(
        session_factory=LocalSession,
        user_repo_factory=UserRepo,
        user_session_repo_factory=UserSessionRepo,
        password_reset_repo_factory=PasswordResetRepo,
    ) as session:
        yield session


async def get_session_opened():
    async with LocalSession() as session:
        yield session
