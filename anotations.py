from sqlalchemy.ext.asyncio import AsyncSession
from domain import UserRepo, UserSessionRepo, PasswordResetRepo
from typing import Callable

SessionFactory = Callable[[], AsyncSession]
UserRepoFactory = Callable[[AsyncSession], UserRepo]
UserSessionRepoFactory = Callable[[AsyncSession], UserSessionRepo]
PasswordResetRepoFactory = Callable[[AsyncSession], PasswordResetRepo]
