from dataclasses import dataclass
from uuid import UUID, uuid4
from datetime import datetime
from typing import Optional


# VO & Agregates
@dataclass(frozen=True, slots=True)
class RefreshToken:
    id: UUID
    token_hash: str
    expire_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None
    session_id: UUID

    @classmethod
    def new(
        cls,
        id: UUID,
        session_id: UUID,
        token_hash: str,
        expire_at: datetime,
        used_at: datetime | None,
        revoked_at: datetime | None = None,
    ):
        return cls(
            id=id,
            session_id=session_id,
            token_hash=token_hash,
            expire_at=expire_at,
            used_at=used_at,
            revoked_at=revoked_at,
        )

    def mark_used(self, now: datetime) -> "RefreshToken":
        return RefreshToken(
            id=self.id,
            session_id=self.session_id,
            token_hash=self.token_hash,
            expire_at=self.expire_at,
            used_at=now,
            revoked_at=self.revoked_at,
        )

    def use_from_refresh(self, token_hash: str) -> "RefreshToken":
        return RefreshToken(
            id=uuid4(),
            session_id=self.session_id,
            token_hash=token_hash,
            expire_at=self.expire_at,
            used_at=self.used_at,
            revoked_at=self.revoked_at,
        )

    def revoke(self, revoked_at: datetime) -> "RefreshToken":
        return RefreshToken(
            id=self.id,
            session_id=self.session_id,
            token_hash=self.token_hash,
            expire_at=self.expire_at,
            used_at=self.used_at,
            revoked_at=revoked_at,
        )

    def change_hash(self, new_hash: str) -> "RefreshToken":
        return RefreshToken(
            id=self.id,
            session_id=self.session_id,
            token_hash=new_hash,
            expire_at=self.expire_at,
            used_at=self.used_at,
            revoked_at=self.revoked_at,
        )

    def is_valid(self, now: datetime) -> bool:
        return self.expire_at > now and self.used_at is None and self.revoked_at is None


@dataclass(frozen=True, slots=True)
class UserSession:
    id: UUID
    refresh_tokens: tuple[RefreshToken, ...]
    user_id: UUID
    expire_at: datetime
    revoked_at: datetime | None

    @classmethod
    def new(
        cls,
        id: UUID,
        refresh_tokens: tuple[RefreshToken, ...],
        user_id: UUID,
        expire_at: datetime,
        revoked_at: Optional[datetime] = None,
    ):
        return cls(
            id=id,
            refresh_tokens=refresh_tokens,
            user_id=user_id,
            expire_at=expire_at,
            revoked_at=revoked_at,
        )

    def revoke(self, revoked_at: datetime) -> "UserSession":
        return UserSession(
            id=self.id,
            refresh_tokens=self.refresh_tokens,
            user_id=self.user_id,
            expire_at=self.expire_at,
            revoked_at=revoked_at,
        )

    def is_valid(self, now: datetime) -> bool:
        return self.expire_at > now and self.revoked_at is None

    def mark_token_used_by_token_hash(
        self, token_hash: str, now: datetime
    ) -> "UserSession":
        refresh_tokens_list = [
            t.mark_used(now) for t in self.refresh_tokens if token_hash == t.token_hash
        ]
        return UserSession(
            id=self.id,
            refresh_tokens=(*refresh_tokens_list,),
            user_id=self.user_id,
            expire_at=self.expire_at,
            revoked_at=self.revoked_at,
        )

    def add_refresh_token(self, token: RefreshToken) -> "UserSession":
        return UserSession(
            id=self.id,
            refresh_tokens=(*self.refresh_tokens, token),
            user_id=self.user_id,
            expire_at=self.expire_at,
            revoked_at=self.revoked_at,
        )

    def revoke_refresh_token(
        self, token: RefreshToken, revoked_at: datetime
    ) -> "UserSession":
        refresh_tokens = [
            t.revoke(revoked_at)
            for t in self.refresh_tokens
            if t.id == token.id or t.token_hash == token.token_hash
        ]
        return UserSession(
            id=self.id,
            refresh_tokens=(*refresh_tokens,),
            user_id=self.user_id,
            expire_at=self.expire_at,
            revoked_at=self.revoked_at,
        )

    def revoke_all_refresh_tokens(self, revoked_at: datetime) -> "UserSession":
        refresh_tokens = [t.revoke(revoked_at) for t in self.refresh_tokens]
        return UserSession(
            id=self.id,
            refresh_tokens=(*refresh_tokens,),
            user_id=self.user_id,
            expire_at=self.expire_at,
            revoked_at=self.revoked_at,
        )


@dataclass(frozen=True, slots=True)
class Credentials:
    password_hash: str

    @classmethod
    def new(
        cls,
        password_hash: str,
    ):
        return cls(
            password_hash=password_hash,
        )


@dataclass(frozen=True, slots=True)
class User:
    id: UUID
    username: str
    email: str
    credentials: Credentials

    @classmethod
    def new(
        cls,
        id: UUID,
        username: str,
        email: str,
        credentials: Credentials,
    ):
        return cls(
            id=id,
            username=username,
            email=email,
            credentials=credentials,
        )

    def change_credentials(self, new_credentials: Credentials) -> "User":
        return User(
            id=self.id,
            username=self.username,
            email=self.email,
            credentials=new_credentials,
        )


@dataclass(frozen=True, slots=True)
class PasswordReset:
    token_hash: str
    expire_at: datetime
    user_id: UUID
    used_at: datetime | None

    @classmethod
    def new(
        cls,
        token_hash: str,
        expire_at: datetime,
        user_id: UUID,
        used_at: datetime | None = None,
    ):
        return cls(
            token_hash=token_hash,
            expire_at=expire_at,
            user_id=user_id,
            used_at=used_at or None,
        )

    def use(
        self,
        used_at: datetime,
    ) -> "PasswordReset":
        return PasswordReset(
            token_hash=self.token_hash,
            expire_at=self.expire_at,
            user_id=self.user_id,
            used_at=used_at,
        )

    def is_valid(self, now: datetime) -> bool:
        return self.used_at is None and self.expire_at > now


from typing import Protocol, Optional


class UserRepo(Protocol):
    async def add(self, user: User) -> User: ...
    async def get_by_email_for_authenticate(self, email: str) -> Optional[User]: ...
    async def get_by_id(self, id: UUID) -> Optional[User]: ...
    async def save(self, domain: User) -> None: ...


class UserSessionRepo(Protocol):
    async def add(self, user_session: UserSession) -> UserSession: ...
    async def get_by_id(self, id: UUID) -> Optional[UserSession]: ...
    async def get_by_user_id(
        self, user_id: UUID, active_only: bool, now: datetime
    ) -> list[UserSession]: ...
    async def get_by_token_hash(self, token_hash: str) -> Optional[UserSession]: ...
    async def save(self, domain: UserSession) -> None: ...


class PasswordResetRepo(Protocol):
    async def add(self, domain: PasswordReset) -> PasswordReset: ...
    async def get_by_token_hash(self, token_hash: str) -> Optional[PasswordReset]: ...
    async def save(self, domain: PasswordReset) -> None: ...


class UoW(Protocol):
    user_sessions: UserSessionRepo
    users: UserRepo
    resets: PasswordResetRepo
