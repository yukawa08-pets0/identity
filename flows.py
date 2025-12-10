from uow import UnitOfWork
from tokens import (
    issue_access_jwt,
    issue_opaque,
    hash_sha256,
)
from clock import (
    expiration_calc_datetime,
    now_datetime,
)
from domain import (
    User,
    Credentials,
    UserSession,
)
from security import hasher
from dataclasses import dataclass
from uuid import uuid4, UUID


@dataclass
class Tokens:
    access_token: str
    refresh_token: str


from domain import RefreshToken
from exceptions import AppException
from typing import Optional


async def register_cmd(
    username: str,
    email: str,
    password: str,
    uow: UnitOfWork,
) -> None:
    async with uow:
        user: Optional[User] = await uow.users.get_by_email_for_authenticate(email)
        if user is not None:
            raise AppException(detail="email already exists")

        credentials = Credentials(password_hash=hasher.hash(password))
        domain_user = User.new(
            uuid4(), username=username, email=email, credentials=credentials
        )

        user = await uow.users.add(domain_user)


INVALID_EMAIL_OR_PASSWORD = "invalid email or password"


async def login_cmd(email: str, password: str, uow: UnitOfWork) -> Tokens:
    async with uow:
        user = await uow.users.get_by_email_for_authenticate(email)
        if user is None:
            raise AppException(INVALID_EMAIL_OR_PASSWORD)

        try:
            hasher.verify(user.credentials.password_hash, password)
        except Exception:
            raise AppException(INVALID_EMAIL_OR_PASSWORD)

        refresh_token = issue_opaque()
        session_id = uuid4()

        refresh_token_domain = RefreshToken.new(
            id=uuid4(),
            expire_at=expiration_calc_datetime(days=15),
            session_id=session_id,
            hash=hash_sha256(refresh_token),
            used_at=None,
        )

        user_session = UserSession.new(
            id=session_id,
            expire_at=expiration_calc_datetime(days=90),
            refresh_tokens=(refresh_token_domain,),
            user_id=user.id,
        )

        access_token = issue_access_jwt(user.id, user_session.id)
        await uow.user_sessions.add(user_session)

    return Tokens(access_token, refresh_token)


from domain import PasswordReset
from mail import send_to_mail


async def reset_password_query(email: str, uow: UnitOfWork):
    async with uow:
        user = await uow.users.get_by_email_for_authenticate(email)
        if user is None:
            return

        raw_token = issue_opaque()

        domain = PasswordReset.new(
            token_hash=hash_sha256(raw_token),
            expire_at=expiration_calc_datetime(minutes=60),
            user_id=user.id,
            used_at=None,
        )

        await uow.password_resets.add(domain)
    send_to_mail(to=user.email, body=raw_token)


async def reset_password_cmd(token_in: str, new_password: str, uow: UnitOfWork):
    async with uow:
        token_hash = hash_sha256(token_in)

        reset = await uow.password_resets.get_by_token_hash(token_hash)
        if reset is None:
            raise AppException("resets token not found")
        now = now_datetime()
        if not reset.is_valid(now):
            raise AppException("reset token is expire or token is already used")

        reset = reset.use(now)

        user = await uow.users.get_by_id(reset.user_id)
        if user is None:
            raise AppException("user not found")

        new_credentials = Credentials(password_hash=hasher.hash(new_password))
        user = user.change_credentials(new_credentials=new_credentials)

        sessions = await uow.user_sessions.get_by_user_id(
            user.id, active_only=True, now=now
        )

        sessions = [s.revoke(now).revoke_all_refresh_tokens(now) for s in sessions]

        await uow.users.save(user)
        for s in sessions:
            await uow.user_sessions.save(s)
        await uow.password_resets.save(reset)


async def refresh_cmd(raw_token: str, uow: UnitOfWork) -> Tokens:
    async with uow:
        hash_ = hash_sha256(raw_token)
        session = await uow.user_sessions.get_by_token_hash(hash_)
        if session is None:
            raise AppException("Session not exists")

        now = now_datetime()
        if not session.is_valid(now):
            raise AppException("Session already revoked or expired")

        old_refresh = next(
            (t for t in session.refresh_tokens if t.hash == hash_),
            None,
        )
        if not old_refresh:
            raise AppException("Token not found")
        if not old_refresh.is_valid(now):
            raise AppException("Token already used or expired or revoked")

        session = session.mark_token_used_by_token_hash(old_refresh.hash, now)
        refresh = issue_opaque()
        refresh_hash = hash_sha256(refresh)
        now = now_datetime()

        new_refresh = RefreshToken.new(
            id=uuid4(),
            session_id=old_refresh.session_id,
            hash=refresh_hash,
            expire_at=min(expiration_calc_datetime(days=15), session.expire_at),
            revoked_at=None,
            used_at=None,
        )

        session = session.add_refresh_token(new_refresh)
        access_token = issue_access_jwt(
            id=session.user_id,
            session_id=session.id,
        )

        await uow.user_sessions.save(session)

    return Tokens(access_token=access_token, refresh_token=refresh)


async def logout_cmd(refresh_raw: str, uow: UnitOfWork):
    async with uow:
        hash_ = hash_sha256(refresh_raw)
        session = await uow.user_sessions.get_by_token_hash(hash_)
        if session is None:
            raise AppException("Session not exists")
        if not session.is_valid(now_datetime()):
            raise AppException("Session revoked or expired")
        now = now_datetime()
        session = session.revoke(now).revoke_all_refresh_tokens(now)
        await uow.user_sessions.save(session)


async def logout_all_cmd(user_id: UUID, uow: UnitOfWork):
    async with uow:
        now = now_datetime()
        sessions = await uow.user_sessions.get_by_user_id(
            user_id, active_only=True, now=now
        )
        if not sessions:
            raise AppException("sessions not found")

        sessions = [s.revoke(now).revoke_all_refresh_tokens(now) for s in sessions]
        for s in sessions:
            await uow.user_sessions.save(s)
