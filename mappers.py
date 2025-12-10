from orm_models import UserORM, CredentialsORM, UserSessionORM, PasswordResetORM
from domain import (
    User as User,
    Credentials as Credentials,
    UserSession as UserSession,
    PasswordReset as PasswordReset,
)


def user_to_domain(orm: UserORM) -> User:
    return User.new(
        id=orm.id,
        username=orm.username,
        email=orm.email,
        credentials=Credentials(password_hash=orm.credentials.password_hash),
    )


def user_to_orm(domain: User) -> UserORM:
    return UserORM(
        id=domain.id,
        username=domain.username,
        email=domain.email,
        credentials=CredentialsORM(password_hash=domain.credentials.password_hash),
    )


def user_session_to_domain(orm: UserSessionORM) -> UserSession:
    return UserSession.new(
        id=orm.id,
        refresh_tokens=(*[refresh_token_to_domain(rt) for rt in orm.refresh_tokens],),
        expire_at=orm.expire_at,
        user_id=orm.user_id,
        revoked_at=orm.revoked_at,
    )


def user_session_to_orm(domain: UserSession) -> UserSessionORM:
    orm = UserSessionORM(
        id=domain.id,
        expire_at=domain.expire_at,
        user_id=domain.user_id,
        revoked_at=domain.revoked_at,
    )
    orm.refresh_tokens = [refresh_token_to_orm(rt) for rt in domain.refresh_tokens]
    return orm


def password_reset_tokens_to_orm(domain: PasswordReset) -> PasswordResetORM:
    return PasswordResetORM(
        token_hash=domain.token_hash,
        expire_at=domain.expire_at,
        user_id=domain.user_id,
        used_at=domain.used_at,
    )


def password_reset_tokens_to_domain(orm: PasswordResetORM) -> PasswordReset:
    return PasswordReset(
        token_hash=orm.token_hash,
        expire_at=orm.expire_at,
        user_id=orm.user_id,
        used_at=orm.used_at,
    )


from orm_models import RefreshToken as RefreshTokenORM
from domain import RefreshToken


def refresh_token_to_orm(domain: RefreshToken) -> RefreshTokenORM:
    return RefreshTokenORM(
        id=domain.id,
        token_hash=domain.hash,
        expire_at=domain.expire_at,
        used_at=domain.used_at,
        revoked_at=domain.revoked_at,
        session_id=domain.session_id,
    )


def refresh_token_to_domain(orm: RefreshTokenORM) -> RefreshToken:
    return RefreshToken(
        id=orm.id,
        session_id=orm.session_id,
        hash=orm.token_hash,
        expire_at=orm.expire_at,
        revoked_at=orm.revoked_at,
        used_at=orm.used_at,
    )
