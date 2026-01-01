from fastapi import FastAPI, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

import time
import httpx
from httpx import AsyncHTTPTransport, Limits, AsyncClient, Timeout
import anyio

import jwt


def get_http_client(
    user_agent: str,
    timeout: int = 2,
    max_connections: int = 10,
    max_keepalive_connections: int = 5,
    max_retries: int = 2,
    follow_redirects: bool = False,
) -> AsyncClient:
    limits = Limits(
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive_connections,
    )
    transport = AsyncHTTPTransport(
        limits=limits,
        retries=max_retries,
    )
    return AsyncClient(
        transport=transport,
        limits=limits,
        follow_redirects=follow_redirects,
        headers={"User-Agent": user_agent},
        timeout=Timeout(timeout),
    )


class JWKSClient:
    def __init__(
        self,
        http_client: AsyncClient,
        http_jwks_url: str,
        time_ban_s: float = 30.0,
        time_cache_ttl_s: float = 300.0,
    ) -> None:
        self._cache: dict[str, jwt.PyJWK] = {}
        self._banned_until: dict[str, float] = {}

        self._time_ban_s: float = time_ban_s
        self._time_cache_ttl_s: float = time_cache_ttl_s
        self._time_last_update_s: float = 0.0

        self._lock = anyio.Lock()

        self._http_jwks_url = http_jwks_url
        self._http_client = http_client

    def _cache_is_fresh(self) -> bool:
        return (time.monotonic() - self._time_last_update_s) < self._time_cache_ttl_s

    def is_banned(self, kid: str) -> bool:
        now = time.monotonic()
        bk = self._banned_until.get(kid)
        if bk and now < bk:
            return True
        return False

    async def _load_remote_jwks(self) -> bool:
        try:
            response = await self._http_client.get(self._http_jwks_url)
            response.raise_for_status()
            data = response.json()
        except Exception:
            print("HTTP Error")
            return False

        if not isinstance(data, dict):
            return False

        keys = data.get("keys")  # type: ignore
        if keys is None or not isinstance(keys, list):
            return False

        new_keys: dict[str, jwt.PyJWK] = {}
        for key_data in keys:  # type: ignore
            if key_data.get("use") != "sig":  # type: ignore
                continue
            try:
                jwk = jwt.PyJWK.from_dict(key_data)  # type: ignore
            except Exception as e:
                print(e)
                print("Error for dump jwk")
                continue

            if jwk.key_id:
                new_keys[jwk.key_id] = jwk

        if not new_keys:
            return False

        if frozenset(new_keys.keys()) != frozenset(self._cache.keys()):
            self._cache = new_keys

        self._banned_until.clear()
        self._time_last_update_s = time.monotonic()
        return True

    async def find_key_by_kid(self, kid: str) -> jwt.PyJWK | None:
        if self.is_banned(kid):
            return None

        if self._cache_is_fresh():
            if key := self._cache.get(kid):
                return key
            self._banned_until[kid] = time.monotonic() + self._time_ban_s
            return None

        async with self._lock:
            if self.is_banned(kid):
                return None

            if self._cache_is_fresh():
                if key := self._cache.get(kid):
                    return key
                self._banned_until[kid] = time.monotonic() + self._time_ban_s
                return None

            if not await self._load_remote_jwks():
                return self._cache.get(kid)

            if not (key := self._cache.get(kid)):
                self._banned_until[kid] = time.monotonic() + self._time_ban_s
            return key

    async def aclose(self) -> None:
        await self._http_client.aclose()


from typing import Annotated, Any, FrozenSet, Optional
from fastapi import HTTPException, status

from pydantic import BaseModel, field_validator


class Principal(BaseModel):
    sub: str
    scope: FrozenSet[str] = frozenset()
    azp: Optional[str] = None
    aud: list[str]
    kid: str
    jti: str
    iss: str
    exp: int
    iat: int

    client_roles: FrozenSet[str] = frozenset()

    @field_validator("scope", mode="before")
    @classmethod
    def scope_validate(cls, v: Any) -> FrozenSet[str]:
        if isinstance(v, str):
            return frozenset(s for s in v.split() if s)
        if isinstance(v, (list, set, tuple, frozenset)):
            return frozenset(str(s) for s in v if s)  # type: ignore
        raise TypeError("Scope must be str or list, set, tuple, frozenset")

    @field_validator("aud", mode="before")
    @classmethod
    def aud_validate(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [v]
        return v


from fastapi import Request


def get_jwks_client(request: Request) -> JWKSClient:
    return request.app.state.jwks_client


from settings import Settings


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


security = HTTPBearer(auto_error=False)


def extract_roles(claims: dict[str, Any], client_id: str):
    return claims.get("resource_access").get(client_id).get("roles")  # type: ignore


async def get_current_user(
    auth: Annotated[Optional[HTTPAuthorizationCredentials], Depends(security)],
    jwks_client: Annotated[JWKSClient, Depends(get_jwks_client)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> Principal:
    if not auth or auth.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer",
            headers={"WWW-Authenticate": 'Bearer error="invalid_request"'},
        )

    token = auth.credentials
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing kid",
                headers={"WWW-Authenticate": 'Bearer error="invalid_request"'},
            )

        key = await jwks_client.find_key_by_kid(kid)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Key not found",
                headers={"WWW-Authenticate": 'Bearer error="invalid_request"'},
            )

        claims: dict[str, Any] = jwt.decode(
            token,
            key=key.key,
            algorithms=settings.jwt_allow_algorithms,
            audience=settings.service_aud,
            issuer=settings.token_issuer,
            leeway=settings.jwt_leeway_seconds,
            options={"require": ["iss", "aud", "exp", "iat", "sub", "jti"]},
        )

        roles = extract_roles(claims, settings.service_aud)
        return Principal(**claims, kid=kid, client_roles=roles)
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    except (jwt.InvalidAudienceError, jwt.InvalidIssuerError, jwt.PyJWTError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
    except httpx.HTTPError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWKS unavailable",
        )


from contextlib import asynccontextmanager
from typing import AsyncIterator


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    from settings import settings

    app.state.jwks_client = JWKSClient(
        http_client=get_http_client(user_agent=settings.service_aud),
        http_jwks_url=settings.jwks_url,
    )
    app.state.settings = settings
    await app.state.jwks_client._load_remote_jwks()  # type: ignore
    yield
    print("Shutdown: Closing JWKS Client connections...")
    await app.state.jwks_client.aclose()


app = FastAPI(lifespan=lifespan)


class RoleChecker:

    def __init__(self, require_role: str) -> None:
        self._require_role = require_role

    def __call__(
        self, user: Annotated[Principal, Depends(get_current_user)]
    ) -> Principal:

        if self._require_role not in user.client_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions",
            )

        return user


@app.get("/protected")
async def protected(principal: Annotated[Principal, Depends(RoleChecker("admin"))]):
    return {
        "sub": str(principal.sub),
        "aud": str(principal.aud),
        "jti": str(principal.jti),
    }


@app.get("/small-protected")
async def small_protected(
    principal: Annotated[Principal, Depends(RoleChecker("user"))],
):
    return {
        "sub": str(principal.sub),
        "aud": str(principal.aud),
        "jti": str(principal.jti),
    }
