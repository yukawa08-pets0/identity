from __future__ import annotations

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import Depends, HTTPException, status
from fastapi import FastAPI
from typing import Any, Annotated, Optional, FrozenSet
from pydantic import BaseModel, field_validator
import jwt

import httpx

from settings import settings


from httpx import Timeout, AsyncHTTPTransport
import asyncio


class Principal(BaseModel):
    sub: str
    scope: FrozenSet[str] = frozenset()
    azp: Optional[str] = None
    aud: list[str]
    kid: Optional[str] = None
    jti: str
    exp: int
    iat: int

    @field_validator("scope", mode="before")
    @classmethod
    def parse_scope(cls, v: Any) -> FrozenSet[str]:
        if v is None:
            return frozenset()
        if isinstance(v, str):
            return frozenset(s for s in v.split() if s)
        if isinstance(v, (list, tuple, set, frozenset)):
            return frozenset(str(s) for s in v if s)  # type: ignore
        raise TypeError("scope must be str or list")

    @field_validator("aud", mode="before")
    @classmethod
    def normalize_aud(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [v]
        return v


import time


class JWKSClient:
    def __init__(
        self,
        jwks_url: str,
        *,
        max_retries: int = 2,
        timeout_s: int = 2,
        ttl_cache_s: int = 300,
    ) -> None:

        self._ttl_cache_s = ttl_cache_s
        self._last_cache_update: float = 0.0
        self._jwks_url = jwks_url
        self._miss_until: dict[str, float] = {}
        self._keys: dict[str, jwt.PyJWK] = {}
        self._lock = asyncio.Lock()

        self._jwks_client = httpx.AsyncClient(
            timeout=Timeout(timeout=timeout_s),
            headers={"User-Agent": "backend-svc1-client"},
            follow_redirects=False,
            transport=AsyncHTTPTransport(
                retries=max_retries,
                limits=httpx.Limits(max_keepalive_connections=5, max_connections=10),
            ),
        )

    def _is_fresh(self) -> bool:
        return (time.monotonic() - self._last_cache_update) <= self._ttl_cache_s

    async def _load_keys_from_remote_jwks(self) -> bool:
        try:
            response = await self._jwks_client.get(self._jwks_url)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError:
            print("HTTPError in GET query to IdP")
            return False

        if (
            not isinstance(data, dict)
            or "keys" not in data
            or not isinstance(data["keys"], list)
        ):
            print("Invalid JWKS payload")
            return False

        new_keys: dict[str, jwt.PyJWK] = {}
        for key_data in data["keys"]:
            if not isinstance(key_data, dict):
                continue
            if key_data.get("use") != "sig":
                continue

            try:
                jwk = jwt.PyJWK.from_dict(key_data)  # type: ignore
            except jwt.PyJWKError:
                print("Parse Error")
                continue

            if jwk.key_id:
                new_keys[jwk.key_id] = jwk

        if not new_keys:
            return False

        self._keys = new_keys
        self._last_cache_update = time.monotonic()
        self._miss_until.clear()
        return True

    async def find_by_kid(self, kid: str) -> jwt.PyJWK | None:

        now = time.monotonic()
        until = self._miss_until.get(kid)
        if until is not None and now < until:
            return None

        k = self._keys.get(kid)
        if k is not None and self._is_fresh():
            return k

        async with self._lock:
            now = time.monotonic()
            until = self._miss_until.get(kid)
            if until is not None and now < until:
                return None

            k = self._keys.get(kid)
            if k is not None and self._is_fresh():
                return k

            ok = await self._load_keys_from_remote_jwks()
            if not ok:
                return self._keys.get(kid)

            k = self._keys.get(kid)
            if k is None:
                self._miss_until[kid] = time.monotonic() + 30.0
            return k

    async def aclose(self) -> None:
        await self._jwks_client.aclose()


app = FastAPI()
security = HTTPBearer(auto_error=False)
jwks_client = JWKSClient(settings.jwks_url)


async def get_current_user(
    cred: Annotated[HTTPAuthorizationCredentials, Depends(security)],
) -> Principal:
    # print(f"\n\nscheme= {cred.scheme}\n\n")
    if not cred or cred.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_request"'},
        )

    token = cred.credentials
    # print(f"\n\ncredentials= {cred.credentials}\n\n")
    try:
        header = jwt.get_unverified_header(token)
        kid = header.get("kid")
        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing kid",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        key = await jwks_client.find_by_kid(kid)

        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Key not Found",
                headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
            )

        claims: dict[str, Any] = jwt.decode(
            token,
            key=key.key,
            algorithms=settings.jwt_allow_algorithms,
            audience=settings.service_aud,
            issuer=settings.token_issuer,
            leeway=settings.jwt_leeway_seconds,
            options={"require": ["exp", "sub", "iat", "jti", "iss", "aud"]},
        )

        return Principal(**claims, kid=key.key_id)
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


@app.get("/protected")
async def protected(user_info: Annotated[Principal, Depends(get_current_user)]):
    print(f"\n\n{user_info}\n\n")
    return {
        "status": "ok",
        "sub": str(user_info.sub),
        "aud": str(user_info.aud),
    }


@app.get("/public")
async def public():
    return {"Hello, ": "World!"}


async def main():
    client = JWKSClient(settings.jwks_url)
    # await client._load_keys_from_remote_jwks()
    key = await client.find_by_kid("n7cdtaci37PxXhOB5WamVu7Hparxr7eLbKNOzqG2m4U")
    print(key.key) if key != None else print(None)


# asyncio.run(main())
