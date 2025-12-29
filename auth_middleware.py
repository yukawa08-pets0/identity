from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, field_validator
import jwt
from jwt import PyJWKClient
from typing import Annotated, Any, Optional
from settings import settings

app = FastAPI()

jwks_client = PyJWKClient(settings.jwks_url)
security = HTTPBearer(auto_error=False)


class Principal(BaseModel):
    sub: str
    scope: frozenset[str]
    azp: Optional[str]
    aud: list[str]
    kid: str
    jti: str
    exp: int
    iat: int

    @field_validator("scope", mode="before")
    @classmethod
    def parse_scope(cls, v: str):
        return frozenset(v.split(" "))


def get_current_user(
    token_obj: Annotated[HTTPAuthorizationCredentials, Depends(security)],
):
    if not token_obj:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = token_obj.credentials

    try:
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        payload: dict[str, Any] = jwt.decode(
            token,
            algorithms=[
                a.strip() for a in settings.allow_algorithms.split(",") if a.strip()
            ],
            key=signing_key.key,
            audience=settings.service_aud,
            issuer=settings.token_issuer,
            options={"require": ["exp", "sub", "iat", "jti"]},
        )

        return Principal(**payload, kid=str(signing_key.key_id))
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidAudienceError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid audience",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
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
