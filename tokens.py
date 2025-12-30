from clock import now_int, expiration_calc_int
import jwt
from typing import Any
from uuid import UUID
import secrets
import hashlib

ALG = "RS256"
KEY = "PPSPPS"


def issue_access_jwt(sub_id: UUID, session_id: UUID) -> str:
    iat = now_int()
    access_claims: dict[str, Any] = {
        "sub": str(sub_id),
        "sid": str(session_id),
        "iat": iat,
        "exp": expiration_calc_int(iat=iat, minutes=15),
    }

    return jwt.encode(payload=access_claims, key=KEY, algorithm=ALG)


def parse_token(token: str) -> dict[str, Any]:
    return jwt.decode(
        token, algorithms=[ALG], key=KEY, options={"require": ["exp", "sub", "iat"]}
    )


def issue_opaque() -> str:
    return secrets.token_urlsafe(32)


def hash_sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
