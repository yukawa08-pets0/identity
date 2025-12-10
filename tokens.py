from clock import now_int, expiration_calc_int
from jwt import decode, encode
from uuid import UUID
from typing import Any
from hashlib import sha256
import secrets


KEY = "jwt-key"
ALG = "HS256"


def issue_access_jwt(id: UUID, session_id: UUID) -> str:
    iat = now_int()
    access_claims: dict[str, Any] = {
        "sub": str(id),
        "sid": str(session_id),
        "iat": iat,
        "exp": expiration_calc_int(iat=iat, minutes=15),
    }

    return encode(payload=access_claims, key=KEY, algorithm=ALG)


def parse_token(token: str) -> dict[str, Any]:
    return decode(token, algorithms=[ALG], key=KEY)


def issue_opaque() -> str:
    return secrets.token_urlsafe(32)


def hash_sha256(token: str) -> str:
    return sha256(token.encode()).hexdigest()
