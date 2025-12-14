from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from clock import now_int, expiration_calc_int
from functools import lru_cache
import jwt
from settings import settings
from typing import Any
from uuid import UUID
import secrets
import hashlib
import base64


def make_kid(public_key: PublicKeyTypes) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    digest = hashlib.sha256(der).digest()
    kid = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    return kid


@lru_cache(maxsize=1)
def load_signing_material() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str]:
    password = settings.key_password.get_secret_value().encode("utf-8")

    with open(settings.private_key_path, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password)

    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("Expected RSA private key")

    public_key = key.public_key()
    kid = make_kid(public_key)
    return key, public_key, kid


def get_signing_material() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str]:
    return load_signing_material()


ALG = "RS256"


def issue_access_jwt(sub_id: UUID, session_id: UUID) -> str:
    iat = now_int()
    key, _, kid = get_signing_material()
    access_claims: dict[str, Any] = {
        "sub": str(sub_id),
        "sid": str(session_id),
        "iat": iat,
        "exp": expiration_calc_int(iat=iat, minutes=15),
    }
    headers = {"kid": kid, "typ": "JWT"}

    return jwt.encode(headers=headers, payload=access_claims, key=key, algorithm=ALG)


def parse_token(token: str) -> dict[str, Any]:
    _, key, _ = get_signing_material()
    return jwt.decode(
        token, algorithms=[ALG], key=key, options={"require": ["exp", "sub", "iat"]}
    )


def issue_opaque() -> str:
    return secrets.token_urlsafe(32)


def hash_sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
