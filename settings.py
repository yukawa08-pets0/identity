from pydantic_settings import BaseSettings, SettingsConfigDict, NoDecode
from pydantic import field_validator
from typing import Any, Annotated


class Settings(BaseSettings):
    db_url: str
    async_pg_db_url: str

    service_aud: str
    jwks_url: str
    token_issuer: str
    jwt_allow_algorithms: Annotated[list[str], NoDecode] = ["RS256", "ES256"]
    jwt_leeway_seconds: int = 15

    model_config = SettingsConfigDict(env_file=".env")

    @field_validator("jwt_allow_algorithms", mode="before")
    @classmethod
    def jwt_allow_algorithms_normalize(cls, algs: Any):
        if isinstance(algs, str):
            return algs.split(" ")
        return algs


settings = Settings()  # type: ignore
# print(f"\n\nsettings= {settings}\n\n")
