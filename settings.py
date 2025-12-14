from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import SecretStr


class Settings(BaseSettings):
    db_url: str
    async_pg_db_url: str

    keys_dir: str
    key_password: SecretStr
    private_key_file_name: str
    public_key_active_file_name: str
    public_key_deprecated_file_name: str

    model_config = SettingsConfigDict(env_file=".env")


settings = Settings()  # type: ignore
