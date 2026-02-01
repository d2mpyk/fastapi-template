from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )

    SECRET_KEY: SecretStr
    ALGORITHM: SecretStr
    ACCESS_TOKEN_EXPIRE_MINUTES: SecretStr

# Carga de variables de entorno
settings = Settings() 