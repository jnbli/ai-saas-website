# config.py
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    secret_key: str
    # You can add more settings here later, with types & defaults
    # e.g. debug: bool = False
    #      database_url: str = "sqlite:///users.db"

    model_config = SettingsConfigDict(
        env_file=".env",  # loads .env automatically in dev
        env_file_encoding="utf-8",
        case_sensitive=False,  # SECRET_KEY or secret_key both work
        extra="ignore",  # ignore unknown env vars
    )


# Create a singleton instance (import this everywhere you need settings)
settings = Settings()
