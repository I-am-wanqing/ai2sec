from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "AI2Sec Backend"
    database_url: str = "sqlite:///./backend/data/ai2sec.db"
    invite_code: str = "demo-invite-code"
    session_hours: int = 24
    upload_dir: Path = Path("./backend/data/uploads")
    evidence_dir: Path = Path("./backend/data/evidence")
    report_dir: Path = Path("./backend/data/reports")
    max_upload_bytes: int = 25 * 1024 * 1024
    allow_private_targets: bool = False
    openai_api_key: str = ""
    openai_base_url: str = "https://api.openai.com/v1"
    openai_model: str = "gpt-4.1-mini"

    model_config = SettingsConfigDict(env_prefix="AI2SEC_", env_file=".env", extra="ignore")

    @property
    def sqlite_path(self) -> Path:
        if not self.database_url.startswith("sqlite:///"):
            raise ValueError("Only sqlite:/// database URLs are supported in the MVP")
        return Path(self.database_url.replace("sqlite:///", "", 1))


@lru_cache
def get_settings() -> Settings:
    return Settings()
