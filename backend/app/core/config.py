"""AegisGrid System Configuration Module.

Uses Pydantic Settings to manage configurations, credentials, and thresholds
securely via environment variables and loaded .env configurations.
"""

from pathlib import Path
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """System settings for the AegisGrid Resilience Engine."""

    # Application configuration
    app_name: str = Field(
        default="AegisGrid Resilience Engine Backend",
        validation_alias="APP_NAME"
    )
    app_version: str = Field(
        default="1.0.0",
        validation_alias="APP_VERSION"
    )
    host: str = Field(
        default="127.0.0.1",
        validation_alias="HOST"
    )
    port: int = Field(
        default=8000,
        validation_alias="PORT"
    )
    debug: bool = Field(
        default=False,
        validation_alias="DEBUG"
    )

    # Supabase cloud credentials
    supabase_url: Optional[str] = Field(
        default=None,
        validation_alias="SUPABASE_URL"
    )
    supabase_key: Optional[str] = Field(
        default=None,
        validation_alias="SUPABASE_KEY"
    )

    # Local storage configurations
    local_sqlite_path: str = Field(
        default="aegisgrid.db",
        validation_alias="LOCAL_SQLITE_PATH"
    )
    isolation_lock_file: str = Field(
        default="isolated_nodes.txt",
        validation_alias="ISOLATION_LOCK_FILE"
    )

    # Machine Learning threshold and parameters
    anomaly_threshold: float = Field(
        default=-0.02,
        validation_alias="ANOMALY_THRESHOLD"
    )
    contamination_rate: float = Field(
        default=0.015,
        validation_alias="CONTAMINATION_RATE"
    )

    # Paths
    base_dir: Path = Path(__file__).resolve().parent.parent.parent

    # Configuration source binding
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Globally shared settings singleton
settings = Settings()
