from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    public_base_url: str = "https://vul.valna.cn"
    database_url: SecretStr = SecretStr("postgresql+psycopg://vul:change-me@db/vul")
    data_dir: Path = Path("/data")
    issuer_url: str = "https://vul.valna.cn/auth/realms/vul"
    keycloak_internal_url: str = "http://keycloak:8080/auth/realms/vul"
    mcp_client_id: str = "vul-mcp"
    web_client_id: str = "vul-web"
    web_client_secret: SecretStr = SecretStr("")
    admin_role: str = "vul-admin"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: SecretStr = SecretStr("")
    smtp_from: str = ""
    smtp_to: str = ""
    smtp_tls: str = "starttls"
    smtp_max_bytes: int = 8_000_000
    webhook_url: str = ""
    webhook_secret: SecretStr = SecretStr("")
    webhook_batch_size: int = 50
    delivery_enabled: bool = False
    nvd_api_key: SecretStr = SecretStr("")
    github_token: SecretStr = SecretStr("")
    source_interval_seconds: int = 3600
    delivery_max_attempts: int = 5

    @model_validator(mode="after")
    def validate_config(self):
        base = urlsplit(self.public_base_url)
        if base.scheme != "https" or not base.hostname or base.path not in ("", "/"):
            raise ValueError("PUBLIC_BASE_URL must be an HTTPS origin without a path")
        if base.username or base.password or base.query or base.fragment:
            raise ValueError("Invalid public origin")
        self.public_base_url = self.public_base_url.rstrip("/")
        if self.smtp_tls not in {"starttls", "ssl"}:
            raise ValueError("SMTP_TLS must be starttls or ssl")
        if self.webhook_batch_size < 1 or self.webhook_batch_size > 100:
            raise ValueError("WEBHOOK_BATCH_SIZE must be 1..100")
        if self.delivery_enabled:
            if not all([self.smtp_host, self.smtp_from, self.smtp_to,
                        self.webhook_url, self.webhook_secret.get_secret_value()]):
                raise ValueError("Both SMTP and Webhook configuration are required before enabling delivery")
        if self.webhook_url and urlsplit(self.webhook_url).scheme != "https":
            raise ValueError("WEBHOOK_URL must use HTTPS")
        return self

    @property
    def resource_url(self):
        return self.public_base_url + "/mcp"


@lru_cache
def settings():
    return Settings()
