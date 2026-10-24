from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
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
    report_max_items: int = Field(default=50, ge=1, le=10000)
    publication_request_interval: float = Field(default=1.0, ge=0.1, le=60)
    publication_cache_hours: int = Field(default=168, ge=1, le=8760)
    publication_reference_hosts: str = ("msrc.microsoft.com,support.apple.com,source.android.com,nodejs.org,go.dev,"
                                        "www.python.org,github.com,www.cisco.com,sec.cloudapps.cisco.com,"
                                        "www.fortiguard.com,www.debian.org,ubuntu.com,access.redhat.com,"
                                        "www.zerodayinitiative.com,googleprojectzero.blogspot.com")

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
            smtp_present = any([self.smtp_host.strip(), self.smtp_from.strip(), self.smtp_to.strip(),
                                self.smtp_user.strip(), self.smtp_password.get_secret_value()])
            webhook_present = bool(self.webhook_url.strip() or self.webhook_secret.get_secret_value())
            if smtp_present and "email" not in self.delivery_channels:
                raise ValueError("SMTP 配置不完整：需要 SMTP_HOST、SMTP_FROM、SMTP_TO；账号和密码须同时填写或同时留空")
            if webhook_present and "webhook" not in self.delivery_channels:
                raise ValueError("Webhook 配置不完整：需要 WEBHOOK_URL 和 WEBHOOK_SECRET")
            if not self.delivery_channels:
                raise ValueError("开启投递至少需要完整配置 SMTP 或 Webhook 中的一个渠道")
        if self.webhook_url and urlsplit(self.webhook_url).scheme != "https":
            raise ValueError("WEBHOOK_URL must use HTTPS")
        return self

    @property
    def delivery_channels(self):
        channels = []
        credentials_paired = bool(self.smtp_user.strip()) == bool(self.smtp_password.get_secret_value())
        if all([self.smtp_host.strip(), self.smtp_from.strip(), self.smtp_to.strip()]) and credentials_paired:
            channels.append("email")
        if self.webhook_url.strip() and self.webhook_secret.get_secret_value():
            channels.append("webhook")
        return tuple(channels)

    @property
    def resource_url(self):
        return self.public_base_url + "/mcp"


@lru_cache
def settings():
    return Settings()
