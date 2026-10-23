import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from vulintel import db as database
from vulintel.config import settings


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///" + (tmp_path / "test.db").as_posix())
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("DELIVERY_ENABLED", "false")
    monkeypatch.setenv("WEB_CLIENT_SECRET", "test-secret")
    # Default business fixtures queue both configured channels with the global gate closed.
    for key, value in {"SMTP_HOST": "mail.example.org", "SMTP_FROM": "a@example.org",
                       "SMTP_TO": "b@example.org", "SMTP_USER": "", "SMTP_PASSWORD": "",
                       "WEBHOOK_URL": "https://receiver.example.org/report",
                       "WEBHOOK_SECRET": "test-signing-key"}.items():
        monkeypatch.setenv(key, value)
    settings.cache_clear()
    engine = create_engine(settings().database_url.get_secret_value(), connect_args={"check_same_thread": False})
    monkeypatch.setattr(database, "_engine", engine)
    database.migrate()
    factory = sessionmaker(engine, expire_on_commit=False)
    with factory() as db:
        from vulintel.sources import seed_sources
        seed_sources(db)
    yield factory
    engine.dispose()
    settings.cache_clear()
