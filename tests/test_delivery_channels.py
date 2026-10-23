from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select

from vulintel.config import Settings, settings
from vulintel.db import Delivery, now
from vulintel.delivery import deliver_one
from vulintel.service import finalize, open_batch


SMTP = {"smtp_host": "smtp.example.org", "smtp_from": "sender@example.org", "smtp_to": "to@example.org"}
WEBHOOK = {"webhook_url": "https://example.org/hook", "webhook_secret": "test-secret"}


@pytest.mark.parametrize("config,channels", [
    (SMTP, ("email",)), (WEBHOOK, ("webhook",)), ({**SMTP, **WEBHOOK}, ("email", "webhook")),
    ({**SMTP, "smtp_user": "sender@example.org", "smtp_password": "test-password"}, ("email",)),
])
def test_delivery_enabled_accepts_one_or_both_complete_channels(config, channels):
    cfg = Settings(_env_file=None, delivery_enabled=True, **config)
    assert cfg.delivery_channels == channels


@pytest.mark.parametrize("config,message", [
    ({}, "至少需要"), ({"smtp_host": "smtp.example.org"}, "SMTP 配置不完整"),
    ({**WEBHOOK, "smtp_to": "to@example.org"}, "SMTP 配置不完整"),
    ({**SMTP, "smtp_user": "sender@example.org"}, "SMTP 配置不完整"),
    ({**SMTP, "smtp_password": "test-password"}, "SMTP 配置不完整"),
    ({**SMTP, "webhook_url": "https://example.org/hook"}, "Webhook 配置不完整"),
    ({"webhook_secret": "test-secret"}, "Webhook 配置不完整"),
    ({"webhook_url": "http://example.org/hook", "webhook_secret": "test-secret"}, "HTTPS"),
])
def test_delivery_enabled_rejects_missing_or_partial_channels(config, message):
    with pytest.raises(ValidationError, match=message):
        Settings(_env_file=None, delivery_enabled=True, **config)


def configure(monkeypatch, channels, enabled):
    values = {**SMTP, **WEBHOOK, "smtp_user": "", "smtp_password": ""}
    for name in values:
        channel = "email" if name.startswith("smtp_") else "webhook"
        monkeypatch.setenv(name.upper(), str(values[name]) if channel in channels else "")
    monkeypatch.setenv("DELIVERY_ENABLED", "true" if enabled else "false")
    settings.cache_clear()


@pytest.mark.parametrize("channels", [("email",), ("webhook",), ("email", "webhook"), ()])
def test_finalize_queues_only_configured_channels_and_stays_idempotent(store, monkeypatch, channels):
    configure(monkeypatch, channels, enabled=False)
    if "email" not in channels:
        monkeypatch.setattr("vulintel.delivery.prepare_email", lambda *args: pytest.fail("Email preparation called"))
    if "webhook" not in channels:
        monkeypatch.setattr("vulintel.delivery.prepare_webhook", lambda *args: pytest.fail("Webhook preparation called"))
    with store() as db:
        bid = open_batch(db, "test")["batch_id"]
        finalize(db, "test", bid, "渠道选择测试")
        first = [(row.id, row.channel) for row in db.scalars(select(Delivery))]
        assert {channel for _, channel in first} == set(channels)
        assert len(first) == len(channels)
        finalize(db, "test", bid, "不重复创建")
        assert [(row.id, row.channel) for row in db.scalars(select(Delivery))] == first
        assert not deliver_one(db, sender=lambda row: pytest.fail("Global gate closed"))


@pytest.mark.parametrize("active", ["email", "webhook"])
def test_disabled_channel_history_is_paused_without_starving_active_channel(store, monkeypatch, active):
    configure(monkeypatch, ("email", "webhook"), enabled=False)
    with store() as db:
        bid = open_batch(db, "test")["batch_id"]
        finalize(db, "test", bid, "历史队列测试")
        rows = list(db.scalars(select(Delivery)))
        disabled = next(row for row in rows if row.channel != active)
        disabled.next_run = now() - timedelta(days=2)
        disabled.error = "previous failure"
        db.commit()
        configure(monkeypatch, (active,), enabled=True)
        sent = []
        monkeypatch.setattr("vulintel.delivery.send_email", lambda row: sent.append(("email", row.id)))
        monkeypatch.setattr("vulintel.delivery.send_webhook", lambda row: sent.append(("webhook", row.id)))
        assert deliver_one(db)
        assert sent[0][0] == active and len(sent) == 1
        assert not deliver_one(db)
        assert disabled.status == "pending" and disabled.attempts == 0
        assert disabled.error == "previous failure"
        disabled.status = "sending"
        disabled.lease_until = now() - timedelta(minutes=1)
        db.commit()
        assert not deliver_one(db)
        assert disabled.status == "sending" and disabled.attempts == 0
        configure(monkeypatch, ("email", "webhook"), enabled=True)
        assert deliver_one(db)
        assert disabled.status == "sent" and len(sent) == 2
        assert not deliver_one(db)


def test_new_channel_does_not_backfill_already_finalized_report(store, monkeypatch):
    configure(monkeypatch, ("email",), enabled=False)
    with store() as db:
        bid = open_batch(db, "test")["batch_id"]
        finalize(db, "test", bid, "仅邮件")
        configure(monkeypatch, ("email", "webhook"), enabled=False)
        finalize(db, "test", bid, "不补发")
        assert {row.channel for row in db.scalars(select(Delivery))} == {"email"}
