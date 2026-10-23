import json
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select

from vulintel.config import settings
from vulintel.db import Alias, Batch, BatchItem, Delivery, Revision, Source, SourceRecord, Vulnerability, now
from vulintel.delivery import canonical_body, deliver_one, email_message, send_webhook, signature
from vulintel.reports import report_dir
from vulintel.service import Analysis, batch_page, due_slot, ingest, submit_analysis
from report_helpers import finalize, open_batch
from vulintel.sources import collect_one, entry, ghsa_record, kev_record, nvd_record, osv_record


def record(alias="CVE-2026-12345", **kwargs):
    cutoff = datetime.fromisoformat(due_slot()).replace(tzinfo=None) - timedelta(hours=8)
    kwargs.setdefault("published", (cutoff - timedelta(days=1)).isoformat() + "Z")
    return entry(alias, "示例漏洞", "原始公告", [alias], ["https://example.org/advisory"],
                 [{"product": "Python"}], severity="high", **kwargs)


def prepared_batch(db):
    vid = ingest(db, "nvd", record())
    cutoff = datetime.fromisoformat(due_slot()).replace(tzinfo=None) - timedelta(hours=8)
    db.get(Vulnerability, vid).updated_at = cutoff - timedelta(seconds=1)
    db.scalar(select(Revision).where(Revision.vulnerability_id == vid)).observed_at = cutoff - timedelta(seconds=1)
    db.commit()
    bid = open_batch(db, "tester")["batch_id"]
    return bid, db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))


def analysis(item_id):
    return Analysis(item_id=item_id, vulnerability_summary="示例漏洞的中文说明", root_cause="厂商未公开", trigger_conditions="需要受影响版本",
                    impact="可能造成拒绝服务", affected_versions="见原始公告", attack_path="入口条件尚未确认",
                    remediation="按厂商公告升级", evidence_level="unknown", evidence_notes="尚未独立验证",
                    references=["https://example.org/advisory"])


def test_alias_merge_and_material_update(store):
    with store() as db:
        first = ingest(db, "nvd", record())
        db.commit()
        stamp = db.get(Vulnerability, first).updated_at
        ingest(db, "nvd", record(modified="2099-01-01T00:00:00Z"))
        db.commit()
        assert db.get(Vulnerability, first).updated_at == stamp
        advisory = record("GHSA-XXXX-YYYY-ZZZZ")
        second = ingest(db, "ghsa", advisory)
        db.commit()
        assert first != second
        advisory["aliases"].append("CVE-2026-12345")
        merged = ingest(db, "ghsa", advisory)
        db.commit()
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        assert db.scalar(select(func.count()).select_from(Alias)) == 2
        assert all(r.vulnerability_id == merged for r in db.scalars(select(SourceRecord)))
        assert db.get(Vulnerability, merged).data["aliases"] == ["CVE-2026-12345", "GHSA-XXXX-YYYY-ZZZZ"]


def test_bulletin_mentions_not_aliases(store):
    with store() as db:
        value = entry("bulletin", "多漏洞公告", "", [], ["https://example.org"],
                      mentioned_cves=["CVE-2026-12345", "CVE-2026-67890"])
        bulletin = ingest(db, "apple", value)
        vulnerability = ingest(db, "nvd", record())
        db.commit()
        assert bulletin != vulnerability


def test_batch_pagination_resume_finalize_idempotent(store):
    with store() as db:
        bid, item = prepared_batch(db)
        assert open_batch(db, "tester")["batch_id"] == bid
        page = batch_page(db, bid)
        assert page["pending_analysis"] == 1 and page["items"][0]["item_id"] == item.id
        with pytest.raises(ValueError, match="需要完成逐条详解"):
            finalize(db, "tester", bid, "摘要")
        submit_analysis(db, "tester", bid, [analysis(item.id)])
        submit_analysis(db, "tester", bid, [analysis(item.id)])
        assert batch_page(db, bid, pending_only=True)["pending_analysis"] == 0
        assert finalize(db, "tester", bid, "中文摘要")["status"] == "finalized"
        count = db.scalar(select(func.count()).select_from(Delivery))
        finalize(db, "tester", bid, "不覆盖原摘要")
        assert count == db.scalar(select(func.count()).select_from(Delivery)) == 2
        assert db.get(Batch, bid).summary == "中文摘要"
        data = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
        assert data["items"][0]["analysis"]["root_cause"] == "厂商未公开"


def test_cross_batch_analysis_rejected(store):
    with store() as db:
        bid, item = prepared_batch(db)
        with pytest.raises(ValueError):
            submit_analysis(db, "tester", bid, [analysis(item.id + 100)])


def test_export_escaping_and_csv_formula(store):
    with store() as db:
        bid, item = prepared_batch(db)
        item.snapshot = {**item.snapshot, "title": "=1+1<script>alert(1)</script>"}
        db.commit()
        submit_analysis(db, "tester", bid, [analysis(item.id)])
        finalize(db, "tester", bid, "<script>alert('summary')</script>")
        assert "<script>" not in (report_dir(bid) / "report.html").read_text(encoding="utf-8")
        assert "'=1+1" in (report_dir(bid) / "index.csv").read_text(encoding="utf-8-sig")


def enable_delivery(monkeypatch):
    for key, value in {"DELIVERY_ENABLED": "true", "SMTP_HOST": "mail.example.org", "SMTP_FROM": "a@example.org",
                       "SMTP_TO": "b@example.org", "WEBHOOK_URL": "https://receiver.example.org/report",
                       "WEBHOOK_SECRET": "test-signing-key"}.items():
        monkeypatch.setenv(key, value)
    settings.cache_clear()


def test_channel_independence_retry_and_stable_id(store, monkeypatch):
    with store() as db:
        bid, item = prepared_batch(db)
        submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid, "摘要")
        assert not deliver_one(db, sender=lambda d: None)  # Deployment gate closed.
        enable_delivery(monkeypatch)
        seen = []
        def sender(delivery):
            seen.append((delivery.id, delivery.channel))
            if delivery.channel == "webhook":
                raise httpx.ConnectError("sensitive URL must not appear in error")
        deliver_one(db, sender)
        deliver_one(db, sender)
        email = db.scalar(select(Delivery).where(Delivery.channel == "email"))
        webhook = db.scalar(select(Delivery).where(Delivery.channel == "webhook"))
        assert email.status == "sent" and webhook.status == "pending"
        assert "sensitive" not in webhook.error
        stable = webhook.id
        webhook.next_run = now() - timedelta(seconds=1)
        db.commit()
        assert deliver_one(db, sender=lambda d: seen.append((d.id, d.channel)))
        assert db.get(Delivery, stable).status == "sent"
        assert sum(channel == "email" for _, channel in seen) == 1


def test_webhook_signature_and_email(store, monkeypatch):
    enable_delivery(monkeypatch)
    with store() as db:
        bid, item = prepared_batch(db)
        submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid, "摘要")
        webhook = db.scalar(select(Delivery).where(Delivery.channel == "webhook"))
        def receive(request):
            assert request.headers["X-Vul-Message-Id"] == webhook.id
            assert request.headers["X-Vul-Signature"] == signature("test-signing-key",
                request.headers["X-Vul-Timestamp"], request.content)
            assert request.content == canonical_body(webhook.payload)
            return httpx.Response(204)
        with httpx.Client(transport=httpx.MockTransport(receive)) as client:
            send_webhook(webhook, client)
        mail = db.scalar(select(Delivery).where(Delivery.channel == "email"))
        message = email_message(mail)
        assert message["To"] == "b@example.org" and message.is_multipart()
        assert len(list(message.iter_attachments())) == 1


def test_source_failure_retains_cursor_and_partial_data(store):
    class Broken:
        def records(self, source, start, end):
            yield record()
            raise httpx.ReadTimeout("failure")
    with pytest.raises(httpx.ReadTimeout):
        collect_one("nvd", upstream=Broken())
    with store() as db:
        assert db.get(Source, "nvd").last_success is None
        assert db.get(Source, "nvd").error
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
    class Fixed:
        def records(self, source, start, end):
            yield record()
    assert collect_one("nvd", upstream=Fixed()) == 1
    with store() as db:
        assert db.get(Source, "nvd").last_success and not db.get(Source, "nvd").error
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1


def test_parsers_keep_upstream_versions():
    nvd = nvd_record({"id": "CVE-2026-11111", "descriptions": [{"lang": "en", "value": "bug"}],
                      "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.8}}]}})
    assert nvd["severity"] == "high" and nvd["score"] == 8.8
    osv = osv_record({"id": "GO-2026-1234", "aliases": ["CVE-2026-11111"],
                      "affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}]}]})
    assert osv["affected"][0]["ranges"][0]["events"][-1]["fixed"] == "1.2.3"
    ghsa = ghsa_record({"ghsa_id": "GHSA-test", "html_url": "https://example.org", "severity": "critical"})
    assert ghsa["severity"] == "critical"
    assert kev_record({"cveID": "CVE-2026-11111"})["exploited"]


def test_empty_report_queues_both_channels(store):
    with store() as db:
        bid = open_batch(db, "test")["batch_id"]
        finalize(db, "test", bid, "本期没有新增；部分来源尚未采集。")
        rows = list(db.scalars(select(Delivery).where(Delivery.batch_id == bid)))
        assert {r.channel for r in rows} == {"email", "webhook"}
        assert next(r for r in rows if r.channel == "webhook").payload["items"] == []


def test_partitioned_webhook_and_resumable_pages(store, monkeypatch):
    monkeypatch.setenv("WEBHOOK_BATCH_SIZE", "2")
    settings.cache_clear()
    with store() as db:
        cutoff = datetime.fromisoformat(due_slot()).replace(tzinfo=None) - timedelta(hours=8)
        for number in range(5):
            vid = ingest(db, "nvd", record(f"CVE-2026-{20000 + number}"))
            db.get(Vulnerability, vid).updated_at = cutoff - timedelta(seconds=1)
            db.scalar(select(Revision).where(Revision.vulnerability_id == vid)).observed_at = cutoff - timedelta(seconds=1)
        db.commit()
        bid = open_batch(db, "test")["batch_id"]
        processed = set()
        while True:
            page = batch_page(db, bid, limit=2, pending_only=True)
            if not page["items"]:
                break
            submit_analysis(db, "test", bid, [analysis(i["item_id"]) for i in page["items"]])
            processed.update(i["item_id"] for i in page["items"])
        assert len(processed) == 5
        finalize(db, "test", bid, "5条，已分批核实")
        messages = list(db.scalars(select(Delivery).where(Delivery.channel == "webhook").order_by(Delivery.part)))
        assert [len(r.payload["items"]) for r in messages] == [2, 2, 1]
        assert all(r.payload["parts"] == 3 and r.payload["message_id"] == r.id for r in messages)


def test_delivery_crash_lease_recovers_without_resending_success(store, monkeypatch):
    enable_delivery(monkeypatch)
    with store() as db:
        bid, item = prepared_batch(db)
        submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid, "摘要")
        rows = list(db.scalars(select(Delivery).order_by(Delivery.channel)))
        rows[0].status = "sent"
        rows[1].status, rows[1].attempts = "sending", 1
        rows[1].lease_until = now() - timedelta(seconds=1)
        db.commit()
        sent = []
        assert deliver_one(db, sender=lambda row: sent.append(row.id))
        assert sent == [rows[1].id] and rows[0].status == "sent"
