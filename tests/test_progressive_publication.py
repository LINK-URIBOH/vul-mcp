import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from vulintel.config import settings
from vulintel.db import (Batch, BatchItem, Delivery, Publication, PublicationClaim, PublicationReceipt,
                         ReportBacklog, ReportState, now)
from vulintel.publisher import tick
from vulintel.report_jobs import batch_page, evidence_wire_size, item_evidence, status
from vulintel.reports import report_dir
from vulintel.service import Analysis, due_slot, finalize, ingest, open_batch, submit_analysis
from vulintel.sources import entry
from vulintel.timeline import iso, stamp


@pytest.fixture
def progressive(store, monkeypatch):
    monkeypatch.setenv("PUBLISHER_ENABLED", "true")
    settings.cache_clear()
    return store


def seed(db, count, slot=None, severity="critical"):
    slot = slot or due_slot()
    cutoff = stamp(slot)
    ids = []
    for i in range(count):
        key = f"CVE-2026-{800000 + i}"
        record = entry(key, "严重漏洞 " + key, "Official description " + str(i), [key],
            ["https://example.org/advisory/" + key], [{"product": "Example", "versions": "<2.0"}],
            severity=severity, published=iso(cutoff - timedelta(days=1)),
            disclosed_at=iso(cutoff - timedelta(days=1)), disclosure_reference="https://example.org/advisory/" + key)
        ids.append(ingest(db, "nvd", record, observed=cutoff - timedelta(minutes=2)))
    db.commit()
    return ids


def pump(store, predicate, limit=1800):
    for _ in range(limit):
        with store() as db:
            if predicate(db):
                return
        tick()
        with store() as db:
            failed = list(db.scalars(select(Batch).where(Batch.status == "failed")))
            assert not failed, [b.error for b in failed]
    pytest.fail("publisher did not reach expected checkpoint")


def open_progressive(store, count=139):
    with store() as db:
        seed(db, count)
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        bid, fid = result["batch_id"], result["fact_report"]["report_id"]
    pump(store, lambda db: db.get(Batch, fid).status == "finalized" and
         db.get(ReportState, bid).work.get("prepared"))
    return bid, fid


def analysis(identity):
    return Analysis(item_id=identity, vulnerability_summary="厂商公告描述的严重漏洞。",
        root_cause="公开资料未确认根因", trigger_conditions="受影响版本和入口见引用公告",
        impact="来源未给出独立影响验证", affected_versions="公告标注低于2.0的版本",
        attack_path="尚未独立验证", remediation="公告修复边界为2.0，部署前核对适用产品",
        evidence_level="unknown", evidence_notes="仅读取公开来源，未实际复现",
        references=["https://example.org/advisory"])


def test_cloud_interruption_all_facts_139_and_50_detail_cap(progressive):
    bid, fid = open_progressive(progressive)
    with progressive() as db:
        assert db.get(ReportState, fid).total == 139
        assert db.get(ReportState, bid).total == 50
        assert db.scalar(select(func.count()).select_from(ReportBacklog)) == 139
        assert db.scalar(select(func.count()).select_from(PublicationReceipt).where(PublicationReceipt.kind == "facts")) == 139
        assert db.scalar(select(func.count()).select_from(PublicationReceipt).where(PublicationReceipt.kind == "detail")) == 0
        facts = json.loads((report_dir(fid) / "report.json").read_text(encoding="utf-8"))
        assert len(facts["items"]) == 139 and all(item["analysis"] is None for item in facts["items"])
        assert facts["report_kind"] == "facts" and facts["item_limit"] is None
        assert "模型详解待补充" in (report_dir(fid) / "report.html").read_text(encoding="utf-8")
        repeated = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        assert repeated["fact_report"]["report_id"] == fid and repeated["batch_id"] == bid
        assert db.scalar(select(func.count()).select_from(Publication)) == 1


def test_23_saved_publish_10_10_3_and_no_duplicate_or_missing_ack(progressive, monkeypatch):
    bid, fid = open_progressive(progressive)
    with progressive() as db:
        items = list(db.scalars(select(BatchItem).where(BatchItem.batch_id == bid).order_by(BatchItem.id).limit(23)))
        for offset in range(0, 23, 10):
            submit_analysis(db, "cloud", bid, [analysis(item.id) for item in items[offset:offset + 10]])
    pump(progressive, lambda db: db.scalar(select(func.count()).select_from(PublicationReceipt).where(
        PublicationReceipt.kind == "detail")) == 20)
    with progressive() as db:
        assert db.scalar(select(func.count()).select_from(PublicationClaim)) == 20
        state = db.get(ReportState, bid)
        state.work = {**state.work, "last_analysis_at": iso(now() - timedelta(minutes=16))}
        db.commit()
    pump(progressive, lambda db: db.scalar(select(func.count()).select_from(PublicationReceipt).where(
        PublicationReceipt.kind == "detail")) == 23)
    with progressive() as db:
        pubs = list(db.scalars(select(Publication).where(Publication.kind == "supplement").order_by(Publication.triggered_at)))
        assert [db.get(ReportState, p.id).total for p in pubs] == [10, 10, 3]
        assert all(p.parent_fact_id == fid for p in pubs)
        assert status(db, db.get(Batch, bid))["pending_analysis"] == 27
        assert db.scalar(select(func.count()).select_from(ReportBacklog)) == 116
        with pytest.raises(ValueError, match="冻结"):
            changed = analysis(items[0].id)
            changed.impact = "新分析不能覆盖已经冻结版本"
            submit_analysis(db, "cloud", bid, [changed])
        db.rollback()
        finalize(db, "cloud", bid, mode="supplement")
        assert db.scalar(select(func.count()).select_from(PublicationClaim)) == 23
        assert db.get(Batch, bid).status == "analyzing"
    # Both channels use the real queue with mocked transports, never real recipients.
    monkeypatch.setenv("DELIVERY_ENABLED", "true")
    settings.cache_clear()
    from vulintel.delivery import deliver_one
    seen = []
    with progressive() as db:
        while deliver_one(db, sender=lambda d: seen.append((d.id, d.channel))):
            pass
        assert seen and {channel for _, channel in seen} == {"email", "webhook"}
        assert len({identity for identity, _ in seen}) == len(seen)
        assert all(d.status == "sent" for d in db.scalars(select(Delivery)))


def test_bulk_complete_evidence_and_oversized_fallback(progressive):
    bid, _ = open_progressive(progressive, 5)
    with progressive() as db:
        page = batch_page(db, bid, limit=50, pending_only=True, include_evidence=True)
        assert len(page["items"]) == 5 and all(i["evidence_complete"] for i in page["items"])
        assert len(json.dumps(page, ensure_ascii=False).encode()) <= 262144
        assert evidence_wire_size(page) <= 262144
        assert all(i["snapshot"]["source_records"] for i in page["items"])
        item = db.get(BatchItem, page["items"][0]["item_id"])
        item.snapshot = {**item.snapshot, "description": "大" * 300000}
        db.commit()
        page = batch_page(db, bid, limit=50, include_evidence=True)
        assert page["items"][0]["evidence_complete"] is False
        assert "snapshot" not in page["items"][0]
        offset, chunks = 0, []
        while offset is not None:
            evidence = item_evidence(db, bid, item.id, offset)
            chunks.append(evidence["text"])
            offset = evidence["next_offset"]
        assert json.loads("".join(chunks))["description"] == "大" * 300000


def test_old_analysis_does_not_block_current_fact_report(progressive):
    old_slot = (datetime.fromisoformat(due_slot()) - timedelta(days=1)).isoformat(timespec="minutes")
    with progressive() as db:
        seed(db, 1, old_slot)
        first = open_batch(db, "cloud", old_slot, ensure_facts=True, progressive=True)
        bid = first["batch_id"]
    pump(progressive, lambda db: db.get(Batch, first["fact_report"]["report_id"]).status == "finalized"
         and db.get(ReportState, bid).work.get("prepared"))
    with progressive() as db:
        second = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        assert second["batch_id"] == bid
        assert second["fact_report"]["slot"] == due_slot()
        assert second["fact_report"]["report_id"] != first["fact_report"]["report_id"]
        fid = second["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized")
    with progressive() as db:
        assert db.get(ReportState, fid).total == 0
        assert db.get(Batch, bid).status == "analyzing"


def test_aggregate_archives_without_duplicate_deliveries(progressive):
    bid, _ = open_progressive(progressive, 3)
    with progressive() as db:
        items = list(db.scalars(select(BatchItem).where(BatchItem.batch_id == bid)))
        submit_analysis(db, "cloud", bid, [analysis(i.id) for i in items])
        finalize(db, "cloud", bid, mode="supplement")
        finalize(db, "cloud", bid, summary="运维诊断不进入正文", overview={
            "risk_summary": ["优先处理受影响版本的严重漏洞"], "repair_priorities": ["按各条引用核对并升级修复版本"]})
    pump(progressive, lambda db: db.get(Batch, bid).status == "finalized")
    with progressive() as db:
        assert db.scalar(select(func.count()).select_from(Delivery).where(Delivery.batch_id == bid)) == 0
        assert db.get(ReportState, bid).work["archive_only"]
        assert (report_dir(bid) / "report.json").exists()
        archive = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
        assert archive["overview"]["risk_summary"] == ["优先处理受影响版本的严重漏洞"]
        assert "运维诊断不进入正文" not in (report_dir(bid) / "report.md").read_text(encoding="utf-8")


def test_unknown_dates_and_noncritical_never_count_as_confirmed_new(progressive):
    with progressive() as db:
        seed(db, 1, severity="high")
        key = "CVE-2026-999999"
        ingest(db, "ghsa", entry(key, "日期未知严重漏洞", "raw", [key], ["https://example.org/unknown"],
                               severity="critical"), observed=stamp(due_slot()) - timedelta(minutes=1))
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        fid = result["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized")
    with progressive() as db:
        assert db.get(ReportState, fid).total == 0 and db.get(ReportState, fid).unknown_count == 1
        from vulintel.report_metrics import volume
        assert volume(db)["new_disclosures"] == 0
        assert volume(db)["complete"] is False


def test_transient_render_failure_retains_checkpoint_and_retries_without_cloud(progressive, monkeypatch):
    from vulintel import report_render
    original = report_render.append
    with progressive() as db:
        seed(db, 2)
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        fid = result["fact_report"]["report_id"]
    failed = [False]
    def fail_once(*args):
        original(*args)
        if not failed[0]:
            failed[0] = True
            raise OSError("simulated storage interruption")
    monkeypatch.setattr(report_render, "append", fail_once)
    for _ in range(50):
        tick()
        with progressive() as db:
            if db.get(Batch, fid).status == "failed":
                state = db.get(ReportState, fid)
                assert state.work["retry_at"]
                assert db.scalar(select(func.count()).select_from(PublicationReceipt)) == 0
                state.work = {**state.work, "retry_at": iso(now() - timedelta(seconds=1))}
                db.commit()
                break
    else:
        pytest.fail("failure was not persisted")
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized")
    assert len(json.loads((report_dir(fid) / "report.json").read_text(encoding="utf-8"))["items"]) == 2


def test_new_evidence_after_freeze_not_consumed_by_old_supplement(progressive):
    from vulintel.db import SourceRecord
    bid, fid = open_progressive(progressive, 1)
    with progressive() as db:
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        source = db.scalar(select(SourceRecord).where(SourceRecord.vulnerability_id == item.vulnerability_id))
        newer = {**source.data, "description": "A later published fix", "remediations": [
            {"Date": iso(stamp(due_slot()) + timedelta(minutes=1)), "Description": "Vendor Fix"}]}
        ingest(db, source.source_id, newer, observed=stamp(due_slot()) + timedelta(minutes=2))
        db.commit()
        assert item.snapshot["description"] != newer["description"]
        newer_revision = db.get(ReportBacklog, item.vulnerability_id).revision_id
        submit_analysis(db, "cloud", bid, [analysis(item.id)])
        finalize(db, "cloud", bid, mode="supplement")
        vid = item.vulnerability_id
    pump(progressive, lambda db: db.get(Batch, bid).status == "finalized")
    with progressive() as db:
        pending = db.get(ReportBacklog, vid)
        assert pending and pending.revision_id == newer_revision and pending.category == "update"
        assert json.loads((report_dir(fid) / "report.json").read_text(encoding="utf-8"))["items"][0]["facts"]["description"] != newer["description"]


def test_reset_includes_publication_dependencies_and_controlled_archives(progressive):
    from vulintel.recent_reset import run_reset
    from vulintel.db import Vulnerability
    bid, fid = open_progressive(progressive, 1)
    with progressive() as db:
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        submit_analysis(db, "cloud", bid, [analysis(item.id)])
        finalize(db, "cloud", bid, mode="supplement")
    pump(progressive, lambda db: db.get(Batch, bid).status == "finalized")
    result = run_reset(emit=lambda _: None)
    assert result["complete"]
    with progressive() as db:
        for model in [Publication, PublicationClaim, PublicationReceipt, Batch, Delivery, Vulnerability]:
            assert db.scalar(select(func.count()).select_from(model)) == 0
    assert not report_dir(fid).exists()


def test_migration_supersedes_draft_preserves_archive_and_is_repeatable(progressive):
    from vulintel import db as database
    from vulintel.db import Migration
    from sqlalchemy import delete
    with progressive() as db:
        seed(db, 1)
        high_id = ingest(db, "nvd", entry("CVE-2026-999995", "旧高危待报", "raw", ["CVE-2026-999995"],
            ["https://example.org/high"], severity="high", disclosed_at=iso(stamp(due_slot()) - timedelta(days=1)),
            disclosure_reference="https://example.org/high"), observed=stamp(due_slot()) - timedelta(minutes=1))
        db.commit()
        draft = open_batch(db, "legacy")["batch_id"]
        from report_helpers import drain
        drain(db, draft, "analyzing")
        assert db.get(ReportBacklog, high_id)
        db.execute(delete(Migration).where(Migration.version == 6))
        db.commit()
    database.migrate()
    database.migrate()
    with progressive() as db:
        assert db.get(Batch, draft).status == "superseded"
        assert db.get(ReportBacklog, high_id) is None
        assert db.get(Batch, draft).slot.startswith("old:")
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        assert result["batch_id"] != draft


def test_discovery_date_verification_evidence_analysis_archive_mock_delivery(progressive, monkeypatch):
    import httpx
    from vulintel.collector import CollectorHTTP
    from vulintel.db import RecentCandidate, Source, Vulnerability
    from vulintel.recent import discover_once, verify_once
    from vulintel.recent_reset import run_reset
    monkeypatch.setattr(CollectorHTTP, "pause", lambda *_: None)
    with progressive() as db:
        for source in db.scalars(select(Source)):
            source.enabled = source.id == "nvd"
        db.commit()
    run_reset(emit=lambda _: None)
    key, published = "CVE-2026-888888", iso(stamp(due_slot()) - timedelta(days=1))
    def respond(request):
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [{"cve": {
                "id": key, "published": published, "lastModified": published,
                "descriptions": [{"lang": "en", "value": "Official vulnerability description"}],
                "metrics": {"cvssMetricV31": [{"source": "vendor", "cvssData": {
                    "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]}, "references": []}}]})
        assert request.url.host == "cveawg.mitre.org"
        return httpx.Response(200, json={"cveMetadata": {"cveId": key, "state": "PUBLISHED", "datePublished": published},
            "containers": {"cna": {"datePublic": published, "references": []}}})
    transport = httpx.MockTransport(respond)
    assert discover_once(transport=transport)
    with progressive() as db:
        candidate = db.scalar(select(RecentCandidate))
        # Simulate collection before the cutoff; never present post-cutoff facts as earlier knowledge.
        candidate.collected_at = stamp(due_slot()) - timedelta(minutes=2)
        db.commit()
    for _ in range(12):
        if not verify_once(transport=transport):
            break
    with progressive() as db:
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        bid, fid = result["batch_id"], result["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized" and db.get(ReportState, bid).work.get("prepared"))
    with progressive() as db:
        page = batch_page(db, bid, include_evidence=True)
        assert page["items"][0]["evidence_complete"]
        facts = page["items"][0]["snapshot"]
        assert facts["timeline"]["publication_status"] == "confirmed"
        value = analysis(page["items"][0]["item_id"])
        value.references = ["https://cveawg.mitre.org/api/cve/" + key]
        submit_analysis(db, "cloud", bid, [value])
        finalize(db, "cloud", bid, mode="supplement")
    pump(progressive, lambda db: db.get(Batch, bid).status == "finalized")
    monkeypatch.setenv("DELIVERY_ENABLED", "true")
    settings.cache_clear()
    from vulintel.delivery import deliver_one
    confirmations = []
    with progressive() as db:
        while deliver_one(db, sender=lambda d: confirmations.append((d.batch_id, d.channel))):
            pass
        assert {channel for _, channel in confirmations} == {"email", "webhook"}
        assert db.get(ReportState, fid).total == 1


def test_mcp_explicit_publish_scope_and_optional_volume(progressive):
    import time
    from cryptography.hazmat.primitives.asymmetric import rsa
    from starlette.testclient import TestClient
    from test_auth_web import token
    from vulintel.app import create_app
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    app = create_app()
    app.state.verifier.keys = {"test-key": key.public_key()}
    app.state.verifier.loaded = time.monotonic()
    headers = {"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-06-18"}
    with TestClient(app, base_url="https://vul.valna.cn", headers=headers) as client:
        def call(name, arguments, scopes="vul.read vul.submit vul.deliver"):
            return client.post("/mcp", headers={"Authorization": "Bearer " + token(key, scope=scopes)}, json={
                "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": arguments}}).json()["result"]
        result = call("open_report_batch", {"ensure_facts": True, "progressive": True}, "vul.read vul.submit")
        assert result.get("isError")
        assert "vul.deliver" in str(result["content"])
        with progressive() as db:
            assert db.scalar(select(func.count()).select_from(Publication)) == 0
        result = call("open_report_batch", {"ensure_facts": True, "progressive": True})["structuredContent"]
        assert result["fact_report"]["report_id"] != result["batch_id"]
        result = call("get_source_status", {"include_volume": True})["structuredContent"]
        assert result["report_volume"]["severity"] == "critical"
        assert result["report_volume"]["complete"] is False


def test_disclosure_already_includes_patch_does_not_repeat_as_important_update(progressive):
    from vulintel.db import SourceRecord
    old_slot = (datetime.fromisoformat(due_slot()) - timedelta(days=1)).isoformat(timespec="minutes")
    with progressive() as db:
        seed(db, 1, old_slot)
        record = db.scalar(select(SourceRecord))
        ingest(db, record.source_id, {**record.data, "remediations": [
            {"Date": iso(stamp(old_slot) - timedelta(hours=1)), "Description": "Vendor Fix"}]},
            observed=stamp(old_slot) - timedelta(minutes=1))
        db.commit()
        result = open_batch(db, "cloud", old_slot, ensure_facts=True, progressive=True)
        fid = result["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized")
    with progressive() as db:
        assert db.get(ReportState, fid).total == 1
        second = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        fid2 = second["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid2).status == "finalized")
    with progressive() as db:
        assert db.get(ReportState, fid2).total == 0


def test_large_original_fields_archive_intact_without_blocking_fact_delivery(progressive):
    from vulintel.db import SourceRecord
    with progressive() as db:
        seed(db, 1)
        source = db.scalar(select(SourceRecord))
        title, body = "Large title " * 50000, "Large original evidence " * 50000
        refs = [f"https://example.org/original/{i}" for i in range(10000)]
        ingest(db, source.source_id, {**source.data, "title": title, "description": body, "references": refs},
               observed=stamp(due_slot()) - timedelta(minutes=1))
        db.commit()
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        fid = result["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized")
    archive = json.loads((report_dir(fid) / "report.json").read_text(encoding="utf-8"))
    facts = archive["items"][0]["facts"]
    assert facts["title"] == title and facts["description"] == body and len(facts["references"]) == 10000
    assert "节选" in (report_dir(fid) / "report.html").read_text(encoding="utf-8")
    with progressive() as db:
        assert list(db.scalars(select(Delivery).where(Delivery.batch_id == fid)))


def test_unknown_large_index_cannot_block_verified_facts(progressive):
    with progressive() as db:
        seed(db, 1)
        title = "未知日期的长原文标题" * 50000
        ingest(db, "ghsa", entry("CVE-2026-999998", title, "Unknown publication date", ["CVE-2026-999998"],
            [f"https://example.org/unknown/{i}" for i in range(10000)], severity="critical"),
            observed=stamp(due_slot()) - timedelta(minutes=1))
        db.commit()
        result = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        fid = result["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized")
    archive = json.loads((report_dir(fid) / "report.json").read_text(encoding="utf-8"))
    assert len(archive["items"]) == 1 and len(archive["unverified"]) == 1
    assert archive["unverified"][0]["title"] == title
    assert "字段节选" in (report_dir(fid) / "unverified.csv").read_text(encoding="utf-8")


def test_backlog_supplement_links_original_fact_not_empty_current_fact(progressive):
    old_slot = (datetime.fromisoformat(due_slot()) - timedelta(days=1)).isoformat(timespec="minutes")
    with progressive() as db:
        seed(db, 139, old_slot)
        first = open_batch(db, "cloud", old_slot, ensure_facts=True, progressive=True)
        bid, fid = first["batch_id"], first["fact_report"]["report_id"]
    pump(progressive, lambda db: db.get(Batch, fid).status == "finalized" and db.get(ReportState, bid).work.get("prepared"))
    with progressive() as db:
        items = list(db.scalars(select(BatchItem).where(BatchItem.batch_id == bid).order_by(BatchItem.id)))
        for offset in range(0, len(items), 10):
            submit_analysis(db, "cloud", bid, [analysis(i.id) for i in items[offset:offset + 10]])
    pump(progressive, lambda db: db.get(Batch, bid).status == "finalized")
    with progressive() as db:
        second = open_batch(db, "cloud", ensure_facts=True, progressive=True)
        bid2, fid2 = second["batch_id"], second["fact_report"]["report_id"]
        assert bid2 != bid
    pump(progressive, lambda db: db.get(Batch, fid2).status == "finalized" and db.get(ReportState, bid2).work.get("prepared"))
    with progressive() as db:
        assert db.get(ReportState, fid2).total == 0
        items = list(db.scalars(select(BatchItem).where(BatchItem.batch_id == bid2).order_by(BatchItem.id).limit(10)))
        submit_analysis(db, "cloud", bid2, [analysis(i.id) for i in items])
    pump(progressive, lambda db: db.scalar(select(func.count()).select_from(PublicationReceipt).where(
        PublicationReceipt.kind == "detail")) == 60)
    with progressive() as db:
        supplement = db.scalar(select(Publication).where(Publication.kind == "supplement", Publication.source_batch_id == bid2))
        assert supplement.parent_fact_id == fid and supplement.parent_fact_id != fid2
