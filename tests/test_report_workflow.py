import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select

from report_helpers import drain
from test_business import analysis
from vulintel.db import (Batch, BatchItem, Delivery, MetadataState, ReportState, Revision,
                         UnverifiedItem, Vulnerability, now, uid)
from vulintel.delivery import deliver_one
from vulintel.report_jobs import item_evidence, run_report_once
from vulintel.reports import report_dir
from vulintel.service import Overview, batch_page, due_slot, finalize, ingest, open_batch, submit_analysis
from vulintel.sources import entry, kev_record
from vulintel.timeline import BACKFILL_KEY, backfill_step, explicit_publication


@pytest.fixture
def cutoff(monkeypatch):
    value = datetime.fromisoformat(due_slot()).replace(tzinfo=None) - timedelta(hours=8)
    monkeypatch.setattr("vulintel.timeline.now", lambda: value - timedelta(seconds=1))
    return value


def seed(db, cutoff, name, age=1, **extra):
    value = entry(name, "漏洞 " + name, extra.pop("description", "公开事实"), [name],
                  ["https://example.org/advisory"], [{"product": "示例产品"}],
                  published=(cutoff - timedelta(days=age)).isoformat() + "Z" if age is not None else None,
                  **extra)
    identity = ingest(db, "nvd", value)
    db.commit()
    return identity


def test_publication_window_kev_update_unknown_and_legacy_archive(store, cutoff):
    with store() as db:
        legacy = Batch(id=uid(), slot="2026-01-01T09:00+08:00", cutoff=datetime(2026, 1, 1, 1), status="finalized")
        db.add(legacy)
        seed(db, cutoff, "CVE-2026-10001", age=1)
        seed(db, cutoff, "CVE-2026-10002", age=7)  # Exact lower boundary is included.
        seed(db, cutoff, "CVE-2026-10003", age=8)
        seed(db, cutoff, "CVE-2026-10004", age=None)
        seed(db, cutoff, "CVE-2020-10005", age=365)
        value = kev_record({"cveID": "CVE-2020-10005", "dateAdded": (cutoff - timedelta(days=1)).date().isoformat()})
        assert value["published"] is None
        ingest(db, "kev", value)
        db.commit()
        result = open_batch(db, "test")
        assert result["status"] == "preparing" and result["total"] is None
        early = batch_page(db, result["batch_id"])
        assert early["pending_analysis"] is None and early["ready"] is False
        assert open_batch(db, "test")["batch_id"] == result["batch_id"]
        drain(db, result["batch_id"], "analyzing")
        state = db.get(ReportState, result["batch_id"])
        assert (state.total, state.new_count, state.update_count, state.unknown_count) == (3, 2, 1, 1)
        assert db.scalar(select(func.count()).select_from(UnverifiedItem)) == 1
        assert db.get(Batch, legacy.id).status == "finalized"


def test_frozen_snapshot_paginated_evidence_and_all_items_required(store, cutoff):
    with store() as db:
        identity = seed(db, cutoff, "CVE-2026-10006", description="完整证据" * 200000, severity="low")
        result = open_batch(db, "test")
        drain(db, result["batch_id"], "analyzing")
        bid = result["batch_id"]
        page = batch_page(db, bid, pending_only=True)
        assert len(json.dumps(page, ensure_ascii=False).encode()) < 20000
        item_id = page["items"][0]["item_id"]
        fragments, offset = [], 0
        while True:
            part = item_evidence(db, bid, item_id, offset, 16000)
            assert len(part["text"]) <= 16000
            fragments.append(part["text"])
            if part["next_offset"] is None:
                break
            offset = part["next_offset"]
        original = json.loads("".join(fragments))
        assert len(original["description"]) == 4 * 200000
        with pytest.raises(ValueError):
            item_evidence(db, uid(), item_id)
        with pytest.raises(ValueError, match="需要完成逐条详解"):
            finalize(db, "test", bid)
        vuln = db.get(Vulnerability, identity)
        vuln.data = {**vuln.data, "description": "后来更改"}
        db.commit()
        assert db.get(BatchItem, item_id).snapshot["description"] == original["description"]
        value = analysis(item_id)
        value.vulnerability_summary = ""
        with pytest.raises(ValueError, match="中文漏洞说明"):
            submit_analysis(db, "test", bid, [value])


def test_render_checkpoint_replay_and_staged_delivery_gate(store, cutoff, monkeypatch):
    with store() as db:
        seed(db, cutoff, "CVE-2026-10007")
        seed(db, cutoff, "CVE-2026-10008", age=None)
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        submit_analysis(db, "test", bid, [analysis(item.id)])
        result = finalize(db, "test", bid, "EXECUTION-PROCESS-MUST-NOT-APPEAR",
                          Overview(risk_summary=["存在受影响版本时优先核对"], repair_priorities=["按照厂商版本修复"]))
        assert result["status"] == "rendering"
        assert db.scalar(select(func.count()).select_from(Delivery)) == 0
        # Inject a crash after file bytes are appended but before the checkpoint transaction commits.
        from vulintel import report_render
        original = report_render.append
        calls = []
        def fail_once(*args):
            original(*args)
            calls.append(True)
            if len(calls) == 4:
                raise RuntimeError("PRIVATE-EXCEPTION-DATA")
        monkeypatch.setattr(report_render, "append", fail_once)
        assert run_report_once()
        db.expire_all()
        assert db.get(Batch, bid).status == "failed"
        assert "PRIVATE" not in db.get(Batch, bid).error
        monkeypatch.setattr(report_render, "append", original)
        open_batch(db, "test")  # Resume the same durable batch.
        for _ in range(100):
            db.expire_all()
            if db.get(Batch, bid).status == "finalized":
                break
            # Global gate false; staged tasks would also be unselectable with the gate on.
            assert not deliver_one(db, sender=lambda row: pytest.fail("Partial publication sent"))
            db.commit()
            assert run_report_once()
        assert db.get(Batch, bid).status == "finalized"
        root = report_dir(bid)
        data = json.loads((root / "report.json").read_text(encoding="utf-8"))
        assert len(data["items"]) == 1 and len(data["unverified"]) == 1
        html = (root / "report.html").read_text(encoding="utf-8")
        assert "EXECUTION-PROCESS" not in html and "风险概览" in html and "日期待核实清单" in html
        assert html.count(f'id="item-{item.id}"') == 1
        assert "<pre" not in html
        assert all(row.status == "pending" for row in db.scalars(select(Delivery)))
        assert (root / "manifest.json").is_file()


def test_metadata_backfill_checkpoints_and_known_dates(store, cutoff):
    with store() as db:
        for number in range(7):
            db.add(Vulnerability(id=str(number), data=entry(str(number), "历史记录", "", published="2026-10-01T00:00:00Z"),
                                 title="历史记录", updated_at=cutoff - timedelta(seconds=1)))
        db.commit()
        assert not backfill_step(db, limit=2)
        db.commit()
        assert db.get(MetadataState, BACKFILL_KEY).value["processed"] == 2
        while not backfill_step(db, limit=2):
            db.commit()
        db.commit()
        assert db.scalar(select(func.count()).select_from(Revision)) == 7
        assert all(row.first_seen_at is None for row in db.scalars(select(Revision)))
        assert backfill_step(db)
        assert explicit_publication('<meta property="article:published_time" content="2026-10-21T00:00:00Z">', "apple", "")[0]
        assert explicit_publication('<p>Updated: October 22, 2026</p>', "apple", "")[0] is None


def test_ordinary_update_is_not_important_and_later_patch_is(store, cutoff, monkeypatch):
    with store() as db:
        identity = seed(db, cutoff, "CVE-2026-10009", age=30)
        initial = db.scalar(select(Revision).where(Revision.vulnerability_id == identity))
        assert initial.important_at is None
        value = entry("CVE-2026-10009", "漏洞 CVE-2026-10009", "公开事实", ["CVE-2026-10009"],
                      ["https://example.org/advisory"], [{"product": "示例产品"}],
                      published=(cutoff - timedelta(days=30)).isoformat() + "Z", modified="2026-10-23T00:00:00Z")
        before = db.scalar(select(func.count()).select_from(Revision))
        ingest(db, "nvd", value)
        db.commit()
        assert db.scalar(select(func.count()).select_from(Revision)) == before
        value["affected"] = [{"product": "示例产品", "versions": ["1.0", "1.1"]}]
        ingest(db, "nvd", value)
        db.commit()
        latest = db.scalar(select(Revision).order_by(Revision.id.desc()).limit(1))
        assert latest.important_at is not None
        assert latest.snapshot["timeline"]["published_at"] == initial.snapshot["timeline"]["published_at"]


def test_mcp_error_has_safe_tracking_id(store, caplog):
    import asyncio
    from mcp.server.mcpserver.exceptions import ToolError
    from vulintel.mcp_app import transaction
    def broken(db):
        raise ValueError("SMTP_PASSWORD=PRIVATE-SECRET")
    with pytest.raises(ToolError) as error:
        asyncio.run(transaction(broken))
    assert "追踪编号" in str(error.value) and "PRIVATE" not in str(error.value)
    assert "PRIVATE" not in caplog.text


def test_staged_tasks_do_not_send_even_when_gate_enabled(store, monkeypatch):
    from vulintel.config import settings
    monkeypatch.setenv("DELIVERY_ENABLED", "true")
    settings.cache_clear()
    with store() as db:
        batch = Batch(id=uid(), slot="2026-01-02T09:00+08:00", cutoff=now(), status="rendering")
        db.add(batch)
        db.flush()
        db.add(Delivery(batch_id=batch.id, channel="email", part=1, payload={}, status="staged"))
        db.commit()
        assert not deliver_one(db, sender=lambda row: pytest.fail("Staged message sent"))


def test_subsequent_reports_skip_duplicate_disclosures_and_include_new_material_changes(store, cutoff, monkeypatch):
    with store() as db:
        identity = seed(db, cutoff, "CVE-2026-10100")
        first = open_batch(db, "test")["batch_id"]
        drain(db, first, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == first))
        submit_analysis(db, "test", first, [analysis(item.id)])
        finalize(db, "test", first)
        drain(db, first, "finalized")
        next_cutoff = cutoff + timedelta(hours=9 if (cutoff + timedelta(hours=8)).hour == 9 else 15)
        monkeypatch.setattr("vulintel.report_jobs.now", lambda: next_cutoff + timedelta(seconds=1))
        monkeypatch.setattr("vulintel.timeline.now", lambda: next_cutoff - timedelta(seconds=1))
        # A second source describing the same CVE is not a new disclosure or substantive update.
        ingest(db, "ghsa", entry("GHSA-test-1111-2222", "重复来源", "同一漏洞", ["CVE-2026-10100"],
                                ["https://example.org/duplicate"], published=(cutoff - timedelta(days=1)).isoformat() + "Z"))
        db.commit()
        slot = (next_cutoff + timedelta(hours=8)).isoformat(timespec="minutes") + "+08:00"
        second = open_batch(db, "test", slot)["batch_id"]
        drain(db, second, "analyzing")
        assert db.get(ReportState, second).total == 0
        finalize(db, "test", second)
        drain(db, second, "finalized")
        third_cutoff = next_cutoff + timedelta(hours=9 if (next_cutoff + timedelta(hours=8)).hour == 9 else 15)
        monkeypatch.setattr("vulintel.report_jobs.now", lambda: third_cutoff + timedelta(seconds=1))
        monkeypatch.setattr("vulintel.timeline.now", lambda: third_cutoff - timedelta(seconds=1))
        value = entry("CVE-2026-10100", "漏洞 CVE-2026-10100", "公开事实", ["CVE-2026-10100"],
                      ["https://example.org/advisory"], [{"product": "示例产品", "versions": ["1.0"]}],
                      published=(cutoff - timedelta(days=1)).isoformat() + "Z")
        assert ingest(db, "nvd", value) == identity
        db.commit()
        slot = (third_cutoff + timedelta(hours=8)).isoformat(timespec="minutes") + "+08:00"
        third = open_batch(db, "test", slot)["batch_id"]
        drain(db, third, "analyzing")
        assert db.get(ReportState, third).update_count == 1
        assert db.get(ReportState, third).new_count == 0
        assert db.get(BatchItem, item.id).snapshot["title"] == "漏洞 CVE-2026-10100"


def test_additive_migration_keeps_old_archives_and_is_idempotent(store):
    from vulintel import db as database
    from vulintel.db import Migration, ReportBacklog, ReportCandidate, ReportSelection
    from sqlalchemy import delete
    with store() as db:
        old = Batch(id=uid(), slot="2000-01-01T09:00+08:00", cutoff=datetime(2000, 1, 1, 1), status="finalized", summary="旧报告")
        db.add(old)
        db.execute(delete(Migration).where(Migration.version >= 2))
        db.commit()
    with database.engine().begin() as conn:
        for table in [ReportCandidate, ReportBacklog, UnverifiedItem, ReportSelection, ReportState, Revision, MetadataState]:
            table.__table__.drop(conn)
    database.migrate()
    database.migrate()
    with store() as db:
        assert db.get(Batch, old.id).summary == "旧报告"
        assert db.scalar(select(func.count()).select_from(Migration)) == 3


def test_historical_kev_import_does_not_become_today_update(store, cutoff):
    with store() as db:
        identity = seed(db, cutoff, "CVE-2020-10101", age=365)
        ingest(db, "kev", kev_record({"cveID": "CVE-2020-10101", "dateAdded": "2020-01-01"}))
        db.commit()
        latest = db.scalar(select(Revision).where(Revision.vulnerability_id == identity).order_by(Revision.id.desc()).limit(1))
        assert latest.important_at == datetime(2020, 1, 1)
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        assert db.get(ReportState, bid).total == 0


def test_explicit_recent_vendor_remediation_date_enters_update_section(store, cutoff):
    with store() as db:
        identity = seed(db, cutoff, "CVE-2020-10102", age=365)
        value = entry("CVE-2020-10102", "厂商修复", "修复说明", ["CVE-2020-10102"],
                      ["https://example.org/vendor-patch"], remediations=[{"Date": (cutoff - timedelta(days=1)).isoformat() + "Z", "Description": "Vendor Fix"}])
        assert ingest(db, "msrc", value) == identity
        db.commit()
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        assert db.get(ReportState, bid).update_count == 1
        facts = db.scalar(select(BatchItem.snapshot).where(BatchItem.batch_id == bid))
        assert facts["timeline"]["change_basis"] == "修复／缓解发布时间"


def test_overview_refuses_execution_diagnostics():
    with pytest.raises(ValueError, match="执行诊断"):
        Overview(risk_summary=["pending_analysis=0，open_report_batch 调用成功"])


def test_date_only_is_not_displayed_as_an_invented_time(store, cutoff):
    from vulintel.report_content import label_time
    with store() as db:
        value = (cutoff - timedelta(days=1)).date().isoformat()
        ingest(db, "nvd", entry("CVE-2026-10103", "日期精度", "", ["CVE-2026-10103"], published=value))
        db.commit()
        data = db.scalar(select(Revision.snapshot))["timeline"]
        assert data["publication_precision"] == "day" and data["publication_original"] == value
        rendered = label_time(data["published_at"], data["publication_precision"])
        assert "仅到日" in rendered and "08:00" not in rendered


def test_product_group_uses_cpe_and_ecosystem_without_guessing():
    from vulintel.timeline import product_group
    assert product_group({"affected": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*"}]}]}]}) == "microsoft / windows 11"
    assert product_group({"affected": [{"package": {"ecosystem": "PyPI", "name": "django"}}]}) == "PyPI / django"


def test_analysis_budget_rejected_before_rendering(store, cutoff):
    with store() as db:
        seed(db, cutoff, "CVE-2026-10104")
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        value = analysis(item.id)
        for key in ["vulnerability_summary", "root_cause", "trigger_conditions", "impact", "affected_versions",
                    "attack_path", "remediation", "evidence_notes"]:
            setattr(value, key, "中" * 8000)
        with pytest.raises(ValueError, match="192000"):
            submit_analysis(db, "test", bid, [value])
        assert db.get(BatchItem, item.id).analysis is None


def test_short_staged_file_fails_closed(store):
    with store() as db:
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        finalize(db, "test", bid)
        for _ in range(20):
            db.expire_all()
            work = db.get(ReportState, bid).work.get("render", {})
            if work.get("phase") == "publish_files":
                first = sorted(work["offsets"])[0]
                (report_dir(bid) / (first + ".tmp")).write_bytes(b"")
                break
            db.commit()
            assert run_report_once()
        else:
            pytest.fail("Did not reach publication checkpoint")
        db.commit()
        run_report_once()
        db.expire_all()
        assert db.get(Batch, bid).status == "failed"
        assert all(row.status == "staged" for row in db.scalars(select(Delivery)))


def test_large_unknown_index_is_checkpointed_with_byte_budget(store, cutoff, monkeypatch):
    from vulintel.config import settings
    for key in ["SMTP_HOST", "SMTP_FROM", "SMTP_TO", "WEBHOOK_URL", "WEBHOOK_SECRET"]:
        monkeypatch.setenv(key, "")
    settings.cache_clear()
    with store() as db:
        seed(db, cutoff, "CVE-2026-10105", age=None)
        seed(db, cutoff, "CVE-2026-10106", age=None)
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        for row in db.scalars(select(UnverifiedItem)):
            row.title = "x" * 1_100_000
        db.commit()
        finalize(db, "test", bid)
        for _ in range(20):
            db.expire_all()
            if db.get(ReportState, bid).work.get("render", {}).get("phase") == "unknown":
                break
            db.commit()
            run_report_once()
        else:
            pytest.fail("Did not reach unknown-date stage")
        db.commit()
        run_report_once()
        db.expire_all()
        assert db.get(ReportState, bid).work["render"]["unknown_written"] == 1
        drain(db, bid, "finalized")
        data = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
        assert len(data["unverified"]) == 2 and len(data["unverified"][1]["title"]) == 1_100_000


def test_finalize_retry_preserves_committed_render_checkpoints(store, cutoff, monkeypatch):
    from vulintel import report_render
    with store() as db:
        seed(db, cutoff, "CVE-2026-10107")
        bid = open_batch(db, "test")["batch_id"]
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid, overview=Overview(risk_summary=["保留原始风险摘要"]))
        run_report_once()  # Details and file offsets are committed.
        db.expire_all()
        checkpoint = db.get(ReportState, bid).work["render"]
        original = report_render.render_step
        def fail(*args):
            raise RuntimeError("injected rendering failure")
        monkeypatch.setattr(report_render, "render_step", fail)
        run_report_once()
        db.expire_all()
        assert db.get(Batch, bid).status == "failed"
        finalize(db, "test", bid, overview=Overview(risk_summary=["不能覆盖冻结摘要"]))
        assert db.get(ReportState, bid).work["render"] == checkpoint
        assert db.get(ReportState, bid).overview["risk_summary"] == ["保留原始风险摘要"]
        monkeypatch.setattr(report_render, "render_step", original)
        drain(db, bid, "finalized")
        data = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
        assert len(data["items"]) == 1
