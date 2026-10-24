import copy
import json
from datetime import datetime, timedelta

import pytest
from sqlalchemy import func, select, text

from report_helpers import drain
from test_business import analysis
from vulintel import maintenance
from vulintel.config import settings
from vulintel.db import (Alias, Batch, BatchItem, Delivery, Job, MetadataState, ReportBacklog, ReportCandidate, ReportSelection,
                         ReportState, Revision, Source, SourceRecord, UnverifiedItem, Vulnerability, uid)
from vulintel.delivery import deliver_one
from vulintel.report_jobs import batch_page, finalize, item_evidence, open_batch, run_report_once, status
from vulintel.reports import report_dir
from vulintel.service import ingest, submit_analysis
from vulintel.sources import entry
from vulintel.timeline import BACKFILL_KEY, EVENT_POLICY

CUTOFF = datetime(2026, 10, 1, 10)


def seed(db, name="CVE-2026-10001", **extra):
    return ingest(db, "nvd", entry(name, "测试漏洞 " + name, "完整公开事实", [name],
                  ["https://example.org/advisory"], published="2026-09-30T00:00:00Z", **extra))


def freeze_time(monkeypatch):
    monkeypatch.setattr("vulintel.timeline.now", lambda: CUTOFF - timedelta(seconds=1))
    monkeypatch.setattr("vulintel.report_jobs.now", lambda: CUTOFF + timedelta(days=20))


def finish(db, bid):
    items = list(db.scalars(select(BatchItem).where(BatchItem.batch_id == bid).order_by(BatchItem.id)))
    for item in items:
        pieces, offset = [], 0
        while True:
            part = item_evidence(db, bid, item.id, offset, 97)
            pieces.append(part["text"])
            if part["next_offset"] is None:
                break
            offset = part["next_offset"]
        assert json.loads("".join(pieces)) == item.snapshot
    for start in range(0, len(items), 3):
        submit_analysis(db, "test", bid, [analysis(item.id) for item in items[start:start + 3]])
    finalize(db, "test", bid)
    drain(db, bid, "finalized")
    return items


def test_full_repair_clears_reports_keeps_facts_and_is_idempotent(store, monkeypatch):
    freeze_time(monkeypatch)
    with store() as db:
        db.execute(text("PRAGMA foreign_keys=ON"))
        identity = seed(db)
        db.commit()
        bid = open_batch(db, "test", "2026-10-01T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        finish(db, bid)
        archive = report_dir(bid)
        assert archive.exists()
        source_count = db.scalar(select(func.count()).select_from(SourceRecord))
        sources = db.scalar(select(func.count()).select_from(Source))
    result = maintenance.run_repair(emit=lambda _: None)
    assert result["complete"] and result["phase"] == "complete"
    assert not archive.exists()
    with store() as db:
        for model in [Batch, BatchItem, ReportSelection, ReportState, Delivery, UnverifiedItem, ReportBacklog, ReportCandidate]:
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.scalar(select(func.count()).select_from(SourceRecord)) == source_count
        assert db.scalar(select(func.count()).select_from(Source)) == sources
        assert db.get(Vulnerability, identity)
        assert db.get(Job, result["job_id"]).status == "done"
        fresh = Batch(id=uid(), slot="2026-10-02T18:00+08:00", cutoff=CUTOFF + timedelta(days=1))
        db.add(fresh)
        db.commit()
        fresh_id = fresh.id
    assert maintenance.run_repair(emit=lambda _: None)["complete"]
    with store() as db:
        assert db.get(Batch, fresh_id)
        assert db.scalar(select(func.count()).select_from(Job).where(Job.kind == "maintenance")) == 1


@pytest.mark.parametrize("phase", ["cleanup", "aliases", "events", "validation"])
def test_interrupt_each_phase_and_resume(store, monkeypatch, phase):
    freeze_time(monkeypatch)
    with store() as db:
        seed(db)
        db.commit()
    def interrupt(line):
        if json.loads(line)["phase"] == phase:
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        maintenance.run_repair(emit=interrupt)
    with store() as db:
        state = maintenance.progress(db)
        assert state["status"] == "failed" and not state["complete"]
        assert maintenance.active(db)
        with pytest.raises(ValueError, match="历史数据维护"):
            open_batch(db, "test", "2026-10-01T18:00+08:00")
        db.rollback()
        with pytest.raises(ValueError, match="历史数据维护"):
            submit_analysis(db, "test", uid(), [])
        db.rollback()
        with pytest.raises(ValueError, match="历史数据维护"):
            finalize(db, "test", uid())
        db.rollback()
        assert not deliver_one(db, sender=lambda _: pytest.fail("Must not send"))
        assert not run_report_once()
    assert maintenance.run_repair(emit=lambda _: None)["complete"]
    with store() as db:
        assert "error" not in maintenance.progress(db)


def test_file_cleanup_failure_retains_target_and_retries(store, monkeypatch):
    with store() as db:
        bid = uid()
        db.add(Batch(id=bid, slot="2026-10-01T18:00+08:00", cutoff=CUTOFF))
        db.commit()
    root = report_dir(bid)
    root.mkdir(parents=True)
    (root / "report.json").write_text("{}")
    original = maintenance.shutil.rmtree
    monkeypatch.setattr(maintenance.shutil, "rmtree", lambda _: (_ for _ in ()).throw(OSError("file busy")))
    with pytest.raises(OSError):
        maintenance.run_repair(emit=lambda _: None)
    with store() as db:
        assert db.get(Batch, bid)
        assert db.get(MetadataState, maintenance.KEY).value["cleanup_index"] == 0
    monkeypatch.setattr(maintenance.shutil, "rmtree", original)
    assert maintenance.run_repair(emit=lambda _: None)["complete"]
    assert not root.exists()


def test_repair_continues_after_one_thousand_steps(store, monkeypatch):
    calls = 0
    def sliced(db):
        nonlocal calls
        calls += 1
        state = db.get(MetadataState, BACKFILL_KEY)
        if state is None:
            state = MetadataState(key=BACKFILL_KEY)
            db.add(state)
        state.value = {"phase": "events", "processed": calls, "complete": calls > 1000}
        return calls > 1000
    monkeypatch.setattr(maintenance, "backfill_step", sliced)
    assert maintenance.run_repair(emit=lambda _: None)["complete"]
    assert calls == 1001


def test_duplicate_process_lock_and_stale_heartbeat(store):
    with maintenance.repair_owner():
        with pytest.raises(ValueError, match="运行锁"):
            with maintenance.repair_owner():
                pass
    with store() as db:
        row = maintenance.start(db)
        job = db.get(Job, row.value["job_id"])
        job.lease_until = datetime(2000, 1, 1)
        db.commit()
        assert maintenance.progress(db)["status"] == "interrupted"


def test_120_candidates_are_50_50_20_and_survive_window_with_mock_delivery(store, monkeypatch):
    freeze_time(monkeypatch)
    with store() as db:
        priority_id = None
        for index in range(120):
            identity = seed(db, f"CVE-2026-{10000 + index}", severity="critical" if index == 119 else "low",
                            exploited=index == 119)
            if index == 119:
                priority_id = identity
        db.commit()
        seen = set()
        for offset, expected in [(0, 50), (8, 50), (9, 20)]:
            slot = (CUTOFF + timedelta(days=offset, hours=8)).isoformat(timespec="minutes") + "+08:00"
            bid = open_batch(db, "test", slot)["batch_id"]
            drain(db, bid, "analyzing")
            current = status(db, db.get(Batch, bid))
            assert current["total"] == expected and current["item_limit"] == 50
            assert current["candidate_total"] == 120 - len(seen)
            assert current["backlog_selected"] == (expected if offset else 0)
            if not offset:
                assert priority_id in db.scalars(select(BatchItem.vulnerability_id).where(BatchItem.batch_id == bid))
            with pytest.raises(ValueError, match="需要完成逐条详解"):
                finalize(db, "test", bid)
            items = finish(db, bid)
            identities = {item.vulnerability_id for item in items}
            assert not seen & identities
            seen |= identities
            assert db.scalar(select(func.count()).select_from(ReportBacklog)) == 120 - len(seen)
            data = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
            assert data["item_limit"] == 50 and data["deferred_count"] == 120 - len(seen)
            md = (report_dir(bid) / "report.md").read_text(encoding="utf-8")
            assert "持久待报" in md
            if offset:
                assert "积压补报（首次公开）" in md
        assert len(seen) == 120
        monkeypatch.setenv("DELIVERY_ENABLED", "true")
        settings.cache_clear()
        sent = []
        while deliver_one(db, sender=lambda delivery: sent.append((delivery.channel, delivery.part))):
            pass
        assert {channel for channel, _ in sent} == {"email", "webhook"}
        assert all(row.status == "sent" for row in db.scalars(select(Delivery)))


def test_evidence_update_after_freeze_remains_pending_and_limit_is_frozen(store, monkeypatch):
    freeze_time(monkeypatch)
    with store() as db:
        identity = seed(db, affected=[{"product": "P", "versions": ["1"]}])
        db.commit()
        bid = open_batch(db, "test", "2026-10-01T18:00+08:00")["batch_id"]
        monkeypatch.setenv("REPORT_MAX_ITEMS", "1")
        settings.cache_clear()
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        original = copy.deepcopy(item.snapshot)
        monkeypatch.setattr("vulintel.timeline.now", lambda: CUTOFF + timedelta(hours=1))
        seed(db, affected=[{"product": "P", "versions": ["1", "2"]}])
        db.commit()
        new_id = db.get(ReportBacklog, identity).revision_id
        assert status(db, db.get(Batch, bid))["item_limit"] == 50
        assert item.snapshot == original
        finish(db, bid)
        candidate = db.get(ReportBacklog, identity)
        assert candidate.revision_id == new_id and candidate.category == "update"
        next_bid = open_batch(db, "test", "2026-10-02T18:00+08:00")["batch_id"]
        drain(db, next_bid, "analyzing")
        assert batch_page(db, next_bid)["total"] == 1
        assert batch_page(db, next_bid)["items"][0]["snapshot"]["report_category"] == "update"


def test_repair_merges_old_sources_without_today_event_and_ignores_v3_checkpoint(store, monkeypatch):
    freeze_time(monkeypatch)
    with store() as db:
        canonical = seed(db, "CVE-2020-12345")
        facts = entry("DEBIAN-CVE-2020-12345", "发行版记录", "", ["DEBIAN-CVE-2020-12345"],
                      published="2026-10-01T00:00:00Z")
        db.add(Vulnerability(id="legacy", data={**facts, "source_records": [{"source": "osv-debian", **facts}]},
                             title=facts["title"], updated_at=CUTOFF - timedelta(days=1)))
        db.flush()
        db.add(Alias(alias=facts["source_key"], vulnerability_id="legacy"))
        db.add(SourceRecord(source_id="osv-debian", source_key=facts["source_key"], vulnerability_id="legacy",
                            data=facts, fingerprint="legacy"))
        db.add(MetadataState(key="source_event_backfill_v3", value={"complete": True, "processed": 99999}))
        db.commit()
        old_updated = db.get(Vulnerability, canonical).updated_at
    result = maintenance.run_repair(emit=lambda _: None)
    assert result["complete"]
    with store() as db:
        canonical = db.get(Alias, "CVE-2020-12345").vulnerability_id
        revision = db.scalar(select(Revision).where(Revision.vulnerability_id == canonical)
                             .order_by(Revision.id.desc()).limit(1))
        assert len(revision.snapshot["source_records"]) == 2
        assert revision.important_at is None
        assert revision.snapshot["timeline"]["event_policy"] == EVENT_POLICY
        assert db.get(Vulnerability, canonical).updated_at == old_updated
        assert db.get(MetadataState, BACKFILL_KEY).value["complete"]


def test_prepare_freezes_candidate_even_if_new_evidence_arrives_before_select(store, monkeypatch):
    freeze_time(monkeypatch)
    with store() as db:
        identity = seed(db, affected=[{"product": "P", "versions": ["1"]}])
        db.commit()
        bid = open_batch(db, "test", "2026-10-01T18:00+08:00")["batch_id"]
        for _ in range(50):
            db.expire_all()
            if db.get(ReportState, bid).work["phase"] == "select":
                break
            db.commit()
            assert run_report_once()
        else:
            pytest.fail("Did not reach selection")
        frozen = db.scalar(select(ReportCandidate).where(ReportCandidate.batch_id == bid))
        frozen_id = frozen.revision_id
        monkeypatch.setattr("vulintel.timeline.now", lambda: CUTOFF + timedelta(hours=1))
        seed(db, affected=[{"product": "P", "versions": ["1", "2"]}])
        db.commit()
        new_id = db.get(ReportBacklog, identity).revision_id
        assert new_id > frozen_id
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        assert item.snapshot["affected"] == [{"product": "P", "versions": ["1"]}]
        assert db.get(ReportSelection, item.id).revision_id == frozen_id
        finish(db, bid)
        assert db.get(ReportBacklog, identity).revision_id == new_id


def test_unknown_date_stays_unverified_after_pending_evidence_is_corrected(store, monkeypatch):
    freeze_time(monkeypatch)
    monkeypatch.setenv("REPORT_MAX_ITEMS", "1")
    settings.cache_clear()
    with store() as db:
        seed(db, "CVE-2026-10101", severity="critical")
        identity = seed(db, "CVE-2026-10102", severity="low")
        db.commit()
        bid = open_batch(db, "test", "2026-10-01T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        finish(db, bid)
        value = entry("CVE-2026-10102", "日期被撤回", "未确认公开日期", ["CVE-2026-10102"],
                      ["https://example.org/advisory"], published=None)
        ingest(db, "nvd", value)
        db.commit()
        bid = open_batch(db, "test", "2026-10-02T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        current = status(db, db.get(Batch, bid))
        assert current["total"] == 0 and current["unverified_dates"] == 1
        assert db.get(ReportBacklog, identity)
        finish(db, bid)


def test_render_failure_does_not_acknowledge_backlog(store, monkeypatch):
    from vulintel import report_render
    freeze_time(monkeypatch)
    with store() as db:
        identity = seed(db)
        db.commit()
        bid = open_batch(db, "test", "2026-10-01T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid)
        original = report_render.render_step
        def fail(*_):
            raise OSError("simulated file failure")
        monkeypatch.setattr(report_render, "render_step", fail)
        assert run_report_once()
        db.expire_all()
        assert db.get(Batch, bid).status == "failed"
        assert db.get(ReportBacklog, identity)
        monkeypatch.setattr(report_render, "render_step", original)
        finalize(db, "test", bid)
        drain(db, bid, "finalized")
        assert db.get(ReportBacklog, identity) is None


def test_cli_runs_to_complete_and_requires_clear_flag(store, monkeypatch, capsys):
    import signal
    import sys
    from vulintel.cli import main
    monkeypatch.setattr(signal, "signal", lambda *_: None)
    monkeypatch.setattr(sys, "argv", ["vulintel", "repair-history"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2
    monkeypatch.setattr(sys, "argv", ["vulintel", "repair-history", "--clear-reports"])
    main()
    lines = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert lines[-1]["complete"] and lines[-1]["phase"] == "complete"
    assert "targets" not in lines[-1]


def test_backlog_canonical_merge_preserves_pending_candidate(store, monkeypatch):
    freeze_time(monkeypatch)
    with store() as db:
        first = seed(db)
        second = ingest(db, "ghsa", entry("GHSA-test", "另一条来源", "", ["GHSA-TEST"],
                        published="2026-09-30T00:00:00Z"))
        db.commit()
        for identity in [first, second]:
            revision = db.scalar(select(Revision).where(Revision.vulnerability_id == identity))
            db.add(ReportBacklog(vulnerability_id=identity, revision_id=revision.id, category="new", rank=0,
                                 first_eligible_at=CUTOFF))
        db.commit()
        canonical = ingest(db, "ghsa", entry("GHSA-test", "来源合并", "", ["GHSA-TEST", "CVE-2026-10001"],
                           published="2026-09-30T00:00:00Z"))
        db.commit()
        rows = list(db.scalars(select(ReportBacklog)))
        assert len(rows) == 1 and rows[0].vulnerability_id == canonical
        assert db.get(Revision, rows[0].revision_id).vulnerability_id == canonical


def test_maintenance_task_page_shows_interruption_and_progress(store):
    from starlette.testclient import TestClient
    from vulintel.app import create_app
    from vulintel.auth import token_hash
    from vulintel.db import WebSession, now
    with store() as db:
        row = maintenance.start(db)
        db.get(Job, row.value["job_id"]).lease_until = datetime(2000, 1, 1)
        db.add(WebSession(id=token_hash("test-cookie"), subject="admin", csrf="test-csrf",
                          expires=now() + timedelta(minutes=5)))
        db.commit()
    with TestClient(create_app(), base_url="https://vul.valna.cn") as client:
        response = client.get("/admin/tasks", headers={"Cookie": "vul_session=test-cookie"})
        assert response.status_code == 200
        assert "历史数据修复" in response.text and "清理旧报告" in response.text
        assert "已中断／等待恢复" in response.text
        assert "repair-history --clear-reports" in response.text


def test_validation_failure_never_marks_complete(store, monkeypatch):
    original = maintenance.validate_step
    def fail(*_):
        raise ValueError("simulated validation failure")
    monkeypatch.setattr(maintenance, "validate_step", fail)
    with pytest.raises(ValueError, match="validation failure"):
        maintenance.run_repair(emit=lambda _: None)
    with store() as db:
        value = maintenance.progress(db)
        assert not value["complete"] and value["phase"] == "validation" and value["status"] == "failed"
    monkeypatch.setattr(maintenance, "validate_step", original)
    assert maintenance.run_repair(emit=lambda _: None)["complete"]


def test_authoritative_older_publication_invalidates_false_new_backlog(store, monkeypatch):
    freeze_time(monkeypatch)
    monkeypatch.setenv("REPORT_MAX_ITEMS", "1")
    settings.cache_clear()
    with store() as db:
        seed(db, "CVE-2026-10101", severity="critical")
        identity = seed(db, "CVE-2026-10102", severity="low")
        db.commit()
        bid = open_batch(db, "test", "2026-10-01T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        finish(db, bid)
        value = entry("CVE-2026-10102", "公开日期校正", "实际早于本周", ["CVE-2026-10102"],
                      ["https://example.org/advisory"], published="2020-01-01T00:00:00Z", severity="low")
        ingest(db, "nvd", value)
        db.commit()
        bid = open_batch(db, "test", "2026-10-02T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        assert status(db, db.get(Batch, bid))["total"] == 0
        assert db.get(ReportBacklog, identity) is None
