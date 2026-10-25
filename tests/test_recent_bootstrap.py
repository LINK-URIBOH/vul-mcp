import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import httpx
import pytest
from sqlalchemy import func, select, text

from report_helpers import drain
from test_business import analysis, record
from vulintel import db as database
from vulintel.collector import CollectorHTTP
from vulintel.config import settings
from vulintel.date_enrichment import fetch_cached, fetch_group
from vulintel.db import (Audit, Batch, BatchItem, DateEvidenceCache, Delivery, Job, LoginFlow, MetadataState,
                         PublicationState, RecentCandidate, RecentSource, ReportState, Revision, Source,
                         Vulnerability, WebSession, uid)
from vulintel.maintenance import active, repair_owner, report_write_guard
from vulintel.publication import cache_key
from vulintel.recent import discover_once, offer, progress, verify_once
from vulintel.recent_reset import KEY, run_reset, tables
from vulintel.report_jobs import finalize, item_evidence, open_batch, status
from vulintel.reports import report_dir
from vulintel.service import ingest, source_status, submit_analysis
from vulintel.sources import nvd_record

START = datetime(2026, 10, 25, 2)
CVE = "CVE-2026-12345"
API = "https://cveawg.mitre.org/api/cve/" + CVE
ORIGINAL_PAUSE = CollectorHTTP.pause


@pytest.fixture
def clock(store, monkeypatch):
    state = [START]
    for module in ["recent_reset", "recent", "publication", "date_enrichment", "service", "timeline", "report_jobs", "maintenance"]:
        monkeypatch.setattr("vulintel." + module + ".now", lambda: state[0])
    monkeypatch.setattr("vulintel.date_enrichment._last_request", 0)
    monkeypatch.setattr("vulintel.recent._last_touch", 0)
    monkeypatch.setattr(CollectorHTTP, "pause", lambda *_: None)
    monkeypatch.setenv("PUBLICATION_REQUEST_INTERVAL", "0.1")
    settings.cache_clear()
    return state


def enable(store, *ids):
    with store() as db:
        for source in db.scalars(select(Source)):
            source.enabled = source.id in ids
        db.commit()


def payload(cve=CVE, published="2026-10-24T00:00:00Z", **extra):
    return nvd_record({"id": cve, "published": published, "references": [], **extra})


def cna(disclosed="2026-10-24T00:00:00Z", cve=CVE):
    return {"cveMetadata": {"cveId": cve, "state": "PUBLISHED", "datePublished": "2026-10-24T12:00:00Z"},
            "containers": {"cna": {"datePublic": disclosed, "references": []}}}


def stage(store, source_id="nvd"):
    with store() as db:
        return db.scalar(select(RecentSource).where(RecentSource.source_id == source_id))


def stage_record(store, value, source_id="nvd", initial=True):
    with store() as db:
        state = db.scalar(select(RecentSource).where(RecentSource.source_id == source_id))
        state.initial = initial
        if not initial:
            state.end_at = START + timedelta(hours=1)
        offer(db, state, value)
        db.commit()


def verify_all(transport, limit=40):
    for _ in range(limit):
        if not verify_once(transport=transport):
            return
    pytest.fail("candidate verification did not reach a saved terminal state")


def test_reset_cleans_foreign_keys_preserves_auth_configuration_cache_and_audit(store, clock):
    enable(store, "nvd")
    with store() as db:
        db.execute(text("PRAGMA foreign_keys=ON"))
        db.commit()
        identity = ingest(db, "nvd", record())
        batch = Batch(id=uid(), slot="2026-10-24T18:00+08:00", cutoff=START, status="finalized")
        db.add(batch)
        db.flush()
        db.add(BatchItem(batch_id=batch.id, vulnerability_id=identity, snapshot={"title": "old"}, priority=True))
        db.add(Delivery(batch_id=batch.id, channel="webhook", payload={}, status="sent"))
        db.add(ReportState(batch_id=batch.id))
        db.add(WebSession(id="session", subject="admin", csrf="csrf", expires=START + timedelta(days=1)))
        db.add(LoginFlow(state="login", verifier="v", nonce="n", expires=START + timedelta(days=1)))
        db.add(DateEvidenceCache(key=cache_key(API), url=API, status="ok", data={"evidence": []}, retry_at=START + timedelta(days=7)))
        old_job = Job(kind="maintenance", source_id="publication_date_repair_v1", status="running")
        db.add(old_job)
        db.flush()
        db.add(MetadataState(key="publication_date_repair_v1", value={"job_id": old_job.id, "complete": False}))
        db.commit()
        old_job_id = old_job.id
        root = report_dir(batch.id)
        root.mkdir(parents=True)
        (root / "report.json").write_text("old", encoding="utf-8")
    result = run_reset(emit=lambda _: None)
    assert result["complete"] and result["window_end"] == "2026-10-25T02:00:00Z"
    assert not root.exists()
    with store() as db:
        for model in tables():
            if model is RecentSource:
                continue
            assert db.scalar(select(func.count()).select_from(model)) == 0
        assert db.get(WebSession, "session") and db.get(LoginFlow, "login")
        assert db.get(DateEvidenceCache, cache_key(API)).status == "ok"
        assert db.get(Job, old_job_id).status == "superseded"
        assert not active(db)
        assert db.get(Source, "nvd").enabled and not db.get(Source, "ghsa").enabled
        assert db.scalar(select(func.count()).select_from(Audit)) > 0
        assert db.scalar(select(Job).where(Job.kind == "bootstrap")).status == "pending"


@pytest.mark.parametrize("phase", ["cleanup", "tables", "validation"])
def test_reset_interruption_resumes_same_frozen_window_and_noop_preserves_new_data(store, clock, phase):
    enable(store, "nvd")
    with store() as db:
        db.add(Batch(id=uid(), slot="2026-10-24T18:00+08:00", cutoff=START))
        db.commit()
    def interrupt(line):
        if json.loads(line)["phase"] == phase:
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        run_reset(emit=interrupt)
    with store() as db:
        saved = db.get(MetadataState, KEY).value
        assert not saved["complete"] and active(db)
        with pytest.raises(ValueError, match="近七天重置"):
            report_write_guard(db)
    clock[0] += timedelta(hours=2)
    result = run_reset(emit=lambda _: None)
    assert result["window_end"] == saved["window_end"] and result["run_id"] == saved["run_id"]
    with store() as db:
        identity = ingest(db, "nvd", record())
        db.commit()
    assert run_reset(emit=lambda _: None)["run_id"] == result["run_id"]
    with store() as db:
        assert db.get(Vulnerability, identity)
    assert run_reset(new_run=True, emit=lambda _: None)["run_id"] != result["run_id"]


def test_reset_requires_owner_lock_and_file_failure_does_not_advance(store, clock, monkeypatch):
    with repair_owner():
        with pytest.raises(ValueError, match="持有运行锁"):
            run_reset(emit=lambda _: None)
    with store() as db:
        batch = Batch(id=uid(), slot="2026-10-24T18:00+08:00", cutoff=START)
        db.add(batch)
        db.commit()
        root = report_dir(batch.id)
        root.mkdir(parents=True)
    original = __import__("shutil").rmtree
    monkeypatch.setattr("vulintel.recent_reset.shutil.rmtree", lambda *_: (_ for _ in ()).throw(OSError("injected")))
    with pytest.raises(OSError):
        run_reset(emit=lambda _: None)
    with store() as db:
        assert db.get(MetadataState, KEY).value["cleanup_index"] == 0
        assert db.get(Batch, batch.id)
    monkeypatch.setattr("vulintel.recent_reset.shutil.rmtree", original)
    assert run_reset(emit=lambda _: None)["complete"]


def test_nvd_publication_query_does_not_download_80000_modified_old_records(store, clock):
    enable(store, "nvd", "osv-pypi")
    run_reset(emit=lambda _: None)
    calls = []
    def respond(request):
        calls.append(str(request.url))
        assert "pubStartDate" in request.url.params and "lastModStartDate" not in request.url.params
        assert "modified_id.csv" not in str(request.url)
        assert request.url.params["pubStartDate"] == "2026-10-18T02:00:00Z"
        if "lastModStartDate" in request.url.params:
            return httpx.Response(200, json={"totalResults": 80000, "vulnerabilities": []})
        return httpx.Response(200, json={"totalResults": 1, "vulnerabilities": [
            {"cve": {"id": CVE, "published": "2026-10-24T00:00:00Z"}}]})
    assert discover_once(transport=httpx.MockTransport(respond))
    with store() as db:
        assert db.scalar(select(func.count()).select_from(RecentCandidate)) == 1
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0
        state = progress(db)
        assert state["scan_complete"] and state["pending"] == 1
        limited = next(item for item in source_status(db) if item["id"] == "osv-pypi")
        assert limited["coverage_limited"] and not limited["stale"] and not limited["error"]
    assert len(calls) == 1


def test_discovery_resume_keeps_page_offset_and_deduplicates(store, clock):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    offsets = []
    def respond(request):
        offset = int(request.url.params["startIndex"])
        offsets.append(offset)
        return httpx.Response(200, json={"totalResults": 2, "vulnerabilities": [{"cve": {
            "id": CVE if offset == 0 else "CVE-2026-12346", "published": "2026-10-24T00:00:00Z"}}]})
    assert discover_once(transport=httpx.MockTransport(respond))
    assert discover_once(transport=httpx.MockTransport(respond))
    assert offsets == [0, 1]
    with store() as db:
        assert db.scalar(select(func.count()).select_from(RecentCandidate)) == 2
        assert progress(db)["scan_complete"]


@pytest.mark.parametrize("disclosed,status_name,count", [("2026-10-24T00:00:00Z", "admitted", 1),
                                                        ("2020-01-01T00:00:00Z", "excluded", 0),
                                                        (None, "unverified", 0)])
def test_candidates_only_admitted_after_disclosure_evidence(store, clock, disclosed, status_name, count):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    stage_record(store, payload())
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna(disclosed))))
    with store() as db:
        candidate = db.scalar(select(RecentCandidate))
        assert candidate.status == status_name
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == count
        assert not active(db)
        if count:
            assert db.scalar(select(Revision)).observed_at == START
        else:
            assert candidate.reason


def test_conflict_and_day_boundary_remain_staged_without_false_new(store, clock):
    enable(store, "nvd", "ghsa")
    run_reset(emit=lambda _: None)
    item = payload()
    item.update(disclosed_at="2026-10-24T00:00:00Z", disclosure_reference="https://support.apple.com/advisory")
    stage_record(store, item)
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna("2020-01-01T00:00:00Z"))))
    with store() as db:
        assert db.scalar(select(RecentCandidate)).status == "conflict"
    stage_record(store, {"source_key": "GHSA-aaaa-bbbb-cccc", "title": "day", "aliases": [],
                 "published": "2026-10-18", "references": ["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"]}, "ghsa")
    verify_all(httpx.MockTransport(lambda _: httpx.Response(404)))
    with store() as db:
        candidate = db.scalar(select(RecentCandidate).where(RecentCandidate.source_id == "ghsa"))
        assert candidate.status == "unverified" and "精度" in candidate.reason
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0


def test_old_entry_is_excluded_before_any_http_and_initial_patch_does_not_import_it(store, clock):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    old = payload(published="2020-01-01T00:00:00Z")
    old.update(remediations=[{"Date": "2026-10-24T00:00:00Z", "URL": "https://support.apple.com/fix"}])
    stage_record(store, old)
    assert not verify_once(transport=httpx.MockTransport(lambda _: pytest.fail("old row fetched")))
    with store() as db:
        assert db.scalar(select(RecentCandidate)).status == "excluded"
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0


def test_later_old_vulnerability_with_dated_patch_is_admitted_as_update(store, clock):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    old = payload(published="2020-01-01T00:00:00Z")
    old.update(remediations=[{"Date": "2026-10-25T02:30:00Z", "URL": "https://support.apple.com/fix"}])
    clock[0] += timedelta(hours=1)
    stage_record(store, old, initial=False)
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna("2020-01-01T00:00:00Z"))))
    with store() as db:
        assert db.scalar(select(RecentCandidate)).status == "admitted"
        revision = db.scalar(select(Revision))
        assert revision.important_at == datetime(2026, 10, 25, 2, 30)
        assert revision.published_at is None  # Raw NVD facts do not claim a disclosure date.
        assert db.scalar(select(PublicationState)).start_at == datetime(2020, 1, 1)
        clock[0] = datetime(2026, 10, 25, 11)
        bid = open_batch(db, "test", "2026-10-25T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        report = status(db, db.get(Batch, bid))
        assert report["new_disclosures"] == 0 and report["important_updates"] == 1


def test_recent_flow_reads_full_evidence_exports_and_confirms_mock_channels(store, clock, monkeypatch):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    stage_record(store, payload())
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna())))
    clock[0] = datetime(2026, 10, 25, 11)
    with store() as db:
        bid = open_batch(db, "test", "2026-10-25T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        assert status(db, db.get(Batch, bid))["total"] == 1
        item = db.scalar(select(BatchItem))
        pieces, offset = [], 0
        while True:
            page = item_evidence(db, bid, item.id, offset, 64)
            pieces.append(page["text"])
            if page["next_offset"] is None:
                break
            offset = page["next_offset"]
        assert json.loads("".join(pieces)) == item.snapshot
        submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid)
        drain(db, bid, "finalized")
        archive = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
        assert archive["bootstrap"]["verified_candidates"] == 1
        monkeypatch.setenv("DELIVERY_ENABLED", "true")
        settings.cache_clear()
        from vulintel.delivery import deliver_one
        sent = []
        while deliver_one(db, sender=lambda row: sent.append(row.channel)):
            db.commit()
        assert set(sent) == {"email", "webhook"}
        assert all(row.status == "sent" for row in db.scalars(select(Delivery)))


def test_evidence_singleflight_and_max_four_network_requests(store, clock):
    release, guard = threading.Event(), threading.Lock()
    active_count, peak, calls = 0, 0, []
    def respond(request):
        nonlocal active_count, peak
        with guard:
            active_count += 1
            peak = max(peak, active_count)
            calls.append(str(request.url))
            if active_count == 4:
                release.set()
        release.wait(timeout=1)
        with guard:
            active_count -= 1
        return httpx.Response(200, text="No date metadata")
    urls = [("https://support.apple.com/advisory-" + str(index), None) for index in range(8)]
    fetch_group(urls, transport=httpx.MockTransport(respond))
    assert peak == 4 and len(calls) == 8
    calls.clear()
    def one(request):
        calls.append(str(request.url))
        time.sleep(0.1)
        return httpx.Response(200, text="No date metadata")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: fetch_cached("https://support.apple.com/shared", transport=httpx.MockTransport(one)), range(8)))
    assert len(calls) == 1 and all(item == results[0] for item in results)


def test_shared_request_limiter_spaces_parallel_requests(store, clock, monkeypatch):
    monkeypatch.setattr(CollectorHTTP, "pause", ORIGINAL_PAUSE)
    times = []
    def respond(_):
        times.append(time.monotonic())
        return httpx.Response(200, text="No date metadata")
    fetch_group([("https://support.apple.com/limited-" + str(i), None) for i in range(4)], transport=httpx.MockTransport(respond))
    assert len(times) == 4
    assert min(right - left for left, right in zip(sorted(times), sorted(times)[1:])) >= 0.08


def test_schema_upgrade_preserves_existing_dates_and_new_tables(store):
    from vulintel.db import Migration
    with store() as db:
        ingest(db, "nvd", record())
        db.execute(text("DELETE FROM schema_migrations WHERE version=5"))
        db.commit()
    database.migrate()
    database.migrate()
    with store() as db:
        assert db.scalar(select(func.count()).select_from(Migration)) == 5
        assert db.scalar(select(func.count()).select_from(Revision)) == 1


def test_ghsa_initial_publication_and_incremental_modified_queries(store, clock):
    enable(store, "ghsa")
    run_reset(emit=lambda _: None)
    queries = []
    def respond(request):
        queries.append(dict(request.url.params))
        return httpx.Response(200, json=[])
    assert discover_once(transport=httpx.MockTransport(respond))
    clock[0] += timedelta(hours=2)
    assert discover_once(transport=httpx.MockTransport(respond))
    assert "published" in queries[0] and "modified" not in queries[0]
    assert "modified" in queries[1] and "published" not in queries[1]
    assert queries[1]["modified"].endswith("2026-10-25T04:00:00Z")


def test_vendor_feed_resumes_frozen_snapshot_without_downloading_again(store, clock):
    enable(store, "nodejs")
    run_reset(emit=lambda _: None)
    feed = '<rss version="2.0"><channel><title>Security</title>' + "".join(
        '<item><title>CVE-2026-' + str(20000 + i) + '</title><link>https://nodejs.org/security/' + str(i)
        + '</link><pubDate>Sat, 24 Oct 2026 00:00:00 GMT</pubDate></item>' for i in range(205)) + '</channel></rss>'
    calls = []
    def respond(request):
        calls.append(str(request.url))
        assert len(calls) == 1, "resume must use the frozen feed"
        return httpx.Response(200, text=feed)
    for _ in range(3):
        assert discover_once(transport=httpx.MockTransport(respond))
    with store() as db:
        assert db.scalar(select(func.count()).select_from(RecentCandidate)) == 205
        assert progress(db)["scan_complete"]
    assert len(calls) == 1


def test_later_conflicting_source_updates_current_date_and_blocks_false_new(store, clock):
    enable(store, "nvd", "ghsa")
    run_reset(emit=lambda _: None)
    stage_record(store, payload())
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna())))
    new = {"source_key": "GHSA-aaaa-bbbb-cccc", "title": "contradictory", "aliases": [CVE],
           "published": "2020-01-01T00:00:00Z", "disclosed_at": "2020-01-01T00:00:00Z",
           "disclosure_reference": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "references": []}
    stage_record(store, new, "ghsa", initial=False)
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna())))
    with store() as db:
        assert db.scalar(select(PublicationState)).status == "conflict"
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        assert db.scalar(select(RecentCandidate).where(RecentCandidate.source_id == "ghsa")).status == "conflict"


def test_subsequent_kev_fetch_filters_old_catalog_before_enrichment(store, clock):
    enable(store, "kev")
    run_reset(emit=lambda _: None)
    calls = []
    def respond(request):
        calls.append(str(request.url))
        assert "cveawg" not in str(request.url)
        return httpx.Response(200, json={"vulnerabilities": [
            {"cveID": "CVE-2020-99999", "dateAdded": "2020-01-01"},
            {"cveID": CVE, "dateAdded": "2026-10-24"}]})
    assert discover_once(transport=httpx.MockTransport(respond))
    with store() as db:
        rows = list(db.scalars(select(RecentCandidate)))
        assert len(rows) == 1 and rows[0].source_key == CVE and not rows[0].initial
        assert stage(store, "kev").mode == "events"


def test_osv_supplement_fetches_only_known_id_and_checks_identity(store, clock):
    enable(store, "ghsa", "osv-pypi")
    run_reset(emit=lambda _: None)
    ghsa = {"source_key": "GHSA-aaaa-bbbb-cccc", "title": "package security", "aliases": ["GHSA-aaaa-bbbb-cccc", CVE],
            "published": "2026-10-24T00:00:00Z", "references": [],
            "affected": [{"package": {"ecosystem": "pip", "name": "test"}}]}
    stage_record(store, ghsa, "ghsa")
    calls = []
    def respond(request):
        url = str(request.url)
        calls.append(url)
        assert "modified_id.csv" not in url
        if "cveawg" in url:
            return httpx.Response(200, json=cna())
        return httpx.Response(200, json={"id": "GHSA-aaaa-bbbb-cccc", "aliases": [CVE],
            "published": "2026-10-24T12:00:00Z", "affected": [{"package": {"ecosystem": "PyPI", "name": "test"}}]})
    verify_all(httpx.MockTransport(respond))
    assert any(url.endswith("/GHSA-aaaa-bbbb-cccc.json") for url in calls)
    with store() as db:
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        assert db.scalar(select(RecentCandidate).where(RecentCandidate.source_id == "osv-pypi")).status == "admitted"


def test_new_reset_removes_old_snapshot_directories(store, clock):
    run = run_reset(emit=lambda _: None)
    root = settings().data_dir / "recent-snapshots" / run["run_id"] / uid() / "0"
    root.mkdir(parents=True)
    (root / "data").write_text("old raw source", encoding="utf-8")
    assert run_reset(new_run=True, emit=lambda _: None)["complete"]
    assert not root.exists()


def test_mcp_and_admin_show_independent_staging_counts(store, clock):
    from starlette.testclient import TestClient
    from vulintel.app import create_app
    from vulintel.auth import token_hash
    enable(store, "nvd", "osv-pypi")
    run_reset(emit=lambda _: None)
    stage_record(store, payload())
    verify_all(httpx.MockTransport(lambda _: httpx.Response(404)))
    with store() as db:
        db.add(WebSession(id=token_hash("recent-cookie"), subject="admin", csrf="csrf", expires=database.now() + timedelta(days=1)))
        db.commit()
    with TestClient(create_app(), base_url="https://vul.valna.cn") as client:
        headers = {"Cookie": "vul_session=recent-cookie"}
        tasks = client.get("/admin/tasks", headers=headers)
        assert tasks.status_code == 200 and "近七天分阶段初始化" in tasks.text and "日期待核实 1" in tasks.text
        rows = client.get("/admin/recent-candidates", headers=headers)
        assert CVE in rows.text and "公开日期" in rows.text
        sources = client.get("/admin/sources", headers=headers)
        assert "定向补充／首次覆盖有限" in sources.text
        with store() as db:
            candidate = db.scalar(select(RecentCandidate))
            candidate_id = candidate.id
        detail = client.get("/admin/recent-candidates/" + candidate_id, headers=headers)
        assert detail.status_code == 200 and "date_fetches" in detail.text and "source_facts" in detail.text


def test_first_report_does_not_backdate_facts_before_slot(store, clock):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    stage_record(store, payload())
    verify_all(httpx.MockTransport(lambda _: httpx.Response(200, json=cna())))
    with store() as db:
        bid = open_batch(db, "test", "2026-10-25T09:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        assert status(db, db.get(Batch, bid))["total"] == 0
        assert db.scalar(select(Revision)).observed_at == START


def test_verification_saves_at_most_four_url_checkpoints_per_step(store, clock):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    value = payload()
    value["references"] = ["https://support.apple.com/original-" + str(i) for i in range(10)]
    stage_record(store, value)
    calls = []
    def respond(request):
        calls.append(str(request.url))
        if "cveawg" in str(request.url):
            return httpx.Response(200, json=cna())
        return httpx.Response(200, text="No earlier publication metadata")
    transport = httpx.MockTransport(respond)
    assert verify_once(transport=transport)
    assert len(calls) == 4
    with store() as db:
        candidate = db.scalar(select(RecentCandidate))
        assert len(candidate.evidence_cursor["done"]) == 4
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0
    verify_all(transport)
    assert len(calls) == 11 and len(set(calls)) == 11


def test_github_cursor_refuses_external_next_url(store, clock):
    enable(store, "ghsa")
    run_reset(emit=lambda _: None)
    urls = []
    def respond(request):
        urls.append(str(request.url))
        return httpx.Response(200, json=[], headers={"Link": '<https://evil.example/next>; rel="next"'})
    assert discover_once(transport=httpx.MockTransport(respond))
    assert discover_once(transport=httpx.MockTransport(respond))
    assert len(urls) == 1 and urls[0].startswith("https://api.github.com/")
    assert stage(store, "ghsa").status == "failed"


def test_source_failure_retains_cursor_without_report_maintenance_fence(store, clock):
    enable(store, "nvd")
    run_reset(emit=lambda _: None)
    assert discover_once(transport=httpx.MockTransport(lambda _: httpx.Response(404)))
    with store() as db:
        saved = db.scalar(select(RecentSource).where(RecentSource.source_id == "nvd"))
        assert saved.status == "failed" and saved.error and saved.cursor == {}
        assert not active(db)
        state = progress(db)
        assert state["percent"] is None and state["estimated_remaining_seconds"] is None


@pytest.mark.parametrize("initial", [True, False])
def test_github_fractional_query_expands_to_seconds_keeps_precise_window(store, clock, initial):
    from vulintel.recent import page
    enable(store, "ghsa")
    run_reset(emit=lambda _: None)
    with store() as db:
        state = db.scalar(select(RecentSource).where(RecentSource.source_id == "ghsa"))
        state.start_at = state.start_at.replace(microsecond=138383)
        state.end_at = state.end_at.replace(microsecond=138383)
        state.initial = initial
        original = (state.start_at, state.end_at)
        db.commit()
        source = db.get(Source, "ghsa")
    calls = []
    def respond(request):
        value = request.url.params["published" if initial else "modified"]
        assert value == "2026-10-18T02:00:00Z..2026-10-25T02:00:01Z"
        calls.append(value)
        return httpx.Response(200, json=[])
    page(source, state, httpx.MockTransport(respond))
    assert calls and (state.start_at, state.end_at) == original


def test_github_saved_cursor_with_microseconds_is_normalized_without_losing_cursor(store, clock):
    from vulintel.recent import page
    enable(store, "ghsa")
    run_reset(emit=lambda _: None)
    with store() as db:
        state = db.scalar(select(RecentSource).where(RecentSource.source_id == "ghsa"))
        state.cursor = {"url": "https://api.github.com/advisories?published=2026-10-18T02%3A00%3A00.138383Z..2026-10-25T02%3A00%3A00.138383Z&after=opaque-cursor"}
        db.commit()
        source = db.get(Source, "ghsa")
    def respond(request):
        assert request.url.params["after"] == "opaque-cursor"
        assert request.url.params["published"] == "2026-10-18T02:00:00Z..2026-10-25T02:00:00Z"
        return httpx.Response(200, json=[])
    page(source, state, httpx.MockTransport(respond))


def test_cisa_2_4mb_record_keeps_complete_body_and_scan_can_continue(store, clock):
    enable(store, "cisa-advisories")
    run_reset(emit=lambda _: None)
    body = "x" * 2_396_298
    feed = ('<rss version="2.0"><channel><title>Security</title><item><title>' + CVE + '</title>'
            '<link>https://www.cisa.gov/advisory/big</link><description>' + body + '</description>'
            '<pubDate>Sat, 24 Oct 2026 00:00:00 GMT</pubDate></item><item><title>CVE-2026-12346</title>'
            '<link>https://www.cisa.gov/advisory/next</link><description>next full item</description>'
            '<pubDate>Sat, 24 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>')
    transport = httpx.MockTransport(lambda _: httpx.Response(200, text=feed))
    assert discover_once(transport=transport)
    assert discover_once(transport=transport)
    with store() as db:
        rows = list(db.scalars(select(RecentCandidate)))
        assert len(rows) == 2
        assert any(row.data.get("description") == body for row in rows)
        assert all(row.status == "pending" for row in rows)
        assert progress(db)["scan_complete"] and progress(db)["oversized"] == 0
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0


def test_over_8mib_is_quarantined_intact_not_analysed_and_following_item_is_discovered(store, clock):
    from vulintel.recent import MAX_CANDIDATE_BYTES, raw_candidate_path
    enable(store, "nodejs")
    run_reset(emit=lambda _: None)
    body = "z" * (MAX_CANDIDATE_BYTES + 1)
    feed = ('<rss version="2.0"><channel><title>Security</title><item><title>' + CVE + '</title>'
            '<link>https://nodejs.org/advisory/big</link><description>' + body + '</description>'
            '<pubDate>Sat, 24 Oct 2026 00:00:00 GMT</pubDate></item><item><title>CVE-2026-12346</title>'
            '<link>https://nodejs.org/advisory/next</link><description>next</description>'
            '<pubDate>Sat, 24 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>')
    transport = httpx.MockTransport(lambda _: httpx.Response(200, text=feed))
    assert discover_once(transport=transport)
    assert discover_once(transport=transport)
    with store() as db:
        quarantined = db.scalar(select(RecentCandidate).where(RecentCandidate.status == "oversized"))
        assert quarantined and not quarantined.data["evidence_complete"] and quarantined.vulnerability_id is None
        path = raw_candidate_path(quarantined)
        assert json.loads(path.read_text(encoding="utf-8"))["description"] == body
        assert progress(db)["scan_complete"] and progress(db)["oversized"] == 1
        assert db.scalar(select(func.count()).select_from(RecentCandidate)) == 2
        source = next(item for item in source_status(db) if item["id"] == "nodejs")
        assert source["coverage_limited"] and source["oversized_candidates"] == 1 and not source["error"]
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0
        path.write_bytes(b"corrupt")
        with pytest.raises(ValueError, match="校验"):
            raw_candidate_path(quarantined)


def test_quarantine_disk_failure_keeps_page_checkpoint_and_does_not_drop_record(store, clock, monkeypatch):
    from pathlib import Path
    from vulintel.recent import MAX_CANDIDATE_BYTES
    enable(store, "nodejs")
    run_reset(emit=lambda _: None)
    body = "z" * (MAX_CANDIDATE_BYTES + 1)
    feed = ('<rss version="2.0"><channel><title>Security</title><item><title>' + CVE + '</title>'
            '<link>https://nodejs.org/advisory/big</link><description>' + body + '</description>'
            '<pubDate>Sat, 24 Oct 2026 00:00:00 GMT</pubDate></item></channel></rss>')
    original = Path.write_bytes
    def fail(path, data):
        if path.parent.name == "quarantine":
            raise OSError("disk unavailable")
        return original(path, data)
    monkeypatch.setattr(Path, "write_bytes", fail)
    assert discover_once(transport=httpx.MockTransport(lambda _: httpx.Response(200, text=feed)))
    with store() as db:
        state = db.scalar(select(RecentSource).where(RecentSource.source_id == "nodejs"))
        assert state.status == "failed" and not state.cursor.get("offset")
        assert db.scalar(select(func.count()).select_from(RecentCandidate)) == 0


def test_github_query_rounding_does_not_expand_actual_admission_window(store, clock):
    enable(store, "ghsa")
    run_reset(emit=lambda _: None)
    with store() as db:
        state = db.scalar(select(RecentSource).where(RecentSource.source_id == "ghsa"))
        state.end_at = START.replace(microsecond=138383)
        offer(db, state, {"source_key": "GHSA-aaaa-bbbb-cccc", "title": "too late", "aliases": [],
                         "published": "2026-10-25T02:00:00.500000Z", "references": []})
        db.commit()
    clock[0] += timedelta(seconds=2)
    verify_all(httpx.MockTransport(lambda _: pytest.fail("no evidence URL should be fetched")))
    with store() as db:
        row = db.scalar(select(RecentCandidate))
        assert row.status == "excluded" and row.end_at.microsecond == 138383
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 0


def test_quarantine_download_requires_admin_and_serves_the_intact_original(store, clock, monkeypatch):
    from starlette.testclient import TestClient
    from vulintel.app import create_app
    from vulintel.auth import token_hash
    monkeypatch.setattr("vulintel.recent.MAX_CANDIDATE_BYTES", 1024)
    enable(store, "nodejs")
    run_reset(emit=lambda _: None)
    original = {"source_key": "big", "title": "full evidence", "aliases": [], "references": [], "description": "x" * 2048}
    stage_record(store, original, "nodejs")
    with store() as db:
        row = db.scalar(select(RecentCandidate))
        cid = row.id
        db.add(WebSession(id=token_hash("raw-cookie"),
                          subject="admin", csrf="csrf", expires=database.now() + timedelta(days=1)))
        db.commit()
    with TestClient(create_app(), base_url="https://vul.valna.cn") as client:
        assert client.get("/admin/recent-candidates/" + cid + "/raw", follow_redirects=False).status_code == 303
        response = client.get("/admin/recent-candidates/" + cid + "/raw", headers={"Cookie": "vul_session=raw-cookie"})
        assert response.status_code == 200 and response.json() == original
        assert "attachment" in response.headers["content-disposition"]
        assert response.headers["x-content-type-options"] == "nosniff"
