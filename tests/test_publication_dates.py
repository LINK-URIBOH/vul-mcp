import copy
import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import func, select, text

from report_helpers import drain
from test_business import analysis
from vulintel import date_repair
from vulintel.config import settings
from vulintel.date_enrichment import cve_facts, enrich, fetch_cached, page_facts, run_once
from vulintel.db import (Batch, BatchItem, DateEvidenceCache, Job, MetadataState, PublicationAnnotation,
                         PublicationState, ReportState, Revision, RevisionDateProjection, Vulnerability, uid)
from vulintel.publication import (DATE_POLICY, REPAIR_KEY, annotate, cache_key, coverage,
                                 date_in_window, date_interval, proof, resolve_publication)
from vulintel.report_jobs import batch_page, finalize, open_batch, run_report_once, status
from vulintel.service import ingest, submit_analysis
from vulintel.sources import ghsa_record, nvd_record, osv_record
from vulintel.timeline import EVENT_POLICY, derive_revision

NOW = datetime(2026, 10, 24, 6)
CUTOFF = datetime(2026, 10, 23, 10)
CVE = "CVE-2026-12345"
API = "https://cveawg.mitre.org/api/cve/" + CVE


def facts(published="2026-10-22T00:00:00Z", disclosed=None, **kwargs):
    data = nvd_record({"id": CVE, "published": published, "references": [{"url": "https://support.apple.com/advisory"}]})
    if disclosed:
        data.update(disclosed_at=disclosed, disclosure_reference="https://support.apple.com/advisory")
    return {**data, **kwargs}


def cna_payload(disclosed="2026-10-22T00:00:00Z", record_date="2026-10-22T12:00:00Z"):
    return {"cveMetadata": {"cveId": CVE, "state": "PUBLISHED", "datePublished": record_date},
            "containers": {"cna": {"datePublic": disclosed, "references": [], "affected": [{"versions": ["FUTURE-999"]}]}}}


@pytest.fixture
def dates_clock(monkeypatch):
    monkeypatch.setattr("vulintel.timeline.now", lambda: CUTOFF - timedelta(seconds=1))
    monkeypatch.setattr("vulintel.report_jobs.now", lambda: NOW)
    monkeypatch.setenv("PUBLICATION_REQUEST_INTERVAL", "0.1")
    settings.cache_clear()
    monkeypatch.setattr("vulintel.collector.CollectorHTTP.pause", lambda *_: None)


@pytest.mark.parametrize("source,payload", [
    ("nvd", nvd_record({"id": CVE, "published": "2026-10-22T00:00:00Z"})),
    ("osv-debian", osv_record({"id": "DEBIAN-" + CVE, "published": "2026-10-22T00:00:00Z"})),
    ("osv-linux", osv_record({"id": CVE, "published": "2026-10-22T00:00:00Z"})),
    ("osv-pypi", osv_record({"id": "PYSEC-2026-1", "published": "2026-10-22T00:00:00Z"})),
])
def test_database_entry_date_never_becomes_a_disclosure(source, payload):
    result = resolve_publication({"source_records": [{"source": source, **payload}]}, assessed=NOW)
    assert result["publication_status"] == "unknown" and result["published_at"] is None
    assert result["date_evidence"] or result["rejected_date_evidence"]


def test_cna_disclosure_precedes_record_and_keeps_field_provenance():
    data = {"source_records": [{"source": "nvd", **facts()}]}
    extra = cve_facts(cna_payload("2020-01-01T12:00:00Z"), CVE, API)["evidence"]
    result = resolve_publication(data, extra, assessed=NOW)
    assert result["published_at"] == "2020-01-01T12:00:00Z"
    assert result["publication_field"] == "containers.cna.datePublic"
    assert result["cve_record_publications"] and result["publication_reference"] == API


def test_inconsistent_explicit_disclosures_and_earlier_public_record_are_conflicts():
    data = {"source_records": [{"source": "nvd", **facts("2020-01-01T00:00:00Z")} ]}
    claim = proof("cna", CVE, "datePublic", "2026-10-22T00:00:00Z", "disclosure", API)
    assert resolve_publication(data, [claim], NOW)["publication_status"] == "conflict"
    another = proof("vendor", CVE, "datePublic", "2026-10-21T00:00:00Z", "disclosure", "https://support.apple.com/advisory")
    result = resolve_publication({}, [claim, another], NOW)
    assert result["publication_status"] == "conflict" and result["published_at"] is None


def test_invalid_future_and_timezone_unknown_are_explicitly_rejected():
    for value in ["0001-01-01", "0001-01-01T00:00:00Z", "2099-01-01T00:00:00Z", "2026-10-22T12:00:00"]:
        result = resolve_publication({}, [proof("cna", CVE, "datePublic", value, "disclosure", API)], NOW)
        assert result["publication_status"] == "unknown"
        assert result["rejected_date_evidence"][0]["rejected_reason"]


def test_date_only_preserves_precision_and_window_uncertainty():
    result = resolve_publication({}, [proof("vendor", CVE, "datePublic", "2026-10-17", "disclosure", API)], NOW)
    assert result["published_at"] == "2026-10-17" and result["publication_status"] == "day"
    annotation = SimpleNamespace(status="day", start_at=date_interval("2026-10-17")[0],
                                 end_at=date_interval("2026-10-17")[1])
    assert not date_in_window(annotation, datetime(2026, 10, 17, 1), datetime(2026, 10, 24, 1))
    assert date_in_window(annotation, datetime(2026, 10, 16), datetime(2026, 10, 24, 1))
    exact = date_interval("2026-10-22T08:00:00+08:00")
    assert exact[0] == datetime(2026, 10, 22) and exact[0] == exact[1]


def test_multi_cve_page_and_untrusted_commands_do_not_supply_shared_dates():
    payload = '<meta itemprop="datePublished" content="2026-10-22T00:00:00Z"><h1>CVE-2026-12345 CVE-2026-12346</h1><script>throw new Error("execute exploit")</script>'
    assert page_facts(payload, "https://support.apple.com/advisory")["evidence_by_cve"] == {}
    single = payload.replace(" CVE-2026-12346", "")
    result = page_facts(single, "https://support.apple.com/advisory")
    assert result["evidence_by_cve"][CVE][0]["kind"] == "advisory_publication"


def test_enrichment_uses_cache_and_retains_network_errors_without_fabrication(store, dates_clock):
    calls = []
    def respond(request):
        calls.append(str(request.url))
        if str(request.url) != API:
            return httpx.Response(200, text="No publication metadata")
        return httpx.Response(200, json=cna_payload("2020-01-01T00:00:00Z"))
    with store() as db:
        identity = ingest(db, "nvd", facts())
        db.commit()
    transport = httpx.MockTransport(respond)
    assert enrich(identity, transport=transport)["status"] == "confirmed"
    enrich(identity, transport=transport)
    assert calls == [API, "https://support.apple.com/advisory"]
    with store() as db:
        annotation = db.get(PublicationAnnotation, db.get(PublicationState, identity).annotation_id)
        assert annotation.data["published_at"] == "2020-01-01T00:00:00Z"
        assert "FUTURE-999" not in json.dumps(annotation.data)
        assert db.scalar(select(Revision)).published_at is None
    with pytest.raises(ValueError, match="白名单"):
        fetch_cached("https://127.0.0.1/private", transport=transport)
    other = "CVE-2026-12346"
    failed = fetch_cached("https://cveawg.mitre.org/api/cve/" + other, identifier=other,
                          transport=httpx.MockTransport(lambda _: httpx.Response(429, headers={"Retry-After": "3600"})))
    assert failed["reason"] == "retry_deferred"
    with store() as db:
        cached = db.get(DateEvidenceCache, cache_key("https://cveawg.mitre.org/api/cve/" + other))
        assert cached.status == "error" and cached.retry_at > datetime.now(timezone.utc).replace(tzinfo=None)


def test_only_observation_is_not_a_reportable_update(dates_clock):
    initial = facts(disclosed="2020-01-01T00:00:00Z", affected=[{"versions": ["1"]}])
    initial["published"] = "2020-01-01T00:00:00Z"
    row = derive_revision(SimpleNamespace(id="test", data={"source_records": [{"source": "nvd", **initial}]}), observed=CUTOFF)
    changed = copy.deepcopy(initial)
    changed["affected"] = [{"versions": ["1", "2"]}]
    update = derive_revision(SimpleNamespace(id="test", data={"source_records": [{"source": "nvd", **changed}]}), row, observed=CUTOFF)
    assert update.important_at is None
    assert update.snapshot["timeline"]["change_observed_at"]


@pytest.mark.parametrize("disclosed,expected", [("2020-01-01T00:00:00Z", 0), ("2026-10-22T00:00:00Z", 1)])
def test_historical_cutoff_uses_corrected_date_and_original_facts(store, dates_clock, monkeypatch, disclosed, expected):
    with store() as db:
        identity = ingest(db, "nvd", facts(affected=[{"versions": ["1"]}]))
        db.commit()
        old = db.scalar(select(Revision))
        old.snapshot = {**old.snapshot, "timeline": {"event_policy": 3, "published_at": "2026-10-22T00:00:00Z"}}
        old.published_at = datetime(2026, 10, 22)
        before = copy.deepcopy(old.snapshot)
        old_id = old.id
        batch = Batch(id=uid(), slot="2026-10-23T18:00+08:00", cutoff=CUTOFF, status="analyzing")
        db.add(batch)
        db.flush()
        db.add(ReportState(batch_id=batch.id, policy=4, total=1, work={"phase": "analyzing", "prepared": True, "item_limit": 50}))
        db.add(BatchItem(batch_id=batch.id, vulnerability_id=identity, snapshot=copy.deepcopy(old.snapshot), priority=True))
        db.commit()
        bid = batch.id
        monkeypatch.setattr("vulintel.timeline.now", lambda: CUTOFF + timedelta(hours=1))
        ingest(db, "nvd", facts(affected=[{"versions": ["1", "2"]}]))
        db.commit()
        assert status(db, db.get(Batch, bid))["old_date_mixed_count"] == 1
    result = date_repair.run_repair(emit=lambda _: None, transport=httpx.MockTransport(lambda _: httpx.Response(200, json=cna_payload(disclosed))))
    assert result["complete"] and result["validated"] == 1 and result["projections_written"] == 2
    with store() as db:
        assert db.get(Revision, old_id).snapshot == before
        assert db.get(Revision, old_id).published_at == datetime(2026, 10, 22)
        drain(db, bid, "analyzing")
        current = status(db, db.get(Batch, bid))
        assert current["total"] == expected and current["old_date_mixed_count"] == 0
        if expected:
            item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
            assert item.snapshot["affected"] == [{"versions": ["1"]}]
            assert item.snapshot["timeline"]["published_at"] == disclosed
            assert item.snapshot["timeline"]["date_policy"] == DATE_POLICY
            assert item.snapshot["timeline"]["event_policy"] == EVENT_POLICY
            assert "FUTURE-999" not in json.dumps(item.snapshot)
            from vulintel.report_jobs import item_evidence
            fragments, offset = [], 0
            while True:
                page = item_evidence(db, bid, item.id, offset, 64)
                fragments.append(page["text"])
                if page["next_offset"] is None:
                    break
                offset = page["next_offset"]
            assert json.loads("".join(fragments)) == item.snapshot
            submit_analysis(db, "test", bid, [analysis(item.id)])
        finalize(db, "test", bid)
        drain(db, bid, "finalized")
        from vulintel.reports import report_dir
        exported = json.loads((report_dir(bid) / "report.json").read_text(encoding="utf-8"))
        assert len(exported["items"]) == expected
        if expected:
            assert exported["items"][0]["facts"]["timeline"]["published_at"] == disclosed
            csv = (report_dir(bid) / "index.csv").read_text(encoding="utf-8-sig")
            assert "日期标注版本" in csv and API in csv
        from vulintel.delivery import deliver_one
        from vulintel.db import Delivery
        monkeypatch.setenv("DELIVERY_ENABLED", "true")
        settings.cache_clear()
        sent = []
        while deliver_one(db, sender=lambda row: sent.append(row.channel)):
            db.commit()
        assert set(sent) == {"email", "webhook"}
        assert all(row.status == "sent" for row in db.scalars(select(Delivery).where(Delivery.batch_id == bid)))


def test_missing_projection_blocks_instead_of_silently_omitting_old_records(store, dates_clock):
    with store() as db:
        ingest(db, "nvd", facts(disclosed="2026-10-22T00:00:00Z"))
        db.execute(text("DELETE FROM revision_date_projections"))
        db.commit()
        bid = open_batch(db, "test", "2026-10-23T18:00+08:00")["batch_id"]
        assert run_report_once()
        db.expire_all()
        result = status(db, db.get(Batch, bid))
        assert result["status"] == "failed" and not result["ready"]
        assert "repair-publication-dates" in result["error"]


def test_failed_enrichment_is_cached_and_rescheduled_without_fake_dates(store, dates_clock):
    calls = []
    def missing(request):
        calls.append(str(request.url))
        return httpx.Response(404)
    with store() as db:
        identity = ingest(db, "nvd", facts())
        db.commit()
    assert run_once(transport=httpx.MockTransport(missing))
    assert not run_once(transport=httpx.MockTransport(missing))
    with store() as db:
        state = db.get(PublicationState, identity)
        assert state.status == "unknown" and state.start_at is None
        job = db.scalar(select(Job).where(Job.kind == "publication"))
        assert job.status == "pending" and job.lease_until > datetime.now(timezone.utc).replace(tzinfo=None)
        assert coverage(db)["evidence_fetch_errors"] == 2
    enrich(identity, transport=httpx.MockTransport(missing))
    assert len(calls) == 2


def test_date_repair_failure_resume_and_completed_rerun_preserves_new_reports(store, dates_clock):
    calls = []
    with store() as db:
        identity = ingest(db, "nvd", facts())
        db.commit()
        finalized = Batch(id=uid(), slot="2020-01-01T09:00+08:00", cutoff=datetime(2020, 1, 1, 1), status="finalized")
        db.add(finalized)
        db.commit()
        finalized_id = finalized.id
    def respond(request):
        calls.append(str(request.url))
        return httpx.Response(200, json=cna_payload())
    def interrupt(line):
        if json.loads(line).get("processed") == 1:
            raise KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        date_repair.run_repair(emit=interrupt, transport=httpx.MockTransport(respond))
    with store() as db:
        value = db.get(MetadataState, REPAIR_KEY).value
        assert not value["complete"] and value["cursor"] == identity
        assert db.get(Job, value["job_id"]).status == "failed"
    result = date_repair.run_repair(emit=lambda _: None, transport=httpx.MockTransport(respond))
    assert result["complete"] and calls == [API, "https://support.apple.com/advisory"]
    with store() as db:
        assert db.get(Batch, finalized_id)
        fresh = Batch(id=uid(), slot="2026-10-24T09:00+08:00", cutoff=NOW)
        db.add(fresh)
        db.commit()
        fresh_id = fresh.id
    assert date_repair.run_repair(emit=lambda _: None)["complete"]
    with store() as db:
        assert db.get(Batch, fresh_id)
        assert db.scalar(select(func.count()).select_from(RevisionDateProjection)) == db.scalar(select(func.count()).select_from(Revision))


def test_repair_with_unavailable_sources_finishes_with_explicit_quality_gaps(store, dates_clock):
    with store() as db:
        ingest(db, "nvd", facts())
        # A pre-upgrade library has no new background date jobs yet.
        db.execute(text("DELETE FROM jobs WHERE kind='publication'"))
        db.commit()
    result = date_repair.run_repair(emit=lambda _: None, transport=httpx.MockTransport(lambda _: httpx.Response(404)))
    assert result["complete"] and result["network_gaps"] == 1
    assert result["after"]["unknown"] == 1 and result["after"]["confirmed"] == 0
    with store() as db:
        assert db.scalar(select(func.count()).select_from(Job).where(Job.kind == "publication", Job.status == "pending")) == 1
        bid = open_batch(db, "test", "2026-10-23T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        assert status(db, db.get(Batch, bid))["total"] == 0
        assert status(db, db.get(Batch, bid))["unverified_dates"] == 1


def test_frontend_filters_publication_instead_of_import_time(store, dates_clock):
    from starlette.testclient import TestClient
    from vulintel.app import create_app
    from vulintel.auth import token_hash
    from vulintel.db import WebSession, now
    with store() as db:
        old_id = ingest(db, "nvd", facts(published="2020-01-01T00:00:00Z", disclosed="2020-01-01T00:00:00Z", title="OLD-DISCLOSURE"))
        recent_facts = facts(disclosed="2026-10-22T00:00:00Z", title="RECENT-DISCLOSURE")
        recent_facts["source_key"] = "CVE-2026-99999"
        recent_facts["aliases"] = ["CVE-2026-99999"]
        recent_id = ingest(db, "nvd", recent_facts)
        db.get(Vulnerability, recent_id).updated_at = datetime(2018, 1, 1)
        db.get(Vulnerability, old_id).updated_at = NOW
        db.add(WebSession(id=token_hash("date-cookie"), subject="admin", csrf="csrf", expires=now() + timedelta(minutes=5)))
        db.commit()
    with TestClient(create_app(), base_url="https://vul.valna.cn") as client:
        headers = {"Cookie": "vul_session=date-cookie"}
        response = client.get("/admin/vulnerabilities?since=2026-10-22&until=2026-10-22", headers=headers)
        assert response.status_code == 200
        assert "RECENT-DISCLOSURE" in response.text and "OLD-DISCLOSURE" not in response.text
        detail = client.get("/admin/vulnerabilities/" + recent_id, headers=headers)
        assert "最早可核实公开时间" in detail.text and "2026-10-22" in detail.text
        assert "disclosure_reference" in detail.text


def test_snapshot_annotation_is_frozen_when_new_date_evidence_arrives(store, dates_clock):
    with store() as db:
        identity = ingest(db, "nvd", facts(disclosed="2026-10-22T00:00:00Z"))
        db.commit()
        bid = open_batch(db, "test", "2026-10-23T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        item = db.scalar(select(BatchItem).where(BatchItem.batch_id == bid))
        before = copy.deepcopy(item.snapshot)
        cache = DateEvidenceCache(key=cache_key(API), url=API, checked_at=NOW, retry_at=NOW + timedelta(days=7), status="ok",
                    data=cve_facts(cna_payload("2020-01-01T00:00:00Z"), CVE, API))
        db.add(cache)
        annotate(db, db.get(Vulnerability, identity), enqueue=False)
        db.commit()
        assert db.get(BatchItem, item.id).snapshot == before
        assert db.get(PublicationState, identity).annotation_id != before["timeline"]["date_annotation_id"]
        assert batch_page(db, bid)["old_date_mixed_count"] == 0


def test_cve_identity_mismatch_cannot_poison_a_cached_annotation(store, dates_clock):
    wrong = cna_payload()
    wrong["cveMetadata"]["cveId"] = "CVE-2026-99999"
    data = fetch_cached(API, identifier=CVE, transport=httpx.MockTransport(lambda _: httpx.Response(200, json=wrong)))
    assert data["reason"] == "date_identity_mismatch" and "evidence" not in data


def test_ghsa_advisory_timestamp_is_preserved_as_advisory_evidence():
    record = ghsa_record({"ghsa_id": "GHSA-aaaa-bbbb-cccc", "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                          "published_at": "2026-10-22T00:00:00Z", "identifiers": [{"value": CVE}]})
    result = resolve_publication({"source_records": [{"source": "ghsa", **record}]}, assessed=NOW)
    assert result["publication_status"] == "confirmed" and result["publication_field"] == "published_at"


def test_enrichment_checks_earlier_original_even_when_cna_date_is_known(store, dates_clock):
    calls = []
    def respond(request):
        calls.append(str(request.url))
        if str(request.url) == API:
            return httpx.Response(200, json=cna_payload())
        return httpx.Response(200, text='<meta itemprop="datePublished" content="2020-01-01T12:00:00Z">'
                              '<h1>CVE-2026-12345 original disclosure</h1>')
    with store() as db:
        identity = ingest(db, "nvd", facts())
        db.commit()
    enrich(identity, transport=httpx.MockTransport(respond))
    with store() as db:
        annotation = db.get(PublicationAnnotation, db.get(PublicationState, identity).annotation_id)
        assert annotation.data["published_at"] == "2020-01-01T12:00:00Z"
        assert annotation.data["publication_reference"] == "https://support.apple.com/advisory"
        assert annotation.data["cve_record_publications"]
    assert calls == [API, "https://support.apple.com/advisory"]


def test_rss_preserves_date_only_and_original_timezone(dates_clock):
    from test_cisa import source
    from vulintel.sources import Upstream
    for raw, precision in [("2026-10-22", "day"), ("Thu, 22 Oct 2026 08:00:00 +0800", "datetime")]:
        payload = ('<?xml version="1.0"?><rss version="2.0"><channel><title>Security</title><item>'
                   '<title>CVE-2026-12345 security fix</title><link>https://nodejs.org/advisory</link>'
                   '<pubDate>' + raw + '</pubDate></item></channel></rss>')
        upstream = Upstream(httpx.MockTransport(lambda _: httpx.Response(200, text=payload)))
        try:
            record = next(upstream.records(source("nodejs"), datetime(2026, 10, 1), NOW))
        finally:
            upstream.close()
        assert record["published"] == raw and record["feed_published_original"] == raw
        assert record["modified"] is None and record["feed_updated_original"] is None
        result = resolve_publication({"source_records": [{"source": "nodejs", **record}]}, assessed=NOW)
        assert result["publication_precision"] == precision and result["publication_original"] == raw


def test_reportable_patch_requires_public_reference_and_retains_event_date(dates_clock):
    data = {"source_records": [{"source": "msrc", "remediations": [{"Date": "2026-10-22T08:00:00+08:00"}]}]}
    assert derive_revision(SimpleNamespace(id="v", data=data), observed=NOW).important_at is None
    data["source_records"][0]["references"] = ["https://msrc.microsoft.com/update-guide/vulnerability/" + CVE]
    revision = derive_revision(SimpleNamespace(id="v", data=data), observed=NOW)
    assert revision.important_at == datetime(2026, 10, 22)
    event = revision.snapshot["timeline"]["event_dates"][0]
    assert event["field"] == "remediations.Date" and event["original"] == "2026-10-22T08:00:00+08:00"
    assert event["url"].startswith("https://msrc.microsoft.com/")


def test_unmodified_ingest_schedules_new_linked_evidence_without_rewriting_facts(store, dates_clock):
    with store() as db:
        data = facts()
        identity = ingest(db, "nvd", data)
        db.commit()
        revision_id = db.scalar(select(Revision.id))
        db.execute(text("DELETE FROM jobs WHERE kind='publication'"))
        db.add(DateEvidenceCache(key=cache_key(API), url=API, status="ok", data=cve_facts(cna_payload(), CVE, API),
                                retry_at=datetime(2099, 1, 1)))
        db.commit()
        ingest(db, "nvd", data)
        db.commit()
        assert db.scalar(select(Revision.id)) == revision_id
        assert db.scalar(select(Job).where(Job.source_id == identity, Job.kind == "publication"))


def test_legacy_feed_precision_and_android_url_guesses_require_new_evidence():
    for source, extra in [("nodejs", {}), ("android", {"publication_basis": "Android 公告日期"})]:
        record = {"source": source, "source_key": "old", "published": "2026-10-22T00:00:00Z",
                  "references": ["https://source.android.com/docs/security/bulletin/2026-10-22"], **extra}
        result = resolve_publication({"source_records": [record]}, assessed=NOW)
        assert result["publication_status"] == "unknown" and result["source_entry_publications"]


def test_benchmark_seed_uses_current_date_annotations(store, dates_clock, monkeypatch):
    from scripts import report_benchmark
    monkeypatch.setattr(report_benchmark, "due_slot", lambda: "2026-10-23T18:00+08:00")
    report_benchmark.seed(45)
    with store() as db:
        bid = open_batch(db, "test", "2026-10-23T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        result = status(db, db.get(Batch, bid))
        assert result["total"] == 30 and result["unverified_dates"] == 10
        assert result["old_date_mixed_count"] == 0
