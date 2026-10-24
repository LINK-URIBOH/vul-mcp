import copy
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from report_helpers import drain
from vulintel.db import Alias, BatchItem, MetadataState, ReportState, Revision, Vulnerability
from vulintel.event_audit import audit_items, audit_report
from vulintel.identity import record_aliases
from vulintel.service import ingest, open_batch
from vulintel.sources import entry, osv_record
from vulintel.timeline import BACKFILL_KEY, EVENT_POLICY, backfill_step, derive_revision, stamp


OBSERVED = datetime(2026, 10, 23, 9)


def distro(cve="CVE-2020-12345", prefix="DEBIAN", **extra):
    return osv_record({"id": prefix + "-" + cve, "published": "2026-10-21T00:00:00Z",
                       "modified": "2026-10-23T00:00:00Z", **extra})


def projection(facts, latest=None, observed=OBSERVED):
    return derive_revision(SimpleNamespace(id="test", data=facts), latest, observed=observed)


@pytest.mark.parametrize("value", ["0001-01-01T00:00:00Z", "0001-01-01", "0001-01-02T08:00:00+08:00", "bad"])
def test_zero_or_invalid_date_is_not_an_event(value):
    assert stamp(value) is None
    facts = {"title": "时间占位", "source_records": [{"source": "msrc", "published": value,
             "remediations": [{"Date": value}]}]}
    row = projection(facts)
    assert row.published_at is None and row.important_at is None
    assert row.snapshot["timeline"]["patch_published_at"] is None


def test_only_structured_single_cve_namespaces_are_normalized():
    value = distro()
    assert value["aliases"] == ["CVE-2020-12345", "DEBIAN-CVE-2020-12345"]
    assert value["published"] == "2026-10-21T00:00:00Z"
    assert value["publication_scope"] == "source_record"
    assert record_aliases({"source_key": "BULLETIN-CVE-2020-12345", "mentioned_cves": ["CVE-2020-12345"]}) == []
    assert record_aliases({"source_key": "DEBIAN-CVE-2020-12345-CVE-2020-56789"}) == []
    assert record_aliases(distro(prefix="UBUNTU")) == ["CVE-2020-12345", "UBUNTU-CVE-2020-12345"]


@pytest.mark.parametrize("reverse", [False, True])
def test_distro_republication_merges_with_old_cve_in_either_ingest_order(store, monkeypatch, reverse):
    monkeypatch.setattr("vulintel.timeline.now", lambda: OBSERVED)
    with store() as db:
        sources = [("nvd", entry("CVE-2020-12345", "旧漏洞", "", ["CVE-2020-12345"],
                                published="2020-01-01T00:00:00Z")), ("osv-debian", distro())]
        if reverse:
            sources.reverse()
        identities = [ingest(db, source, facts) for source, facts in sources]
        db.commit()
        assert identities[0] == identities[1]
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        latest = db.scalar(select(Revision).order_by(Revision.id.desc()).limit(1))
        assert latest.published_at == datetime(2020, 1, 1)
        assert latest.important_at is None


def test_distro_record_publication_without_cve_disclosure_is_unverified(store, monkeypatch):
    monkeypatch.setattr("vulintel.timeline.now", lambda: OBSERVED)
    with store() as db:
        ingest(db, "osv-debian", distro())
        db.commit()
        bid = open_batch(db, "test", "2026-10-23T18:00+08:00")["batch_id"]
        drain(db, bid, "analyzing")
        state = db.get(ReportState, bid)
        assert state.new_count == 0 and state.unknown_count == 1


def test_osv_version_enumeration_and_order_do_not_emit_important_update():
    affected = [{"package": {"ecosystem": "Debian:12", "name": "linux"},
                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
                 "versions": ["6.1.1", "6.1.2"]}]
    facts = {"title": "旧漏洞", "source_records": [{"source": "osv-debian", "source_key": "DEBIAN-CVE-2020-12345",
             **distro(affected=affected)}]}
    initial = projection(facts)
    updated = copy.deepcopy(facts)
    updated["source_records"][0]["affected"][0]["versions"] = ["6.1.3", "6.1.2", "6.1.1"]
    assert projection(updated, initial).important_at is None
    updated["source_records"][0]["affected"][0]["ranges"][0]["events"].append({"fixed": "6.1.4"})
    changed = projection(updated, initial)
    assert changed.important_at == OBSERVED
    assert changed.snapshot["timeline"]["changed_fields"] == ["affected"]


def test_different_advisories_from_same_source_are_not_compared_as_revisions():
    first = {"title": "first", "source_records": [{"source": "debian", "source_key": "DSA-1", "affected": ["A"]}]}
    second = copy.deepcopy(first)
    second["source_records"].append({"source": "debian", "source_key": "DSA-2", "affected": ["B"]})
    assert projection(second, projection(first)).important_at is None


def test_explicit_osv_versions_outside_unbounded_distro_case_are_material():
    base = {"title": "范围", "source_records": [{"source": "osv-npm", "source_key": "GHSA-test",
            "affected": [{"package": {"name": "P", "ecosystem": "npm"}, "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2"}]}], "versions": ["1"]}]}]}
    changed = copy.deepcopy(base)
    changed["source_records"][0]["affected"][0]["versions"].append("3")
    assert projection(changed, projection(base)).important_at == OBSERVED


def test_legacy_repair_merges_identity_without_mutating_frozen_items(store, monkeypatch):
    monkeypatch.setattr("vulintel.timeline.now", lambda: OBSERVED)
    with store() as db:
        from vulintel.db import Batch, SourceRecord
        nvd = ingest(db, "nvd", entry("CVE-2020-12345", "旧漏洞", "", ["CVE-2020-12345"],
                                     published="2020-01-01T00:00:00Z"))
        # Simulate the pre-fix distro identity without calling the fixed ingestion path.
        facts = entry("DEBIAN-CVE-2020-12345", "发行版记录", "", ["DEBIAN-CVE-2020-12345"],
                      published="2026-10-21T00:00:00Z")
        db.add(Vulnerability(id="legacy", data={**facts, "source_records": [{"source": "osv-debian", **facts}]},
                             title=facts["title"], updated_at=OBSERVED))
        db.flush()
        db.add(Alias(alias="DEBIAN-CVE-2020-12345", vulnerability_id="legacy"))
        db.add(SourceRecord(source_id="osv-debian", source_key=facts["source_key"], vulnerability_id="legacy",
                            data=facts, fingerprint="legacy"))
        batch = Batch(id="frozen", slot="2026-10-23T09:00+08:00", cutoff=OBSERVED, status="analyzing")
        db.add(batch)
        db.flush()
        item = BatchItem(batch_id=batch.id, vulnerability_id="legacy", snapshot=copy.deepcopy(facts),
                         priority=True, analysis={"saved": True})
        db.add(item)
        db.commit()
        while not backfill_step(db, limit=1):
            db.commit()
        db.commit()
        assert db.scalar(select(func.count()).select_from(Vulnerability)) == 1
        canonical = db.get(Alias, "CVE-2020-12345").vulnerability_id
        assert db.get(Alias, "DEBIAN-CVE-2020-12345").vulnerability_id == canonical
        latest = db.scalar(select(Revision).where(Revision.vulnerability_id == canonical)
                           .order_by(Revision.id.desc()).limit(1))
        assert latest.published_at == datetime(2020, 1, 1)
        assert item.snapshot == facts and item.analysis == {"saved": True}
        assert db.get(Batch, "frozen").status == "analyzing"
        assert nvd in {canonical, "legacy"}  # Winning UUID does not define event time.


def test_metadata_repair_replays_real_changes_and_keeps_frozen_batch(store, monkeypatch):
    monkeypatch.setattr("vulintel.timeline.now", lambda: OBSERVED)
    with store() as db:
        identity = ingest(db, "nvd", entry("CVE-2020-12345", "旧漏洞", "", ["CVE-2020-12345"],
                                          affected=[{"product": "P", "versions": ["1"]}],
                                          published="2020-01-01T00:00:00Z"))
        db.commit()
        initial = db.scalar(select(Revision).where(Revision.vulnerability_id == identity))
        initial.snapshot = {**initial.snapshot, "timeline": {**initial.snapshot["timeline"], "event_policy": 2}}
        changed = copy.deepcopy(initial.snapshot)
        changed["source_records"][0]["affected"] = [{"product": "P", "versions": ["1", "2"]}]
        legacy = Revision(vulnerability_id=identity, observed_at=OBSERVED + timedelta(seconds=1),
                          first_seen_at=initial.first_seen_at, published_at=initial.published_at,
                          important_at=OBSERVED + timedelta(seconds=1), content_hash="legacy",
                          snapshot_bytes=1000, snapshot=changed)
        db.add(legacy)
        db.commit()
        before = copy.deepcopy(initial.snapshot)
        while not backfill_step(db, limit=1):
            db.commit()
        db.commit()
        latest = db.scalar(select(Revision).order_by(Revision.id.desc()).limit(1))
        assert latest.snapshot["timeline"]["event_policy"] == EVENT_POLICY
        assert latest.important_at == OBSERVED + timedelta(seconds=1)
        assert latest.first_seen_at == initial.first_seen_at
        assert initial.snapshot == before
        count = db.scalar(select(func.count()).select_from(Revision))
        assert backfill_step(db)
        db.commit()
        assert db.scalar(select(func.count()).select_from(Revision)) == count
        assert db.get(MetadataState, BACKFILL_KEY).value["complete"]


def test_audit_groups_distro_duplicates_and_distinguishes_calendar_week():
    nvd = {"title": "公开记录", "source_key": "CVE-2026-12345", "aliases": ["CVE-2026-12345"],
           "published": "2026-10-17T00:00:00Z", "report_category": "new"}
    debian = {**distro("CVE-2026-12345"), "report_category": "new"}
    result = audit_items([(1, nvd), (2, debian)], datetime(2026, 10, 23, 10))
    assert result["identity_groups"] == 1 and result["summary"]["duplicate_rows"] == 1
    assert result["summary"]["supported_in_window"] == 1
    assert result["summary"].get("supported_in_calendar_week", 0) == 0
    assert result["groups"][0]["earliest_supported_publication"] == nvd["published"]


def test_old_cve_id_year_is_not_used_to_guess_publication():
    facts = {"title": "迟公开", "aliases": ["CVE-2012-20002"], "published": "2026-10-20T00:00:00Z"}
    assert projection(facts).published_at == datetime(2026, 10, 20)


def test_audit_report_is_read_only_and_can_find_earlier_canonical_record(store, monkeypatch):
    monkeypatch.setattr("vulintel.timeline.now", lambda: OBSERVED)
    with store() as db:
        identity = ingest(db, "nvd", entry("CVE-2020-12345", "旧漏洞", "", ["CVE-2020-12345"],
                                          published="2020-01-01T00:00:00Z"))
        db.commit()
        # Simulate a frozen v2 report that mistook a distro entry date for a new CVE.
        from vulintel.db import Batch
        batch = Batch(id="audit", slot="2026-10-23T18:00+08:00", cutoff=datetime(2026, 10, 23, 10))
        db.add(batch)
        db.flush()
        facts = {**distro(), "report_category": "new"}
        item = BatchItem(batch_id=batch.id, vulnerability_id="legacy-distro", snapshot=facts, priority=True,
                         analysis={"saved": True})
        db.add(item)
        db.commit()
        before = copy.deepcopy(item.snapshot)
        result = audit_report(db, batch.id)
        assert result["original_new_rows_by_corrected_group"] == {"outside_window": 1}
        assert item.snapshot == before and item.analysis == {"saved": True}
        assert db.get(Alias, "CVE-2020-12345").vulnerability_id == identity
