"""Versioned publication decisions, independent of immutable historical facts.

An entry's publication is not a disclosure assertion. No date is synthesized from
an import time, an identifier's year, a URL path, or an upstream modified field.
"""
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from .db import (DateEvidenceCache, Job, PublicationAnnotation, PublicationState,
                 RevisionDateProjection, Vulnerability, now)
from .identity import CVE_ID

DATE_POLICY = 1
VERIFIED = {"confirmed", "day"}
REPAIR_KEY = "publication_date_repair_v1"
RSS_SOURCES = {"nodejs", "go-blog", "php", "debian", "ubuntu", "cisco", "fortinet", "cisa-advisories"}
DATES_BLOCKED = "公开日期修复尚未完成，请运行 repair-publication-dates --rebuild-unpublished 恢复"
DATES_MISSING = "日期标注或历史投影尚未就绪，请运行 repair-publication-dates 恢复"


def iso(value):
    return value.isoformat() + "Z" if value else None


def https_url(value):
    if not isinstance(value, str) or len(value) > 2048:
        return False
    try:
        parsed = urlsplit(value)
        return bool(parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
                    and parsed.port in (None, 443))
    except ValueError:
        return False


def date_interval(raw, zone=None):
    """Conservative UTC bounds; a day stays a day, never a fabricated instant."""
    if not isinstance(raw, str):
        return None
    try:
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", raw):
            local = datetime.fromisoformat(raw)
            if local.year <= 1:
                return None
            if zone:
                begin = local.replace(tzinfo=ZoneInfo(zone)).astimezone(timezone.utc).replace(tzinfo=None)
                end = (local + timedelta(days=1)).replace(tzinfo=ZoneInfo(zone)).astimezone(timezone.utc).replace(tzinfo=None)
            else:
                # An unspecified local day can span UTC-12 through UTC+14.
                begin, end = local - timedelta(hours=14), local + timedelta(days=1, hours=12)
            return begin, end, "day"
        try:
            value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            value = parsedate_to_datetime(raw)
        if value.year <= 1 or (value.tzinfo is None and not zone):
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=ZoneInfo(zone))
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
        if value.year <= 1:
            return None
        return value, value, "datetime"
    except (ValueError, TypeError, OverflowError, KeyError):
        return None


def proof(source, key, field, value, kind, url, zone=None):
    return {"source": source, "source_key": key, "field": field, "original": value,
            "kind": kind, "url": url, "timezone": zone}


def source_evidence(data):
    evidence = []
    for record in data.get("source_records", [data]):
        source, key = record.get("source", ""), record.get("source_key", "")
        urls = [url for url in record.get("references", []) if https_url(url)]
        url = record.get("publication_reference") or next(iter(urls), "")
        if source == "nvd" and CVE_ID.fullmatch(str(key)):
            url = "https://nvd.nist.gov/vuln/detail/" + key
        elif source == "ghsa" and re.fullmatch(r"GHSA-[A-Za-z0-9-]+", str(key)):
            url = "https://github.com/advisories/" + key
        elif source == "msrc" and CVE_ID.fullmatch(str(key)):
            url = "https://msrc.microsoft.com/update-guide/vulnerability/" + key
        value = record.get("published")
        # Explicit upstream fields, not the legacy publication_scope default.
        if record.get("disclosed_at"):
            evidence.append(proof(source, key, "disclosed_at", record["disclosed_at"], "disclosure",
                                  record.get("disclosure_reference") or url, record.get("publication_timezone")))
        kind = "source_entry"
        field = "published"
        if source == "nvd":
            kind = "record_publication"
        elif source == "ghsa":
            kind, field = "advisory_publication", "published_at"
        elif source == "msrc":
            kind = "advisory_publication" if record.get("publication_kind") == "initial_disclosure" else "revision_entry"
            field = "RevisionHistory.Revision.Date"
        elif source == "kev":
            kind, value = "kev_added", record.get("kev_added_at")
        elif source in {"apple", "android", "nodejs", "go-blog", "php", "debian", "ubuntu", "cisco", "fortinet", "cisa-advisories"}:
            kind = "advisory_publication"
        if source in RSS_SOURCES:
            # Old adapters erased timezone/precision and sometimes substituted
            # publication for update. Retain that value only as legacy evidence.
            if "feed_published_original" not in record:
                kind, field = "source_entry", "legacy_normalized_feed_published"
            else:
                value, field = record["feed_published_original"], "feed.published"
        if source == "android" and record.get("publication_basis") == "Android 公告日期":
            kind, field = "source_entry", "legacy_url_inferred_date"
        if record.get("record_type") == "bulletin" and len(set(record.get("mentioned_cves", []))) != 1:
            kind = "bulletin_publication"
        # Every OSV ecosystem is a database entry unless separately supported by
        # an explicit disclosure assertion. Historical v3/v4 scope is ignored.
        if source.startswith("osv-") or record.get("source_authority") == "OSV":
            kind = "source_entry"
        if value:
            evidence.append(proof(source, key, field, value, kind, url,
                                  "UTC" if source in {"nvd", "msrc", "ghsa"} or source.startswith("osv-") else
                                  record.get("publication_timezone")))
    return evidence


def resolve_publication(data, extra=(), assessed=None):
    assessed = assessed or now()
    evidence = source_evidence(data) + list(extra)
    valid, rejected = [], []
    for original in evidence:
        item = dict(original)
        bounds = date_interval(item.get("original"), item.get("timezone"))
        reason = ""
        if not https_url(item.get("url")):
            reason = "missing_public_https_reference"
        elif not bounds:
            reason = "invalid_date_or_unknown_timezone"
        elif bounds[0] > assessed:
            reason = "future_date"
        if reason:
            rejected.append({**item, "rejected_reason": reason})
            continue
        begin, end, precision = bounds
        # The evidence is already public at assessment; this caps uncertainty,
        # without claiming that assessment is the actual disclosure time.
        end = min(end, assessed)
        valid.append({**item, "start_at": iso(begin), "end_at": iso(end), "precision": precision})
    public = [item for item in valid if item["kind"] in {"disclosure", "advisory_publication"}]
    def instant(value):
        return datetime.fromisoformat(value.removesuffix("Z"))
    public.sort(key=lambda item: (instant(item["start_at"]), instant(item["end_at"]), item["source"], item["field"]))
    disclosures = [item for item in public if item["kind"] == "disclosure"]
    conflicts = []
    for first, second in zip(disclosures, disclosures[1:]):
        if instant(first["end_at"]) < instant(second["start_at"]):
            conflicts.append({"reason": "inconsistent_explicit_disclosure_dates", "claims": [first, second]})
    selected = public[0] if public else None
    if selected:
        earlier = [item for item in valid if item["kind"] in {"record_publication", "source_entry"}
                   and instant(item["end_at"]) < instant(selected["start_at"])]
        if earlier:
            conflicts.append({"reason": "record_already_public_before_claim", "claims": earlier})
    status = "conflict" if conflicts else selected["precision"] if selected and selected["precision"] == "day" else "confirmed" if selected else "unknown"
    if status not in VERIFIED:
        selected = None
    result = {"date_policy": DATE_POLICY, "publication_status": status,
              "published_at": (selected["original"] if selected["precision"] == "day" else selected["start_at"]) if selected else None,
              "publication_source": selected["source"] if selected else None,
              "publication_basis": ("明确披露日期" if selected["kind"] == "disclosure" else "可对应到漏洞的原始公告公开日期") if selected else "日期冲突" if conflicts else "未确认漏洞首次公开时间",
              "publication_field": selected["field"] if selected else None,
              "publication_original": selected["original"] if selected else None,
              "publication_precision": selected["precision"] if selected else None,
              "publication_reference": selected["url"] if selected else None,
              "publication_start_at": selected["start_at"] if selected else None,
              "publication_end_at": selected["end_at"] if selected else None,
              "date_evidence": valid, "rejected_date_evidence": rejected, "date_conflicts": conflicts,
              "cve_record_publications": [item for item in valid if item["kind"] == "record_publication"],
              "source_entry_publications": [item for item in valid if item["kind"] in {"source_entry", "revision_entry", "bulletin_publication"}]}
    return result


def cve_ids(data):
    return sorted({str(value).upper() for value in data.get("aliases", []) if CVE_ID.fullmatch(str(value))})


def cache_key(url):
    return hashlib.sha256(url.encode()).hexdigest()


def cached_evidence(db, data):
    evidence, diagnostics = [], []
    for cve in cve_ids(data):
        url = "https://cveawg.mitre.org/api/cve/" + cve
        row = db.get(DateEvidenceCache, cache_key(url))
        if row:
            evidence.extend(row.data.get("evidence", []))
            diagnostics.append({"url": url, "status": row.status, "checked_at": iso(row.checked_at),
                                "retry_at": iso(row.retry_at), "reason": row.data.get("reason")})
            for reference in row.data.get("references", []):
                cached = db.get(DateEvidenceCache, cache_key(reference))
                if cached:
                    evidence.extend(cached.data.get("evidence_by_cve", {}).get(cve, []))
                    diagnostics.append({"url": reference, "status": cached.status, "reason": cached.data.get("reason"),
                                        "retry_at": iso(cached.retry_at)})
    for url in data.get("references", []):
        if isinstance(url, str):
            row = db.get(DateEvidenceCache, cache_key(url))
            if row:
                for cve in cve_ids(data):
                    evidence.extend(row.data.get("evidence_by_cve", {}).get(cve, []))
                diagnostics.append({"url": url, "status": row.status, "reason": row.data.get("reason")})
    return evidence, diagnostics


def annotate(db, vuln, assessed=None, enqueue=True):
    assessed = assessed or now()
    extra, diagnostics = cached_evidence(db, vuln.data)
    data = resolve_publication(vuln.data, extra, assessed)
    data["date_fetches"] = diagnostics
    # Assessment bounds of an imprecise current day are knowledge-dependent;
    # keep them versioned. No original source facts are edited.
    identity_data = {key: value for key, value in data.items() if key not in {"publication_end_at", "date_fetches"}}
    identity_data["date_fetch_outcomes"] = sorted({(item["url"], item["status"], item.get("reason"))
                                                  for item in diagnostics}, key=lambda item: item[0])
    identity_data["date_evidence"] = [{key: value for key, value in item.items() if key != "end_at"}
                                      for item in data["date_evidence"]]
    fingerprint = hashlib.sha256(json.dumps(identity_data, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    current = db.get(PublicationState, vuln.id)
    previous = db.get(PublicationAnnotation, current.annotation_id) if current else None
    if previous and previous.fingerprint == fingerprint and previous.policy == DATE_POLICY:
        annotation = previous
    else:
        from .timeline import stamp
        from .db import Revision
        legacy = db.scalar(select(Revision).where(Revision.vulnerability_id == vuln.id).order_by(Revision.id.desc()).limit(1))
        old_value = previous.data.get("published_at") if previous else iso(legacy.published_at) if legacy else None
        data["date_correction"] = {"previous_annotation_id": previous.id if previous else None,
                                   "original_revision_id": legacy.id if legacy else None,
                                   "previous_published_at": old_value,
                                   "changed": old_value != data.get("published_at")}
        annotation = PublicationAnnotation(vulnerability_id=vuln.id, policy=DATE_POLICY, assessed_at=assessed,
                    status=data["publication_status"], start_at=stamp(data["publication_start_at"]),
                    end_at=stamp(data["publication_end_at"]), fingerprint=fingerprint, data=data)
        db.add(annotation)
        db.flush()
        if current is None:
            current = PublicationState(vulnerability_id=vuln.id)
            db.add(current)
        current.annotation_id, current.policy, current.status = annotation.id, DATE_POLICY, annotation.status
        current.start_at, current.end_at = annotation.start_at, annotation.end_at
    if enqueue and cve_ids(vuln.data):
        from .date_enrichment import allowed_reference
        urls = {"https://cveawg.mitre.org/api/cve/" + cve for cve in cve_ids(vuln.data)}
        for url in list(urls):
            cached = db.get(DateEvidenceCache, cache_key(url))
            if cached:
                urls.update(cached.data.get("references", []))
        urls.update(url for url in vuln.data.get("references", []) if allowed_reference(url))
        missing = any((row := db.get(DateEvidenceCache, cache_key(url))) is None
                      or row.retry_at <= assessed for url in urls)
        job = db.scalar(select(Job).where(Job.kind == "publication", Job.source_id == vuln.id,
                                         Job.status.in_(["pending", "running"])).limit(1))
        if missing and job is None:
            db.add(Job(kind="publication", source_id=vuln.id))
    return annotation, diagnostics


def project_revision(db, revision, derived=None):
    from .timeline import EVENT_POLICY, derive_revision, stamp
    from types import SimpleNamespace
    derived = derived or derive_revision(SimpleNamespace(id=revision.vulnerability_id, data=revision.snapshot),
                                        observed=revision.observed_at, baseline=True)
    row = db.get(RevisionDateProjection, revision.id)
    if row is None:
        row = RevisionDateProjection(revision_id=revision.id)
        db.add(row)
    row.policy, row.timeline = EVENT_POLICY, dict(derived.snapshot["timeline"])
    row.important_at = derived.important_at
    row.important_end_at = stamp(row.timeline.get("important_end_at")) or row.important_at
    return row


def corrected_snapshot(revision, projection, annotation):
    from .timeline import EVENT_POLICY
    if projection is None or projection.policy != EVENT_POLICY or annotation is None or annotation.policy != DATE_POLICY:
        raise ValueError(DATES_MISSING)
    timeline = {**projection.timeline, **annotation.data, "date_annotation_id": annotation.id,
                "date_assessed_at": iso(annotation.assessed_at), "event_policy": EVENT_POLICY}
    date_references = sorted({item["url"] for item in annotation.data.get("date_evidence", []) if https_url(item.get("url"))})
    return {**revision.snapshot, "timeline": timeline, "date_references": date_references}


def date_in_window(annotation, start, cutoff):
    return bool(annotation and annotation.status in VERIFIED and annotation.start_at is not None
                and annotation.start_at >= start and annotation.end_at <= cutoff)


def coverage(db):
    counts = dict(db.execute(select(PublicationState.status, func.count()).where(
        PublicationState.policy == DATE_POLICY).group_by(PublicationState.status)).all())
    total = db.scalar(select(func.count()).select_from(Vulnerability))
    return {"date_policy": DATE_POLICY, "total": total, "confirmed": counts.get("confirmed", 0),
            "day": counts.get("day", 0), "unknown": counts.get("unknown", 0), "conflict": counts.get("conflict", 0),
            "missing_current_annotation": max(0, total - sum(counts.values())),
            "evidence_fetch_errors": db.scalar(select(func.count()).select_from(DateEvidenceCache).where(DateEvidenceCache.status == "error")),
            "pending_evidence_jobs": db.scalar(select(func.count()).select_from(Job).where(Job.kind == "publication", Job.status == "pending"))}


def replay_projections(db, vulnerability_id):
    """Recompute every observation, retaining original facts and observation times."""
    from types import SimpleNamespace
    from .db import Revision
    from .timeline import derive_revision
    ids = list(db.scalars(select(Revision.id).where(Revision.vulnerability_id == vulnerability_id)
                          .order_by(Revision.observed_at, Revision.id)))
    if not ids:
        from .timeline import append_revision
        vuln = db.get(Vulnerability, vulnerability_id)
        revision = append_revision(db, vuln, observed=vuln.updated_at, baseline=True)
        db.flush()
        ids = [revision.id]
    previous, sources = None, {}
    for identity in ids:
        original = db.get(Revision, identity)
        for record in original.snapshot.get("source_records", []):
            sources[(record.get("source"), record.get("source_key"))] = record
        facts = {**original.snapshot, "source_records": list(sources.values())} if sources else original.snapshot
        if sources:
            facts["exploited"] = any(record.get("exploited", False) for record in sources.values())
        previous = derive_revision(SimpleNamespace(id=vulnerability_id, data=facts), previous,
                                   observed=original.observed_at, baseline=previous is None)
        project_revision(db, original, derived=previous)
        db.flush()
        db.expunge(original)
    return len(ids)
