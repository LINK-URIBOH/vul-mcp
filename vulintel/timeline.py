"""Publication provenance, substantive changes and resumable historical metadata repair."""
import hashlib
import json
import re
from datetime import datetime, timezone

from sqlalchemy import or_, select

from .db import MetadataState, Revision, SourceRecord, Vulnerability, now
from .identity import publication_scope, record_aliases

EVENT_POLICY = 5
BACKFILL_KEY = "source_event_backfill_v4"  # Legacy identity-repair checkpoint, not publication annotation readiness.


def stamp(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        result = result.astimezone(timezone.utc).replace(tzinfo=None)
        if result.year == 1:  # .NET/Go zero-time placeholders are not publication events.
            return None
        return result
    except (ValueError, TypeError, OverflowError):
        return None


def iso(value):
    return value.isoformat() + "Z" if value else None


def product_group(data):
    records = data.get("source_records", [data])
    def cpe_product(value, depth=0):
        if depth > 8:
            return None
        if isinstance(value, dict):
            criterion = value.get("criteria", "")
            if isinstance(criterion, str) and criterion.startswith("cpe:2.3:"):
                parts = re.split(r"(?<!\\):", criterion)
                if len(parts) >= 5:
                    return (parts[3] + " / " + parts[4]).replace("_", " ")[:160]
            for key in ("nodes", "children", "cpeMatch"):
                found = cpe_product(value.get(key), depth + 1)
                if found:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = cpe_product(child, depth + 1)
                if found:
                    return found
        return None
    for record in records:
        for value in record.get("affected", []):
            if isinstance(value, dict):
                package = value.get("package") or {}
                package = package if isinstance(package, dict) else {}
                name = value.get("product") or package.get("name")
                if isinstance(name, str) and name.strip():
                    ecosystem = package.get("ecosystem")
                    return ((str(ecosystem) + " / " if ecosystem else "") + name.strip())[:160]
        cpe = cpe_product(record.get("affected", []))
        if cpe:
            return cpe
    for record in records:
        authority = record.get("source_authority")
        if authority and authority not in {"NVD", "OSV", "GitHub Advisory", "CISA KEV"}:
            return authority[:160]
    return "其他产品／待确认"


def normalized(value):
    if isinstance(value, dict):
        return {key: normalized(child) for key, child in value.items()}
    if isinstance(value, list):
        return sorted((normalized(child) for child in value), key=lambda child: json.dumps(child, sort_keys=True))
    return value


def affected_facts(values, source=""):
    result = []
    for value in values or []:
        if isinstance(value, dict) and "package" in value:
            # A distro's unbounded introduced=0 range already covers every build;
            # enumerating another version does not change that range. Do not drop
            # explicit versions for other ecosystems or bounded ranges (OSV union).
            value = {key: value[key] for key in ("package", "ranges", "versions") if key in value}
            ranges = value.get("ranges") or []
            unbounded = any(r.get("type") == "ECOSYSTEM" and r.get("events") == [{"introduced": "0"}]
                            for r in ranges if isinstance(r, dict))
            if source in {"osv-debian", "osv-ubuntu"} and unbounded:
                value.pop("versions", None)
        result.append(value)
    return normalized(result)


def material(data):
    """Source additions alone do not constitute a patch or impact change."""
    result = {}
    for record in data.get("source_records", []):
        remediations = [{key: value for key, value in remediation.items() if key != "Date"}
                        if isinstance(remediation, dict) else remediation
                        for remediation in record.get("remediations", [])]
        result[(record.get("source", ""), record.get("source_key", ""))] = {
            "affected": affected_facts(record.get("affected"), record.get("source")),
            "remediations": normalized(remediations),
            "remediation": record.get("remediation"), "exploited": bool(record.get("exploited")),
            "withdrawn": bool(record.get("withdrawn"))}
    return result


def without_modified(value):
    if isinstance(value, dict):
        return {key: without_modified(child) for key, child in value.items() if key != "modified"}
    if isinstance(value, list):
        return [without_modified(child) for child in value]
    return value


def derive_revision(vuln, latest=None, previous=None, observed=None, baseline=False):
    """Recompute derived metadata without modifying an immutable source snapshot."""
    observed = observed or now()
    data = dict(vuln.data)
    records = data.get("source_records", [data])
    from .publication import RSS_SOURCES, date_interval, https_url, resolve_publication
    publication = resolve_publication(data, assessed=observed)
    updates, events, source_publications = [], [], []
    for record in records:
        source = record.get("source", "")
        reference = next((url for url in record.get("references", []) if https_url(url)), None)
        original_public = record.get("published")
        public = stamp(original_public) if source != "kev" else None
        basis = record.get("publication_basis", "上游公开时间")
        if not public and source in {"apple", "android"}:
            value, basis = explicit_publication(record.get("description", ""), source,
                                                next(iter(record.get("references", [])), ""))
            original_public = value
            public = stamp(value)
        scope = publication_scope(record)
        source_publications.append({"source": source, "source_key": record.get("source_key"),
                                    "original": original_public, "published_at": iso(public), "scope": scope,
                                    "valid": bool(public and public <= observed)})
        modified = stamp(record.get("modified"))
        if modified and modified <= observed:
            updates.append(modified)
        added = record.get("kev_added_at") if source == "kev" else record.get("exploitation_added_at") if source == "nvd" else None
        if added:
            events.append((added, None, "CISA KEV 收录时间", source,
                           "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "dateAdded"))
        for remediation in record.get("remediations", []):
            if isinstance(remediation, dict):
                url = remediation.get("URL") if https_url(remediation.get("URL")) else reference
                if remediation.get("Date") and url:
                    events.append((remediation["Date"], "UTC" if source == "msrc" else None,
                                   "修复／缓解发布时间", source, url, "remediations.Date"))
    published = stamp(publication.get("publication_start_at"))
    previous = previous if previous is not None else (latest.snapshot if latest else {})
    first_seen = (latest.first_seen_at if latest else
                  stamp(data.get("timeline", {}).get("first_seen_at")) if baseline else
                  None if previous else observed)
    old_material, new_material = material(previous), material(data)
    changed_fields = sorted({field for source in old_material.keys() & new_material.keys()
                             for field in new_material[source] if new_material[source][field] != old_material[source][field]})
    changed = bool(changed_fields)
    important = (latest.important_at if latest and stamp(latest.important_at)
                 and latest.snapshot.get("timeline", {}).get("event_policy") == EVENT_POLICY else None)
    old_timeline = latest.snapshot.get("timeline", {}) if latest else {}
    event_value = old_timeline.get("material_changed_at") if important else None
    event_end = old_timeline.get("important_end_at") if important else None
    event_precision = old_timeline.get("important_precision") if important else None
    event_basis = old_timeline.get("change_basis", "未确认") if important else "未确认"
    event_reference = old_timeline.get("important_reference") if important else None
    event_dates = []
    kev_value, patch_value = None, None
    observation = old_timeline.get("change_observed_at")
    if previous and not baseline and changed:
        observation = iso(observed)
        # A local comparison proves observation, not when a patch/disclosure
        # happened. Only dated publisher updates supply a reportable event.
        for record in records:
            key = (record.get("source", ""), record.get("source_key", ""))
            source = key[0]
            if (key in old_material and key in new_material and old_material[key] != new_material[key]
                    and source in {"ghsa", "msrc", "apple", "android", "nodejs", "go-blog", "php", "debian", "ubuntu", "cisco", "fortinet"}
                    and (source not in RSS_SOURCES or record.get("feed_updated_original"))
                    and any(https_url(url) for url in record.get("references", [])) and record.get("modified")):
                reference = next(url for url in record["references"] if https_url(url))
                events.append((record["modified"], "UTC" if source in {"msrc", "ghsa"} else None,
                               "公告重要内容更新时间", source, reference, "modified"))
    for raw, zone, event_reason, source, reference, field in events:
        bounds = date_interval(raw, zone)
        if not bounds or bounds[0] > observed:
            continue
        begin, end, precision = bounds
        event_dates.append({"source": source, "field": field, "original": raw, "timezone": zone,
                            "precision": precision, "start_at": iso(begin), "end_at": iso(min(end, observed)),
                            "basis": event_reason, "url": reference})
        if event_reason == "CISA KEV 收录时间":
            kev_value = raw
        elif event_reason == "修复／缓解发布时间":
            patch_value = raw
        if important is None or begin >= important:
            important, event_value, event_end = begin, raw if precision == "day" else iso(begin), iso(min(end, observed))
            event_precision, event_basis = precision, event_reason
            event_reference = reference
    data["product_group"] = product_group(data)
    data["timeline"] = {
        **publication, "event_policy": EVENT_POLICY, "source_publications": source_publications,
        "upstream_updated_at": iso(max(updates)) if updates else None,
        "first_seen_at": iso(first_seen), "material_changed_at": event_value,
        "important_end_at": event_end, "important_precision": event_precision,
        "important_reference": event_reference, "event_dates": event_dates,
        "change_observed_at": observation,
        "kev_added_at": kev_value, "patch_published_at": patch_value,
        "changed_fields": changed_fields if previous and not baseline else [],
        "change_basis": event_basis,
    }
    # Ignore timestamp-only changes, but preserve corrections to publication provenance.
    comparable = without_modified({k: v for k, v in data.items() if k != "timeline"})
    comparable["publication"] = {key: value for key, value in data["timeline"].items()
                                 if key not in {"upstream_updated_at", "source_publications", "changed_fields", "change_observed_at"}}
    fingerprint = hashlib.sha256(json.dumps(comparable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    if latest and latest.content_hash == fingerprint:
        return latest
    encoded = json.dumps(data, ensure_ascii=False).encode()
    revision = Revision(vulnerability_id=vuln.id, observed_at=observed, first_seen_at=first_seen,
                        published_at=published, important_at=important, content_hash=fingerprint,
                        snapshot_bytes=len(encoded), snapshot=data)
    return revision


def append_revision(db, vuln, previous=None, observed=None, baseline=False):
    latest = db.scalar(select(Revision).where(Revision.vulnerability_id == vuln.id)
                       .order_by(Revision.id.desc()).limit(1))
    revision = derive_revision(vuln, latest, previous, observed, baseline)
    if revision is not latest:
        db.add(revision)
    return revision


def backfill_step(db, limit=100):
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy import func
        db.execute(select(func.pg_advisory_xact_lock(86221026)))
    state = db.get(MetadataState, BACKFILL_KEY)
    if not state:
        state = MetadataState(key=BACKFILL_KEY, value={"cursor": "", "processed": 0, "phase": "aliases"})
        db.add(state)
        db.flush()
    value = dict(state.value)
    if value.get("complete"):
        return True
    if value.get("phase") == "aliases":
        from .service import ingest
        ids = list(db.scalars(select(SourceRecord.id).where(SourceRecord.id > value.get("alias_cursor", ""))
                              .order_by(SourceRecord.id).limit(limit)))
        budget = 0
        for identity in ids:
            record = db.get(SourceRecord, identity)
            budget += len(json.dumps(record.data, ensure_ascii=False).encode())
            if record_aliases(record.data) != record.data.get("aliases", []):
                value["relinked_records"] = value.get("relinked_records", 0) + 1
            # Rebuild even already-normalized records: v3 may have checkpointed
            # their aliases without replaying all merged facts. Never emit an
            # event (or change updated_at) merely because maintenance ran.
            ingest(db, record.source_id, record.data, maintenance=True)
            value["alias_cursor"] = identity
            value["alias_processed"] = value.get("alias_processed", 0) + 1
            db.flush()
            db.expunge(record)
            if budget >= 2_000_000:
                break
        if not ids:
            value["phase"] = "events"
        else:
            state.value = value
            db.flush()
            return False
    # Select identifiers only; at most one large facts object is materialized at a time.
    ids = list(db.scalars(select(Vulnerability.id).where(Vulnerability.id > value.get("cursor", ""))
                          .order_by(Vulnerability.id).limit(limit)))
    budget = 0
    for identity in ids:
        vuln = db.get(Vulnerability, identity)
        latest = db.scalar(select(Revision).where(Revision.vulnerability_id == identity)
                           .order_by(Revision.id.desc()).limit(1))
        legacy = None
        if latest is None:
            revision = append_revision(db, vuln, observed=vuln.updated_at, baseline=True)
            budget += revision.snapshot_bytes
            db.flush()
        else:
            budget += latest.snapshot_bytes
            policy_column = Revision.snapshot["timeline"]["event_policy"].as_integer()
            legacy = db.scalar(select(Revision.id).where(Revision.vulnerability_id == identity,
                               or_(policy_column != EVENT_POLICY, policy_column.is_(None))).limit(1))
        if latest is not None and (latest.snapshot.get("timeline", {}).get("event_policy") != EVENT_POLICY
                                   or (legacy and not latest.snapshot.get("timeline", {}).get("history_replayed"))
                                   or any(latest.snapshot.get(key) != child for key, child in vuln.data.items()
                                          if key != "timeline")):
            # Replay original facts in observation order. This preserves actual old
            # impact changes while removing zero dates and version-enumeration noise.
            # Only append the final corrected projection; keep all originals intact.
            from types import SimpleNamespace
            revision_ids = list(db.scalars(select(Revision.id).where(Revision.vulnerability_id == identity)
                                           .order_by(Revision.observed_at, Revision.id)))
            projection, source_history = None, {}
            for revision_id in revision_ids:
                original = db.get(Revision, revision_id)
                for facts in original.snapshot.get("source_records", []):
                    source_history[(facts.get("source"), facts.get("source_key"))] = facts
                data = {**original.snapshot, "source_records": list(source_history.values())}
                if source_history:
                    data["exploited"] = any(facts.get("exploited", False) for facts in source_history.values())
                projection = derive_revision(SimpleNamespace(id=identity, data=data),
                                             projection, observed=original.observed_at, baseline=projection is None)
                if original is not latest:
                    db.expunge(original)
            # The final projection must represent ALL current canonical records,
            # rather than whichever pre-merge identity happened to be seen last.
            projection = derive_revision(vuln, projection, observed=projection.observed_at, baseline=True)
            projection.snapshot = {**projection.snapshot, "timeline": {**projection.snapshot["timeline"],
                                                                         "history_replayed": True}}
            projection.snapshot_bytes = len(json.dumps(projection.snapshot, ensure_ascii=False).encode())
            db.add(projection)
            budget += projection.snapshot_bytes
            db.flush()
        if latest is not None:
            db.expunge(latest)
        value.update(cursor=identity, processed=value.get("processed", 0) + 1)
        db.expunge(vuln)
        if budget >= 2_000_000:
            break
    if not ids:
        value["complete"] = True
    state.value = value
    db.flush()
    return value.get("complete", False)


def explicit_publication(page, source_id, url):
    """Only named publication metadata or explicitly labelled dates, never a random page date."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(page, "html.parser")
    for attrs in ({"property": "article:published_time"}, {"itemprop": "datePublished"}, {"name": "datePublished"}):
        tag = soup.find("meta", attrs=attrs)
        if tag and stamp(tag.get("content")):
            return tag["content"], "厂商公告公开时间"
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(tag.get_text())
            objects = data if isinstance(data, list) else [data, *data.get("@graph", [])]
            for obj in objects:
                if isinstance(obj, dict) and stamp(obj.get("datePublished")):
                    return obj["datePublished"], "厂商结构化公开时间"
        except (ValueError, TypeError, AttributeError):
            continue
    match = re.search(r"Published Date:\s*([A-Za-z]+\s+\d{1,2},\s*\d{4})", soup.get_text(" ", strip=True))
    if match:
        try:
            return datetime.strptime(match[1], "%B %d, %Y").date().isoformat(), "厂商标注的公开日期"
        except ValueError:
            pass
    return None, "未确认"
