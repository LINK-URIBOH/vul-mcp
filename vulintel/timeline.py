"""Publication provenance, substantive changes and resumable historical metadata repair."""
import hashlib
import json
import re
from datetime import datetime, timezone

from sqlalchemy import select

from .db import MetadataState, Revision, Vulnerability, now


def stamp(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if result.tzinfo is None:
            result = result.replace(tzinfo=timezone.utc)
        return result.astimezone(timezone.utc).replace(tzinfo=None)
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


def material(data):
    """Source additions alone do not constitute a patch or impact change."""
    return {record.get("source", ""): {key: record.get(key) for key in
            ("affected", "remediations", "remediation", "exploited", "withdrawn")}
            for record in data.get("source_records", [])}


def append_revision(db, vuln, previous=None, observed=None, baseline=False):
    latest = db.scalar(select(Revision).where(Revision.vulnerability_id == vuln.id)
                       .order_by(Revision.id.desc()).limit(1))
    observed = observed or now()
    data = dict(vuln.data)
    records = data.get("source_records", [data])
    dates, updates, kev, patches = [], [], [], []
    for record in records:
        source = record.get("source", "")
        original_public = record.get("published")
        public = stamp(original_public) if source != "kev" else None
        basis = record.get("publication_basis", "上游公开时间")
        if not public and source in {"apple", "android"}:
            value, basis = explicit_publication(record.get("description", ""), source,
                                                next(iter(record.get("references", [])), ""))
            original_public = value
            public = stamp(value)
        if public and public <= observed:
            dates.append((public, source, basis, str(original_public), "day" if len(str(original_public)) == 10 else "datetime"))
        modified = stamp(record.get("modified"))
        if modified and modified <= observed:
            updates.append(modified)
        if source == "kev":
            added = stamp(record.get("kev_added_at") or record.get("published"))
            if added and added <= observed:
                kev.append(added)
        elif source == "nvd":
            added = stamp(record.get("exploitation_added_at"))
            if added and added <= observed:
                kev.append(added)
        for remediation in record.get("remediations", []):
            if isinstance(remediation, dict):
                released = stamp(remediation.get("Date"))
                if released and released <= observed:
                    patches.append(released)
    dates.sort()
    published = dates[0][0] if dates else None
    previous = previous if previous is not None else (latest.snapshot if latest else {})
    first_seen = latest.first_seen_at if latest else (None if baseline or previous else observed)
    old_material, new_material = material(previous), material(data)
    changed = any(new_material[source] != old_material[source] for source in old_material.keys() & new_material.keys())
    important = latest.important_at if latest else None
    if kev:
        important = max([*kev, *([important] if important else [])])
    if patches:
        important = max([*patches, *([important] if important else [])])
    if previous and not baseline and (changed or (data.get("exploited") and not previous.get("exploited") and not kev)):
        important = observed
    data["product_group"] = product_group(data)
    data["timeline"] = {
        "published_at": iso(published), "publication_source": dates[0][1] if dates else None,
        "publication_basis": dates[0][2] if dates else "未确认",
        "publication_original": dates[0][3] if dates else None,
        "publication_precision": dates[0][4] if dates else None,
        "upstream_updated_at": iso(max(updates)) if updates else None,
        "first_seen_at": iso(first_seen), "material_changed_at": iso(important),
        "kev_added_at": iso(max(kev)) if kev else None,
        "patch_published_at": iso(max(patches)) if patches else None,
        "change_basis": ("CISA KEV 收录时间" if kev and important == max(kev) else
                         "修复／缓解发布时间" if patches and important == max(patches) else
                         "实质变化观察时间" if important else "未确认"),
    }
    # Ignore timestamp-only changes, but preserve corrections to publication provenance.
    comparable = {k: v for k, v in data.items() if k not in {"modified", "timeline"}}
    comparable["publication"] = data["timeline"]["published_at"]
    fingerprint = hashlib.sha256(json.dumps(comparable, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    if latest and latest.content_hash == fingerprint:
        return latest
    encoded = json.dumps(data, ensure_ascii=False).encode()
    revision = Revision(vulnerability_id=vuln.id, observed_at=observed, first_seen_at=first_seen,
                        published_at=published, important_at=important, content_hash=fingerprint,
                        snapshot_bytes=len(encoded), snapshot=data)
    db.add(revision)
    return revision


def backfill_step(db, limit=100):
    state = db.get(MetadataState, "publication_backfill_v2")
    if not state:
        state = MetadataState(key="publication_backfill_v2", value={"cursor": "", "processed": 0})
        db.add(state)
        db.flush()
    value = dict(state.value)
    if value.get("complete"):
        return True
    # Select identifiers only; at most one large facts object is materialized at a time.
    ids = list(db.scalars(select(Vulnerability.id).where(Vulnerability.id > value.get("cursor", ""))
                          .order_by(Vulnerability.id).limit(limit)))
    budget = 0
    for identity in ids:
        vuln = db.get(Vulnerability, identity)
        existing = db.scalar(select(Revision.id).where(Revision.vulnerability_id == identity).limit(1))
        if existing is None:
            revision = append_revision(db, vuln, observed=vuln.updated_at, baseline=True)
            budget += revision.snapshot_bytes
            db.flush()
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
    if source_id == "android":
        candidate = url.rsplit("/", 1)[-1]
        if re.fullmatch(r"\d{4}-\d{2}-\d{2}", candidate) and stamp(candidate):
            return candidate, "Android 公告日期"
    return None, "未确认"
