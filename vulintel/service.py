import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, update

from .db import Alias, Audit, Batch, BatchItem, Delivery, Source, SourceRecord, Vulnerability, now, uid
from .sources import RANK


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def audit(db, actor, action, target):
    db.add(Audit(actor=actor[:200], action=action, target=str(target)[:200]))


def ingest(db, source_id, data):
    """Idempotent source records; aliases link CVEs, never a bulletin's mentioned CVEs."""
    source_key = data["source_key"][:240]
    record = db.scalar(select(SourceRecord).where(SourceRecord.source_id == source_id,
                                                SourceRecord.source_key == source_key))
    fingerprint = digest({k: v for k, v in data.items() if k not in {"modified"}})
    if record and record.fingerprint == fingerprint:
        return record.vulnerability_id
    aliases = sorted(set([str(a).upper() for a in data.get("aliases", [])] or [f"{source_id}:{source_key}".upper()]))
    ids = list(db.scalars(select(Alias.vulnerability_id).where(Alias.alias.in_(aliases)).distinct()))
    if record:
        ids.append(record.vulnerability_id)
    ids = sorted(set(ids))
    if ids:
        vuln = db.get(Vulnerability, ids[0])
        # Late alias bridging can merge previously separate source entities.
        for other in ids[1:]:
            db.execute(update(Alias).where(Alias.vulnerability_id == other).values(vulnerability_id=vuln.id))
            db.execute(update(SourceRecord).where(SourceRecord.vulnerability_id == other).values(vulnerability_id=vuln.id))
            # Historical batch snapshots deliberately retain their immutable original identity.
            db.execute(delete(Vulnerability).where(Vulnerability.id == other))
    else:
        vuln = Vulnerability(id=uid(), data={}, title=data["title"])
        db.add(vuln)
        db.flush()
    for alias in aliases:
        if not db.get(Alias, alias):
            db.add(Alias(alias=alias, vulnerability_id=vuln.id))
    if record is None:
        record = SourceRecord(source_id=source_id, source_key=source_key,
                              vulnerability_id=vuln.id, data=data, fingerprint=fingerprint)
        db.add(record)
    else:
        record.data, record.fingerprint, record.vulnerability_id = data, fingerprint, vuln.id
    db.flush()
    records = list(db.scalars(select(SourceRecord).where(SourceRecord.vulnerability_id == vuln.id)))
    # Rich structured records precede KEV; all source facts remain inspectable.
    ordered = sorted(records, key=lambda r: (r.source_id == "kev", r.source_id.startswith("osv-"), r.source_id))
    main = ordered[0].data
    all_aliases = sorted(db.scalars(select(Alias.alias).where(Alias.vulnerability_id == vuln.id)))
    severity = max((r.data.get("severity", "unknown") for r in records), key=lambda s: RANK.get(s, 0))
    merged = {**main, "id": vuln.id, "aliases": all_aliases, "severity": severity,
              "exploited": any(r.data.get("exploited", False) for r in records),
              "references": sorted({url for r in records for url in r.data.get("references", [])}),
              "source_records": [{"source": r.source_id, **r.data} for r in ordered]}
    vuln.data = merged
    vuln.title = main["title"]
    vuln.product = " ".join(sorted({json.dumps(r.data.get("affected", []), ensure_ascii=False) for r in records}))
    vuln.severity, vuln.exploited = severity, merged["exploited"]
    vuln.updated_at = now()
    return vuln.id


def source_status(db):
    return [{"id": s.id, "name": s.name, "enabled": s.enabled,
             "last_success_utc": s.last_success.isoformat() + "Z" if s.last_success else None,
             "error": s.error,
             "stale": not s.last_success or (now() - s.last_success) > timedelta(hours=2)}
            for s in db.scalars(select(Source).order_by(Source.id))]


def due_slot():
    local = datetime.now(timezone.utc).astimezone(ZoneInfo("Asia/Shanghai"))
    if local.hour >= 18:
        local = local.replace(hour=18, minute=0, second=0, microsecond=0)
    elif local.hour >= 9:
        local = local.replace(hour=9, minute=0, second=0, microsecond=0)
    else:
        local = (local - timedelta(days=1)).replace(hour=18, minute=0, second=0, microsecond=0)
    return local.isoformat(timespec="minutes")


def open_batch(db, actor, slot=None):
    slot = slot or due_slot()
    cutoff = datetime.fromisoformat(slot)
    if (cutoff.tzinfo is None or cutoff.utcoffset() != timedelta(hours=8) or cutoff.hour not in {9, 18}
            or cutoff.minute or cutoff.second or cutoff.microsecond):
        raise ValueError("Slot must be YYYY-MM-DDT09:00+08:00 or YYYY-MM-DDT18:00+08:00")
    cutoff = cutoff.astimezone(timezone.utc).replace(tzinfo=None)
    if cutoff > now():
        raise ValueError("Cannot create a future report slot")
    slot = cutoff.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Shanghai")).isoformat(timespec="minutes")
    if db.bind.dialect.name == "postgresql":
        db.execute(select(func.pg_advisory_xact_lock(86221023)))
    existing = db.scalar(select(Batch).where(Batch.slot == slot))
    if existing:
        return {"batch_id": existing.id, "slot": existing.slot, "status": existing.status}
    pending = db.scalar(select(Batch).where(Batch.status != "finalized").order_by(Batch.cutoff))
    if pending:
        return {"batch_id": pending.id, "slot": pending.slot, "status": pending.status,
                "note": "Resume the unfinished batch before opening a later slot"}
    last = db.scalar(select(Batch).where(Batch.status == "finalized").order_by(Batch.cutoff.desc()))
    if last and cutoff <= last.cutoff:
        raise ValueError("Slot precedes the last finalized report")
    batch = Batch(id=uid(), slot=slot, cutoff=cutoff, coverage=source_status(db))
    db.add(batch)
    db.flush()
    query = select(Vulnerability).where(Vulnerability.updated_at <= cutoff)
    if last:
        query = query.where(Vulnerability.updated_at > last.cutoff)
    for vuln in db.scalars(query.execution_options(yield_per=50)):
        priority = vuln.exploited or vuln.severity in {"high", "critical", "unknown"} or bool(last)
        # All changes after a previous report are reviewed, so patch/exploit updates aren't missed.
        db.add(BatchItem(batch_id=batch.id, vulnerability_id=vuln.id, snapshot=vuln.data, priority=priority))
    audit(db, actor, "batch.create", batch.id)
    db.commit()
    return {"batch_id": batch.id, "slot": batch.slot, "status": batch.status}


def batch_page(db, batch_id, after=0, limit=10, pending_only=False):
    batch = db.get(Batch, batch_id)
    if not batch:
        raise ValueError("Unknown batch")
    if limit < 1 or limit > 20 or after < 0:
        raise ValueError("Invalid pagination")
    query = select(BatchItem).where(BatchItem.batch_id == batch_id, BatchItem.id > after)
    if pending_only:
        query = query.where(BatchItem.priority.is_(True), BatchItem.analysis.is_(None))
    items = list(db.scalars(query.order_by(BatchItem.id).limit(limit + 1)))
    page = items[:limit]
    pending = db.scalar(select(func.count()).select_from(BatchItem).where(
        BatchItem.batch_id == batch_id, BatchItem.priority.is_(True), BatchItem.analysis.is_(None)))
    return {"batch_id": batch_id, "status": batch.status, "slot": batch.slot,
            "coverage": batch.coverage, "pending_analysis": pending,
            "items": [{"item_id": i.id, "priority": i.priority, "snapshot": i.snapshot,
                       "analysis": i.analysis} for i in page],
            "next_after": page[-1].id if len(items) > limit else None}


class Analysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    item_id: int
    root_cause: str = Field(min_length=1, max_length=8000)
    trigger_conditions: str = Field(min_length=1, max_length=8000)
    impact: str = Field(min_length=1, max_length=8000)
    affected_versions: str = Field(min_length=1, max_length=8000)
    attack_path: str = Field(min_length=1, max_length=8000)
    remediation: str = Field(min_length=1, max_length=8000)
    evidence_level: Literal["vendor_confirmed", "public_poc", "third_party_verified", "inference", "unknown"]
    evidence_notes: str = Field(min_length=1, max_length=8000)
    references: list[str] = Field(min_length=1, max_length=50)

    @field_validator("references")
    @classmethod
    def safe_references(cls, values):
        from urllib.parse import urlsplit
        for value in values:
            parsed = urlsplit(value)
            if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("Evidence references must be public HTTPS URLs")
        return values


def submit_analysis(db, actor, batch_id, analyses):
    batch = db.scalar(select(Batch).where(Batch.id == batch_id).with_for_update())
    if not batch or batch.status == "finalized":
        raise ValueError("Batch is missing or finalized")
    prepared = []
    for raw in analyses:
        analysis = raw if isinstance(raw, Analysis) else Analysis.model_validate(raw)
        item = db.get(BatchItem, analysis.item_id)
        if not item or item.batch_id != batch_id:
            raise ValueError("Analysis references an item outside this batch")
        prepared.append((item, analysis.model_dump(exclude={"item_id"})))
    for item, data in prepared:
        item.analysis = data
    batch.status, batch.error = "analyzing", None
    audit(db, actor, "batch.submit_analysis", batch_id)
    db.commit()
    return {"saved": len(prepared), "batch_id": batch_id}


def mark_batch_failed(db, actor, batch_id, error_type):
    batch = db.get(Batch, batch_id)
    if batch and batch.status != "finalized":
        batch.status, batch.error = "failed", error_type + " · 报告未完成，请恢复批次或检查运行日志"
        audit(db, actor, "batch.failed", batch_id)
        db.commit()


def finalize(db, actor, batch_id, summary):
    from .delivery import prepare_deliveries
    from .reports import render_report
    batch = db.scalar(select(Batch).where(Batch.id == batch_id).with_for_update())
    if not batch:
        raise ValueError("Unknown batch")
    if batch.status == "finalized":
        return {"batch_id": batch_id, "status": "finalized", "note": "Already finalized; not resent"}
    missing = db.scalar(select(func.count()).select_from(BatchItem).where(
        BatchItem.batch_id == batch_id, BatchItem.priority.is_(True), BatchItem.analysis.is_(None)))
    if missing:
        raise ValueError(f"{missing} priority items still require analysis")
    batch.summary = summary
    count = db.scalar(select(func.count()).select_from(BatchItem).where(BatchItem.batch_id == batch_id))
    artifacts = render_report(batch, db)
    # Artifacts are reproducible; DB transaction makes the final state + delivery rows atomic.
    prepare_deliveries(db, batch, None, artifacts)
    batch.status, batch.error = "finalized", None
    audit(db, actor, "batch.finalize", batch_id)
    db.commit()
    return {"batch_id": batch_id, "status": "finalized", "items": count}


def delivery_status(db, batch_id):
    return [{"id": d.id, "channel": d.channel, "part": d.part, "status": d.status,
             "attempts": d.attempts, "error": d.error}
            for d in db.scalars(select(Delivery).where(Delivery.batch_id == batch_id).order_by(Delivery.channel, Delivery.part))]
