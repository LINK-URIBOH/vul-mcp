import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Literal
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, select, update

from .db import (Alias, Audit, Batch, BatchItem, Delivery, MetadataState, ReportBacklog, ReportState, Revision,
                 Source, SourceRecord, Vulnerability, now, uid)
from .sources import RANK
from .identity import record_aliases


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def audit(db, actor, action, target):
    db.add(Audit(actor=actor[:200], action=action, target=str(target)[:200]))


def ingest(db, source_id, data, *, maintenance=False, observed=None):
    """Idempotent source records; aliases link CVEs, never a bulletin's mentioned CVEs."""
    data = {**data, "aliases": record_aliases(data)}
    source_key = data["source_key"][:240]
    record = db.scalar(select(SourceRecord).where(SourceRecord.source_id == source_id,
                                                SourceRecord.source_key == source_key))
    fingerprint = digest({k: v for k, v in data.items() if k not in {"modified"}})
    if record and record.fingerprint == fingerprint and not maintenance:
        from .publication import annotate
        annotate(db, db.get(Vulnerability, record.vulnerability_id))
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
            from .db import PublicationAnnotation, PublicationState
            db.execute(update(PublicationAnnotation).where(PublicationAnnotation.vulnerability_id == other)
                       .values(vulnerability_id=vuln.id))
            db.execute(delete(PublicationState).where(PublicationState.vulnerability_id == other))
            from .db import Job
            db.execute(delete(Job).where(Job.kind == "publication", Job.source_id == other))
            pending = db.get(ReportBacklog, other)
            if pending:
                current = db.get(ReportBacklog, vuln.id)
                if current:
                    current.first_eligible_at = min(current.first_eligible_at, pending.first_eligible_at)
                    current.category = "new" if "new" in {current.category, pending.category} else "update"
                    if pending.revision_id > current.revision_id:
                        current.revision_id, current.rank = pending.revision_id, pending.rank
                    db.delete(pending)
                else:
                    pending.vulnerability_id = vuln.id
                db.flush()
            db.execute(update(Alias).where(Alias.vulnerability_id == other).values(vulnerability_id=vuln.id))
            db.execute(update(SourceRecord).where(SourceRecord.vulnerability_id == other).values(vulnerability_id=vuln.id))
            db.execute(update(Revision).where(Revision.vulnerability_id == other).values(vulnerability_id=vuln.id))
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
    ordered = sorted(records, key=lambda r: (r.source_id == "kev", r.source_id.startswith("osv-"), r.source_id, r.source_key))
    main = ordered[0].data
    all_aliases = sorted(db.scalars(select(Alias.alias).where(Alias.vulnerability_id == vuln.id)))
    severity = max((r.data.get("severity", "unknown") for r in records), key=lambda s: RANK.get(s, 0))
    merged = {**main, "id": vuln.id, "aliases": all_aliases, "severity": severity,
              "exploited": any(r.data.get("exploited", False) for r in records),
              "references": sorted({url for r in records for url in r.data.get("references", [])}),
              "source_records": [{"source": r.source_id, **r.data} for r in ordered]}
    previous = vuln.data
    vuln.data = merged
    vuln.title = main["title"]
    vuln.product = " ".join(sorted({json.dumps(r.data.get("affected", []), ensure_ascii=False) for r in records}))
    vuln.severity, vuln.exploited = severity, merged["exploited"]
    if not maintenance:
        vuln.updated_at = now()
        from .timeline import append_revision
        revision = append_revision(db, vuln, previous=previous, observed=observed)
        db.flush()
        from .publication import annotate, project_revision
        annotate(db, vuln, assessed=now() if observed else revision.observed_at)
        project_revision(db, revision, derived=revision)
        pending = db.get(ReportBacklog, vuln.id)
        if pending:
            db.flush()
            pending.revision_id = revision.id
            pending.rank = (10 if merged.get("exploited") else 0) + RANK.get(severity, 0)
    return vuln.id


def source_status(db):
    progress = {s.key.split(":", 1)[1]: s.value for s in db.scalars(
        select(MetadataState).where(MetadataState.key.like("source-progress:%")))}
    from .recent import enabled
    from .db import RecentSource
    from .recent_reset import KEY
    run = db.get(MetadataState, KEY)
    stages = {stage.source_id: stage for stage in db.scalars(select(RecentSource).where(
        RecentSource.run_id == run.value["run_id"]))} if enabled(db) else {}
    for stage in stages.values():
        progress[stage.source_id] = {"status": stage.status, "processed": stage.processed,
            "completed_at": stage.updated_at.isoformat() + "Z" if stage.status == "idle" else None,
            "heartbeat_at": stage.updated_at.isoformat() + "Z", "coverage_mode": stage.mode}
    return [{"id": s.id, "name": s.name, "enabled": s.enabled,
             "last_success_utc": s.last_success.isoformat() + "Z" if s.last_success else None,
             "last_attempt_utc": s.last_attempt.isoformat() + "Z" if s.last_attempt else None,
             "next_run_utc": s.next_run.isoformat() + "Z" if s.next_run else None,
             "progress": progress.get(s.id, {}),
             "coverage_mode": stages[s.id].mode if s.id in stages else "standard",
             "coverage_limited": s.id in stages and stages[s.id].mode == "targeted",
             "coverage_note": "定向补充／首次覆盖有限，不执行历史索引回灌" if s.id in stages and stages[s.id].mode == "targeted" else None,
             "bootstrap_status": stages[s.id].status if s.id in stages else None,
             "error": s.error,
             "stale": (not s.last_success or (now() - s.last_success) > timedelta(hours=2))
                      if s.id not in stages or stages[s.id].mode != "targeted" else False}
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
    from .report_jobs import open_batch as invoke
    return invoke(db, actor, slot)


def batch_page(db, batch_id, after=0, limit=10, pending_only=False):
    from .report_jobs import batch_page as invoke
    return invoke(db, batch_id, after, limit, pending_only)


class Analysis(BaseModel):
    model_config = ConfigDict(extra="forbid")
    item_id: int
    vulnerability_summary: str = Field(default="", max_length=8000)
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
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                    or len(value.encode("utf-8")) > 2048):
                raise ValueError("Evidence references must be public HTTPS URLs")
        return values


class Overview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    risk_summary: list[str] = Field(default_factory=list, max_length=6,
                                    description="仅描述漏洞核心风险，不包含工具调用、分页、执行或投递过程")
    repair_priorities: list[str] = Field(default_factory=list, max_length=10,
                                         description="仅描述具体修复优先级，不重复服务器生成的计数和采集状态")

    @field_validator("risk_summary", "repair_priorities")
    @classmethod
    def bounded_bullets(cls, values):
        if any(not value.strip() or len(value) > 600 for value in values):
            raise ValueError("每条风险或修复建议须为 1..600 字符")
        if any(re.search(r"open_report_batch|pending_analysis|next_after|batch_id|submit_batch_analysis|finalize_report|MCP\s*-32603", value, re.I) for value in values):
            raise ValueError("风险摘要或修复建议不得包含工具执行诊断")
        return values


def submit_analysis(db, actor, batch_id, analyses):
    from .maintenance import report_write_guard
    report_write_guard(db)
    batch = db.scalar(select(Batch).where(Batch.id == batch_id).with_for_update())
    if not batch or batch.status == "finalized":
        raise ValueError("批次不存在或已经归档")
    state = db.get(ReportState, batch_id)
    if state and (not state.work.get("prepared") or batch.status != "analyzing"):
        raise ValueError("批次尚未准备完成，或已进入渲染阶段")
    prepared = []
    for raw in analyses:
        analysis = raw if isinstance(raw, Analysis) else Analysis.model_validate(raw)
        if state and not re.search(r"[\u3400-\u9fff]", analysis.vulnerability_summary):
            raise ValueError("每条记录必须提供中文漏洞说明 vulnerability_summary")
        if state and len(json.dumps(analysis.model_dump(), ensure_ascii=False).encode()) > 192000:
            raise ValueError("单条分析总量超过192000字节，请精简表述后重新提交，不删减关键证据")
        item = db.get(BatchItem, analysis.item_id)
        if not item or item.batch_id != batch_id:
            raise ValueError("分析引用了不属于此批次的条目")
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


def finalize(db, actor, batch_id, summary="", overview=None):
    from .report_jobs import finalize as invoke
    return invoke(db, actor, batch_id, summary, overview)


def delivery_status(db, batch_id):
    return [{"id": d.id, "channel": d.channel, "part": d.part, "status": d.status,
             "attempts": d.attempts, "error": d.error}
            for d in db.scalars(select(Delivery).where(Delivery.batch_id == batch_id).order_by(Delivery.channel, Delivery.part))]
