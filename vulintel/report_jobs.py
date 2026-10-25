"""Durable, bounded report preparation and publication on the existing DB job queue."""
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import Text, cast, delete, exists, func, or_, select
from sqlalchemy.orm import aliased

from .db import (Batch, BatchItem, Job, MetadataState, PublicationAnnotation, ReportBacklog, ReportCandidate,
                 ReportSelection, ReportState, Revision, RevisionDateProjection,
                 UnverifiedItem, now, session, uid)
from .timeline import BACKFILL_KEY, EVENT_POLICY, iso
from .publication import (DATE_POLICY, DATES_MISSING, VERIFIED, corrected_snapshot, coverage, date_in_window)

log = logging.getLogger("vulintel.report")


def failure_reason(exc):
    allowed = {
        "单条详解超过邮件分卷预算，请提高 SMTP_MAX_BYTES 后恢复批次",
        "单条索引超过邮件附件预算，请提高 SMTP_MAX_BYTES 后恢复批次",
        "报告暂存文件缺失或短于检查点，请从备份恢复或重新准备该批次",
        "报告暂存文件短于检查点，禁止发布", "发布文件缺失或校验失败",
        "报告条目计数不一致，禁止发布", "日期待核实计数不一致，禁止发布",
        DATES_MISSING,
        "未发布批次仍使用旧日期规则，请运行 repair-publication-dates --rebuild-unpublished",
    }
    raw = str(exc) if isinstance(exc, ValueError) else ""
    if raw in allowed:
        return raw
    if raw == "Email exceeds SMTP_MAX_BYTES":
        return "实际 MIME 大小超过 SMTP_MAX_BYTES，请提高上限后恢复批次"
    return "报告处理失败，请按追踪编号核对脱敏堆栈"


def enqueue(db, batch_id):
    job = db.scalar(select(Job).where(Job.kind == "report", Job.source_id == batch_id,
                                     Job.status.in_(["pending", "running", "failed"])).limit(1))
    if job:
        if job.status == "failed":
            job.status, job.error, job.lease_until = "pending", None, None
        return
    db.add(Job(kind="report", source_id=batch_id))


def status(db, batch, fact_report_id=None):
    state = db.get(ReportState, batch.id)
    wrong_date = db.scalar(select(func.count()).select_from(BatchItem).where(BatchItem.batch_id == batch.id,
        or_(BatchItem.snapshot["timeline"]["date_policy"].as_integer().is_(None),
            BatchItem.snapshot["timeline"]["date_policy"].as_integer() != DATE_POLICY,
            BatchItem.snapshot["timeline"]["event_policy"].as_integer().is_(None),
            BatchItem.snapshot["timeline"]["event_policy"].as_integer() != EVENT_POLICY)))
    result = {"batch_id": batch.id, "slot": state.work.get("logical_slot", batch.slot) if state else batch.slot, "status": batch.status,
              "error": batch.error, "policy": state.policy if state else 1,
              "event_audit_required": bool(state and state.policy < EVENT_POLICY),
              "date_policy": DATE_POLICY, "old_date_mixed_count": wrong_date,
              "date_audit_required": bool(wrong_date or state and state.work.get("date_policy") != DATE_POLICY)}
    if state:
        result.update(report_kind=state.work.get("publication_kind", "analysis"),
                      critical_only=bool(state.work.get("critical_only")), progressive=bool(state.work.get("progressive")),
                      retry_at=state.work.get("retry_at"), heartbeat=state.work.get("heartbeat"),
                      unknown_severity=state.work.get("unknown_severity", 0))
    if fact_report_id or state and state.work.get("progressive"):
        from .publications import related_status
        result.update(related_status(db, batch, fact_report_id))
    if not state:
        total = db.scalar(select(func.count()).select_from(BatchItem).where(BatchItem.batch_id == batch.id))
        analyzed = db.scalar(select(func.count()).select_from(BatchItem).where(
            BatchItem.batch_id == batch.id, BatchItem.analysis.is_not(None)))
        return {**result, "ready": batch.status in {"analyzing", "finalized"}, "legacy": True,
                "total": total, "analyzed": analyzed, "pending_analysis": total - analyzed}
    ready = state.work.get("prepared", False)
    analyzed = db.scalar(select(func.count()).select_from(BatchItem).where(
        BatchItem.batch_id == batch.id, BatchItem.analysis.is_not(None)))
    metadata = db.get(MetadataState, BACKFILL_KEY)
    return {**result, "ready": ready, "total": state.total if ready else None,
            "analyzed": analyzed, "pending_analysis": state.total - analyzed if ready and state.work.get("publication_kind") != "facts" else None,
            "new_disclosures": state.new_count, "important_updates": state.update_count,
            "unverified_dates": state.unknown_count, "phase": state.work.get("phase"),
            "render_stage": state.work.get("render", {}).get("phase"),
            "rendered_items": state.work.get("render", {}).get("count", 0),
            "prepared_items": state.total, "coverage_at_utc": iso(state.coverage_at),
            "item_limit": state.work.get("item_limit"), "candidate_total": state.work.get("candidate_total"),
            "deferred_count": state.work.get("deferred_count"), "backlog_selected": state.work.get("backlog_selected", 0),
            "current_new_disclosures": state.new_count - state.work.get("backlog_new", 0),
            "recent_important_updates": state.update_count - state.work.get("backlog_updates", 0),
            "date_coverage": state.work.get("date_coverage"),
            "bootstrap": state.work.get("bootstrap"),
            "retry_after_seconds": 30 if batch.status in {"preparing", "rendering"} else None,
            "metadata_backfill": metadata.value if metadata else {"complete": False}}


def open_batch(db, actor, slot=None, ensure_facts=False, progressive=False):
    from .maintenance import report_write_guard
    from .config import settings
    report_write_guard(db)
    if (ensure_facts or progressive) and not settings().publisher_enabled:
        raise ValueError("请先启用并运行独立 publisher 服务")
    if progressive and not ensure_facts:
        raise ValueError("渐进发布须同时启用事实版兜底")
    from .service import audit, due_slot, source_status
    slot = slot or due_slot()
    cutoff = datetime.fromisoformat(slot)
    if (cutoff.tzinfo is None or cutoff.utcoffset() != timedelta(hours=8) or cutoff.hour not in {9, 18}
            or cutoff.minute or cutoff.second or cutoff.microsecond):
        raise ValueError("时间段必须为北京时间 09:00 或 18:00，包含 +08:00 时区")
    cutoff = cutoff.astimezone(timezone.utc).replace(tzinfo=None)
    if cutoff > now():
        raise ValueError("不能创建未来时间段的报告")
    slot = cutoff.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Shanghai")).isoformat(timespec="minutes")
    if db.bind.dialect.name == "postgresql":
        db.execute(select(func.pg_advisory_xact_lock(86221023)))
    from .db import Publication
    fact = None
    if ensure_facts:
        from .publications import trigger_facts
        fact = trigger_facts(db, actor, slot)
    query = select(Batch).join(ReportState).where(Batch.status.in_(["preparing", "analyzing", "rendering", "failed"]),
        ~exists(select(Publication.id).where(Publication.id == Batch.id)))
    if ensure_facts:
        query = query.where(ReportState.work["critical_only"].as_boolean().is_(True))
    pending = db.scalar(query.order_by(Batch.cutoff).limit(1))
    same_slot = db.scalar(select(Batch).where(Batch.slot == slot))
    if ensure_facts and same_slot and same_slot.status not in {"finalized", "rendering"}:
        same_state = db.get(ReportState, same_slot.id)
        if not same_state or not same_state.work.get("critical_only"):
            same_slot.status, same_slot.error = "superseded", "新严重级别策略取代旧草稿；分析保留审计"
            same_slot.slot = "old:" + same_slot.id
            db.execute(delete(Job).where(Job.kind == "report", Job.source_id == same_slot.id))
            audit(db, actor, "batch.policy-superseded", same_slot.id)
            db.flush()
            same_slot = None
    batch = pending or same_slot
    if batch:
        state = db.get(ReportState, batch.id)
        if fact and (not state or not state.work.get("critical_only")):
            # Preserve an already-rendering legacy archive without allowing it
            # to roll back the independent current fact trigger.
            db.commit()
            return {**status(db, batch, fact.id), "analysis_note": "旧版归档保留原策略；当前事实版已独立触发"}
        if state and batch.status != "finalized" and state.policy < EVENT_POLICY:
            raise ValueError("未发布批次仍使用旧日期规则，请运行 repair-publication-dates --rebuild-unpublished")
        if state and batch.status == "failed":
            batch.status = "analyzing" if state.work.get("prepared") else "preparing"
            if state.work.get("phase") not in {"prepare", "select", "analyzing"}:
                batch.status = "rendering"
            batch.error = None
            if batch.status != "analyzing":
                enqueue(db, batch.id)
        if fact:
            current = db.get(ReportState, batch.id)
            if progressive and batch.status != "finalized":
                current.work = {**current.work, "progressive": True,
                                "fact_report_id": current.work.get("fact_report_id", fact.id)}
        db.commit()
        return status(db, batch, fact.id if fact else None)
    latest = db.scalar(select(Batch).join(ReportState).where(Batch.status == "finalized",
                       ~exists(select(Publication.id).where(Publication.id == Batch.id)))
                       .order_by(Batch.cutoff.desc()).limit(1))
    if latest and cutoff <= latest.cutoff:
        raise ValueError("时间段早于已完成的新规则报告")
    batch = Batch(id=uid(), slot=slot, cutoff=cutoff, status="preparing", coverage=source_status(db))
    db.add(batch)
    db.flush()
    db.add(ReportState(batch_id=batch.id, work={"phase": "prepare", "prepared": False,
        "item_limit": min(50, settings().report_max_items) if ensure_facts else settings().report_max_items,
        "date_policy": DATE_POLICY, "critical_only": ensure_facts, "progressive": progressive,
        "fact_report_id": fact.id if fact else None}))
    enqueue(db, batch.id)
    audit(db, actor, "batch.create", batch.id)
    db.commit()
    return status(db, batch, fact.id if fact else None)


def prepare_step(db, batch, state):
    if state.work.get("phase") == "select":
        select_step(db, batch, state)
        return
    if state.watermark is None:
        from .recent import progress as bootstrap_progress
        state.watermark = db.scalar(select(func.max(Revision.id))) or 0
        state.work = {**state.work, "date_watermark": db.scalar(select(func.max(PublicationAnnotation.id))) or 0,
                      "date_coverage": coverage(db), "bootstrap": bootstrap_progress(db)}
    other = aliased(Revision)
    later_annotation = aliased(PublicationAnnotation)
    start = batch.cutoff - timedelta(days=7)
    later = exists(select(other.id).where(other.vulnerability_id == Revision.vulnerability_id,
                   other.id > Revision.id, other.id <= state.watermark, other.observed_at <= batch.cutoff))
    annotation_newer = exists(select(later_annotation.id).where(
        later_annotation.vulnerability_id == PublicationAnnotation.vulnerability_id,
        later_annotation.id > PublicationAnnotation.id, later_annotation.id <= state.work["date_watermark"],
        later_annotation.policy == DATE_POLICY))
    query = select(Revision.id, Revision.snapshot_bytes, PublicationAnnotation.id).outerjoin(
        PublicationAnnotation, (PublicationAnnotation.vulnerability_id == Revision.vulnerability_id)
        & (PublicationAnnotation.id <= state.work["date_watermark"]) & (PublicationAnnotation.policy == DATE_POLICY)
        & ~annotation_newer).where(
        Revision.id > state.cursor, Revision.id <= state.watermark, Revision.observed_at <= batch.cutoff,
        ~later).order_by(Revision.id).limit(100)
    candidates = list(db.execute(query))
    used = 0
    for identity, byte_count, annotation_id in candidates:
        if used and used + byte_count > 2_000_000:
            break
        revision = db.get(Revision, identity)
        strict = state.work.get("critical_only")
        if strict and revision.snapshot.get("severity") != "critical":
            rejected = db.get(ReportBacklog, revision.vulnerability_id)
            if rejected and rejected.revision_id <= revision.id:
                from .service import audit
                audit(db, "publisher", "backlog.noncritical-withdrawn", revision.vulnerability_id)
                db.delete(rejected)
            if revision.snapshot.get("severity", "unknown") == "unknown":
                state.work = {**state.work, "unknown_severity": state.work.get("unknown_severity", 0) + 1}
            state.cursor = identity
            used += byte_count
            db.expunge(revision)
            continue
        annotation = db.get(PublicationAnnotation, annotation_id) if annotation_id else None
        projection = db.get(RevisionDateProjection, identity)
        if strict and (not annotation or not projection or projection.policy != EVENT_POLICY):
            db.add(UnverifiedItem(batch_id=batch.id, revision_id=revision.id,
                title=revision.snapshot.get("title", "未确认"), identifiers=", ".join(revision.snapshot.get("aliases", [])),
                references=revision.snapshot.get("references", []), date_annotation_id=annotation_id,
                reason="missing_current_annotation"))
            state.unknown_count += 1
            state.cursor = identity
            used += byte_count
            continue
        facts = corrected_snapshot(revision, projection, annotation)
        from .db import Publication
        prior = db.execute(select(ReportSelection, BatchItem).join(BatchItem).join(Batch)
                           .join(Revision, Revision.id == ReportSelection.revision_id)
                           .where(Revision.vulnerability_id == revision.vulnerability_id,
                                  Batch.status == "finalized",
                                  ~exists(select(Publication.id).where(Publication.id == Batch.id)))
                           .order_by(Batch.cutoff.desc()).limit(1)).first()
        old = db.get(Revision, prior[0].revision_id) if prior else None
        old_projection = db.get(RevisionDateProjection, old.id) if old else None
        new = date_in_window(annotation, start, batch.cutoff) and not prior
        important = (projection.important_at and start <= projection.important_at <= batch.cutoff
                     and projection.important_end_at is not None and projection.important_end_at <= batch.cutoff
                     and (not old_projection or not old_projection.important_at
                          or projection.important_at > old_projection.important_at))
        if strict:
            from .publications import received
            receipt_kind = "facts" if state.work.get("publication_kind") == "facts" else "detail"
            new = new and not received(db, receipt_kind, revision.vulnerability_id, facts, "new")
            important = important and not received(db, receipt_kind, revision.vulnerability_id, facts, "update")
        backlog = db.get(ReportBacklog, revision.vulnerability_id)
        # Later authoritative evidence can invalidate an earlier "new" date.
        # Persistence is for qualified overflow, not for preserving a disproved
        # disclosure classification forever.
        if (backlog and backlog.category == "new" and annotation.start_at
                and annotation.start_at < backlog.first_eligible_at - timedelta(days=7)):
            if projection.important_at and projection.important_at >= backlog.first_eligible_at - timedelta(days=7):
                backlog.category = "update"
            else:
                from .service import audit
                audit(db, "report-worker", "backlog.disclosure_invalidated", revision.vulnerability_id)
                db.delete(backlog)
                backlog = None
        if backlog and backlog.category == "update" and projection.important_at is None:
            from .service import audit
            audit(db, "report-worker", "backlog.unverified-change-date", revision.vulnerability_id)
            db.delete(backlog)
            backlog = None
        uncertain_window = (annotation.status == "day" and annotation.start_at <= batch.cutoff
                            and annotation.end_at >= start and not date_in_window(annotation, start, batch.cutoff))
        if annotation.status not in VERIFIED or uncertain_window:
            db.add(UnverifiedItem(batch_id=batch.id, revision_id=revision.id,
                                 title=revision.snapshot["title"],
                                 identifiers=", ".join(revision.snapshot.get("aliases", [])),
                                 references=revision.snapshot.get("references", []), date_annotation_id=annotation.id,
                                 reason="uncertain_window" if uncertain_window else annotation.status))
            state.unknown_count += 1
        elif new or important or (backlog and (old is None or revision.id > old.id)):
            category = "new" if new else "update" if important else backlog.category
            if strict and received(db, receipt_kind, revision.vulnerability_id, facts, category):
                state.cursor = identity
                used += byte_count
                continue
            risk = {"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            rank = (10 if facts.get("exploited") else 0) + risk.get(facts.get("severity"), 0)
            if backlog is None:
                db.add(ReportBacklog(vulnerability_id=revision.vulnerability_id, revision_id=revision.id,
                                    first_eligible_at=batch.cutoff, category="new" if new else "update", rank=rank))
            elif revision.id >= backlog.revision_id:
                backlog.revision_id, backlog.rank = revision.id, rank
            db.add(ReportCandidate(batch_id=batch.id, vulnerability_id=revision.vulnerability_id,
                                   revision_id=revision.id,
                                   date_annotation_id=annotation.id,
                                   first_eligible_at=backlog.first_eligible_at if backlog else batch.cutoff,
                                   category=category if strict else backlog.category if backlog else "new" if new else "update", rank=rank))
        state.cursor = identity
        used += byte_count
        db.flush()
        db.expunge(revision)
    if not candidates:
        count = db.scalar(select(func.count()).select_from(ReportCandidate).where(ReportCandidate.batch_id == batch.id))
        state.work = {**state.work, "phase": "select", "candidate_total": count}


def select_step(db, batch, state):
    """Freeze the highest priority candidates only after the full scan has finished."""
    from .config import settings
    is_facts = state.work.get("publication_kind") == "facts"
    limit = state.work.get("candidate_total", 0) if is_facts else state.work.get("item_limit", settings().report_max_items)
    selected = select(BatchItem.vulnerability_id).where(BatchItem.batch_id == batch.id)
    rows = list(db.scalars(select(ReportCandidate).where(ReportCandidate.batch_id == batch.id,
        ReportCandidate.vulnerability_id.not_in(selected))
        .order_by(ReportCandidate.rank.desc(), ReportCandidate.first_eligible_at,
                  ReportCandidate.vulnerability_id).limit(min(10, max(0, limit - state.total)))))
    used = 0
    work = dict(state.work)
    for candidate in rows:
        revision = db.get(Revision, candidate.revision_id)
        if used and used + revision.snapshot_bytes > 2_000_000:
            break
        start = batch.cutoff - timedelta(days=7)
        annotation = db.get(PublicationAnnotation, candidate.date_annotation_id) if candidate.date_annotation_id else None
        projection = db.get(RevisionDateProjection, revision.id)
        facts = corrected_snapshot(revision, projection, annotation)
        event_at = annotation.start_at if candidate.category == "new" else projection.important_at
        is_backlog = candidate.first_eligible_at < start or not event_at or event_at < start
        facts = {**facts, "report_category": candidate.category,
                 "report_backlog": is_backlog, "first_eligible_at": iso(candidate.first_eligible_at)}
        if is_facts:
            facts["_report_kind"] = "facts"
        item = BatchItem(batch_id=batch.id, vulnerability_id=candidate.vulnerability_id, snapshot=facts, priority=True)
        db.add(item)
        db.flush()
        db.add(ReportSelection(item_id=item.id, revision_id=revision.id,
                               group_name=facts.get("product_group", "其他产品／待确认"),
                               rank=candidate.rank, category=candidate.category))
        state.total += 1
        if candidate.category == "new":
            state.new_count += 1
        else:
            state.update_count += 1
        work["backlog_selected"] = work.get("backlog_selected", 0) + int(is_backlog)
        if is_backlog:
            key = "backlog_new" if candidate.category == "new" else "backlog_updates"
            work[key] = work.get(key, 0) + 1
        used += revision.snapshot_bytes
        db.flush()
        db.expunge(revision)
    if not rows or state.total >= limit:
        db.execute(delete(ReportCandidate).where(ReportCandidate.batch_id == batch.id))
        work.update(prepared=True, phase="render" if is_facts else "analyzing",
                    deferred_count=max(0, work["candidate_total"] - state.total))
        batch.status = "rendering" if is_facts else "analyzing"
    state.work = work


def batch_page(db, batch_id, after=0, limit=10, pending_only=False, include_evidence=False, max_bytes=262144):
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise ValueError("未知报告批次")
    if not 1 <= limit <= (50 if include_evidence else 20) or after < 0 or not 16384 <= max_bytes <= settings_budget():
        raise ValueError("分页参数无效")
    result = status(db, batch)
    if not result["ready"]:
        return {**result, "coverage": batch.coverage, "items": [], "next_after": None,
                "note": "批次正在准备；尚不能判断是否无记录，请稍后查询"}
    if include_evidence:
        # Keep the evidence budget for evidence, not repeated delivery history
        # or bootstrap diagnostics (available from the dedicated status tools).
        result = {k: v for k, v in result.items() if k not in {
            "bootstrap", "metadata_backfill", "fact_report", "supplements", "aggregate"}}
        query = select(BatchItem.id, func.length(cast(BatchItem.snapshot, Text))).where(BatchItem.batch_id == batch_id, BatchItem.id > after)
        if pending_only:
            query = query.where(BatchItem.analysis.is_(None))
        rows = list(db.execute(query.order_by(BatchItem.id).limit(limit + 1)))
        page = []
        for identity, characters in rows[:limit]:
            value = {"item_id": identity, "evidence_complete": False, "evidence_required": True,
                     "note": "单条超过响应预算，须使用get_item_evidence完整续页"}
            item = db.get(BatchItem, identity) if characters < max_bytes else None
            if item:
                value = {"item_id": item.id, "priority": item.priority, "snapshot": item.snapshot,
                         "evidence_complete": True, "analysis": item.analysis}
            if evidence_wire_size({**result, "items": [*page, value]}) + 2048 > max_bytes:
                if page:
                    break
                value = {"item_id": identity, "evidence_complete": False,
                         "evidence_required": True, "note": "单条超过响应预算，须使用get_item_evidence完整续页"}
            page.append(value)
            if item:
                db.expunge(item)
        return {**result, "items": page, "next_after": page[-1]["item_id"] if page and len(rows) > len(page) else None,
                "max_bytes": max_bytes, "note": "evidence_complete=true包含完整冻结事实；否则必须续读get_item_evidence"}
    columns = [BatchItem.id, BatchItem.priority, BatchItem.analysis]
    names = ["aliases", "severity", "exploited", "product_group", "timeline", "report_category", "mentioned_cves",
             "report_backlog", "first_eligible_at"]
    columns += [BatchItem.snapshot[name].label(name) for name in names]
    title_column = BatchItem.snapshot["title"].as_string()
    columns += [func.substr(title_column, 1, 500).label("title"), func.length(title_column).label("title_length")]
    query = select(*columns).where(BatchItem.batch_id == batch_id, BatchItem.id > after)
    if pending_only:
        query = query.where(BatchItem.analysis.is_(None))
    rows = list(db.execute(query.order_by(BatchItem.id).limit(limit + 1)))
    page, size = [], 0
    for row in rows[:limit]:
        snapshot = {name: row._mapping[name] for name in names}
        timeline = snapshot.get("timeline") or {}
        snapshot["timeline"] = {key: value for key, value in timeline.items() if key not in {
            "date_evidence", "date_conflicts", "rejected_date_evidence", "source_publications", "date_fetches", "event_dates",
            "cve_record_publications", "source_entry_publications"}}
        snapshot["date_evidence_complete"] = False
        snapshot["title"] = row._mapping["title"] or ""
        snapshot["title_complete"] = (row._mapping["title_length"] or 0) <= 500
        aliases = snapshot.get("aliases") or []
        snapshot["aliases"] = aliases[:30]
        snapshot["aliases_complete"] = len(aliases) <= 30
        mentioned = snapshot.get("mentioned_cves") or []
        snapshot["mentioned_cves"] = mentioned[:30]
        snapshot["mentioned_cves_complete"] = len(mentioned) <= 30
        value = {"item_id": row.id, "priority": row.priority, "snapshot": snapshot,
                 "analysis": row.analysis, "evidence_required": True}
        encoded = len(json.dumps(value, ensure_ascii=False).encode())
        if page and size + encoded > 192_000:
            break
        page.append(value)
        size += encoded
    more = len(rows) > len(page)
    return {**result, "coverage": batch.coverage, "items": page,
            "next_after": page[-1]["item_id"] if page and more else None,
            "note": "本页为有界摘要；使用 get_item_evidence 续页读取完整来源事实，不得仅凭摘要分析"}


def settings_budget():
    from .config import settings
    return settings().report_evidence_max_bytes


def evidence_wire_size(payload):
    # MCP 2.3 emits both pretty-printed TextContent and structuredContent.
    # Budget both copies and JSON escaping instead of only the logical data.
    from pydantic_core import to_json
    content = to_json(payload, fallback=str, indent=2).decode()
    return len(to_json({"content": [{"type": "text", "text": content}], "structuredContent": payload}))


def item_evidence(db, batch_id, item_id, offset=0, limit=16000):
    if offset < 0 or not 1 <= limit <= 16000:
        raise ValueError("证据分页参数无效")
    text = cast(BatchItem.snapshot, Text)
    row = db.execute(select(func.substr(text, offset + 1, limit), func.length(text)).where(
        BatchItem.batch_id == batch_id, BatchItem.id == item_id)).first()
    if not row:
        raise ValueError("该条目不属于此批次")
    return {"batch_id": batch_id, "item_id": item_id, "format": "json-text", "offset": offset,
            "text": row[0], "total_characters": row[1],
            "next_offset": offset + len(row[0]) if offset + len(row[0]) < row[1] else None}


def finalize(db, actor, batch_id, summary="", overview=None, mode="complete"):
    from .maintenance import report_write_guard
    report_write_guard(db)
    from .service import audit
    batch = db.scalar(select(Batch).where(Batch.id == batch_id).with_for_update())
    if batch is None:
        raise ValueError("未知报告批次")
    if mode == "supplement":
        from .publications import flush_supplements
        state = db.get(ReportState, batch_id)
        if not state or not state.work.get("progressive"):
            raise ValueError("该批次未授权渐进发布")
        publications = flush_supplements(db, batch_id, force=True)
        db.commit()
        return {**status(db, batch), "queued_supplements": publications}
    if mode != "complete":
        raise ValueError("未知发布模式")
    if batch.status == "finalized":
        return status(db, batch)
    state = db.get(ReportState, batch_id)
    if not state:
        raise ValueError("旧规则批次不能用新规则自动重发，请建立新的时间段报告")
    if state.policy < EVENT_POLICY or status(db, batch)["date_audit_required"]:
        raise ValueError("未发布批次仍使用旧日期规则，请运行 repair-publication-dates --rebuild-unpublished")
    if not state.work.get("prepared"):
        raise ValueError("批次尚未准备完成")
    missing = db.scalar(select(func.count()).select_from(BatchItem).where(
        BatchItem.batch_id == batch_id, BatchItem.analysis.is_(None)))
    if missing:
        raise ValueError(f"仍有{missing}条记录需要完成逐条详解")
    if state.work.get("progressive"):
        from .publications import flush_supplements
        if batch.status == "analyzing":
            if overview is not None:
                state.overview = overview.model_dump() if hasattr(overview, "model_dump") else overview
            batch.summary = summary or batch.summary
            audit(db, actor, "batch.aggregate_requested", batch_id)
        flush_supplements(db, batch_id, force=True)
        db.commit()
        return status(db, batch)
    if batch.status == "rendering":
        return status(db, batch)
    if state.work.get("phase") == "render":
        # Rendering may already have staged deliveries and committed file offsets.
        # Retrying finalize must resume these checkpoints, not restart publication.
        batch.status, batch.error = "rendering", None
        enqueue(db, batch_id)
        audit(db, actor, "batch.render_resumed", batch_id)
        db.commit()
        return status(db, batch)
    state.overview = overview.model_dump() if hasattr(overview, "model_dump") else (overview or {})
    # Legacy free text is retained for admin diagnostics, not inserted into reader-facing reports.
    batch.summary = summary
    batch.status, batch.error = "rendering", None
    state.work = {**state.work, "phase": "render", "render": {}}
    enqueue(db, batch_id)
    audit(db, actor, "batch.render_requested", batch_id)
    db.commit()
    return status(db, batch)


def run_report_once():
    """One short lease and checkpoint transaction, also safe at committed collector boundaries."""
    started = time.monotonic()
    with session() as db:
        from .maintenance import active
        if active(db):
            return False
        stale = db.scalars(select(Job).where(Job.kind == "report", Job.status == "running",
                                            Job.lease_until < now()))
        for job in stale:
            job.status, job.lease_until = "pending", None
        db.commit()
        job = db.scalar(select(Job).where(Job.kind == "report", Job.status == "pending")
                        .order_by(Job.created_at).with_for_update(skip_locked=True).limit(1))
        if not job:
            return False
        identity, batch_id = job.id, job.source_id
        job.status, job.lease_until = "running", now() + timedelta(minutes=5)
        db.commit()
    try:
        with session() as db:
            batch = db.get(Batch, batch_id)
            state = db.get(ReportState, batch_id)
            if not batch or not state:
                raise ValueError("报告任务缺少持久化状态")
            if batch.status == "failed":
                batch.status = "preparing" if state.work["phase"] in {"prepare", "select"} else "rendering"
                batch.error = None
            if state.work["phase"] in {"prepare", "select"}:
                prepare_step(db, batch, state)
            elif state.work["phase"] not in {"analyzing", "complete"}:
                from .report_render import render_step
                render_step(db, batch, state)
            job = db.get(Job, identity)
            job.status = "done" if state.work["phase"] in {"analyzing", "complete"} else "pending"
            job.lease_until, job.error = None, None
            state.work = {**state.work, "heartbeat": iso(now()), "retry_at": None, "retry_attempts": 0}
            db.commit()
            log.info(json.dumps({"event": "report_step", "batch_id": batch_id, "phase": state.work["phase"],
                                 "prepared": state.total, "elapsed": round(time.monotonic() - started, 3)}))
    except Exception as exc:
        from .collector import error_details
        correlation = uid()
        reason = failure_reason(exc)
        log.error(json.dumps({"event": "report_failed", "batch_id": batch_id, "correlation_id": correlation,
                              **error_details(exc), "reason": reason}, ensure_ascii=False))
        with session() as db:
            job, batch = db.get(Job, identity), db.get(Batch, batch_id)
            job.status, job.error, job.lease_until = "failed", f"{reason}；追踪编号 {correlation}", None
            if batch:
                batch.status, batch.error = "failed", job.error
                state = db.get(ReportState, batch_id)
                attempts = state.work.get("retry_attempts", 0) + 1
                state.work = {**state.work, "retry_attempts": attempts,
                    "retry_at": iso(now() + timedelta(seconds=min(3600, 30 * 2 ** min(attempts, 7))))
                    if not isinstance(exc, ValueError) and attempts < 8 else None}
            db.commit()
    return True
