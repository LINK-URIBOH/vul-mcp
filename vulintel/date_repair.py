"""Resumable full-library date annotation and explicit unpublished-batch rebuild."""
import json
import logging
import shutil
import threading
from datetime import timedelta

from sqlalchemy import delete, exists, select, text

from .db import (Batch, BatchItem, Delivery, Job, MetadataState, PublicationAnnotation, PublicationState,
                 ReportBacklog, ReportCandidate, ReportSelection, ReportState, Revision,
                 RevisionDateProjection, UnverifiedItem, Vulnerability, now, session, uid)
from .maintenance import _heartbeat, repair_owner
from .publication import DATE_POLICY, REPAIR_KEY, VERIFIED, annotate, coverage, replay_projections
from .reports import report_dir
from .timeline import EVENT_POLICY, iso

log = logging.getLogger("vulintel.date-repair")


def start(db):
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(86221023)"))
    row = db.get(MetadataState, REPAIR_KEY)
    if row and row.value.get("complete"):
        return row
    if row is None:
        job = Job(id=uid(), kind="maintenance", source_id=REPAIR_KEY, status="running")
        db.add(job)
        targets = list(db.scalars(select(Batch.id).where(Batch.status.in_(["preparing", "analyzing", "rendering", "failed"])).order_by(Batch.id)))
        row = MetadataState(key=REPAIR_KEY, value={"job_id": job.id, "phase": "rebuild", "complete": False,
                "targets": targets, "rebuild_index": 0, "started_at": iso(now()), "before": coverage(db),
                "processed": 0, "corrected_dates": 0, "projections_written": 0, "network_gaps": 0})
        db.add(row)
        from .service import audit
        audit(db, "local-cli", "publication.repair-start", REPAIR_KEY)
    db.flush()
    job = db.get(Job, row.value["job_id"])
    job.status, job.error, job.lease_until = "running", None, now() + timedelta(minutes=5)
    row.value = {key: value for key, value in row.value.items() if key != "error"}
    return row


def cleanup_one(db, value):
    index = value["rebuild_index"]
    if index >= len(value["targets"]):
        value["phase"] = "annotating"
        return
    identity = value["targets"][index]
    batch = db.get(Batch, identity)
    if not batch or batch.status == "finalized":
        raise ValueError("待重建批次状态发生变化，拒绝清理已归档报告")
    root = report_dir(identity)
    if root.is_symlink() or root.resolve().parent != root.parent.resolve():
        raise ValueError("报告归档目录超出受控范围")
    if root.exists():
        shutil.rmtree(root)
    items = select(BatchItem.id).where(BatchItem.batch_id == identity)
    from .db import Publication, PublicationClaim
    publication = db.get(Publication, identity)
    if publication and publication.kind == "supplement":
        # Its immutable analysis still exists in the source batch; release claims for regeneration.
        from .publications import cleanup
        cleanup(db, identity)
        db.execute(delete(PublicationClaim).where(PublicationClaim.source_item_id.in_(items)))
    old_work = dict(db.get(ReportState, identity).work) if db.get(ReportState, identity) else {}
    db.execute(delete(Delivery).where(Delivery.batch_id == identity))
    db.execute(delete(ReportSelection).where(ReportSelection.item_id.in_(items)))
    db.execute(delete(ReportCandidate).where(ReportCandidate.batch_id == identity))
    db.execute(delete(UnverifiedItem).where(UnverifiedItem.batch_id == identity))
    db.execute(delete(BatchItem).where(BatchItem.batch_id == identity))
    db.execute(delete(Job).where(Job.kind == "report", Job.source_id == identity))
    if publication and publication.kind == "supplement":
        state = db.get(ReportState, identity)
        state.work = {"phase": "complete", "prepared": True, "date_policy": DATE_POLICY,
                      "publication_kind": "supplement"}
        batch.status, batch.error = "superseded", "日期重建取代未发布补充版，原始详解仍保留在分析批次"
        value["rebuild_index"] = index + 1
        return
    state = db.get(ReportState, identity)
    from .config import settings
    limit = state.work.get("item_limit", settings().report_max_items) if state else settings().report_max_items
    if state is None:
        state = ReportState(batch_id=identity)
        db.add(state)
    state.policy, state.watermark, state.cursor = EVENT_POLICY, None, 0
    state.total, state.new_count, state.update_count, state.unknown_count = 0, 0, 0, 0
    state.coverage_at, state.overview = now(), {}
    state.work = {**{k: v for k, v in old_work.items() if k in {"critical_only", "progressive", "fact_report_id",
        "publication_kind", "logical_slot", "parent_fact_id"}},
        "phase": "prepare", "prepared": False, "item_limit": limit, "date_policy": DATE_POLICY}
    batch.status, batch.summary, batch.error = "preparing", "", None
    value["rebuild_index"] = index + 1


def reconcile_backlog(db, vuln, annotation):
    candidate = db.get(ReportBacklog, vuln.id)
    if candidate is None:
        return
    revision = db.scalar(select(Revision).where(Revision.vulnerability_id == vuln.id).order_by(Revision.id.desc()).limit(1))
    projection = db.get(RevisionDateProjection, revision.id) if revision else None
    qualified_update = bool(projection and projection.important_at and
                            projection.important_at >= candidate.first_eligible_at - timedelta(days=7))
    invalid = (candidate.category == "new" and annotation.status in VERIFIED and annotation.start_at
               and annotation.start_at < candidate.first_eligible_at - timedelta(days=7))
    if candidate.category == "update" and not qualified_update:
        invalid = True
    if invalid and not qualified_update:
        from .service import audit
        audit(db, "date-repair", "backlog.date-invalidated", vuln.id)
        db.delete(candidate)
    elif qualified_update and invalid:
        candidate.category = "update"


def validate_one(db, value):
    identity = db.scalar(select(Vulnerability.id).where(Vulnerability.id > value.get("validation_cursor", ""))
                         .order_by(Vulnerability.id).limit(1))
    if identity is None:
        value["phase"] = "enqueue"
        return
    state = db.get(PublicationState, identity)
    if not state or state.policy != DATE_POLICY:
        raise ValueError("存在缺失或过期的规范公开日期标注")
    annotation = db.get(PublicationAnnotation, state.annotation_id)
    if (not annotation or annotation.vulnerability_id != identity or annotation.policy != DATE_POLICY
            or annotation.status != state.status or annotation.start_at != state.start_at or annotation.end_at != state.end_at):
        raise ValueError("规范公开日期标注与当前投影不一致")
    if annotation.status in VERIFIED and (not annotation.start_at or not annotation.end_at or
            annotation.start_at > annotation.end_at or not annotation.data.get("publication_reference")):
        raise ValueError("规范公开日期缺少有效区间或证据")
    missing = db.scalar(select(Revision.id).where(Revision.vulnerability_id == identity,
        ~exists(select(RevisionDateProjection.revision_id).where(
            RevisionDateProjection.revision_id == Revision.id, RevisionDateProjection.policy == EVENT_POLICY))).limit(1))
    if missing is not None:
        raise ValueError("仍有历史事实缺少当前规则日期投影")
    value["validation_cursor"] = identity
    value["validated"] = value.get("validated", 0) + 1


def save_progress(db, value):
    value["updated_at"] = iso(now())
    db.get(MetadataState, REPAIR_KEY).value = value
    job = db.get(Job, value["job_id"])
    job.status = "done" if value.get("complete") else "running"
    job.lease_until = None if value.get("complete") else now() + timedelta(minutes=5)
    db.commit()


def run_repair(emit=print, transport=None):
    with session() as db:
        row = db.get(MetadataState, REPAIR_KEY)
        if row and row.value.get("complete"):
            result = dict(row.value)
            emit(json.dumps({key: value for key, value in result.items() if key != "targets"}, ensure_ascii=False))
            return result
    with repair_owner():
        with session() as db:
            value = dict(start(db).value)
            db.commit()
        stop = threading.Event()
        heartbeat = threading.Thread(target=_heartbeat, args=(value["job_id"], stop), daemon=True)
        heartbeat.start()
        try:
            while not value.get("complete"):
                if value["phase"] == "annotating":
                    with session() as db:
                        identity = db.scalar(select(Vulnerability.id).where(Vulnerability.id > value.get("cursor", ""))
                                             .order_by(Vulnerability.id).limit(1))
                        if identity:
                            value["current_vulnerability"] = identity
                            save_progress(db, value)
                    if identity:
                        from .date_enrichment import enrich, schedule_retry
                        result = enrich(identity, transport=transport)
                        with session() as db:
                            vuln = db.get(Vulnerability, identity)
                            annotation, _ = annotate(db, vuln, enqueue=False)
                            latest = db.scalar(select(Revision).where(Revision.vulnerability_id == identity)
                                               .order_by(Revision.id.desc()).limit(1))
                            value["corrected_dates"] += int(bool(latest) and latest.published_at != annotation.start_at)
                            value["projections_written"] += replay_projections(db, identity)
                            reconcile_backlog(db, vuln, annotation)
                            schedule_retry(db, identity, result)
                            value["network_gaps"] += int(any(item["status"] == "error" for item in (result or {}).get("diagnostics", [])))
                            value["processed"] += 1
                            value["cursor"] = identity
                            save_progress(db, value)
                    else:
                        value["phase"] = "validation"
                        with session() as db:
                            save_progress(db, value)
                else:
                    with session() as db:
                        if value["phase"] == "rebuild":
                            cleanup_one(db, value)
                        elif value["phase"] == "validation":
                            validate_one(db, value)
                        elif value["phase"] == "enqueue":
                            from .report_jobs import enqueue, status
                            old_dates = 0
                            for identity in value["targets"]:
                                if db.get(Batch, identity).status == "superseded":
                                    continue
                                batch = db.get(Batch, identity)
                                result = status(db, batch)
                                if result["date_audit_required"]:
                                    raise ValueError("重建批次仍有旧日期规则或缺少当前日期版本")
                                old_dates += result["old_date_mixed_count"]
                                enqueue(db, identity)
                            value.update(phase="complete", complete=True, finished_at=iso(now()), after=coverage(db),
                                         old_date_mixed_count=old_dates, checked_unpublished_batches=len(value["targets"]))
                            from .service import audit
                            audit(db, "local-cli", "publication.repair-complete", REPAIR_KEY)
                        save_progress(db, value)
                emit(json.dumps({key: item for key, item in value.items() if key != "targets"}, ensure_ascii=False))
        except BaseException as exc:
            with session() as db:
                row = db.get(MetadataState, REPAIR_KEY)
                if not row.value.get("complete"):
                    job = db.get(Job, row.value["job_id"])
                    reason = type(exc).__name__ + " · 日期修复中断或失败；使用相同命令恢复"
                    job.status, job.error, job.lease_until = "failed", reason, None
                    row.value = {**row.value, "error": reason, "updated_at": iso(now())}
                    db.commit()
            log.exception("publication_repair_failed")
            raise
        finally:
            stop.set()
            heartbeat.join(timeout=5)
        return value
