"""Explicit, resumable business-data reset. Network discovery happens afterwards."""
import json
import shutil
import threading
from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, text, tuple_

from .db import (Alias, Batch, BatchItem, Delivery, Job, MetadataState, PublicationAnnotation, PublicationState,
                 RecentCandidate, RecentSource, ReportBacklog, ReportCandidate, ReportSelection, ReportState,
                 Revision, RevisionDateProjection, Source, SourceRecord, Vulnerability, now, session, uid)
from .maintenance import _heartbeat, repair_owner
from .reports import report_dir
from .timeline import iso

KEY = "recent_reset_v1"
BLOCKED = "近七天重置尚未完成，请运行 reset-recent --days 7 --clear-vulnerabilities --clear-reports 恢复"


def tables():
    from .db import UnverifiedItem
    return [ReportSelection, ReportCandidate, UnverifiedItem, Delivery, BatchItem, ReportState, Batch,
            ReportBacklog, RecentCandidate, RecentSource, RevisionDateProjection, PublicationState,
            PublicationAnnotation, Revision, Alias, SourceRecord, Vulnerability]


def start(db, days=7, new_run=False):
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(86221023)"))
    row = db.get(MetadataState, KEY)
    if row and not new_run:
        return row
    if row and not row.value.get("complete"):
        raise ValueError("当前重置尚未完成，请使用同一命令恢复，不可开始新一轮")
    run_id, job_id, cutoff = uid(), uid(), now()
    value = {"run_id": run_id, "job_id": job_id, "phase": "cleanup", "complete": False,
             "started_at": iso(cutoff), "window_start": iso(cutoff - timedelta(days=days)),
             "window_end": iso(cutoff), "days": days, "cleanup_index": 0, "table_index": 0,
             "deleted_rows": 0, "targets": list(db.scalars(select(Batch.id).order_by(Batch.id))),
             "snapshot_targets": list(db.scalars(select(RecentSource.run_id).distinct())), "snapshot_index": 0,
             "before": {"vulnerabilities": db.scalar(select(func.count()).select_from(Vulnerability)),
                        "reports": db.scalar(select(func.count()).select_from(Batch))}}
    db.add(Job(id=job_id, kind="maintenance", source_id=KEY, status="running",
               lease_until=cutoff + timedelta(minutes=5)))
    if row is None:
        row = MetadataState(key=KEY, value=value)
        db.add(row)
    else:
        from .service import audit
        audit(db, "local-cli", "recent.previous-reset", json.dumps({k: v for k, v in row.value.items() if k in {"run_id", "finished_at"}}))
        row.value = value
    for old_key in ("history_repair_v4", "publication_date_repair_v1", "source_event_backfill_v4"):
        old = db.get(MetadataState, old_key)
        if old:
            old.value = {**old.value, "superseded_by": run_id}
            job = db.get(Job, old.value.get("job_id", ""))
            if job:
                job.status, job.error, job.lease_until = "superseded", "被显式近七天重置取代", None
    db.execute(delete(Job).where(Job.kind.in_(["collect", "report", "publication", "bootstrap"])))
    from .service import audit
    audit(db, "local-cli", "recent.reset-start", run_id)
    db.flush()
    return row


def step(db, value):
    if value["phase"] == "cleanup":
        index = value["cleanup_index"]
        if index < len(value["targets"]):
            root = report_dir(value["targets"][index])
            if root.is_symlink() or root.resolve().parent != root.parent.resolve():
                raise ValueError("报告目录超出受控范围，停止重置")
            if root.exists():
                shutil.rmtree(root)
            value["cleanup_index"] += 1
        else:
            value["phase"] = "snapshots"
    elif value["phase"] == "snapshots":
        index = value["snapshot_index"]
        if index >= len(value["snapshot_targets"]):
            value["phase"] = "tables"
        else:
            from uuid import UUID
            from .config import settings
            identity = value["snapshot_targets"][index]
            UUID(identity)
            parent = settings().data_dir / "recent-snapshots"
            root = parent / identity
            if parent.is_symlink() or root.is_symlink() or root.resolve().parent != parent.resolve():
                raise ValueError("候选快照目录超出受控范围，停止重置")
            if root.exists():
                shutil.rmtree(root)
            value["snapshot_index"] += 1
    elif value["phase"] == "tables":
        models = tables()
        index = value["table_index"]
        if index >= len(models):
            value["phase"] = "validation"
            return
        model = models[index]
        keys = list(model.__table__.primary_key.columns)
        rows = list(db.execute(select(*keys).order_by(*keys).limit(200)))
        if rows:
            db.execute(delete(model).where(tuple_(*keys).in_([tuple(row) for row in rows])))
            value["deleted_rows"] += len(rows)
        else:
            value["table_index"] += 1
        value["current_table"] = model.__tablename__
    elif value["phase"] == "validation":
        if any(db.scalar(select(func.count()).select_from(model)) for model in tables()):
            raise ValueError("重置后仍有漏洞或报告依赖残留")
        cutoff = datetime.fromisoformat(value["window_end"].removesuffix("Z"))
        start_at = cutoff - timedelta(days=value["days"])
        for source in db.scalars(select(Source)):
            source.last_success, source.last_attempt, source.error, source.next_run = None, None, None, now()
            targeted = source.kind in {"osv", "psf", "kev"}
            db.add(RecentSource(run_id=value["run_id"], source_id=source.id,
                               mode="targeted" if targeted else "published", start_at=start_at, end_at=cutoff,
                               status="deferred" if targeted else "pending"))
        for row in db.scalars(select(MetadataState).where(MetadataState.key.like("source-progress:%"))):
            db.delete(row)
        db.add(Job(kind="bootstrap", source_id=value["run_id"]))
        value.update(phase="complete", complete=True, finished_at=iso(now()),
                     after={"vulnerabilities": 0, "reports": 0}, bootstrap_status="queued")
        from .service import audit
        audit(db, "local-cli", "recent.reset-complete", value["run_id"])


def run_reset(days=7, new_run=False, emit=print):
    if days != 7:
        raise ValueError("本入口仅支持最近7×24小时初始化")
    with session() as db:
        previous = db.get(MetadataState, KEY)
        if previous and previous.value.get("complete") and not new_run:
            value = dict(previous.value)
            emit(json.dumps({k: v for k, v in value.items() if k != "targets"}, ensure_ascii=False))
            return value
    # Acquire the owner lock even for resume; never override a live repair/worker.
    with repair_owner():
        with session() as db:
            row = start(db, days, new_run)
            value = dict(row.value)
            if value.get("complete"):
                emit(json.dumps({k: v for k, v in value.items() if k != "targets"}, ensure_ascii=False))
                return value
            job = db.get(Job, value["job_id"])
            job.status, job.error, job.lease_until = "running", None, now() + timedelta(minutes=5)
            db.commit()
        stop = threading.Event()
        heartbeat = threading.Thread(target=_heartbeat, args=(value["job_id"], stop), daemon=True)
        heartbeat.start()
        try:
            while not value.get("complete"):
                with session() as db:
                    step(db, value)
                    value["updated_at"] = iso(now())
                    value.pop("error", None)
                    db.get(MetadataState, KEY).value = value
                    job = db.get(Job, value["job_id"])
                    job.status = "done" if value.get("complete") else "running"
                    job.lease_until = None if value.get("complete") else now() + timedelta(minutes=5)
                    db.commit()
                emit(json.dumps({k: v for k, v in value.items() if k != "targets"}, ensure_ascii=False))
        except BaseException as exc:
            with session() as db:
                row = db.get(MetadataState, KEY)
                if not row.value.get("complete"):
                    reason = type(exc).__name__ + " · 重置中断或失败，使用同一命令恢复"
                    row.value = {**row.value, "error": reason}
                    job = db.get(Job, value["job_id"])
                    job.status, job.error, job.lease_until = "failed", reason, None
                    db.commit()
            raise
        finally:
            stop.set()
            heartbeat.join(timeout=5)
    return value
