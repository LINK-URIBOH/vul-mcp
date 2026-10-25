"""Explicit, resumable historical repair. No network collection or report delivery."""
import json
import logging
import shutil
import threading
from contextlib import contextmanager
from datetime import timedelta

from sqlalchemy import delete, exists, func, select, text
from sqlalchemy.orm import aliased

from .db import (Alias, Batch, BatchItem, Delivery, Job, MetadataState, ReportBacklog, ReportCandidate, ReportSelection,
                 ReportState, Revision, SourceRecord, UnverifiedItem, Vulnerability, now, session, uid)
from .identity import record_aliases
from .reports import report_dir
from .timeline import BACKFILL_KEY, EVENT_POLICY, backfill_step, iso

KEY = "history_repair_v4"
BLOCKED = "历史数据维护尚未完成，请运行 repair-history --clear-reports 恢复后再生成报告"
log = logging.getLogger("vulintel.maintenance")


def progress(db):
    from .publication import REPAIR_KEY
    from .recent_reset import KEY as RESET_KEY
    row = db.get(MetadataState, RESET_KEY) or db.get(MetadataState, REPAIR_KEY) or db.get(MetadataState, KEY)
    if not row:
        return None
    value = dict(row.value)
    value.pop("targets", None)
    job = db.get(Job, value["job_id"])
    value["status"] = job.status if job else "failed"
    if value["status"] == "running" and (not job.lease_until or job.lease_until < now()):
        value["status"] = "interrupted"
    value["heartbeat_at"] = iso(job.lease_until - timedelta(minutes=5)) if job and job.lease_until else None
    return value


def active(db):
    from .publication import REPAIR_KEY
    from .recent_reset import KEY as RESET_KEY
    return any(row and not row.value.get("complete") and not row.value.get("superseded_by") for row in
               (db.get(MetadataState, KEY), db.get(MetadataState, REPAIR_KEY), db.get(MetadataState, RESET_KEY)))


def report_write_guard(db):
    # Same transaction lock as open_batch: maintenance waits for in-flight writes
    # before setting its durable fence. Subsequent writes see the fence.
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(86221023)"))
    if active(db):
        from .recent_reset import BLOCKED as RESET_BLOCKED, KEY as RESET_KEY
        reset = db.get(MetadataState, RESET_KEY)
        if reset and not reset.value.get("complete"):
            raise ValueError(RESET_BLOCKED)
        from .publication import DATES_BLOCKED, REPAIR_KEY
        row = db.get(MetadataState, REPAIR_KEY)
        if row and not row.value.get("complete"):
            raise ValueError(DATES_BLOCKED)
        raise ValueError(BLOCKED)


@contextmanager
def repair_owner():
    from .config import settings
    from .db import build_engine
    # The long-lived lock must not occupy the application's small connection pool;
    # repair transactions and heartbeat each need a connection during a large item.
    lock_engine = build_engine(settings().database_url.get_secret_value())
    try:
        with lock_engine.connect() as connection:
            with _owner_connection(connection):
                yield
    finally:
        lock_engine.dispose()


@contextmanager
def _owner_connection(connection):
    if connection.dialect.name == "postgresql":
        # Also excludes the collector and any in-flight SMTP send by worker.
        acquired = connection.execute(text("SELECT pg_try_advisory_lock(86221025)")).scalar()
        connection.commit()
        if not acquired:
            raise ValueError("请先停止 worker；已有 worker 或历史修复进程持有运行锁")
        if not connection.execute(text("SELECT pg_try_advisory_lock(86221026)")).scalar():
            connection.execute(text("SELECT pg_advisory_unlock(86221025)"))
            connection.commit()
            raise ValueError("请先停止 publisher；发布进程持有运行锁")
        connection.commit()
    else:
        # SQLite is only used in tests/development; an OS lock excludes CLI replicas.
        import os
        from .config import settings
        root = settings().data_dir
        root.mkdir(parents=True, exist_ok=True)
        handle = (root / "history-repair.lock").open("a+b")
        try:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                handle.write(b"0")
                handle.flush()
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            raise ValueError("已有历史修复进程持有运行锁") from None
    try:
        yield
    finally:
        if connection.dialect.name == "postgresql":
            connection.execute(text("SELECT pg_advisory_unlock(86221026)"))
            connection.execute(text("SELECT pg_advisory_unlock(86221025)"))
            connection.commit()
        else:
            handle.close()


def counts(db):
    return {model.__tablename__: db.scalar(select(func.count()).select_from(model))
            for model in (Vulnerability, SourceRecord, Alias, Revision, Batch)}


def start(db):
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(86221023)"))
    row = db.get(MetadataState, KEY)
    if row and row.value.get("complete"):
        return row
    if not row:
        job = Job(id=uid(), kind="maintenance", source_id=KEY, status="running")
        db.add(job)
        row = MetadataState(key=KEY, value={"job_id": job.id, "phase": "cleanup", "complete": False,
                            "started_at": iso(now()), "targets": list(db.scalars(select(Batch.id).order_by(Batch.id))),
                            "cleanup_index": 0, "before": counts(db)})
        db.add(row)
        from .service import audit
        audit(db, "local-cli", "maintenance.start", KEY)
    job = db.get(Job, row.value["job_id"])
    job.status, job.error, job.lease_until = "running", None, now() + timedelta(minutes=5)
    row.value = {key: value for key, value in row.value.items() if key != "error"}
    return row


def cleanup_one(db, value):
    index, targets = value["cleanup_index"], value["targets"]
    if index >= len(targets):
        db.execute(delete(ReportBacklog))
        db.execute(delete(Job).where(Job.kind == "report"))
        value["phase"] = "aliases"
        # Force a full new-generation scan even if another v4 backfill finished
        # before this explicit maintenance run. Never reset again on resume.
        state = db.get(MetadataState, BACKFILL_KEY)
        if state:
            db.delete(state)
        return
    identity = targets[index]
    # UUID path validation plus a resolved containment check excludes path traversal
    # and links pointing outside the managed reports directory.
    root = report_dir(identity)
    parent = root.parent.resolve()
    if root.is_symlink() or root.resolve().parent != parent:
        raise ValueError("报告目录不在受控归档目录内，停止清理")
    if root.exists():
        shutil.rmtree(root)
    items = select(BatchItem.id).where(BatchItem.batch_id == identity)
    from .publications import cleanup
    cleanup(db, identity)
    db.execute(delete(Delivery).where(Delivery.batch_id == identity))
    db.execute(delete(ReportCandidate).where(ReportCandidate.batch_id == identity))
    db.execute(delete(ReportSelection).where(ReportSelection.item_id.in_(items)))
    db.execute(delete(UnverifiedItem).where(UnverifiedItem.batch_id == identity))
    db.execute(delete(BatchItem).where(BatchItem.batch_id == identity))
    db.execute(delete(ReportState).where(ReportState.batch_id == identity))
    db.execute(delete(Job).where(Job.kind == "report", Job.source_id == identity))
    db.execute(delete(Batch).where(Batch.id == identity))
    value["cleanup_index"] = index + 1


def validate_step(db, value, limit=100):
    """Read one facts object at a time; counters/cursors commit with each page."""
    kind = value.get("validation_kind", "sources")
    model = {"sources": SourceRecord, "aliases": Alias, "vulnerabilities": Vulnerability}[kind]
    column = Alias.alias if kind == "aliases" else model.id
    rows = list(db.scalars(select(column).where(column > value.get("validation_cursor", ""))
                           .order_by(column).limit(limit)))
    budget = 0
    for identity in rows:
        row = db.get(model, identity)
        if kind == "sources":
            if not db.get(Vulnerability, row.vulnerability_id) or record_aliases(row.data) != row.data.get("aliases", []):
                raise ValueError("来源标识或关联校验失败")
            for alias in row.data.get("aliases", []):
                linked = db.get(Alias, str(alias).upper())
                if not linked or linked.vulnerability_id != row.vulnerability_id:
                    raise ValueError("来源与别名关联校验失败")
            budget += len(json.dumps(row.data, ensure_ascii=False).encode())
        elif kind == "aliases":
            if not db.get(Vulnerability, row.vulnerability_id):
                raise ValueError("别名存在孤立关联")
        else:
            revision = db.scalar(select(Revision).where(Revision.vulnerability_id == identity)
                                 .order_by(Revision.id.desc()).limit(1))
            if not revision or revision.snapshot.get("timeline", {}).get("event_policy") != EVENT_POLICY:
                raise ValueError("最新事件策略校验失败")
            if any(revision.snapshot.get(key) != child for key, child in row.data.items() if key != "timeline"):
                raise ValueError("归并后最新来源事实不完整")
            value["unverified_dates"] = value.get("unverified_dates", 0) + int(revision.published_at is None)
            budget += revision.snapshot_bytes
        value["validation_cursor"] = identity
        value["validated"] = value.get("validated", 0) + 1
        db.expunge(row)
        if budget >= 2_000_000:
            break
    if not rows:
        kinds = ["sources", "aliases", "vulnerabilities"]
        index = kinds.index(kind) + 1
        value["validation_cursor"] = ""
        if index < len(kinds):
            value["validation_kind"] = kinds[index]
        else:
            orphan = db.scalar(select(Revision.id).where(~exists(select(Vulnerability.id).where(
                Vulnerability.id == Revision.vulnerability_id))).limit(1))
            selection = aliased(Revision)
            broken = db.scalar(select(ReportSelection.item_id).where(~exists(select(selection.id).where(
                selection.id == ReportSelection.revision_id))).limit(1))
            if orphan is not None or broken is not None:
                raise ValueError("历史修订引用校验失败")
            value.update(phase="complete", complete=True, finished_at=iso(now()), after=counts(db))
            from .service import audit
            audit(db, "local-cli", "maintenance.complete", KEY)


def step(db, row):
    value = dict(row.value)
    if value["phase"] == "cleanup":
        cleanup_one(db, value)
    elif value["phase"] in {"aliases", "events"}:
        complete = backfill_step(db)
        state = db.get(MetadataState, BACKFILL_KEY).value
        value["backfill"] = dict(state)
        value["phase"] = "validation" if complete else state.get("phase", "events")
    elif value["phase"] == "validation":
        validate_step(db, value)
    value["updated_at"] = iso(now())
    row.value = value
    job = db.get(Job, value["job_id"])
    job.status = "done" if value.get("complete") else "running"
    job.lease_until = None if value.get("complete") else now() + timedelta(minutes=5)
    return value


def run_repair(emit=print):
    """Unbounded number of bounded transactions; failures never erase checkpoints."""
    with session() as db:
        existing = db.get(MetadataState, KEY)
        if existing and existing.value.get("complete"):
            value = dict(existing.value)
            emit(json.dumps({k: v for k, v in value.items() if k != "targets"}, ensure_ascii=False))
            return value
    with repair_owner():
        with session() as db:
            row = start(db)
            db.commit()
            value = dict(row.value)
        stop = threading.Event()
        heartbeat = threading.Thread(target=_heartbeat, args=(value["job_id"], stop), daemon=True)
        heartbeat.start()
        try:
            emit(json.dumps({k: v for k, v in value.items() if k != "targets"}, ensure_ascii=False))
            while not value.get("complete"):
                with session() as db:
                    value = step(db, db.get(MetadataState, KEY))
                    db.commit()
                emit(json.dumps({k: v for k, v in value.items() if k != "targets"}, ensure_ascii=False))
        except BaseException as exc:
            with session() as db:
                row = db.get(MetadataState, KEY)
                job = db.get(Job, row.value["job_id"])
                reason = ("已中断；使用相同命令恢复" if isinstance(exc, (KeyboardInterrupt, SystemExit)) else
                          type(exc).__name__ + " · 修复失败；检查日志后使用相同命令恢复")
                if not row.value.get("complete"):
                    job.status, job.error, job.lease_until = "failed", reason, None
                    row.value = {**row.value, "error": reason, "updated_at": iso(now())}
                db.commit()
            log.exception("history_repair_failed")
            raise
        finally:
            stop.set()
            heartbeat.join(timeout=5)
        return value


def _heartbeat(job_id, stop):
    while not stop.wait(30):
        try:
            with session() as db:
                job = db.get(Job, job_id)
                if not job or job.status != "running":
                    return
                job.lease_until = now() + timedelta(minutes=5)
                db.commit()
        except Exception:
            log.exception("history_repair_heartbeat_failed")
