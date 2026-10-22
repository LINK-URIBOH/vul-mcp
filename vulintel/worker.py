import logging
import signal
import time
from datetime import timedelta

from sqlalchemy import delete, select, text

from .app import initialize
from .config import settings
from .collector import error_details, log_event
from .db import Job, LoginFlow, Source, WebSession, build_engine, now, session
from .delivery import deliver_one
from .sources import collect_one

log = logging.getLogger("vulintel.worker")
stopping = False


def touch_heartbeat():
    if stopping:
        raise InterruptedError("Worker stopping")
    settings().data_dir.mkdir(parents=True, exist_ok=True)
    (settings().data_dir / "worker.heartbeat").touch()


def tick_delivery():
    touch_heartbeat()
    with session() as db:
        deliver_one(db)


def work_once():
    with session() as db:
        for stale in db.scalars(select(Job).where(Job.status == "running", Job.lease_until < now())):
            stale.status, stale.error = "failed", "工作进程中断或租约过期，请重试"
        db.commit()
        job = db.scalar(select(Job).where(Job.status == "pending").order_by(Job.created_at)
                        .with_for_update(skip_locked=True).limit(1))
        if job is None:
            source = db.scalar(select(Source).where(Source.enabled.is_(True), Source.next_run <= now())
                               .order_by(Source.next_run).limit(1))
            if source:
                job = Job(kind="collect", source_id=source.id)
                db.add(job)
                db.flush()
        if job is None:
            return False
        job.status, job.lease_until = "running", now() + timedelta(hours=6)
        job_id, source_id = job.id, job.source_id
        db.commit()
    try:
        collect_one(source_id, force=True, heartbeat=touch_heartbeat, delivery_tick=tick_delivery, job_id=job_id)
        status, error = "done", None
    except Exception as exc:
        details = error_details(exc)
        status, error = "failed", details["reason"]
        log_event("job_failed", level=logging.WARNING, source=source_id, job=job_id, **details)
    with session() as db:
        job = db.get(Job, job_id)
        source = db.get(Source, source_id)
        if status == "failed" and source and source.error:
            error = source.error
        job.status, job.error, job.lease_until = status, error, None
        db.commit()
    return True


def main():
    global stopping
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    for name in ("httpx", "httpx2", "httpcore", "httpcore2"):
        logging.getLogger(name).setLevel(logging.WARNING)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: globals().__setitem__("stopping", True))
    initialize()
    # One collector across all replicas. PostgreSQL advisory session lock is released on process death.
    lock_engine = build_engine(settings().database_url.get_secret_value())
    lock = lock_engine.connect()
    if lock.dialect.name == "postgresql":
        if not lock.execute(text("SELECT pg_try_advisory_lock(86221025)")).scalar():
            raise RuntimeError("Another worker already owns the collector lock")
        lock.commit()
    with session() as db:
        for interrupted in db.scalars(select(Job).where(Job.status == "running")):
            interrupted.status, interrupted.error = "failed", "上次工作进程中断，请重试"
        db.commit()
    last_cleanup = 0.0
    try:
        while not stopping:
            try:
                tick_delivery()
                busy = work_once()
                if time.monotonic() - last_cleanup > 3600:
                    with session() as db:
                        db.execute(delete(LoginFlow).where(LoginFlow.expires < now()))
                        db.execute(delete(WebSession).where(WebSession.expires < now()))
                        db.commit()
                    last_cleanup = time.monotonic()
                settings().data_dir.mkdir(parents=True, exist_ok=True)
                (settings().data_dir / "worker.heartbeat").touch()
                if not busy:
                    time.sleep(5)
            except Exception as exc:
                log_event("worker_iteration_failed", level=logging.ERROR, **error_details(exc))
                time.sleep(10)
    finally:
        lock.close()
        lock_engine.dispose()


if __name__ == "__main__":
    main()
