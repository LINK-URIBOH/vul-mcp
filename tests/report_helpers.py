"""Existing business assertions wait for the real durable job pipeline, without inline production work."""
from vulintel.db import Batch
from vulintel.report_jobs import run_report_once
from vulintel.service import finalize as request_finalize, open_batch as request_open


def drain(db, batch_id, wanted):
    for _ in range(2500):
        db.expire_all()
        batch = db.get(Batch, batch_id)
        if batch.status == wanted:
            return
        assert batch.status != "failed", batch.error
        db.commit()  # Do not hold a SQLite read transaction while the background job commits.
        assert run_report_once(), "No pending report job"
    raise AssertionError("Report pipeline did not reach expected state")


def open_batch(db, actor, slot=None):
    result = request_open(db, actor, slot)
    if result["status"] != "finalized":
        drain(db, result["batch_id"], "analyzing")
    return {**result, "status": db.get(Batch, result["batch_id"]).status}


def finalize(db, actor, batch_id, summary, overview=None):
    result = request_finalize(db, actor, batch_id, summary, overview)
    drain(db, batch_id, "finalized")
    return {**result, "status": "finalized"}
