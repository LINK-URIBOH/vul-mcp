"""Cloud-triggered fact archives and independently acknowledged analysis supplements.

Publication IDs are archive Batch IDs, so existing authenticated downloads, MIME
validation, staged activation and stable delivery IDs have a single implementation.
No calendar scheduler or model API is used here.
"""
import hashlib
import json
from datetime import timedelta

from sqlalchemy import delete, exists, func, select

from .db import (Batch, BatchItem, Delivery, Job, Publication, PublicationClaim, PublicationReceipt,
                 ReportBacklog, ReportSelection, ReportState, Revision, now, uid)
from .publication import DATE_POLICY
from .timeline import EVENT_POLICY, iso

LABELS = {"facts": "事实版（尚未完成模型详解）", "supplement": "中文详解补充版", "aggregate": "完整详解汇总"}


def event_key(facts, category):
    timeline = facts.get("timeline", {})
    from .timeline import material
    payload = [[list(key), value] for key, value in sorted(material(facts).items())]
    value = [category] if category == "new" else [category, timeline.get("material_changed_at"), timeline.get("change_basis"), payload]
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def received(db, kind, vulnerability_id, facts, category):
    exact = db.scalar(select(PublicationReceipt.id).where(PublicationReceipt.kind == kind,
        PublicationReceipt.vulnerability_id == vulnerability_id,
        PublicationReceipt.event_key == event_key(facts, category))) is not None
    if exact or category == "new":
        return exact
    from .timeline import material
    current, timeline = material(facts), facts.get("timeline", {})
    for snapshot in db.scalars(select(BatchItem.snapshot).join(ReportSelection,
            ReportSelection.item_id == BatchItem.id).join(PublicationReceipt,
            (PublicationReceipt.revision_id == ReportSelection.revision_id)
            & (PublicationReceipt.publication_id == BatchItem.batch_id)).where(PublicationReceipt.kind == kind,
            PublicationReceipt.vulnerability_id == vulnerability_id)):
        previous = snapshot.get("timeline", {})
        if (previous.get("material_changed_at"), previous.get("change_basis")) != (timeline.get("material_changed_at"), timeline.get("change_basis")):
            continue
        old = material(snapshot)
        common = old.keys() & current.keys()
        if common and all(old[key] == current[key] for key in common):
            # New source attachment alone is not a new important event. The
            # same patch may already have been included in a disclosure edition.
            return True
    return False


def create(db, kind, slot, cutoff, key, source_batch_id=None, parent_fact_id=None):
    existing = db.scalar(select(Publication).where(Publication.key == key))
    if existing:
        return existing
    identity = uid()
    # Internal archive slots are never accepted as user-supplied report cutoffs.
    batch = Batch(id=identity, slot="pub:" + identity, cutoff=cutoff, status="preparing")
    db.add(batch)
    db.flush()
    publication = Publication(id=identity, key=key, kind=kind, slot=slot,
        source_batch_id=source_batch_id, parent_fact_id=parent_fact_id,
        deadline=cutoff + timedelta(minutes=30))
    db.add(publication)
    from .service import source_status
    batch.coverage = source_status(db)
    db.add(ReportState(batch_id=identity, policy=EVENT_POLICY, work={
        "phase": "prepare" if kind == "facts" else "render", "prepared": kind != "facts",
        "publication_kind": kind, "logical_slot": slot, "date_policy": DATE_POLICY,
        "critical_only": True, "item_limit": None, "parent_fact_id": parent_fact_id}))
    db.add(Job(kind="report", source_id=identity))
    db.flush()
    return publication


def trigger_facts(db, actor, slot):
    from .timeline import stamp
    publication = create(db, "facts", slot, stamp(slot), "facts:" + slot)
    from .service import audit
    audit(db, actor, "publication.facts-trigger", publication.id)
    return publication


def publication_status(db, publication):
    batch, state = db.get(Batch, publication.id), db.get(ReportState, publication.id)
    return {"report_id": publication.id, "kind": publication.kind, "label": LABELS[publication.kind],
        "slot": publication.slot, "triggered_at": iso(publication.triggered_at),
        "deadline": iso(publication.deadline) if publication.kind == "facts" else None,
        "status": batch.status, "phase": state.work.get("phase"), "total": state.total if state.work.get("prepared") else None,
        "error": batch.error, "retry_at": state.work.get("retry_at"), "heartbeat": state.work.get("heartbeat"),
        "parent_fact_id": publication.parent_fact_id, "archived_at": state.work.get("published_at"),
        "late": publication.kind == "facts" and
            (stamp_time(state.work["published_at"]) if state.work.get("published_at") else now()) > publication.deadline,
        "deliveries": [{"id": d.id, "channel": d.channel, "part": d.part, "status": d.status,
                        "attempts": d.attempts, "error": d.error, "next_retry": iso(d.next_run)}
                       for d in db.scalars(select(Delivery).where(Delivery.batch_id == publication.id))]}


def related_status(db, batch, fact_report_id=None):
    fact = db.get(Publication, fact_report_id) if fact_report_id else db.scalar(select(Publication).where(
        Publication.kind == "facts", Publication.slot == batch.slot))
    if fact_report_id and (not fact or fact.kind != "facts"):
        raise ValueError("未知事实报告编号")
    supplements = list(db.scalars(select(Publication).where(Publication.source_batch_id == batch.id, Publication.kind == "supplement")
                                 .order_by(Publication.triggered_at, Publication.id)))
    count = db.scalar(select(func.count()).select_from(PublicationClaim).join(Batch,
        Batch.id == PublicationClaim.publication_id).where(Batch.status == "finalized",
        PublicationClaim.source_item_id.in_(select(BatchItem.id).where(BatchItem.batch_id == batch.id))))
    return {"fact_report": publication_status(db, fact) if fact else None,
            "supplements": [publication_status(db, p) for p in supplements], "analyses_published": count,
            "aggregate": publication_status(db, db.get(Publication, batch.id))
            if db.get(Publication, batch.id) and db.get(Publication, batch.id).kind == "aggregate" else None}


def copy_analysis(db, publication, item):
    selection = db.get(ReportSelection, item.id)
    clone = BatchItem(batch_id=publication.id, vulnerability_id=item.vulnerability_id,
                      snapshot=item.snapshot, analysis=item.analysis, priority=item.priority)
    db.add(clone)
    db.flush()
    db.add(ReportSelection(item_id=clone.id, revision_id=selection.revision_id,
        group_name=selection.group_name, rank=selection.rank, category=selection.category))
    db.add(PublicationClaim(source_item_id=item.id, publication_id=publication.id, artifact_item_id=clone.id))
    state = db.get(ReportState, publication.id)
    state.total += 1
    state.new_count += int(selection.category == "new")
    state.update_count += int(selection.category != "new")


def flush_supplements(db, batch_id, force=False):
    state = db.get(ReportState, batch_id)
    if not state or not state.work.get("progressive") or not state.work.get("prepared"):
        return []
    batch = db.scalar(select(Batch).where(Batch.id == batch_id).with_for_update())
    last = state.work.get("last_analysis_at")
    from .timeline import stamp
    idle = bool(last and now() - stamp(last) >= timedelta(minutes=15))
    result = []
    while True:
        rows = list(db.scalars(select(BatchItem).where(BatchItem.batch_id == batch_id,
            BatchItem.analysis.is_not(None), ~exists(select(PublicationClaim.source_item_id).where(
                PublicationClaim.source_item_id == BatchItem.id))).order_by(BatchItem.id).limit(50)))
        groups = {}
        for item in rows:
            selection = db.get(ReportSelection, item.id)
            canonical_id = db.get(Revision, selection.revision_id).vulnerability_id
            parent = db.scalar(select(PublicationReceipt.publication_id).where(PublicationReceipt.kind == "facts",
                PublicationReceipt.vulnerability_id == canonical_id,
                PublicationReceipt.event_key == event_key(item.snapshot, selection.category)))
            if not parent:
                parent = db.scalar(select(PublicationReceipt.publication_id).join(Publication,
                    Publication.id == PublicationReceipt.publication_id).where(PublicationReceipt.kind == "facts",
                    PublicationReceipt.vulnerability_id == canonical_id).order_by(Publication.triggered_at.desc()).limit(1))
            groups.setdefault(parent or state.work.get("fact_report_id"), []).append(item)
        eligible = [(parent, items[:10]) for parent, items in groups.items() if len(items) >= 10 or force or idle]
        if not eligible:
            break
        parent, rows = eligible[0]
        publication = create(db, "supplement", batch.slot, batch.cutoff,
            "supplement:" + batch_id + ":" + str(rows[0].id), batch_id, parent)
        for item in rows:
            copy_analysis(db, publication, item)
        artifact = db.get(Batch, publication.id)
        artifact.status = "rendering"
        pstate = db.get(ReportState, publication.id)
        pstate.work = {**pstate.work, "candidate_total": pstate.total}
        result.append(publication.id)
        db.flush()
    return result


def acknowledge(db, batch, state):
    """Called only after all archive files pass validation, in activation transaction."""
    publication = db.get(Publication, batch.id)
    if not publication:
        return False
    kind = "facts" if publication.kind == "facts" else "detail"
    for item, selection in db.execute(select(BatchItem, ReportSelection).join(ReportSelection,
        ReportSelection.item_id == BatchItem.id).where(BatchItem.batch_id == batch.id)):
        canonical_id = db.get(Revision, selection.revision_id).vulnerability_id
        if not received(db, kind, canonical_id, item.snapshot, selection.category):
            db.add(PublicationReceipt(publication_id=batch.id, kind=kind, vulnerability_id=canonical_id,
                event_key=event_key(item.snapshot, selection.category), revision_id=selection.revision_id,
                date_annotation_id=item.snapshot.get("timeline", {}).get("date_annotation_id")))
        if kind == "detail":
            db.execute(delete(ReportBacklog).where(ReportBacklog.vulnerability_id == canonical_id,
                ReportBacklog.revision_id == selection.revision_id))
            pending = db.get(ReportBacklog, canonical_id)
            if pending and pending.revision_id != selection.revision_id:
                pending.category = "update"
    return True


def coordinate(db):
    """Never creates a time slot: only progresses explicitly triggered batches."""
    from .report_jobs import enqueue
    for state in db.scalars(select(ReportState).join(Batch).where(Batch.status == "analyzing")):
        if not state.work.get("progressive") or not state.work.get("prepared"):
            continue
        flush_supplements(db, state.batch_id)
        pending = db.scalar(select(func.count()).select_from(BatchItem).where(
            BatchItem.batch_id == state.batch_id, BatchItem.analysis.is_(None)))
        if pending == 0:
            flush_supplements(db, state.batch_id, force=True)
            outstanding = db.scalar(select(Publication.id).join(Batch, Batch.id == Publication.id).where(
                Publication.source_batch_id == state.batch_id, Batch.status != "finalized").limit(1))
            if outstanding:
                continue
            batch = db.get(Batch, state.batch_id)
            batch.status = "rendering"
            if not db.get(Publication, batch.id):
                db.add(Publication(id=batch.id, kind="aggregate", key="aggregate:" + batch.id,
                    slot=batch.slot, source_batch_id=batch.id, parent_fact_id=state.work.get("fact_report_id"),
                    deadline=batch.cutoff + timedelta(minutes=30)))
            state.work = {**state.work, "phase": "render", "archive_only": True,
                          "publication_kind": "aggregate"}
            enqueue(db, batch.id)
    # Retry transient rendering errors without requiring the next cloud run.
    for state in db.scalars(select(ReportState).join(Batch).where(Batch.status == "failed")):
        work = state.work
        if work.get("retry_at") and stamp_time(work["retry_at"]) <= now():
            batch = db.get(Batch, state.batch_id)
            batch.status = "preparing" if work.get("phase") in {"prepare", "select"} else "rendering"
            state.work = {**work, "retry_at": None}
            enqueue(db, batch.id)


def stamp_time(value):
    from .timeline import stamp
    return stamp(value)


def cleanup(db, identity):
    db.execute(delete(PublicationReceipt).where(PublicationReceipt.publication_id == identity))
    db.execute(delete(PublicationClaim).where(PublicationClaim.publication_id == identity))
    db.execute(delete(Publication).where(Publication.id == identity))


def publisher_status():
    from .config import settings
    path = settings().data_dir / "publisher.heartbeat"
    import time
    age = time.time() - path.stat().st_mtime if path.exists() else None
    return {"enabled": settings().publisher_enabled, "heartbeat_age_seconds": age,
            "healthy": age is not None and age < 120}
