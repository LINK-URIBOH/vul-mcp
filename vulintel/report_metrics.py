"""Read-only canonical cross-source volume; never an upstream-only estimate."""
from collections import Counter
from datetime import timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from .db import (Batch, Publication, PublicationState, ReportBacklog, ReportState, Revision, RevisionDateProjection,
                 Vulnerability, now)
from .publication import DATE_POLICY, VERIFIED, date_in_window
from .timeline import EVENT_POLICY, iso


def volume(db, days=7, severity="critical"):
    if not 1 <= days <= 30 or severity != "critical":
        raise ValueError("仅支持1..30天的critical统计")
    end = now()
    start = end - timedelta(days=days)
    disclosures, updates, slots, unknown_dates = 0, 0, Counter(), 0
    latest = select(Revision.vulnerability_id, func.max(Revision.id).label("revision_id")).group_by(
        Revision.vulnerability_id).subquery()
    rows = db.execute(select(Vulnerability.id, PublicationState, RevisionDateProjection).outerjoin(
        PublicationState, PublicationState.vulnerability_id == Vulnerability.id).outerjoin(
        latest, latest.c.vulnerability_id == Vulnerability.id).outerjoin(RevisionDateProjection,
        RevisionDateProjection.revision_id == latest.c.revision_id).where(Vulnerability.severity == severity)
        .execution_options(yield_per=100))
    for _, annotation, projection in rows:
        if not annotation or annotation.policy != DATE_POLICY or annotation.status not in VERIFIED:
            unknown_dates += 1
            continue
        event = None
        if date_in_window(annotation, start, end):
            disclosures += 1
            event = annotation.end_at
        elif (projection and projection.policy == EVENT_POLICY and projection.important_at
              and start <= projection.important_at <= end and projection.important_end_at
              and projection.important_end_at <= end):
            updates += 1
            event = projection.important_end_at
        if event:
            local = event.replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Shanghai"))
            morning = local.replace(hour=9, minute=0, second=0, microsecond=0)
            evening = local.replace(hour=18, minute=0, second=0, microsecond=0)
            target = morning if local <= morning else evening
            if local > evening:
                target = (local + timedelta(days=1)).replace(hour=9, minute=0, second=0, microsecond=0)
            slots[target.isoformat(timespec="minutes")] += 1
    from .service import source_status
    from .recent import progress
    coverage, bootstrap = source_status(db), progress(db) or {}
    unknown_rating = db.scalar(select(func.count()).select_from(Vulnerability).where(Vulnerability.severity == "unknown"))
    return {"window_start": iso(start), "window_end": iso(end), "severity": severity,
        "new_disclosures": disclosures, "important_updates": updates, "daily_new_average": disclosures / days,
        "daily_total_average": (disclosures + updates) / days, "BJT_slots": dict(sorted(slots.items())),
        "detail_backlog": db.scalar(select(func.count()).select_from(ReportBacklog).join(
            Vulnerability, Vulnerability.id == ReportBacklog.vulnerability_id).where(Vulnerability.severity == severity)),
        "unknown_critical_dates": unknown_dates, "unknown_severity": unknown_rating,
        "bootstrap": bootstrap, "source_coverage": coverage,
        "complete": not (unknown_dates or unknown_rating or bootstrap.get("pending", 0) or bootstrap.get("unverified", 0)
            or bootstrap.get("conflicts", 0) or any(s["enabled"] and (s.get("coverage_limited") or s["error"] or s["stale"]) for s in coverage)),
        "methodology": "正式库统一漏洞标识去重；规范公开时间优先，旧漏洞可核实重要事件另计；覆盖不足时不代表全渠道准确日均。"}


def publication_progress(db):
    from .publications import publication_status, publisher_status
    from .report_jobs import status
    return {"publisher": publisher_status(), "analysis_batches": [status(db, batch) for batch in db.scalars(
        select(Batch).join(ReportState).where(ReportState.work["progressive"].as_boolean().is_(True))
        .order_by(Batch.cutoff.desc()).limit(10))], "publications": [publication_status(db, p) for p in db.scalars(
        select(Publication).order_by(Publication.triggered_at.desc()).limit(30))]}
