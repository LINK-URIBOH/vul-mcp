"""Read-only review of frozen report selections against corrected source semantics."""
from collections import Counter
from datetime import timedelta
from types import SimpleNamespace

from sqlalchemy import select

from .db import Alias, Batch, BatchItem, PublicationAnnotation, PublicationState
from .identity import CVE_ID, record_aliases
from .timeline import EVENT_POLICY, derive_revision, iso, stamp


def audit_items(items, cutoff, lookup=None, summary_only=False):
    parents, rows = {}, []

    def root(key):
        parents.setdefault(key, key)
        while parents[key] != key:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key

    for item_id, facts in items:
        aliases = record_aliases(facts)
        for record in facts.get("source_records", []):
            aliases.extend(record_aliases(record))
        aliases = sorted(set(aliases)) or ["item:" + str(item_id)]
        for alias in aliases[1:]:
            parents[root(alias)] = root(aliases[0])
        old = facts.get("timeline", {})
        if summary_only:
            public = stamp(old.get("published_at"))
            if old.get("publication_source") in {"osv-debian", "osv-ubuntu"} or (public and public > cutoff):
                public = None
            source_publications = []
        else:
            corrected = derive_revision(SimpleNamespace(id="audit", data=facts), observed=cutoff, baseline=True)
            public = corrected.published_at
            source_publications = corrected.snapshot["timeline"]["source_publications"]
        rows.append({"item_id": item_id, "aliases": aliases, "original_category": facts.get("report_category"),
                     "original_publication": old.get("published_at"),
                     "original_publication_source": old.get("publication_source"),
                     "corrected_publication": iso(public), "source_publications": source_publications,
                     "invalid_event_dates": [key for key in ("material_changed_at", "patch_published_at", "kev_added_at")
                                             if old.get(key) and stamp(old[key]) is None]})
    groups = {}
    for row in rows:
        groups.setdefault(root(row["aliases"][0]), []).append(row)
    start = cutoff - timedelta(days=7)
    # Calendar week is distinct from the service's rolling seven-day window.
    local = cutoff + timedelta(hours=8)
    week_start = (local - timedelta(days=local.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    week_start -= timedelta(hours=8)
    summary, original_new, details = Counter(), Counter(), []
    for row in rows:
        if row["original_category"] != "new":
            continue
        public = stamp(row["original_publication"])
        if public and start <= public <= cutoff:
            summary["original_new_dates_in_window"] += 1
        if public and week_start <= public <= cutoff:
            summary["original_new_dates_in_calendar_week"] += 1
        elif public and public < week_start:
            summary["original_new_dates_before_calendar_week"] += 1
    for members in groups.values():
        aliases = sorted({alias for row in members for alias in row["aliases"]})
        dates = [stamp(row["corrected_publication"]) for row in members if row["corrected_publication"]]
        if lookup:
            dates.extend(lookup([alias for alias in aliases if CVE_ID.fullmatch(alias)]))
        published = min(dates) if dates else None
        category = ("unverified" if published is None else
                    "supported_in_window" if start <= published <= cutoff else "outside_window")
        summary[category] += 1
        new_members = [row for row in members if row["original_category"] == "new"]
        original_new[category] += len(new_members)
        summary["original_new_rows"] += len(new_members)
        summary["duplicate_rows"] += len(members) - 1
        if published and week_start <= published <= cutoff:
            summary["supported_in_calendar_week"] += 1
        details.append({"aliases": aliases, "item_ids": [row["item_id"] for row in members],
                        "earliest_supported_publication": iso(published), "classification": category,
                        "members": members})
    return {"event_policy": EVENT_POLICY, "full_evidence_reviewed": not summary_only,
            "window_start_utc": iso(start), "cutoff_utc": iso(cutoff),
            "calendar_week_start_utc": iso(week_start), "rows": len(rows), "identity_groups": len(groups),
            "summary": dict(summary), "original_new_rows_by_corrected_group": dict(original_new),
            "publication_source_counts": dict(Counter(row["original_publication_source"] for row in rows)),
            "note": "仅核对已保存事实与时间语义；窗口内表示有来源日期支持，不等于独立验证了全球首次公开时间。",
            "groups": details}


def audit_report(db, batch_id):
    batch = db.get(Batch, batch_id)
    if batch is None:
        raise ValueError("未知报告批次")

    def lookup(aliases):
        dates = []
        if not aliases:
            return dates
        ids = list(db.scalars(select(Alias.vulnerability_id).where(Alias.alias.in_(aliases)).distinct()))
        from .publication import DATE_POLICY, VERIFIED
        dates.extend(db.scalars(select(PublicationAnnotation.start_at).join(PublicationState,
             PublicationState.annotation_id == PublicationAnnotation.id).where(
             PublicationState.vulnerability_id.in_(ids), PublicationState.policy == DATE_POLICY,
             PublicationAnnotation.status.in_(VERIFIED), PublicationAnnotation.start_at.is_not(None))))
        return dates

    items = db.execute(select(BatchItem.id, BatchItem.snapshot).where(BatchItem.batch_id == batch_id)
                       .order_by(BatchItem.id).execution_options(yield_per=20))
    return {"batch_id": batch_id, "slot": batch.slot, **audit_items(items, batch.cutoff, lookup)}
