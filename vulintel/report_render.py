"""Checkpointed file streaming and staged deliveries; publication is one DB commit."""
import csv
import hashlib
import io
import json
import os

from sqlalchemy import and_, delete, or_, select, update

from .config import settings
from .db import BatchItem, Delivery, PublicationAnnotation, ReportBacklog, ReportSelection, Revision, UnverifiedItem, uid
from .report_content import (ESC, FONT, SEVERITY, article, category_label, coverage, header, markdown_article,
                             references, report_scope, scope_text)
from .reports import csv_safe, export_item, report_dir
from .timeline import iso


def csv_row(values):
    stream = io.StringIO(newline="")
    csv.writer(stream).writerow([csv_safe(value) for value in values])
    return stream.getvalue()


def append(root, state, name, content):
    """Rollback leaves extra file bytes; truncate back to the committed DB offset on replay."""
    offsets = state.setdefault("offsets", {})
    offset = offsets.get(name, 0)
    path = root / (name + ".tmp")
    if offset and (not path.exists() or path.stat().st_size < offset):
        raise ValueError("报告暂存文件缺失或短于检查点，请从备份恢复或重新准备该批次")
    with path.open("r+b" if path.exists() else "w+b") as stream:
        stream.seek(offset)
        stream.truncate()
        stream.write(content.encode("utf-8"))
        offsets[name] = stream.tell()


def rows_after(db, batch_id, cursor, limit=25):
    query = select(BatchItem.id, ReportSelection.group_name, ReportSelection.rank, Revision.snapshot_bytes).join(
        ReportSelection, ReportSelection.item_id == BatchItem.id).join(
        Revision, Revision.id == ReportSelection.revision_id).where(BatchItem.batch_id == batch_id)
    if cursor:
        group, rank, identity = cursor
        query = query.where(or_(ReportSelection.group_name > group,
                           and_(ReportSelection.group_name == group, ReportSelection.rank < rank),
                           and_(ReportSelection.group_name == group, ReportSelection.rank == rank, BatchItem.id > identity)))
    return list(db.execute(query.order_by(ReportSelection.group_name, ReportSelection.rank.desc(), BatchItem.id).limit(limit)))


def save_webhook(db, batch, state, work, values):
    identity = uid()
    number = work.get("webhook_parts", 0) + 1
    payload = {"schema_version": "2.0", "message_id": identity, "report_id": batch.id, "slot": batch.slot,
               "part": number, "parts": 0, "summary": scope_text(state), "report_scope": report_scope(state),
               "coverage": batch.coverage, "overview": state.overview, "items": values,
               "raw_evidence": "完整原始事实见归档 report.json；本消息包含有界事实和完整分析"}
    if len(json.dumps(payload, ensure_ascii=False).encode()) > 512_000:
        raise ValueError("Webhook 单条或分卷超过512000字节，禁止发布，请缩小分析内容后重试")
    db.add(Delivery(id=identity, batch_id=batch.id, channel="webhook", part=number, payload=payload, status="staged"))
    work["webhook_parts"] = number


def mail_part(root, work, content, batch, state):
    budget = settings().smtp_max_bytes // 12
    if len(content.encode()) > budget:
        raise ValueError("单条详解超过邮件分卷预算，请提高 SMTP_MAX_BYTES 后恢复批次")
    part = work.get("body_parts", 0)
    size = work.get("body_size", 0)
    if not part or size + len(content.encode()) > budget:
        if part:
            append(root, work, f"email-body-{part}.html", coverage(batch, state) + "</div>")
        part += 1
        work.update(body_parts=part, body_size=0)
        append(root, work, f"email-body-{part}.html", header(batch, state) + "<h2>漏洞详情</h2>")
    append(root, work, f"email-body-{part}.html", content)
    work["body_size"] = work.get("body_size", 0) + len(content.encode())


def attachment_row(root, work, content, prefix, columns):
    limit = settings().smtp_max_bytes // 3
    if len(content.encode()) + len(columns.encode()) > limit:
        raise ValueError("单条索引超过邮件附件预算，请提高 SMTP_MAX_BYTES 后恢复批次")
    count = work.get(prefix + "_parts", 0)
    size = work.get(prefix + "_size", 0)
    if not count or size + len(content.encode()) > limit:
        count += 1
        work[prefix + "_parts"] = count
        work[prefix + "_size"] = 0
        append(root, work, f"{prefix}-{count}.csv", "\ufeff" + columns)
    append(root, work, f"{prefix}-{count}.csv", content)
    work[prefix + "_size"] = work.get(prefix + "_size", 0) + len(content.encode())


def render_step(db, batch, state):
    root = report_dir(batch.id)
    root.mkdir(parents=True, exist_ok=True)
    outer = dict(state.work)
    work = json.loads(json.dumps(outer.get("render", {})))
    channels = work.setdefault("channels", list(settings().delivery_channels))
    # Freeze destinations' channel set for this publication; removed channels stay paused in worker.
    columns = csv_row(["编号", "标题", "产品", "严重性", "类别", "公开时间", "公开时间依据", "日期状态", "日期精度", "日期原始值", "日期标注版本", "日期证据地址", "参考来源"])
    unknown_columns = csv_row(["编号", "标题", "原因", "原始修订编号", "参考来源"])
    phase = work.setdefault("phase", "details")
    if not work.get("started"):
        append(root, work, "report.html", '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>漏洞情报报告</title>'
               f'<style>body{{margin:0;background:#f4f7fa;font-family:{FONT}}}p,li{{overflow-wrap:anywhere}} @media(max-width:600px){{h1{{font-size:23px}}}}</style></head><body>' + header(batch, state) + "<h2>漏洞详情</h2>")
        append(root, work, "report.md", f"# 漏洞情报报告\n\n报告编号：{batch.id}\n\n时间段：{batch.slot}\n\n{scope_text(state)}\n\n公开日期待核实 {state.unknown_count} 条。\n\n")
        for key, label in [("risk_summary", "核心风险"), ("repair_priorities", "优先修复建议")]:
            if state.overview.get(key):
                append(root, work, "report.md", f"## {label}\n\n" + "".join(f"- {ESC(v)}\n" for v in state.overview[key]) + "\n")
        metadata = {"schema_version": "2.0", "report_id": batch.id, "slot": batch.slot,
                    "overview": state.overview, "total": state.total, "new_disclosures": state.new_count,
                    "important_updates": state.update_count, "unknown_dates": state.unknown_count,
                    "coverage_at_utc": iso(state.coverage_at), "coverage": batch.coverage, **report_scope(state)}
        append(root, work, "report.json", json.dumps(metadata, ensure_ascii=False)[:-1] + ',"items":[')
        append(root, work, "index.csv", "\ufeff" + columns)
        append(root, work, "unverified.csv", "\ufeff" + unknown_columns)
        if "email" in channels:
            attachment_row(root, work, "", "index-part", columns)
            mail_part(root, work, "", batch, state)
        work["started"] = True
    if phase == "details":
        rows = rows_after(db, batch.id, work.get("cursor"))
        used = 0
        for identity, group, rank, byte_count in rows:
            if used and used + byte_count > 2_000_000:
                break
            item = db.get(BatchItem, identity)
            if group != work.get("group"):
                append(root, work, "report.html", f'<h2 style="color:#173b61;padding-top:22px">{ESC(group)}</h2>')
                append(root, work, "report.md", f"## {ESC(group)}\n\n")
                work["group"] = group
            append(root, work, "report.html", article(item))
            append(root, work, "report.md", markdown_article(item))
            append(root, work, "report.json", ("," if work.get("count") else "") + json.dumps(export_item(item), ensure_ascii=False))
            facts = item.snapshot
            timeline = facts.get("timeline", {})
            line = csv_row([", ".join(facts.get("aliases", [])), facts["title"], group,
                            SEVERITY.get(facts.get("severity"), "未评分"),
                            category_label(facts),
                            timeline.get("published_at"), timeline.get("publication_basis"),
                            timeline.get("publication_status"), timeline.get("publication_precision"),
                            timeline.get("publication_original"), timeline.get("date_policy"),
                            timeline.get("publication_reference"),
                            " ".join(sorted(set(facts.get("references", []) + facts.get("date_references", []))))])
            append(root, work, "index.csv", line)
            if "email" in channels:
                mail_part(root, work, article(item), batch, state)
                attachment_row(root, work, line, "index-part", columns)
            if "webhook" in channels:
                bounded = {k: facts.get(k) for k in ["aliases", "title", "severity", "exploited", "timeline", "product_group",
                                                   "report_category", "report_backlog", "first_eligible_at", "date_references"]}
                bounded["title"] = facts["title"][:500]
                bounded["title_complete"] = len(facts["title"]) <= 500
                bounded["aliases"] = facts.get("aliases", [])[:100]
                bounded["aliases_complete"] = len(facts.get("aliases", [])) <= 100
                bounded["timeline"] = {k: v for k, v in facts.get("timeline", {}).items() if k not in {
                    "date_evidence", "date_conflicts", "rejected_date_evidence", "source_publications", "date_fetches", "event_dates",
                    "cve_record_publications", "source_entry_publications"}}
                bounded["date_evidence_complete"] = False
                value = {"item_id": item.id, "facts": bounded, "analysis": item.analysis}
                chunk = work.get("webhook_chunk", [])
                encoded = len(json.dumps(value, ensure_ascii=False).encode())
                if chunk and (len(chunk) >= settings().webhook_batch_size or work.get("webhook_size", 0) + encoded > 400_000):
                    save_webhook(db, batch, state, work, chunk)
                    chunk = []
                    work["webhook_size"] = 0
                chunk.append(value)
                work["webhook_chunk"] = chunk
                work["webhook_size"] = work.get("webhook_size", 0) + encoded
            work["count"] = work.get("count", 0) + 1
            work["cursor"] = [group, rank, identity]
            used += byte_count
            db.expunge(item)
        if not rows:
            if work.get("count", 0) != state.total:
                raise ValueError("报告条目计数不一致，禁止发布")
            if "webhook" in channels and (work.get("webhook_chunk") or not work.get("webhook_parts")):
                save_webhook(db, batch, state, work, work.pop("webhook_chunk", []))
            if "email" in channels:
                append(root, work, f'email-body-{work["body_parts"]}.html', coverage(batch, state) + "</div>")
            append(root, work, "report.json", '],"unverified":[')
            if not state.total:
                append(root, work, "report.md", "本批次未取得符合条件的记录；不能据此断言公开漏洞没有新增。\n\n")
            append(root, work, "report.html", "<h2>完整索引</h2><p>完整 CSV 索引随报告提供。</p><ul>")
            append(root, work, "report.md", "## 完整索引\n\n")
            work.update(phase="index", cursor=None)
    elif phase == "index":
        rows = rows_after(db, batch.id, work.get("cursor"), limit=100)
        for identity, group, rank, _ in rows:
            title = db.scalar(select(BatchItem.snapshot["title"]).where(BatchItem.id == identity))
            append(root, work, "report.html", f'<li><a href="#item-{identity}">{ESC(str(title))}</a></li>')
            append(root, work, "report.md", f'- {ESC(str(title))}\n')
            work["cursor"] = [group, rank, identity]
        if not rows:
            append(root, work, "report.html", "</ul>" + coverage(batch, state) + '<h2>日期待核实清单</h2><p>以下记录未混入近期公开；完整清单另存 unverified.csv。</p><ul>')
            append(root, work, "report.md", "\n## 采集覆盖\n\n" + f"快照时间：{iso(state.coverage_at)}\n\n" + "".join(
                f'- {ESC(s["name"])}：' + ("停用" if not s["enabled"] else "失败" if s["error"] else "过期" if s["stale"] else "正常") + "\n" for s in batch.coverage) + "\n## 日期待核实清单\n\n")
            work.update(phase="unknown", unknown_cursor=0)
    elif phase == "unknown":
        identities = list(db.scalars(select(UnverifiedItem.id).where(UnverifiedItem.batch_id == batch.id,
                    UnverifiedItem.id > work.get("unknown_cursor", 0)).order_by(UnverifiedItem.id).limit(100)))
        used = 0
        for identity in identities:
            row = db.get(UnverifiedItem, identity)
            annotation = db.get(PublicationAnnotation, row.date_annotation_id) if row.date_annotation_id else None
            reason = {"unknown": "漏洞首次公开日期缺少足够依据", "conflict": "公开日期证据冲突", "uncertain_window": "日期精度不足以确认筛选窗口归属"}.get(row.reason, "公开日期未确认")
            date_data = annotation.data if annotation else {}
            gaps = sorted({item["reason"] for item in date_data.get("date_fetches", []) if item.get("reason")})
            if gaps:
                reason += "；补证结果：" + "、".join(gaps)
            value = {"identifiers": row.identifiers, "title": row.title, "revision_id": row.revision_id,
                     "references": row.references, "reason": reason, "date_annotation_id": row.date_annotation_id,
                     "date_annotation": date_data}
            line = csv_row([row.identifiers, row.title, reason, row.revision_id, " ".join(row.references)])
            byte_count = len(line.encode("utf-8")) + len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
            if used and used + byte_count > 2_000_000:
                db.expunge(row)
                break
            append(root, work, "unverified.csv", line)
            append(root, work, "report.html", f'<li>{ESC(row.identifiers)}：{ESC(row.title)}（{ESC(reason)}）' + references(row.references) + '</li>')
            append(root, work, "report.md", f'- {ESC(row.identifiers)}：{ESC(row.title)}（{ESC(reason)}）\n')
            append(root, work, "report.json", ("," if work.get("unknown_written") else "") + json.dumps(value, ensure_ascii=False))
            if "email" in channels:
                attachment_row(root, work, line, "unverified-part", unknown_columns)
            work["unknown_cursor"] = row.id
            work["unknown_written"] = work.get("unknown_written", 0) + 1
            used += byte_count
            db.expunge(row)
        if not identities:
            if work.get("unknown_written", 0) != state.unknown_count:
                raise ValueError("日期待核实计数不一致，禁止发布")
            append(root, work, "report.json", "]}")
            append(root, work, "report.html", "</ul><footer>未知信息不代表没有风险。证据等级不等于本服务实际复现。</footer></div></body></html>")
            work.update(phase="publish_files", published=0)
    elif phase == "publish_files":
        names = sorted(work["offsets"])
        index = work.get("published", 0)
        if index < len(names):
            name = names[index]
            temporary, final = root / (name + ".tmp"), root / name
            if temporary.exists():
                if temporary.stat().st_size < work["offsets"][name]:
                    raise ValueError("报告暂存文件短于检查点，禁止发布")
                if temporary.stat().st_size != work["offsets"][name]:
                    # A previous failed transaction may have appended beyond its checkpoint.
                    with temporary.open("r+b") as stream:
                        stream.truncate(work["offsets"][name])
                os.replace(temporary, final)
            if not final.exists() or final.stat().st_size != work["offsets"][name]:
                raise ValueError("发布文件缺失或校验失败")
            digest = hashlib.sha256()
            with final.open("rb") as stream:
                for chunk in iter(lambda: stream.read(65536), b""):
                    digest.update(chunk)
            work.setdefault("hashes", {})[name] = digest.hexdigest()
            work["published"] = index + 1
        else:
            (root / "manifest.json").write_text(json.dumps(work["hashes"], indent=2), encoding="utf-8")
            work.update(phase="delivery", delivery_cursor=0)
    elif phase == "delivery":
        attachment_count = work.get("index-part_parts", 0) + work.get("unverified-part_parts", 0)
        parts = max(work.get("body_parts", 0), attachment_count) if "email" in channels else 0
        cursor = work.get("delivery_cursor", 0)
        for offset in range(cursor, min(cursor + 20, parts)):
            number = offset + 1
            attachment = None
            if offset < work.get("index-part_parts", 0):
                attachment = root / f"index-part-{number}.csv"
            elif offset < attachment_count:
                attachment = root / f'unverified-part-{number - work.get("index-part_parts", 0)}.csv'
            payload = {"schema_version": "2.0", "slot": batch.slot,
                       "summary": scope_text(state), "report_scope": report_scope(state),
                       "coverage": batch.coverage, "attachment": str(attachment) if attachment else None,
                       "html_body": str(root / f"email-body-{number}.html") if offset < work.get("body_parts", 0) else None,
                       "parts": parts}
            row = Delivery(batch_id=batch.id, channel="email", part=number, payload=payload, status="staged")
            db.add(row)
            db.flush()
            from .delivery import email_message
            email_message(row)  # Validate actual MIME size before any channel is activated.
            work["delivery_cursor"] = number
        if work.get("delivery_cursor", 0) >= parts:
            work.update(phase="webhook_parts", webhook_cursor=0)
    elif phase == "webhook_parts":
        rows = list(db.scalars(select(Delivery).where(Delivery.batch_id == batch.id, Delivery.channel == "webhook",
                       Delivery.part > work.get("webhook_cursor", 0)).order_by(Delivery.part).limit(20)))
        for row in rows:
            row.payload = {**row.payload, "parts": work.get("webhook_parts", 0)}
            work["webhook_cursor"] = row.part
        if not rows:
            work["phase"] = "complete"
            batch.status, batch.error = "finalized", None
            # Publication and coverage acknowledgement are one DB transaction.
            # Evidence learned after selection remains queued for a later batch.
            selections = select(ReportSelection.revision_id).join(BatchItem).where(BatchItem.batch_id == batch.id)
            db.execute(delete(ReportBacklog).where(ReportBacklog.revision_id.in_(selections)))
            remaining = db.scalars(select(ReportBacklog).where(ReportBacklog.vulnerability_id.in_(
                select(BatchItem.vulnerability_id).where(BatchItem.batch_id == batch.id))))
            for candidate in remaining:
                candidate.category = "update"
            db.execute(update(Delivery).where(Delivery.batch_id == batch.id, Delivery.status == "staged").values(status="pending"))
    outer["render"] = work
    outer["phase"] = "complete" if work["phase"] == "complete" else "render"
    state.work = outer
