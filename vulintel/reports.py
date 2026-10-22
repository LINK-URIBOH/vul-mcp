import csv
import html
import json
import os
from pathlib import Path

from sqlalchemy import select

from .config import settings
from .db import BatchItem

LABELS = {"root_cause": "原理", "trigger_conditions": "触发前提", "impact": "影响",
          "affected_versions": "影响版本", "attack_path": "攻击路径", "remediation": "修复与缓解",
          "evidence_level": "证据等级", "evidence_notes": "证据说明"}


def report_dir(batch_id):
    # Only DB-generated UUIDs are accepted, not user paths.
    import uuid
    return settings().data_dir / "reports" / str(uuid.UUID(batch_id))


def items_for(db, batch_id):
    return db.scalars(select(BatchItem).where(BatchItem.batch_id == batch_id)
                      .order_by(BatchItem.id).execution_options(yield_per=20))


def export_item(item):
    return {"item_id": item.id, "priority": item.priority,
            "facts": item.snapshot, "analysis": item.analysis}


def csv_safe(value):
    value = str(value or "")
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


def render_report(batch, db):
    root = report_dir(batch.id)
    root.mkdir(parents=True, exist_ok=True)
    files = {kind: root / name for kind, name in {
        "json": "report.json", "html": "report.html", "markdown": "report.md", "csv": "index.csv"}.items()}
    coverage = batch.coverage
    warning = [s for s in coverage if s["enabled"] and (s["error"] or s["stale"])]
    coverage_text = "采集不完整：" + "、".join(s["name"] for s in warning) if warning else "配置的启用来源均在正常更新窗口内"
    esc = html.escape
    # Stream all four exports; no template or in-memory list proportional to the whole database.
    with (files["json"].with_suffix(".json.tmp").open("w", encoding="utf-8") as jf,
          files["html"].with_suffix(".html.tmp").open("w", encoding="utf-8") as hf,
          files["markdown"].with_suffix(".md.tmp").open("w", encoding="utf-8") as mf,
          files["csv"].with_suffix(".csv.tmp").open("w", encoding="utf-8-sig", newline="") as cf):
        header = {"schema_version": "1.0", "report_id": batch.id, "slot": batch.slot,
                  "summary": batch.summary, "coverage": coverage}
        jf.write(json.dumps(header, ensure_ascii=False)[:-1] + ',"items":[')
        hf.write('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width">'
                 '<title>漏洞情报报告</title><body style="font-family:sans-serif;max-width:960px;margin:32px auto;padding:16px">'
                 f'<h1>漏洞情报 · {esc(batch.slot)}</h1><p>{esc(coverage_text)}</p><p>{esc(batch.summary)}</p>')
        mf.write(f"# 漏洞情报 · {batch.slot}\n\n{coverage_text}\n\n{batch.summary}\n\n")
        writer = csv.writer(cf)
        writer.writerow(["编号", "标题", "严重性", "已利用", "来源", "参考地址"])
        count = 0
        for item in items_for(db, batch.id):
            facts = item.snapshot
            if count:
                jf.write(",")
            jf.write(json.dumps(export_item(item), ensure_ascii=False))
            count += 1
            aliases = ", ".join(facts.get("aliases", []))
            refs = facts.get("references", [])
            writer.writerow([csv_safe(aliases), csv_safe(facts["title"]), facts["severity"],
                             "是" if facts["exploited"] else "未确认", csv_safe(", ".join(
                                 r["source"] for r in facts.get("source_records", []))), csv_safe(" ".join(refs))])
            hf.write(f'<article><h2>{esc(facts["title"])}</h2><p>{esc(aliases)} · {esc(facts["severity"])}'
                     f' · 已利用：{"是" if facts["exploited"] else "未确认"}</p>')
            mf.write(f'## {facts["title"]}\n\n{aliases} · {facts["severity"]}\n\n')
            if item.analysis:
                for key, label in LABELS.items():
                    value = item.analysis[key]
                    hf.write(f'<h3>{label}</h3><p style="white-space:pre-wrap">{esc(str(value))}</p>')
                    mf.write(f"### {label}\n\n{value}\n\n")
                refs = sorted(set(refs + item.analysis["references"]))
            else:
                hf.write(f'<p>{esc(facts.get("description", ""))}</p><p>索引条目，未展开分析。</p>')
                mf.write(f'{facts.get("description", "")}\n\n索引条目，未展开分析。\n\n')
            hf.write('<h3>来源</h3><ul>')
            for url in refs:
                # Text-only display keeps even malformed upstream URLs inert.
                hf.write(f'<li>{esc(url)}</li>')
                mf.write(f"- {url}\n")
            hf.write('</ul></article><hr>')
        if count == 0:
            hf.write("<p>本期没有新增或重要更新记录。</p>")
            mf.write("本期没有新增或重要更新记录。\n")
        jf.write("]}")
        hf.write("</body></html>")
    for path in files.values():
        os.replace(path.with_suffix(path.suffix + ".tmp"), path)
    return {kind: str(path) for kind, path in files.items()}


def split_csv(path: Path, max_bytes: int):
    """Create bounded attachments without losing any index row."""
    limit = max_bytes // 2  # Leave room for MIME encoding and message body.
    if limit < 8192:
        raise ValueError("SMTP_MAX_BYTES must be at least 16384")
    parts = []
    with path.open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        out = None
        try:
            for row in reader:
                encoded_estimate = len(json.dumps(row, ensure_ascii=False).encode()) * 2
                if encoded_estimate > limit:
                    raise ValueError("A single index row exceeds the email attachment limit")
                if out is None or out.tell() + encoded_estimate > limit:
                    if out:
                        out.close()
                    part = path.with_name(f"index-part-{len(parts) + 1}.csv")
                    parts.append(str(part))
                    out = part.open("w", encoding="utf-8-sig", newline="")
                    writer = csv.writer(out)
                    writer.writerow(header)
                writer.writerow(row)
            if not parts:
                parts = [str(path)]
        finally:
            if out:
                out.close()
    return parts


def email_body_parts(batch, db, max_bytes):
    """Bound email HTML by complete advisory blocks, escaping all upstream/model text."""
    root = report_dir(batch.id)
    limit = max_bytes // 8  # Quoted-printable encoding of Chinese text needs extra headroom.
    parts, current, size = [], None, 0
    try:
        for item in items_for(db, batch.id):
            text = item.snapshot["title"] + "\n" + ", ".join(item.snapshot.get("aliases", [])) + "\n"
            if item.analysis:
                text += "\n\n".join(f"{label}：{item.analysis[key]}" for key, label in LABELS.items())
                text += "\n\n来源：\n" + "\n".join(item.analysis["references"])
            else:
                text += item.snapshot.get("description", "")
            block = '<article><pre style="white-space:pre-wrap;font-family:sans-serif">' + html.escape(text) + '</pre></article><hr>'
            block_size = len(block.encode())
            if block_size > limit:
                raise ValueError("One advisory exceeds SMTP_MAX_BYTES/8; increase email limit")
            if current is None or size + block_size > limit:
                if current:
                    current.close()
                path = root / f"email-body-{len(parts) + 1}.html"
                parts.append(str(path))
                current, size = path.open("w", encoding="utf-8"), 0
            current.write(block)
            size += block_size
        return parts
    finally:
        if current:
            current.close()
