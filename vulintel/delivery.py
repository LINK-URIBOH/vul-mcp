import hashlib
import hmac
import json
import smtplib
import ssl
import time
from datetime import timedelta
from email.message import EmailMessage
from pathlib import Path

import httpx
from sqlalchemy import select

from .config import settings
from .db import Delivery, now, uid
from .reports import email_body_parts, export_item, items_for, split_csv


def prepare_deliveries(db, batch, unused_items, artifacts):
    cfg = settings()
    # Store small, stable batches. No network I/O occurs inside report finalization.
    part_ids, chunk, size = [], [], 0

    def save_part(values):
        did = uid()
        payload = {"schema_version": "1.0", "message_id": did, "report_id": batch.id,
                   "slot": batch.slot, "part": len(part_ids) + 1, "parts": 0,
                   "summary": batch.summary, "coverage": batch.coverage, "items": values}
        db.add(Delivery(id=did, batch_id=batch.id, channel="webhook", part=len(part_ids) + 1, payload=payload))
        db.flush()
        part_ids.append(did)
    for item in items_for(db, batch.id):
        value = export_item(item)
        encoded_size = len(json.dumps(value, ensure_ascii=False).encode())
        if chunk and (len(chunk) >= cfg.webhook_batch_size or size + encoded_size > 512_000):
            save_part(chunk)
            chunk, size = [], 0
        chunk.append(value)
        size += encoded_size
    if chunk or not part_ids:
        save_part(chunk)
    # Payloads are persisted per part, so retry never reconstructs a different message.
    for did in part_ids:
        row = db.get(Delivery, did)
        row.payload = {**row.payload, "parts": len(part_ids)}
        db.flush()
    attachments = split_csv(Path(artifacts["csv"]), cfg.smtp_max_bytes)
    bodies = email_body_parts(batch, db, cfg.smtp_max_bytes)
    part_count = max(len(attachments), len(bodies))
    for offset in range(part_count):
        attachment = attachments[offset] if offset < len(attachments) else None
        body = bodies[offset] if offset < len(bodies) else None
        number = offset + 1
        db.add(Delivery(batch_id=batch.id, channel="email", part=number,
                        payload={"slot": batch.slot, "summary": batch.summary, "coverage": batch.coverage,
                                 "attachment": attachment, "html_body": body, "parts": part_count}))


def canonical_body(payload):
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def signature(secret, timestamp, body):
    return "sha256=" + hmac.new(secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256).hexdigest()


def send_webhook(delivery, client=None):
    cfg = settings()
    body = canonical_body(delivery.payload)
    stamp = str(int(time.time()))
    headers = {"Content-Type": "application/json", "X-Vul-Timestamp": stamp,
               "X-Vul-Message-Id": delivery.id,
               "X-Vul-Signature": signature(cfg.webhook_secret.get_secret_value(), stamp, body)}
    own = client is None
    client = client or httpx.Client(timeout=30, follow_redirects=False)
    try:
        response = client.post(cfg.webhook_url, content=body, headers=headers)
        response.raise_for_status()
        if response.status_code >= 300:
            raise ValueError("Webhook redirect refused")
    finally:
        if own:
            client.close()


def email_message(delivery):
    import html
    cfg = settings()
    payload = delivery.payload
    message = EmailMessage()
    message["Subject"] = f"漏洞情报 {payload['slot']} [{delivery.part}/{payload['parts']}]"
    message["From"] = cfg.smtp_from
    message["To"] = cfg.smtp_to
    message["Message-ID"] = f"<{delivery.id}@{cfg.public_base_url.split('//')[1]}>"
    message.set_content(payload["summary"] + "\n\n完整索引见附件；详细报告见管理网页。")
    failures = [s["name"] for s in payload["coverage"] if s["enabled"] and (s["error"] or s["stale"])]
    warning = "采集不完整：" + "、".join(failures) if failures else "启用来源状态正常"
    details = Path(payload["html_body"]).read_text(encoding="utf-8") if payload.get("html_body") else ""
    message.add_alternative(
        f'<h1>漏洞情报</h1><p>{html.escape(payload["slot"])}</p><p>{html.escape(warning)}</p>'
        f'<p style="white-space:pre-wrap">{html.escape(payload["summary"])}</p>'
        f'<p>完整索引按分卷提供。<a href="{html.escape(cfg.public_base_url)}/admin/reports/{delivery.batch_id}">查看完整报告</a></p>' + details,
        subtype="html")
    if payload.get("attachment"):
        attachment = Path(payload["attachment"])
        message.add_attachment(attachment.read_bytes(), maintype="text", subtype="csv", filename=attachment.name)
    if len(message.as_bytes()) > cfg.smtp_max_bytes:
        raise ValueError("Email exceeds SMTP_MAX_BYTES")
    return message


def send_email(delivery):
    cfg = settings()
    context = ssl.create_default_context()
    factory = smtplib.SMTP_SSL if cfg.smtp_tls == "ssl" else smtplib.SMTP
    kwargs = {"timeout": 30}
    if cfg.smtp_tls == "ssl":
        kwargs["context"] = context
    with factory(cfg.smtp_host, cfg.smtp_port, **kwargs) as connection:
        if cfg.smtp_tls == "starttls":
            connection.ehlo()
            connection.starttls(context=context)
            connection.ehlo()
        if cfg.smtp_user:
            connection.login(cfg.smtp_user, cfg.smtp_password.get_secret_value())
        refused = connection.send_message(email_message(delivery))
        if refused:
            raise ValueError("Some email recipients were rejected")


def deliver_one(db, sender=None):
    cfg = settings()
    if not cfg.delivery_enabled:
        return False
    # Reclaim expired leases. Stable message IDs protect receivers from crash/retry duplicates.
    expired = list(db.scalars(select(Delivery).where(Delivery.status == "sending", Delivery.lease_until < now())))
    for row in expired:
        row.status = "failed" if row.attempts >= cfg.delivery_max_attempts else "pending"
    db.commit()
    row = db.scalar(select(Delivery).where(Delivery.status == "pending", Delivery.next_run <= now())
                    .order_by(Delivery.next_run, Delivery.id).with_for_update(skip_locked=True).limit(1))
    if row is None:
        return False
    row.status, row.attempts, row.lease_until = "sending", row.attempts + 1, now() + timedelta(minutes=10)
    db.commit()
    try:
        (sender or (send_email if row.channel == "email" else send_webhook))(row)
        row.status, row.error = "sent", None
    except Exception as exc:
        status = getattr(getattr(exc, "response", None), "status_code", None)
        row.error = type(exc).__name__ + (f" · HTTP {status}" if status else " · 投递失败")
        row.status = "failed" if row.attempts >= cfg.delivery_max_attempts else "pending"
        row.next_run = now() + timedelta(seconds=min(3600, 60 * 2 ** (row.attempts - 1)))
    row.lease_until = None
    db.commit()
    return True
