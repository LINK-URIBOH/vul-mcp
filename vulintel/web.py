import base64
import hashlib
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode

import httpx
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy import func, or_, select
from starlette.exceptions import HTTPException
from starlette.responses import FileResponse, HTMLResponse, RedirectResponse
from starlette.routing import Route

from .auth import token_hash
from .config import settings
from .db import (Alias, Audit, Batch, BatchItem, Delivery, Job, LoginFlow, PublicationAnnotation, PublicationState,
                 ReportState, Source, Vulnerability,
                 WebSession, now, session)
from .reports import report_dir
from .service import audit, source_status

TEMPLATES = Environment(loader=FileSystemLoader(Path(__file__).parent / "templates"),
                        autoescape=select_autoescape(["html"]))
STATUS_LABELS = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "unknown": "未评分",
                 "pending": "排队", "sending": "发送中", "sent": "已发送", "failed": "失败",
                 "running": "运行中", "done": "完成", "analyzing": "分析中", "finalized": "已归档",
                 "preparing": "准备中", "rendering": "生成文件中", "staged": "待统一发布",
                 "email": "邮件", "webhook": "Webhook"}
STATUS_LABELS.update(maintenance="历史修复", publication="公开日期补证", bootstrap="近七天初始化",
                     superseded="已被重置取代", interrupted="已中断／等待恢复", admitted="已核实入库",
                     excluded="已排除", unverified="日期待核实", conflict="日期冲突", lookup="定向补充", error="补证错误")
STATUS_LABELS["oversized"] = "超大条目待核查"
TEMPLATES.filters["statuslabel"] = lambda value: STATUS_LABELS.get(value, value) if isinstance(value, str) else value


def admin_session(request, db):
    cookie = request.cookies.get("vul_session", "")
    record = db.get(WebSession, token_hash(cookie)) if cookie else None
    if not record or record.expires < now():
        return None
    return record


def page(request, identity, title, **context):
    return HTMLResponse(TEMPLATES.get_template("page.html").render(
        title=title, path=request.url.path, csrf=identity.csrf, **context),
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
                 "Content-Security-Policy": "default-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})


async def login(request):
    cfg = settings()
    state, verifier, nonce = secrets.token_urlsafe(32), secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    with session() as db:
        db.add(LoginFlow(state=token_hash(state), verifier=verifier, nonce=nonce,
                         expires=now() + timedelta(minutes=10)))
        db.commit()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    params = {"client_id": cfg.web_client_id, "redirect_uri": cfg.public_base_url + "/admin/callback",
              "response_type": "code", "scope": "openid", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    response = RedirectResponse(cfg.issuer_url + "/protocol/openid-connect/auth?" + urlencode(params))
    response.set_cookie("vul_login", state, secure=True, httponly=True, samesite="lax",
                        path="/admin/", max_age=600)
    return response


async def callback(request):
    cfg = settings()
    state = request.query_params.get("state", "")
    cookie = request.cookies.get("vul_login", "")
    if not state or not cookie or not secrets.compare_digest(state, cookie):
        raise HTTPException(400, "登录状态不匹配，请重新登录")
    with session() as db:
        flow = db.get(LoginFlow, token_hash(state))
        if not flow or flow.expires < now():
            raise HTTPException(400, "登录已过期")
        verifier, nonce = flow.verifier, flow.nonce
        db.delete(flow)
        db.commit()  # Single-use state before token exchange, including failed attempts.
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            result = await client.post(cfg.keycloak_internal_url + "/protocol/openid-connect/token", data={
                "grant_type": "authorization_code", "client_id": cfg.web_client_id,
                "client_secret": cfg.web_client_secret.get_secret_value(),
                "redirect_uri": cfg.public_base_url + "/admin/callback", "code_verifier": verifier,
                "code": request.query_params.get("code", ""),
            })
            result.raise_for_status()
            tokens = result.json()
        verifier_service = request.app.state.verifier
        claims = await verifier_service.decode(tokens["id_token"], cfg.web_client_id)
        access = await verifier_service.decode(tokens["access_token"], cfg.web_client_id)
        if (claims.get("nonce") != nonce or claims["sub"] != access["sub"]
                or access.get("azp") != cfg.web_client_id
                or cfg.admin_role not in access.get("realm_access", {}).get("roles", [])):
            raise ValueError("Not an administrator")
    except Exception:
        raise HTTPException(403, "登录验证失败或账号没有管理权限") from None
    raw_session = secrets.token_urlsafe(48)
    with session() as db:
        db.add(WebSession(id=token_hash(raw_session), subject=claims["sub"], csrf=secrets.token_urlsafe(32),
                          expires=now() + timedelta(minutes=30)))
        audit(db, claims["sub"], "web.login", "admin")
        db.commit()
    response = RedirectResponse("/admin/", status_code=303)
    response.delete_cookie("vul_login", path="/admin/")
    response.set_cookie("vul_session", raw_session, secure=True, httponly=True,
                        samesite="lax", path="/admin/", max_age=1800)
    return response


async def dashboard(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        stats = {"漏洞记录": db.scalar(select(func.count()).select_from(Vulnerability)),
                 "待完成报告": db.scalar(select(func.count()).select_from(Batch).where(Batch.status != "finalized")),
                 "失败投递": db.scalar(select(func.count()).select_from(Delivery).where(Delivery.status == "failed"))}
        rows = list(db.scalars(select(Vulnerability).where(or_(Vulnerability.exploited.is_(True),
            Vulnerability.severity.in_(["critical", "high"]))).order_by(Vulnerability.updated_at.desc()).limit(20)))
        return page(request, identity, "情报工作台", stats=stats, coverage=source_status(db),
                    columns=["编号", "漏洞", "严重性", "已利用", "更新时间（UTC）"],
                    rows=[{"cells": [", ".join(v.data.get("aliases", [])), v.title, v.severity,
                                      "是" if v.exploited else "未确认", v.updated_at],
                           "link": "/admin/vulnerabilities/" + v.id} for v in rows])


async def vulnerabilities(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        query = select(Vulnerability).outerjoin(PublicationState, PublicationState.vulnerability_id == Vulnerability.id)
        params = request.query_params
        if params.get("q"):
            term = "%" + params["q"][:200] + "%"
            query = query.where(or_(Vulnerability.title.ilike(term), Vulnerability.id.in_(
                select(Alias.vulnerability_id).where(Alias.alias.ilike(term)))))
        if params.get("product"):
            query = query.where(Vulnerability.product.ilike("%" + params["product"][:100] + "%"))
        if params.get("severity") in {"critical", "high", "medium", "low", "unknown"}:
            query = query.where(Vulnerability.severity == params["severity"])
        if params.get("exploited") in {"yes", "no"}:
            query = query.where(Vulnerability.exploited.is_(params["exploited"] == "yes"))
        for key, bound in [("since", True), ("until", False)]:
            if params.get(key):
                try:
                    stamp = datetime.strptime(params[key], "%Y-%m-%d") - timedelta(hours=8)
                except ValueError:
                    raise HTTPException(400, "日期格式应为 YYYY-MM-DD") from None
                query = query.where(PublicationState.end_at >= stamp) if bound else query.where(
                    PublicationState.start_at < stamp + timedelta(days=1))
        try:
            offset = max(0, int(params.get("offset", "0")))
        except ValueError:
            raise HTTPException(400, "无效分页") from None
        from .publication import DATE_POLICY
        date_status = params.get("date_status")
        if date_status:
            if date_status not in {"confirmed", "day", "unknown", "conflict", "missing"}:
                raise HTTPException(400, "无效日期状态")
            query = query.where(PublicationState.annotation_id.is_(None)) if date_status == "missing" else query.where(
                PublicationState.status == date_status, PublicationState.policy == DATE_POLICY)
        values = list(db.scalars(query.order_by(PublicationState.start_at.desc().nullslast(),
                                               Vulnerability.updated_at.desc()).offset(offset).limit(51)))
        from .report_content import DATE_STATUS, label_time
        dates = {vid: data for vid, data in db.execute(select(PublicationState.vulnerability_id, PublicationAnnotation.data)
                 .join(PublicationAnnotation).where(PublicationState.vulnerability_id.in_([v.id for v in values])))}
        more = dict(params)
        more["offset"] = str(offset + 50)
        return page(request, identity, "漏洞索引", filters=params,
                    columns=["编号", "标题", "严重性", "已利用", "漏洞公开时间", "日期状态", "更新时间（UTC）"],
                    rows=[{"cells": [", ".join(v.data.get("aliases", [])), v.title, v.severity,
                                      "是" if v.exploited else "未确认",
                                      label_time(dates.get(v.id, {}).get("published_at"), dates.get(v.id, {}).get("publication_precision")),
                                      DATE_STATUS.get(dates.get(v.id, {}).get("publication_status"), "尚未标注"), v.updated_at],
                           "link": "/admin/vulnerabilities/" + v.id} for v in values[:50]],
                    next_url="?" + urlencode(more) if len(values) > 50 else None)


async def detail(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        record = db.get(Vulnerability, request.path_params["vid"])
        if not record:
            raise HTTPException(404)
        latest = db.scalar(select(BatchItem).join(Batch, Batch.id == BatchItem.batch_id).where(
            BatchItem.vulnerability_id == record.id, Batch.status == "finalized", BatchItem.analysis.is_not(None))
            .order_by(Batch.cutoff.desc()).limit(1))
        from .reports import LABELS
        narrative = [(label, latest.analysis.get(key, "未公开／未确认")) for key, label in LABELS.items()] if latest else []
        from .publication import cached_evidence
        state = db.get(PublicationState, record.id)
        annotation = db.get(PublicationAnnotation, state.annotation_id) if state else None
        date_data = annotation.data if annotation else {"publication_status": "unknown", "published_at": None}
        _, diagnostics = cached_evidence(db, record.data)
        from .report_content import DATE_STATUS, label_time
        return page(request, identity, record.title, vulnerability=record.data, narrative=narrative,
                    publication_time=label_time(date_data.get("published_at"), date_data.get("publication_precision")),
                    publication_status=DATE_STATUS.get(date_data.get("publication_status"), "待核实"),
                    date_evidence=date_data.get("date_evidence", []), publication_basis=date_data.get("publication_basis", "未确认"),
                    raw_detail=json.dumps({"source_facts": record.data, "date_annotation": date_data,
                                           "date_fetches": diagnostics}, ensure_ascii=False, indent=2))


def offset_page(request):
    try:
        offset = max(0, int(request.query_params.get("offset", "0")))
    except ValueError:
        raise HTTPException(400, "无效分页") from None
    return offset


async def reports(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        offset = offset_page(request)
        records = list(db.scalars(select(Batch).order_by(Batch.cutoff.desc()).offset(offset).limit(101)))
        counts = {row.batch_id: row for row in db.execute(select(ReportState.batch_id, ReportState.total,
                  ReportState.new_count, ReportState.update_count, ReportState.unknown_count).where(
                      ReportState.batch_id.in_([record.id for record in records])))}
        from .db import Publication
        publications = {p.id: p for p in db.scalars(select(Publication).where(Publication.id.in_([b.id for b in records])))}
        from .publications import LABELS
        return page(request, identity, "报告归档", columns=["时间段（北京时间）", "类型", "状态", "摘要"],
                    rows=[{"cells": [publications[b.id].slot if b.id in publications else b.slot,
                           LABELS[publications[b.id].kind] if b.id in publications else "模型详解批次", b.status,
                           f"条目 {counts[b.id].total} 条；日期待核实 {counts[b.id].unknown_count} 条" if b.id in counts else "旧规则历史报告"],
                           "link": "/admin/reports/" + b.id} for b in records[:100]],
                    next_url=f"?offset={offset + 100}" if len(records) > 100 else None)


async def report_detail(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        batch = db.get(Batch, request.path_params["bid"])
        if not batch:
            raise HTTPException(404)
        state = db.get(ReportState, batch.id)
        from .report_jobs import status as report_status
        from .report_content import scope_text
        progress = report_status(db, batch)
        from .publications import publisher_status
        return page(request, identity, "报告 · " + batch.slot,
                    summary=((scope_text(state) + f" 公开日期待核实 {state.unknown_count} 条。" if progress["ready"] else
                              "正在准备候选与冻结证据，尚不能判断为空报告。") if state else "旧规则历史报告，保留原始归档。"),
                    diagnostic_summary=batch.summary,
                    report_view=f"/admin/reports/{batch.id}/view" if batch.status == "finalized" else None,
                    detail=json.dumps({"进度": progress, "publisher": publisher_status()}, ensure_ascii=False, indent=2),
                    downloads=[{"label": label, "url": f"/admin/reports/{batch.id}/download/{kind}"}
                               for kind, label in [("html", "HTML"), ("markdown", "Markdown"), ("json", "JSON"), ("csv", "完整索引")]
                               + ([("unverified", "日期待核实清单")] if state else [])]
                    if batch.status == "finalized" else [], coverage=batch.coverage)


async def download(request):
    kinds = {"html": "report.html", "markdown": "report.md", "json": "report.json", "csv": "index.csv", "unverified": "unverified.csv"}
    with session() as db:
        if not admin_session(request, db):
            return RedirectResponse("/admin/login", status_code=303)
        batch = db.get(Batch, request.path_params["bid"])
        if not batch or batch.status != "finalized" or request.path_params["kind"] not in kinds:
            raise HTTPException(404)
        path = report_dir(batch.id) / kinds[request.path_params["kind"]]
        if not path.is_file():
            raise HTTPException(404, "报告文件缺失，请检查持久卷或从备份恢复")
        return FileResponse(path, filename=path.name, headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


async def report_view(request):
    with session() as db:
        if not admin_session(request, db):
            return RedirectResponse("/admin/login", status_code=303)
        batch = db.get(Batch, request.path_params["bid"])
        if not batch or batch.status != "finalized":
            raise HTTPException(404)
        path = report_dir(batch.id) / "report.html"
        if not path.is_file():
            raise HTTPException(404)
        return FileResponse(path, media_type="text/html", headers={"Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'"})


async def sources(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        values = list(db.scalars(select(Source).order_by(Source.id)))
        status_map = {row["id"]: row for row in source_status(db)}
        return page(request, identity, "采集来源", columns=["来源", "状态", "成功窗口终点（UTC）", "实际完成（UTC）", "任务进度", "下次采集/重试（UTC）", "错误"],
                    rows=[{"cells": [s.name, "启用" if s.enabled else "停用", s.last_success or "尚未采集",
                                      status_map[s.id]["progress"].get("completed_at", "尚无实际完成记录"),
                                      status_map[s.id]["coverage_note"] or str(status_map[s.id].get("bootstrap_status") or status_map[s.id]["progress"].get("status", "—")),
                                      s.next_run if s.enabled else "—", s.error or "—"],
                           "actions": [{"label": "停用" if s.enabled else "启用", "url": f"/admin/actions/source/{s.id}/toggle"},
                                       {"label": "补采", "url": f"/admin/actions/source/{s.id}/collect"}]} for s in values])


async def tasks(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        offset = offset_page(request)
        jobs = list(db.scalars(select(Job).order_by(Job.created_at.desc()).offset(offset).limit(101)))
        events = list(db.scalars(select(Audit).order_by(Audit.id.desc()).limit(30)))
        from .maintenance import progress
        maintenance = progress(db)
        from .recent import progress as bootstrap_progress
        return page(request, identity, "任务与操作记录", columns=["任务", "来源", "状态", "创建时间（UTC）", "错误"],
                    maintenance=maintenance, bootstrap=bootstrap_progress(db),
                    rows=[{"cells": [j.kind, j.source_id or "—",
                                     maintenance["status"] if j.kind == "maintenance" and maintenance and j.id == maintenance["job_id"] else j.status,
                                     j.created_at, j.error or "—"],
                           "actions": [{"label": "重试", "url": f"/admin/actions/job/{j.id}/retry"}]
                           if j.status == "failed" and j.kind != "maintenance" else []}
                          for j in jobs[:100]], events=events,
                    next_url=f"?offset={offset + 100}" if len(jobs) > 100 else None)


async def recent_candidates(request):
    from .db import RecentCandidate
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        offset = offset_page(request)
        query = select(RecentCandidate)
        selected_status = request.query_params.get("status")
        if selected_status:
            if selected_status not in {"pending", "lookup", "unverified", "conflict", "error", "excluded", "admitted", "oversized"}:
                raise HTTPException(400, "无效候选状态")
            query = query.where(RecentCandidate.status == selected_status)
        values = list(db.scalars(query.order_by(RecentCandidate.updated_at.desc(), RecentCandidate.id).offset(offset).limit(51)))
        return page(request, identity, "候选核实清单（独立于正式漏洞库）", columns=["来源", "编号", "标题", "状态", "原因", "取得事实时间（UTC）"],
                    rows=[{"cells": [row.source_id, row.source_key, row.data.get("title", "待获取详情"), row.status,
                                      row.reason or "—", row.collected_at], "link": "/admin/recent-candidates/" + row.id} for row in values[:50]],
                    next_url="?" + urlencode({"offset": offset + 50, **({"status": selected_status} if selected_status else {})}) if len(values) > 50 else None)


async def recent_candidate_detail(request):
    from .db import RecentCandidate
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        row = db.get(RecentCandidate, request.path_params["cid"])
        if row is None:
            raise HTTPException(404)
        return page(request, identity, "候选 · " + row.source_key,
                    summary=row.reason or "已核实入库" if row.status == "admitted" else row.reason or "正在补证",
                    downloads=[{"label": "完整原始JSON（超大条目，尚未核查）", "url": "/admin/recent-candidates/" + row.id + "/raw"}]
                              if row.status == "oversized" else [],
                    detail=json.dumps({"source_facts": row.data, "date_annotation": row.annotation,
                        "status": row.status, "reason": row.reason, "collected_at": row.collected_at.isoformat(),
                        "window_start": row.start_at.isoformat(), "window_end": row.end_at.isoformat(),
                        "evidence_cursor": row.evidence_cursor}, ensure_ascii=False, indent=2))


async def recent_candidate_raw(request):
    from .db import RecentCandidate
    from .recent import raw_candidate_path
    with session() as db:
        if not admin_session(request, db):
            return RedirectResponse("/admin/login", status_code=303)
        row = db.get(RecentCandidate, request.path_params["cid"])
        if row is None or row.status != "oversized":
            raise HTTPException(404)
        try:
            path = raw_candidate_path(row)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        return FileResponse(path, media_type="application/json", filename="source-" + row.id + ".json",
                            headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})


async def deliveries(request):
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            return RedirectResponse("/admin/login", status_code=303)
        offset = offset_page(request)
        records = list(db.scalars(select(Delivery).order_by(Delivery.next_run.desc()).offset(offset).limit(101)))
        return page(request, identity, "投递记录", delivery_enabled=settings().delivery_enabled,
                    configured_channels=[STATUS_LABELS.get(c, c) for c in settings().delivery_channels],
                    columns=["报告", "渠道", "分卷", "状态", "次数", "错误"],
                    rows=[{"cells": [d.batch_id, d.channel, d.part, d.status, d.attempts, d.error or "—"],
                           "actions": [{"label": "重试失败渠道", "url": f"/admin/actions/delivery/{d.id}/retry"}]
                           if d.status == "failed" else []} for d in records[:100]],
                    next_url=f"?offset={offset + 100}" if len(records) > 100 else None)


async def action(request):
    form = await request.form()
    with session() as db:
        identity = admin_session(request, db)
        if not identity:
            raise HTTPException(401)
        if not secrets.compare_digest(str(form.get("csrf", "")), identity.csrf):
            raise HTTPException(403, "表单已过期，请刷新后重试")
        kind, target, operation = (request.path_params[k] for k in ("kind", "target", "operation"))
        from .maintenance import report_write_guard
        try:
            report_write_guard(db)
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from None
        if kind == "source":
            obj = db.get(Source, target)
            if not obj:
                raise HTTPException(404)
            if operation == "toggle":
                obj.enabled = not obj.enabled
            elif operation == "collect":
                pending = db.scalar(select(Job).where(Job.source_id == target, Job.status.in_(["pending", "running"])))
                if not pending:
                    db.add(Job(kind="collect", source_id=target))
            else:
                raise HTTPException(400)
            back = "/admin/sources"
        elif kind in {"job", "delivery"} and operation == "retry":
            cls = Job if kind == "job" else Delivery
            obj = db.get(cls, target)
            if not obj or obj.status != "failed":
                raise HTTPException(409, "仅可重试失败记录，成功记录不会重发")
            if kind == "job" and obj.kind == "maintenance":
                raise HTTPException(409, "请使用任务记录显示的服务器修复命令恢复维护任务")
            obj.status, obj.error, obj.lease_until = "pending", None, None
            if kind == "delivery":
                obj.attempts, obj.next_run = 0, now()
            back = "/admin/tasks" if kind == "job" else "/admin/deliveries"
        else:
            raise HTTPException(400)
        audit(db, identity.subject, f"web.{kind}.{operation}", target)
        db.commit()
    return RedirectResponse(back, status_code=303)


async def logout(request):
    form = await request.form()
    with session() as db:
        identity = admin_session(request, db)
        if not identity or not secrets.compare_digest(str(form.get("csrf", "")), identity.csrf):
            raise HTTPException(403)
        db.delete(identity)
        db.commit()
    response = RedirectResponse("/admin/login", status_code=303)
    response.delete_cookie("vul_session", path="/admin/")
    return response


def routes():
    return [Route("/admin/", dashboard), Route("/admin/login", login), Route("/admin/callback", callback),
            Route("/admin/logout", logout, methods=["POST"]), Route("/admin/vulnerabilities", vulnerabilities),
            Route("/admin/vulnerabilities/{vid}", detail), Route("/admin/reports", reports),
            Route("/admin/reports/{bid}/download/{kind}", download), Route("/admin/reports/{bid}/view", report_view),
            Route("/admin/reports/{bid}", report_detail),
            Route("/admin/sources", sources), Route("/admin/tasks", tasks), Route("/admin/deliveries", deliveries),
            Route("/admin/recent-candidates", recent_candidates), Route("/admin/recent-candidates/{cid}", recent_candidate_detail),
            Route("/admin/recent-candidates/{cid}/raw", recent_candidate_raw),
            Route("/admin/actions/{kind}/{target}/{operation}", action, methods=["POST"])]
