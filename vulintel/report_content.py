"""Shared, escaped Chinese report content for browser, downloads and MIME HTML."""
import html
from datetime import timedelta, timezone
from urllib.parse import urlsplit
from .config import settings

SEVERITY = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "unknown": "未评分"}
DATE_STATUS = {"confirmed": "有可核对公开依据", "day": "仅精确到日", "unknown": "待核实", "conflict": "日期冲突待核实"}
EVIDENCE = {"vendor_confirmed": "厂商确认", "public_poc": "公开 PoC", "third_party_verified": "第三方验证",
            "inference": "推测", "unknown": "未确认"}
FIELDS = {"vulnerability_summary": "漏洞说明", "root_cause": "漏洞原理", "trigger_conditions": "触发条件",
          "impact": "影响", "affected_versions": "影响范围与版本", "attack_path": "攻击路径",
          "remediation": "修复版本与缓解措施", "evidence_level": "证据等级", "evidence_notes": "证据说明"}
ESC = html.escape
FONT = "'Microsoft YaHei','PingFang SC','Noto Sans CJK SC',sans-serif"


def report_scope(state):
    work = state.work
    return {"item_limit": work.get("item_limit"), "candidate_total": work.get("candidate_total", state.total),
            "bootstrap": work.get("bootstrap"),
            "date_policy": work.get("date_policy"), "date_coverage": work.get("date_coverage"),
            "deferred_count": work.get("deferred_count", 0), "backlog_selected": work.get("backlog_selected", 0),
            "current_new_disclosures": state.new_count - work.get("backlog_new", 0),
            "recent_important_updates": state.update_count - work.get("backlog_updates", 0)}


def scope_text(state):
    scope = report_scope(state)
    return (f'本批次合格候选 {scope["candidate_total"]} 条，详细分析 {state.total} 条'
            + (f'（上限 {scope["item_limit"]} 条）' if scope["item_limit"] is not None else '')
            + f'：本期公开 {scope["current_new_disclosures"]} 条，近期重要更新 {scope["recent_important_updates"]} 条，'
            f'积压补报 {scope["backlog_selected"]} 条。另有 {scope["deferred_count"]} 条持久待报，未计为已覆盖。')


def category_label(facts):
    category = "近期公开" if facts.get("report_category") == "new" else "重要更新"
    if facts.get("report_backlog"):
        category = "积压补报（" + ("首次公开" if facts.get("report_category") == "new" else "重要变化") + "）"
    return category


def label_time(value, precision=None):
    from .timeline import stamp
    parsed = stamp(value)
    if parsed is None:
        return "未确认"
    if precision == "day":
        return parsed.strftime("%Y-%m-%d") + "（仅到日；上游未提供时刻）"
    return (parsed + timedelta(hours=8)).strftime("%Y-%m-%d %H:%M") + "（北京时间）"


def text(value):
    return ESC(str(value or "未公开／未确认")).replace("\n", "<br>")


def references(values):
    result = []
    for value in sorted(set(values)):
        parsed = urlsplit(value)
        safe = parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password
        result.append('<li style="overflow-wrap:anywhere">' +
                      (f'<a style="color:#174b76" href="{ESC(value, quote=True)}">{ESC(value)}</a>' if safe else ESC(value)) + "</li>")
    return "<ul>" + "".join(result) + "</ul>"


def header(batch, state):
    start = batch.cutoff - timedelta(days=7)
    title = label_time(batch.cutoff.replace(tzinfo=timezone.utc).isoformat())
    overview = state.overview or {}
    result = (f'<div style="font-family:{FONT};color:#183047;line-height:1.75;max-width:860px;margin:0 auto;padding:20px">'
              '<header style="border-top:6px solid #173b61;padding:12px 0 18px;border-bottom:1px solid #bdcbd8">'
              f'<h1 style="font-size:27px;margin:8px 0">漏洞情报报告</h1><p>{ESC(title)}</p>'
              f'<p style="font-size:12px;color:#50677a;overflow-wrap:anywhere">报告编号：{ESC(batch.id)}</p>'
              f'<p><a style="color:#174b76" href="{ESC(settings().public_base_url)}/admin/reports/{ESC(batch.id)}/view">阅读网页版完整报告</a></p></header>'
              '<!--VOLUME--><section><h2 style="font-size:20px">风险概览</h2>'
              f'<p>{ESC(scope_text(state))}</p><p>另有 {state.unknown_count} 条公开日期待核实，未混入近期公开。</p>'
              f'<p style="font-size:13px;color:#50677a">本期筛选窗口：{ESC(label_time(start))} 至 {ESC(label_time(batch.cutoff))}。'
              '积压补报可早于此窗口，其原始时间和首次待报时间逐条列示。</p>')
    bootstrap = state.work.get("bootstrap")
    if bootstrap:
        result += (f'<p>分阶段采集：暂存候选待核实 {bootstrap["unverified"]} 条、日期冲突 {bootstrap["conflicts"]} 条、'
                   f'待补证 {bootstrap["pending"]} 条、超大待核查 {bootstrap.get("oversized", 0)} 条；这些数量独立于正式漏洞库和本批合格候选。'
                   f'<a href="{ESC(settings().public_base_url)}/admin/recent-candidates">查看候选核实清单</a>。'
                   '定向来源覆盖有限，不代表全部来源已扫描。</p>')
    for key, label in [("risk_summary", "核心风险"), ("repair_priorities", "优先修复建议")]:
        bullets = overview.get(key, [])
        if bullets:
            result += f'<h3 style="font-size:16px">{label}</h3><ul>' + "".join(f"<li>{text(v)}</li>" for v in bullets) + "</ul>"
    if not state.total:
        result += '<p style="padding:12px;border-left:4px solid #b47416;background:#fff5df">本批次未取得符合条件的记录。此结论限于筛选窗口和已采集数据，不能据此断言公开漏洞没有新增。</p>'
    return result + "</section>"


def article(item):
    facts, analysis = item.snapshot, item.analysis or {}
    severity = SEVERITY.get(facts.get("severity"), "未评分")
    identifiers = ", ".join(facts.get("aliases", [])) or "暂无公开编号"
    if facts.get("mentioned_cves"):
        identifiers += "；关联 CVE（非别名）：" + ", ".join(facts["mentioned_cves"])
    category = category_label(facts)
    timeline = facts.get("timeline", {})
    result = (f'<article id="item-{item.id}" style="padding:18px 0;border-bottom:1px solid #cad5df;break-inside:avoid">'
              f'<h3 style="font-size:20px;margin:6px 0;overflow-wrap:anywhere">{text(facts["title"])}</h3>'
              f'<p>产品：{text(facts.get("product_group"))}</p><p style="color:#8e3128;font-weight:600">{ESC(severity)}　{category}　已利用：'
              f'{"是" if facts.get("exploited") else "未确认"}</p><p style="overflow-wrap:anywhere">编号：{ESC(identifiers)}</p>'
              f'<p style="font-size:13px;color:#50677a">公开时间：{ESC(label_time(timeline.get("published_at"), timeline.get("publication_precision")))}<br>'
              f'时间依据：{text(timeline.get("publication_basis"))}；来源：{text(timeline.get("publication_source"))}<br>'
              f'日期状态：{text(DATE_STATUS.get(timeline.get("publication_status"), "待核实"))}；原始值：{text(timeline.get("publication_original"))}<br>'
              f'上游更新时间：{ESC(label_time(timeline.get("upstream_updated_at")))}<br>'
              f'重要变化时间：{ESC(label_time(timeline.get("material_changed_at"), timeline.get("important_precision")))}；依据：{text(timeline.get("change_basis"))}<br>'
              f'本库观察到变化：{ESC(label_time(timeline.get("change_observed_at")))}<br>'
              f'首次待报时间：{ESC(label_time(facts.get("first_eligible_at")))}</p>')
    for field, label in FIELDS.items():
        value = analysis.get(field) or "未公开／未确认"
        if field == "evidence_level":
            value = EVIDENCE.get(value, "未确认")
        result += f'<h4 style="font-size:15px;margin:16px 0 4px;color:#173b61">{label}</h4><p style="margin:0;overflow-wrap:anywhere">{text(value)}</p>'
    return result + '<h4 style="font-size:15px;color:#173b61">参考来源</h4>' + references(
        list(facts.get("references", [])) + list(facts.get("date_references", [])) + list(analysis.get("references", []))) + "</article>"


def markdown_article(item):
    facts, analysis = item.snapshot, item.analysis or {}
    result = f'### {ESC(facts["title"])}\n\n编号：{ESC(", ".join(facts.get("aliases", [])))}\n\n'
    result += f'严重性：{SEVERITY.get(facts.get("severity"), "未评分")}；已利用：{"是" if facts.get("exploited") else "未确认"}\n\n'
    result += f'类别：{category_label(facts)}；首次待报时间：{label_time(facts.get("first_eligible_at"))}\n\n'
    timeline = facts.get("timeline", {})
    result += f'公开时间：{label_time(timeline.get("published_at"), timeline.get("publication_precision"))}；时间依据：{ESC(timeline.get("publication_basis", "未确认"))}\n\n'
    result += f'日期原始值：{ESC(str(timeline.get("publication_original") or "未确认"))}；状态：{DATE_STATUS.get(timeline.get("publication_status"), "待核实")}\n\n'
    result += f'重要变化时间：{label_time(timeline.get("material_changed_at"), timeline.get("important_precision"))}；依据：{ESC(str(timeline.get("change_basis") or "未确认"))}\n\n'
    result += f'本库观察到变化：{label_time(timeline.get("change_observed_at"))}\n\n'
    result += f'上游更新时间：{label_time(timeline.get("upstream_updated_at"))}\n\n'
    for field, label in FIELDS.items():
        value = analysis.get(field) or "未公开／未确认"
        if field == "evidence_level":
            value = EVIDENCE.get(value, "未确认")
        result += f'#### {label}\n\n{ESC(value)}\n\n'
    return result + "参考来源：\n\n" + "".join("- " + ESC(url) + "\n" for url in sorted(set(
        list(facts.get("references", [])) + list(facts.get("date_references", [])) + list(analysis.get("references", []))))) + "\n"


def coverage(batch, state):
    result = f'<section><h2 style="font-size:20px">采集覆盖</h2><p>状态快照：{ESC(label_time(state.coverage_at))}；不代表当前实时状态。</p>'
    result += '<div style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:13px"><tr><th align="left">来源</th><th align="left">状态</th><th align="left">最近成功（北京时间）</th></tr>'
    for source in batch.coverage:
        label = "停用" if not source["enabled"] else ("覆盖有限／超大条目待核查" if source.get("oversized_candidates") else
                "覆盖有限／定向补充" if source.get("coverage_limited") else
                "失败" if source["error"] else "过期" if source["stale"] else "正常")
        result += f'<tr><td style="padding:6px;border-bottom:1px solid #dbe2e9">{text(source["name"])}</td><td>{label}</td><td>{ESC(label_time(source.get("last_success_utc")))}</td></tr>'
    return result + '</table></div><p>失败或过期来源存在覆盖缺口，不等于没有新增漏洞。详细采集错误和任务诊断见管理页。</p></section>'
