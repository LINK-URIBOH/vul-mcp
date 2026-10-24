# 报告工作流接口

## 服务器状态

批次状态为 preparing、analyzing、rendering、finalized、failed。仅 finalized 可下载正式文件。get_report_status 返回 policy、ready、total、analyzed、pending_analysis、new_disclosures、important_updates、unverified_dates、metadata_backfill、phase、render_stage、rendered_items、coverage_at_utc、error；准备前未知计数为 null，不是零。

旧批次 policy=1、legacy=true，v1.1.0 为 policy=2，v1.1.1 为 policy=3，v1.2.0 新批次为 policy=4，时间段仍唯一。未完成批次优先恢复，升级本身不清理或重选旧批次；显式运行 `repair-history --clear-reports` 时清理该维护首次启动前的全部旧报告、分析、投递及归档，然后重新筛选。工具完成后再次运行不会删除新报告。旧策略仍存在时返回 event_audit_required=true。

v1.2.0 默认每批最多50条详细分析（REPORT_MAX_ITEMS，批次创建时冻结）。完整扫描候选后按已利用、严重性、首次待报时间及稳定编号选择；超额条目持久待报，超过七天以积压补报展示。归档成功才确认覆盖，冻结之后的新证据继续待报。未知公开日期单列，不占50条分析额度。

`get_report_status` 新增 `item_limit`、`candidate_total`、`deferred_count`、`backlog_selected`；候选扫描尚未完成时候选/延期数可为null。`get_batch_page` 和完整事实增加 `report_backlog`、`first_eligible_at`，以区分当前窗口与历史积压。

原 `new_disclosures`、`important_updates` 保留按原始类别计数（可包含积压）；新增 `current_new_disclosures`、`recent_important_updates` 排除积压，与 `backlog_selected` 合计等于本批详细分析总数。归档 JSON、Webhook 的 `report_scope` 和邮件正文使用相同覆盖口径。

`health_check` 新增 `maintenance`（未运行过时为null），包含阶段、任务状态、心跳及前后数量。维护状态持久保存，未完成（包括中断、失败）时拒绝报告创建、分析提交和完成，并暂停后台报告、投递及采集。通过服务器相同维护命令恢复。九个MCP工具的名称和权限不变。

timeline.event_policy=3 区分 source_publications（来源条目公开时间与作用范围）和 published_at（有公开依据的漏洞/公告公开时间）。Debian/Ubuntu OSV 条目 published 不再直接作为漏洞公开时间；无其他日期依据时保持未知。零值日期不作为事件；changed_fields 记录真正变化字段。数据库工具、权限和九个 MCP 工具数量保持不变。

## 有界分页与证据

get_batch_page 仍接受 batch_id、after、limit（1..20）、pending_only。返回最多约192 KB的摘要页（不含来源覆盖表）；标题/编号/关联CVE提供完整性标志，完整原文不在摘要内。analysis 为已保存分析，不能以未提供原文推断信息不存在。

get_item_evidence 接受 batch_id、item_id、offset（从0开始）、limit（1..16000字符）。返回 format=json-text、text、total_characters、next_offset。按顺序连接所有 text 可恢复该条目完整冻结 JSON；offset 单位为字符，不是字节。服务器核对条目与批次归属，不接受路径或 URL。

submit_batch_analysis 的每条分析新增 vulnerability_summary（中文必填），其余字段为 root_cause、trigger_conditions、impact、affected_versions、attack_path、remediation、evidence_level、evidence_notes、references。已有原理/影响等字符串上限8000字符，引用为1..50个公开HTTPS地址，每地址最多2048 UTF-8字节，单条分析 JSON 总量最多192000字节；超限在提交阶段明确拒绝，可修正后再次提交。未知信息明确写未公开/未确认，证据等级不得冒充本服务实际复现。

finalize_report 接受 batch_id、可选 summary（旧参数，仅诊断）、overview。overview={risk_summary:[...],repair_priorities:[...]}；分别最多6/10条，每条1..600字符，不允许工具执行字段。所有入选项完整分析后才进入 rendering。重复调用不重复建队列；生成失败保留检查点，重试finalize恢复原渲染进度与冻结摘要，不重置文件或分卷。

## 文件与投递兼容性

新 report.json / Webhook schema_version=2.0。报告 JSON 保留完整 facts 和 analysis，新增 overview、权威计数、coverage_at_utc、unverified。HTML/Markdown展示中文证据标签，JSON 保留原始枚举。

Webhook 顶层仍有 message_id、report_id、slot、part、parts、coverage、summary、items，增加 overview 和 raw_evidence 说明。items 中 facts 是有界的编号、标题、严重性、利用状态、产品、日期、类别；analysis 保留完整详解。完整原始 source_records 在归档 report.json；不会为缩短消息静默丢弃详解。接收端需要兼容 schema_version=2.0。

HMAC 算法、时间戳、消息编号、固定服务器目标及接收端去重要求不变。staged 分卷只供后台准备，不可发送；所有文件校验及 MIME 大小检查成功后，事务统一将分卷激活为 pending，并标记 finalized。之后渠道各自重试，sent 不重发。HTML和纯文本邮件均包含该卷完整详解，CSV索引和日期待核实清单按大小分卷。

权限与工具标记不变：读取和状态/证据工具只读；创建、提交及完成为写操作。MCP 异常返回关联编号，详细诊断仅供服务器日志和管理页，不出现在报告正文。
