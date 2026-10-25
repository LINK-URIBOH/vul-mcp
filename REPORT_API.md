# 报告工作流接口

## 服务器状态

v1.4.1无需数据库迁移。`bootstrap.oversized`和各来源oversized/oversized_candidates表示超过8MiB、原文完整保存但尚待核查的候选，不是已分析数或已核实新增。来源coverage_limited和coverage_note说明此类缺口；扫描可以完成，隔离项仍保留。管理页增加oversized筛选及管理员原文下载。旧报告冻结快照缺少新字段时按0兼容。

v1.4.0 增加显式 `reset-recent --days 7 --clear-vulnerabilities --clear-reports`（服务器CLI，不增加MCP工具）。迁移005增加独立候选及来源扫描水位；重置范围、恢复和幂等说明见 [升级文档](UPGRADE_v1.4.0.md)。普通升级不自动切换或清库。

近七天模式下 `health_check`、`get_source_status` 返回 `bootstrap`：固定window_start/end、phase、scan_complete、candidates、processed、verified_candidates、admitted_vulnerabilities、excluded_old、unverified、conflicts、pending、errors、status、updated_at、heartbeat_at、items_per_hour、percent、estimated_remaining_seconds和sources。来源发现总量未知时percent/ETA为null；队列ETA不包含未来新增、所有来源覆盖或延期重试。

`get_source_status.sources` 增加 coverage_mode（published/events/targeted）、coverage_limited、coverage_note、bootstrap_status。targeted不是当前来源失败，也不是已完成全量采集；last_success为空且coverage_limited=true仍表示覆盖有限。来源启停配置保留。

正式库只接收通过日期资格核实的首次候选，暂存未知/冲突记录独立展示。后续新证据纠正已有正式记录时保留事实并更新规范标注。`get_report_status` 和归档 `report_scope` 增加准备时冻结的bootstrap快照；暂存候选数量与本批candidate_total、total、unverified_dates不同，不能相加当作已核实新增。候选完整证据及失败原因可在管理页 `/admin/recent-candidates` 查看。网络补证不持有维护屏障，第一阶段尚未覆盖的来源明确列示。

批次状态为 preparing、analyzing、rendering、finalized、failed。仅 finalized 可下载正式文件。get_report_status 返回 policy、ready、total、analyzed、pending_analysis、new_disclosures、important_updates、unverified_dates、metadata_backfill、phase、render_stage、rendered_items、coverage_at_utc、error；准备前未知计数为 null，不是零。

旧批次 policy=1、legacy=true，v1.1.0 为2，v1.1.1 为3，v1.2.0 为4，v1.3.0 为5；时间段仍唯一。旧的未发布批次拒绝沿用旧日期规则，须先运行 `repair-publication-dates --rebuild-unpublished`。该工具重置首次启动冻结的未发布批次（同一批次编号、时间段和上限），清除这些批次的分析及暂存文件，修复完成后重新准备；已归档报告不改写。完成后重跑不清理后来生成的报告。旧 `repair-history --clear-reports` 仍是清理全部报告的独立工具，不代替日期修复。

v1.2.0 默认每批最多50条详细分析（REPORT_MAX_ITEMS，批次创建时冻结）。完整扫描候选后按已利用、严重性、首次待报时间及稳定编号选择；超额条目持久待报，超过七天以积压补报展示。归档成功才确认覆盖，冻结之后的新证据继续待报。未知公开日期单列，不占50条分析额度。

`get_report_status` 新增 `item_limit`、`candidate_total`、`deferred_count`、`backlog_selected`；候选扫描尚未完成时候选/延期数可为null。`get_batch_page` 和完整事实增加 `report_backlog`、`first_eligible_at`，以区分当前窗口与历史积压。

原 `new_disclosures`、`important_updates` 保留按原始类别计数（可包含积压）；新增 `current_new_disclosures`、`recent_important_updates` 排除积压，与 `backlog_selected` 合计等于本批详细分析总数。归档 JSON、Webhook 的 `report_scope` 和邮件正文使用相同覆盖口径。

`health_check` 新增 `maintenance`（未运行过时为null），包含阶段、任务状态、心跳及前后数量。维护状态持久保存，未完成（包括中断、失败）时拒绝报告创建、分析提交和完成，并暂停后台报告、投递及采集。通过服务器相同维护命令恢复。九个MCP工具的名称和权限不变。

v1.3.0 `timeline.event_policy=5`、`date_policy=1`。规范 `published_at` 是最早可核实公开时间；NVD/CVE记录日期与所有OSV条目日期独立保存在证据中，不能直接替代披露。`publication_status` 为 confirmed、day、unknown、conflict；后两类不计已核实新增。精确到日时 `published_at` 保持 YYYY-MM-DD，边界使用 `publication_start_at/end_at` 保守判定，不伪造小时。

`get_report_status` 新增 `date_policy`、`date_coverage`、`date_audit_required`、`old_date_mixed_count`。日期覆盖包含 total、confirmed、day、unknown、conflict、missing_current_annotation、evidence_fetch_errors、pending_evidence_jobs；覆盖快照与本批入选数量不同。`health_check` 和 `get_source_status` 返回当前 `date_coverage`。维护结果另有 corrected_dates、projections_written、validated、network_gaps、checked_unpublished_batches 和重建批次的 old_date_mixed_count。零混入仅表示已检查对象版本一致，不表示所有漏洞日期已确认。

完整证据包含 `date_annotation_id`、`date_assessed_at`、`publication_original/field/reference/precision`、`date_evidence`、`rejected_date_evidence`、`date_conflicts`、`cve_record_publications` 和 `source_entry_publications`。原始修订不可变；报告在截止时间内选择事实修订，再关联准备阶段冻结的日期标注编号。后来补证只校正日期，不把后来影响版本或补丁信息带入旧事实。缺少当前日期标注或历史投影时明确阻塞，不回退旧日期。

`material_changed_at` 使用实际补丁、公告内容更新或已利用收录时间，`important_reference` 和 `event_dates` 保存依据；本库 `change_observed_at` 单列。日期修复不制造维护当天事件。待核实清单保留具体原因和标注证据，含日期未知、冲突及窗口边界不确定。

## 有界分页与证据

get_batch_page 仍接受 batch_id、after、limit（1..20）、pending_only。返回最多约192 KB的摘要页（不含来源覆盖表）；标题/编号/关联CVE提供完整性标志，`date_evidence_complete=false` 表示摘要未含完整日期证据，完整原文须续页读取。analysis 为已保存分析，不能以未提供原文推断信息不存在。

get_item_evidence 接受 batch_id、item_id、offset（从0开始）、limit（1..16000字符）。返回 format=json-text、text、total_characters、next_offset。按顺序连接所有 text 可恢复该条目完整冻结 JSON；offset 单位为字符，不是字节。服务器核对条目与批次归属，不接受路径或 URL。

submit_batch_analysis 的每条分析新增 vulnerability_summary（中文必填），其余字段为 root_cause、trigger_conditions、impact、affected_versions、attack_path、remediation、evidence_level、evidence_notes、references。已有原理/影响等字符串上限8000字符，引用为1..50个公开HTTPS地址，每地址最多2048 UTF-8字节，单条分析 JSON 总量最多192000字节；超限在提交阶段明确拒绝，可修正后再次提交。未知信息明确写未公开/未确认，证据等级不得冒充本服务实际复现。

finalize_report 接受 batch_id、可选 summary（旧参数，仅诊断）、overview。overview={risk_summary:[...],repair_priorities:[...]}；分别最多6/10条，每条1..600字符，不允许工具执行字段。所有入选项完整分析后才进入 rendering。重复调用不重复建队列；生成失败保留检查点，重试finalize恢复原渲染进度与冻结摘要，不重置文件或分卷。

## 文件与投递兼容性

新 report.json / Webhook schema_version=2.0。报告 JSON 保留完整 facts 和 analysis，新增 overview、权威计数、coverage_at_utc、unverified。HTML/Markdown展示中文证据标签，JSON 保留原始枚举。

Webhook 顶层仍有 message_id、report_id、slot、part、parts、coverage、summary、items，增加 overview 和 raw_evidence 说明。items 中 facts 是有界的编号、标题、严重性、利用状态、产品、日期、类别；analysis 保留完整详解。完整原始 source_records 在归档 report.json；不会为缩短消息静默丢弃详解。接收端需要兼容 schema_version=2.0。

HMAC 算法、时间戳、消息编号、固定服务器目标及接收端去重要求不变。staged 分卷只供后台准备，不可发送；所有文件校验及 MIME 大小检查成功后，事务统一将分卷激活为 pending，并标记 finalized。之后渠道各自重试，sent 不重发。HTML和纯文本邮件均包含该卷完整详解，CSV索引和日期待核实清单按大小分卷。

权限与工具标记不变：读取和状态/证据工具只读；创建、提交及完成为写操作。MCP 异常返回关联编号，详细诊断仅供服务器日志和管理页，不出现在报告正文。
