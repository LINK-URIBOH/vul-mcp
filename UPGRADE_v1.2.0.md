# 1.2.0：一次启动修复全部历史数据、清理旧报告、每批最多50条

本版新增迁移3（持久待报队列和批次候选暂存表），事件策略升级为4。更新代码或构建镜像不会自动清理报告；只有显式运行 `repair-history --clear-reports` 才执行清理。

## 部署与一键修复

在服务器项目目录完成代码同步后执行。原始来源记录、漏洞事实、来源配置、登录账号及投递配置均保留；修复首次启动时存在的**全部报告、已保存分析、报告任务、投递队列与对应归档文件将清理**。不保留旧报告覆盖标记，之后按修复结果重新筛选。已有邮件无法撤回，也不会把修复工具描述为报告发送任务。

如需保留旧报告备份，先使用已有 `scripts/backup.sh` 备份到新的目录。本工具无需交互确认，不要求备份才能继续。

```bash
docker compose stop worker
docker compose build web
docker compose up -d --no-deps web
bash scripts/repair_history.sh
```

Web 管理页在修复期间可查看“任务记录 → 历史数据修复”；worker 被脚本暂停。每个分片提交进度，且进程每30秒续约心跳。修复工具使用独立运行锁，重复启动或尚有 worker 运行会明确拒绝。

工具直到 `complete=true`、`phase=complete` 且退出码0才算完成，**没有1000步的总执行上限**。来源重放或超大漏洞会增加单步耗时，进度和心跳是独立显示的。不要凭来源数量、`processed=0` 或某次游标判断完成。

## 用 screen 持久运行

```bash
screen -S vul-history-repair
bash scripts/repair_history.sh
```

按 `Ctrl+A`，再按 `D` 分离会话；使用 `screen -r vul-history-repair` 恢复查看。正常修复过程中无需重复执行命令。

如果进程被中断、容器停止或服务器重启，重新运行同一个脚本即可继续。脚本退出时会恢复 worker；未完成的维护状态会使 worker 暂停采集、报告生成和投递，不会假装修复完成。Web 显示错误或心跳过期，必须恢复修复。再次运行已完成的工具只返回原完成结果，**不会清理后来生成的新报告**。

直接调用方式（先停止 worker）：

```bash
docker compose run --rm --no-deps -T web python -u -m vulintel.cli repair-history --clear-reports
docker compose exec -T web python -m vulintel.cli status
```

原 `backfill --max-steps` 仍是有步数上限的兼容命令，不替代新的全量修复工具。

## 报告上限及延期处理

`REPORT_MAX_ITEMS=50` 默认对每批生效，取值1..10000。Compose 将该值传入 web/worker；调整后重新创建两项服务。批次创建时冻结上限，运行途中改配置不会改变已准备或正在分析的批次。

准备阶段扫描完整候选集，按已利用优先、严重性降序、首次待报时间升序、稳定编号排序，最多选择50条详细分析。公开日期未知的清单不占此额度。超额记录保存在数据库待报队列，跨七天后标为积压补报，不会静默遗漏或标为已覆盖。来源状态过期或失败仍按实际情况说明。

候选暂存表在准备阶段固定本批修订编号，采集取得的新证据不会替换本批时间范围内的候选；准备完成后清除暂存行。后续权威资料若纠正了曾用于入选的公开日期，已不符合原入选条件的“近期公开”会转为有效的重要更新，或撤销候选并保留审计；原始记录仍可检索。日期被撤回的记录进入待核实，不冒充新漏洞。

只有归档成功才确认本批次覆盖；投递失败由现有分卷重试处理，不会重新分析已归档的内容。冻结后取得的新证据保留供后续批次处理。优先级排序会优先处理高风险，新流入长期超过处理能力时积压可能持续增加。

修复完成后通过已有云端任务调用九个工具继续正式流程。工具不会替模型生成分析；仍须读取每条完整证据、保存全部入选分析并调用 finalize。上限控制数量，不保证云端运行额度或渠道送达。

## 状态和归档兼容性

- CLI `status` 与 `health_check` 增加 `maintenance`，列出阶段、任务状态、心跳和前后数量。
- `get_report_status` 增加 `item_limit`、`candidate_total`、`deferred_count`、`backlog_selected`。
- 摘要和冻结事实增加 `report_backlog`、`first_eligible_at`；HTML、Markdown、邮件、Webhook和JSON展示实际覆盖范围。
- 保留九个工具和原字段；归档 JSON/Webhook 仍为 schema_version=2.0，新增字段兼容读取。
- 不修改云端计划、登录权限或渠道目标。维护期间写操作明确返回维护未完成；`rendering`、`finalized`、`sent` 的含义不变。
