# v1.4.1：GitHub日期格式及超大候选阻塞修复

适用于已执行v1.4.0初始化、GHSA出现422或CISA出现“单条初始化候选超过2MB预算”的服务器。本版无新增数据库迁移，保留当前run_id、初始化窗口、分页位置、候选、正式数据、报告和缓存。

## 升级后继续现有任务

同步代码后，在项目目录执行：

```bash
docker compose stop worker
docker compose build web
docker compose up -d --no-deps web worker
docker compose exec -T web python -m vulintel.cli status
docker compose logs --tail=100 worker
```

**不要重新执行reset-recent、reset_recent.sh或添加--new-run。** 本次只需升级应用并恢复worker。来源会按原重试时间从原分页位置继续；没有清空或重新创建初始化任务。

若尚未到来源next_run，可等待自动重试，或在“采集来源”点击GHSA/CISA对应的“补采”，让现有来源任务尽快恢复。补采不重建初始化窗口，也不清库。初始化扫描完成与全部日期核实完成仍分别统计。

## 修复内容

- GitHub接口拒绝带小数秒的范围。发往GitHub的查询起点向下取整到秒、终点有微秒时向上取整到下一秒，避免查询边界漏项。数据库内仍保留原来的微秒窗口，入选核对使用原值，不扩大实际报告资格。
- 同时修正首次published、后续modified及保存的分页URL；before/after游标保留。HTTP失败原因带状态码，便于区分参数错误、权限和限流。
- 2,000,000字节仍是多条候选的分片预算，单条完整JSON允许最多8MiB。允许单独处理一个较大的完整条目，不截断正文、编号或版本条件。
- 超过8MiB的条目先保存完整JSON及SHA256，再记为oversized并继续扫描下一条；不入库、不分析、不算已核实新增。磁盘写入失败时不会推进该页游标，避免丢失原文。
- 管理页“候选核实”增加“超大条目待核查”；详情提供需管理员登录的完整原始JSON下载，校验路径、大小及哈希。轻量显示字段明确标为证据不完整，不能拿摘要代替原文。
- MCP初始化状态增加oversized计数；来源、HTML、Markdown、JSON、邮件及Webhook保留覆盖缺口说明。扫描完成不表示隔离条目已处理完成。

旧失败页会重新读取原有冻结快照。正常条目按稳定编号去重；约2.4MB的CISA条目可以保留完整正文并推进，真正超过新上限的条目单独隔离。不会静默丢弃超限记录或描述为已发送报告。
