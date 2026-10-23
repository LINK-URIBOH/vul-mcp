# 报告批次与近七天逐条详解升级

本版解决批次构建时整批 ORM 对象累积、准备中被误判为空报告、报告混入工具执行文字的问题。采用后台可恢复流程：准备 → 全部逐条分析 → 渲染与分卷 → 统一发布 → 已配置渠道投递。默认投递总开关仍关闭，SMTP/Webhook 可独立配置。

## 日期与报告规则

- 首次新规则报告覆盖最近到期的北京时间 09:00/18:00 时间段，公开窗口为截止前 7×24 小时（含边界）；后续仅处理未报告的近期公开记录及近期重要变化。
- KEV 收录、厂商明确给出的修复/缓解发布日期、已知来源影响范围或修复内容变化，进入重要更新。纯时间戳变化、重复来源收录不视为新增披露。观察到的变化和厂商声明的日期分别注明依据。
- NVD、GHSA、OSV 使用其公开字段；RSS 使用公开字段；微软优先使用条目最早公开修订日期；Apple/Android 仅提取明确的公开元数据、标注日期或公告日期。无法确定时不编造。
- 日期仅到日的上游记录以 UTC 零点归一化用于窗口比较，正文明确显示“仅到日”，不宣称具体披露时刻；边界有日期精度限制。时间依据和原始日期保留在 JSON。
- 日期未知进入待核实清单，提供数量、编号、标题和来源索引，不混入近期公开。其他历史数据仍可检索，不删除。
- 原数据库只保留当时最新事实，无法还原升级前未保存的历史版本或最早采集时刻；历史回填对此保留未知，不伪造。未来采集生成不可变修订和已知首次采集时间。
- 多 CVE 公告保存“关联 CVE”，不将不同编号当作同一漏洞的别名。日期、版本或影响无法对应某个 CVE 时，分析必须明确未确认。

旧报告与原投递行保留。旧空报告不作为新策略的完成水位；若当前时间段已被旧版正式报告占用，则不覆盖它，使用下一个未占用的计划时间段执行首次新规则补报。

## 1. 升级前备份

先暂停既有云端计划，避免旧提示词在迁移期间调用。以下在服务器仍保留旧 Compose 和镜像时执行：

```bash
cd /opt/vul-mcp
umask 077
backup_dir=$(mktemp -d /root/vul-before-report-workflow-XXXXXXXX)
cp -a .env compose.yaml "$backup_dir/"
[ ! -d secrets ] || cp -a secrets "$backup_dir/"
git rev-parse HEAD > "$backup_dir/git-head.txt"
docker image tag vul-intel:1.0.3 vul-intel:rollback-before-report-workflow
bash scripts/backup.sh "$backup_dir/data"
echo "备份目录：$backup_dir"
```

编辑现有 `.env`，暂时设置 `DELIVERY_ENABLED=false`。不重新运行 bootstrap，不删除 `.env`、认证密钥或数据卷，不执行 `docker compose down -v`。

## 2. 更新、编号迁移与元数据回填

覆盖发布包到原项目目录，或确认远端已包含本次修改后通过 Git 更新。保持原 Compose 项目和端口：

```bash
docker compose stop web worker
docker compose config --quiet
docker compose build web
docker compose run --rm --no-deps -T web python -m vulintel.cli init
docker compose up -d --no-deps web worker
docker compose ps
```

迁移 002（`vulintel/migrations.py`）仅新增 metadata_state、vulnerability_revisions、report_states、report_selections、unverified_report_items 及索引，由 schema_migrations 记录版本，在 PostgreSQL advisory lock 下执行。不改写旧报告表，不重建 Keycloak，重复执行安全。

历史日期回填按最多100条、约2 MB快照预算分片，保存 UUID 检查点；首个报告准备任务会自动完成回填，也可先短暂停止 worker 手工推进，避免小服务器上同时启动两个回填器：

```bash
(
  trap 'docker compose start worker' EXIT
  docker compose stop worker
  docker compose run --rm --no-deps -T web python -m vulintel.cli backfill --max-steps 1000
)
docker compose exec -T web python -m vulintel.cli status
```

检查 `metadata_backfill.complete`；未完成可重复运行，或者交给后台报告任务继续。回填复用现有来源事实，未来官方采集会继续补齐日期；它不会猜测日期或抓取任意地址。至少预留与现有事实数据规模相当的额外数据库及报告空间，先在备份或测试副本评估磁盘。

## 3. 刷新 MCP 与更新云端提示词

保持现有 OAuth 客户端、回调、权限和续期配置。刷新连接的工具列表，确认有九个工具，包括新增的 get_report_status 和 get_item_evidence；权限仍为 vul.read / vul.submit / vul.deliver。

必须替换 `CLOUD_TASK.md` 的新版提示词，不能沿用把“没有待分析页”等同“报告为空”的旧逻辑：

| 工具 | 新行为 |
| --- | --- |
| open_report_batch | 快速返回编号及 preparing 状态，后台准备；重复调用恢复同一批次 |
| get_report_status | 只读查询准备、逐条分析、渲染阶段、计数与错误追踪编号 |
| get_batch_page | 准备完成前 ready=false、总数和待分析数为 null；完成后返回有界摘要 |
| get_item_evidence | 按字符位置分页读取完整 JSON 事实；继续到 next_offset=null |
| submit_batch_analysis | 每条必须有中文 vulnerability_summary，所有入选项都须分析 |
| finalize_report | overview 提交风险要点和修复优先级；返回 rendering，不能视为已发布 |
| get_delivery_status | 保留按渠道和分卷状态及总开关；staged 不是可发送任务 |

summary 旧参数仍可接受，但只供管理诊断；正文风险摘要使用结构化 overview 和服务器统计。准备/渲染未完成时如实返回进度，后续云运行恢复，不快速循环请求，不生成半成品正式报告。

## 4. 手动与无人值守验收

1. health_check 确认版本 1.1.0，调用 open_report_batch 获取编号；准备阶段应能持续读取状态，web 不重启。
2. 准备完成后核对公开/重要更新/日期未知数量；对全部入选记录读取完整证据并提交详解。没有证据时写未确认，不运行利用代码。
3. 全部分析完成后 finalize；等待 finalized，再核对网页、HTML、Markdown、JSON、CSV 和日期待核实清单数量一致。
4. 正文应为“风险概览 → 按产品分组详情 → 完整索引 → 采集覆盖 → 日期待核实”，没有分页参数、重试过程或旧 summary。
5. 在服务器配置已授权测试目标；确认旧队列和固定目标后启用投递，核对所有已配置渠道及所有分卷。单渠道不要求填另一渠道。
6. 执行一次云端测试，确认准备、分析、渲染、投递均可恢复，且无需人工批准；再恢复 09:00、18:00 既有计划。若平台要求人工批准，记录限制，不改标只读绕过。

本次交付未修改生产数据库或连接、未发送真实邮件/Webhook、未改动云端计划；这些生产步骤需部署后执行。完整逐条分析可能跨次完成，正式发送可以晚于计划触发时间。

## 5. 异常定位与回退

```bash
docker compose logs --since 30m --timestamps web worker
docker compose exec -T web python -m vulintel.cli status
```

MCP 返回追踪编号后，在 web 日志定位 mcp_started / mcp_failed / mcp_completed；后台异常定位 report_failed 及批次编号。日志只记录异常类型与脱敏堆栈位置，不包含 SQL 参数、凭据或上游正文。若对应请求没有 mcp_started，核对已有 Nginx/Cloudflare 访问记录和云端调用限制，不能仅凭 -32603 断定数据库或 OOM。

失败任务可通过管理页或 `python -m vulintel.cli retry job <ID>` 恢复，或再次 open_report_batch 恢复同一批次。文件暂存检查点缺失会明确失败，不自动填补字节或跳过条目。

回退前暂停云端计划、关闭投递、停止 web/worker，并保留升级后的数据库和报告卷。迁移虽为新增表，旧 worker 不认识 report 任务、旧 MCP 也不理解新阶段，不能直接启动旧 worker 消费新库。临时回退只能用于停止 worker 后的只读查看；需要恢复旧业务流程时，从升级前备份恢复到独立数据库和卷，再按旧 Compose 切换，避免覆盖升级后已采集数据。不要直接删除新表或恢复备份覆盖当前库。
