# 来源事件标记修复与批次审计

v1.1.1 / event_policy=3。此补丁修正入库身份与事件分类，不增加模型执行器，不保证单次云端运行能分析任意数量记录。未部署到生产环境。

## 修复范围

- 仅从明确的单漏洞结构化编号 `DEBIAN-CVE-…`、`UBUNTU-CVE-…` 补齐规范 CVE 别名，并与 NVD、GHSA、其他 OSV 来源归并。不从标题、描述、参考链接、related 或多 CVE 公告推断别名。
- 发行版 OSV 的 `published` 原值保留为来源条目公开时间，不直接充当漏洞首次公开时间。合并事实存在其他公开日期时使用可核对的最早日期；没有依据时进入待核实，不按 CVE 年份猜测。
- 拒绝 `0001-01-01` 等零值时间。明确的 KEV 收录、有效修复日期、已知来源同一条目的影响/修复变化仍能成为重要事件。
- 忽略列表排序、纯 modified 变化，以及 Debian/Ubuntu `introduced=0` 无界影响范围内版本枚举增长造成的假变化。其他生态、有限范围或范围外显式版本仍保留在比较中。
- 为事件保留来源日期、作用范围、原值、有效性和 changed_fields。历史修复追加新的派生修订，保留原始 Revision 快照、冻结 BatchItem 和已有分析。

OSV 的 published 定义为该数据库条目的公开时间，不保证它是跨所有数据库的漏洞首次公开时间。依据：https://ossf.github.io/osv-schema/#published-field 。

## 本次线上批次审计结论

批次 `a39a3c93-d975-4414-855c-298e380d10b1`；时间段 2026-10-23 18:00 Asia/Shanghai。通过 get_batch_page、pending_only=false、limit=20 读取全部215页，共4,287条摘要，其中new=4,279、update=8。未调用写入、归档或投递工具。

| 核对项 | 结果 |
| --- | --- |
| 4,279条 new 的已保存公开日期是否都在滚动七天 | 是，窗口为10月16日18:00至10月23日18:00（北京时间） |
| 是否都在自然周内（本周一10月19日00:00起） | 否，其中698条标注日期早于本周一；3,581条位于本周内 |
| 是否是4,279个独立漏洞 | 否，规范编号归并发现687组重复，多计861条 |
| 仅对new记录按明确别名归并后的候选实体 | 3,418组，不是已经确认的新增漏洞总数；其中仍可能有多漏洞公告 |
| 仅有Debian/Ubuntu来源日期支持的候选实体 | 567组，需原始证据或其他来源的漏洞公开时间，不直接认定近期新漏洞 |
| new记录含零值修复日期 | 232条 |

例：`CVE-2026-98828` 的 item 5、3091、3443 分别是 OSV Linux、Debian、Ubuntu 对同一 CVE 的记录；原策略把它们分别计数。

本轮完整核对的是全部摘要中的身份与日期字段，并未逐一读取4,287条完整证据或重新完成漏洞分析。不能把3,418或其中有其他来源日期支持的2,851组，直接宣称为全球首次公开的新漏洞数量。CVE编号年份也不能代替公开时间。

## 可复现的只读审计

本地摘要导出见 outputs/event-audit-20261023-summaries.json，包含全部215页记录；计数见 outputs/event-audit-20261023-counts.json。可用下列命令重新生成摘要审计（不会连接数据库）：

```bash
python -m vulintel.cli audit-report a39a3c93-d975-4414-855c-298e380d10b1 --snapshot-json outputs/event-audit-20261023-summaries.json > event-audit-summary.json
```

输出 `full_evidence_reviewed=false`。摘要不能证明完整来源是否包含更早公开时间。

服务器数据库审计会读取冻结事实，并通过规范 CVE 别名检查数据库中截止时间前已知的其他修订；不改变批次、分析或投递状态，不执行初始化或迁移：

```bash
docker compose exec -T web python -m vulintel.cli audit-report a39a3c93-d975-4414-855c-298e380d10b1 > event-audit-full.json
```

这里的 `full_evidence_reviewed=true` 只表示程序读取了完整冻结事实进行事件元数据审计，不表示人工或模型复现验证了漏洞，也不代表完成全部中文分析。

## 升级与历史元数据修复

先按现有备份流程备份数据库、报告和配置，暂停云端计划并停止worker以避免迁移中同时采集。保留原Compose项目、OAuth配置和数据卷，不重新初始化认证、不修改投递目标或投递总开关。

在确认代码已同步到服务器后执行：

```bash
docker compose stop worker
docker compose build web
docker compose run --rm --no-deps -T web python -m vulintel.cli backfill --max-steps 1000
docker compose up -d --no-deps web worker
docker compose exec -T web python -m vulintel.cli status
```

新检查点为 `source_event_backfill_v3`，先分片补齐结构化CVE归并，再重放已有修订的事件语义。`phase=aliases` 时查看 alias_cursor、relinked_records；`phase=events` 时查看cursor、processed；直到complete=true。未完成可停止worker后重复backfill，或由新批次准备任务继续。单步读取有条数/字节预算；单个超大记录和同一漏洞的全部历史重放仍会增加耗时，应先在备份副本评估。使用PostgreSQL事务锁避免两个回填器推进同一检查点。

不新增数据库表。原 policy=2 批次及其已保存3条分析不自动重选、删除、完成或发送。其旧计数不会因升级自动变成新结果，状态会显示 event_audit_required=true。先保存 full 审计并核对入选清单，再另行安排有审计记录的未发布批次重建；本补丁不提供隐式重建或把旧分析套用到不同证据的新条目。

## 验证

针对归并顺序、发行版日期与CVE日期区分、零值时间、版本枚举与真实范围变化、历史事件重放、幂等回填和冻结批次保留提供回归测试。运行 pytest、ruff 和 git diff --check。生产数据库回填耗时、Docker镜像构建及真实邮件投递需在部署环境另行验证。
