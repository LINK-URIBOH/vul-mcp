# 1.3.0：按最早可核实公开时间标注和推送

本版新增编号迁移004、事件策略5和独立日期标注策略1。修复扫描全部历史漏洞及其原始修订，使用新检查点 `publication_date_repair_v1`；先前v1.2.0修复完成不会跳过此次扫描。历史事实原样保留，日期校正保存在独立标注及修订投影中。

## 部署及启动一次修复

在服务器项目目录同步代码后执行：

```bash
docker compose stop worker
docker compose build web
docker compose up -d --no-deps web
bash scripts/repair_publication_dates.sh
```

最后一行是本版服务器入口。脚本暂停worker，执行 `python -u -m vulintel.cli repair-publication-dates --rebuild-unpublished`，退出时恢复worker。数据库、认证及Web保持可用，任务页显示阶段、心跳、处理量、错误和完成统计。已有v1.2.0标识修复若尚未完成，应先恢复其原命令完成，避免两个维护检查点相互阻塞。

修复会清除首次启动时冻结的**未发布**批次的分析、候选暂存、投递任务及对应受控归档目录，然后以原批次编号、时间段和上限重新准备。这些尚未发布的分析需要重新执行。已 `finalized` 的报告、已发送结果、原始漏洞事实、来源、账号和渠道配置保留；旧报告不改写或重新发送。待报队列根据规范日期重核，失去依据的候选撤销并记审计。

不要改用旧 `repair_history.sh`：旧工具会清理全部报告，而且不能完成新版日期补证。

## screen、恢复和完成条件

```bash
screen -S vul-date-repair
bash scripts/repair_publication_dates.sh
```

按 `Ctrl+A` 再按 `D` 分离；`screen -r vul-date-repair` 返回。正常运行无需反复执行，也没有总步数上限。逐漏洞提交检查点，HTTP证据逐URL缓存；中断后重跑同一脚本恢复。并发运行会被互斥锁拒绝。进程失联显示中断，持久维护屏障继续暂停采集、报告写入和投递。

`complete=true`、`phase=complete`、退出码0表示全库已扫描并通过标注版本和历史投影一致性校验；**不等于所有漏洞日期都已核实**。核对 `after` 中 confirmed（已确认）、day（精确到日）、unknown（未知）、conflict（冲突）、missing_current_annotation（缺少新版标注），以及 corrected_dates、network_gaps。缺少新版标注必须为0；旧日期混入统计仅针对本次重建的未发布批次，已归档旧报告有意保留。

错误响应、未公开披露日期、无法对应到具体CVE的多漏洞公告或冲突均保留原因，进入待核实清单，不用采集时间补齐。后台补证任务会继续重试未知/冲突日期。成功完成后再次执行直接返回原结果，不重新清理后来创建的报告。

全库补证需要联网，固定访问官方CVE API及已引用、允许的原始公告。默认每次请求间隔1秒，成功缓存168小时；数万条历史记录可能需要数小时到数天，限流和网络故障会增加耗时。Web进度和缓存用于判断进展，不能用固定等待时长认定失败。

## 日期规则与配置

- `REPORT_MAX_ITEMS=50` 继续限制每批详解；超额持久待报，跨七天标为积压补报，归档成功才确认覆盖。
- `PUBLICATION_REQUEST_INTERVAL=1.0` 控制补证请求最小间隔，取值0.1..60秒；`PUBLICATION_CACHE_HOURS=168` 控制成功缓存时长，取值1..8760小时。
- `PUBLICATION_REFERENCE_HOSTS` 可覆盖原始厂商/研究者域名白名单，使用逗号分隔的精确主机名。只访问已有来源或CNA引用的HTTPS地址，不自动跟随跨主机重定向，不执行网页指令或代码。补证不会承诺覆盖所有公告格式。
- CNA `datePublic`、可对应到该漏洞的原始公告日期参与最早公开判定；CVE/NVD记录公开和全部OSV生态条目公开分别保留。显式披露日期互相矛盾或数据库更早已公开却缺少对应披露解释时，保守列为冲突。
- 仅到日的值保持精度及保守时区区间；跨窗口边界不确定时另列待核实。重要更新按实际补丁、重要公告更新或已利用收录时间推送，本库观察时间单列。

## 修复后检查

```bash
docker compose exec -T web python -m vulintel.cli status
```

然后使用现有九个MCP工具检查健康、日期覆盖及旧批次恢复。`preparing` 仍是后台准备，不是空报告；准备完成后核对 candidate_total、total、deferred_count、unverified_dates、date_policy=1、old_date_mixed_count=0 和 date_audit_required=false。全部入选条目应为事件策略5/日期策略1，且每条都有可追溯日期依据；未知或冲突不会计为已核实新增。

报告历史事实取截止时间内的原始修订，日期标注按准备时水位冻结。日期补证可以晚于截止时间，`date_assessed_at` 明确说明此事；补证所得影响版本和修复内容不会写进历史事实。前端以公开日期筛选，更新时间独立显示。日期区间与查询区间重叠的记录可在前端检索，报告要求日期区间完整落在窗口内，边界不确定会明确列入待核实。

本次不改变云端定时任务和真实渠道配置。仍须完成逐条证据读取、中文分析、finalize，以及 configured_channels 的投递确认；`rendering`、`finalized`、`sent` 含义不变。
