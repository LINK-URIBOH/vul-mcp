# 1.5.0升级与运行

不重新清库，不改账号、渠道或云端时间，不调用模型API。升级前备份数据库与reports卷。006迁移新增发布、认领及覆盖凭据表；已发布归档保持，旧未发布prepare/analyze/failed草稿记为superseded，原分析保留审计，释放原slot。已经rendering的旧批次按原策略完成。

```bash
docker compose stop worker publisher
docker compose build web
docker compose run --rm --no-deps -T web python -m vulintel.cli init
docker compose up -d --no-deps web worker publisher
docker compose ps
docker compose logs --tail=100 publisher
docker compose exec -T web python -m vulintel.cli report-status
docker compose exec -T web python -m vulintel.cli report-volume --days 7 --severity critical
```

Compose统一设置PUBLISHER_ENABLED=true，独立publisher承担渲染与投递，worker继续采集和日期核实。裸进程须统一设置该开关并运行`python -m vulintel.publisher`。publisher只推进已触发任务，不按日历创建报告；维修脚本现在同时停止worker/publisher并取得两个运行锁。

刷新MCP九工具，确认1.5.0，把[CLOUD_TASK_v1.5.0.md](CLOUD_TASK_v1.5.0.md)全文替换到**已有**09:00、18:00任务，不新建任务。open_report_batch声明投递副作用；ensure_facts/progressive须具备vul.submit和vul.deliver，平台要求人工批准则无人值守验收不通过。

## 状态与恢复

- 事实版覆盖当前已核实的全部合格critical记录，中文字段及原文摘要，完整事实在JSON归档。目标为slot后30分钟内归档进入投递，迟触发或故障显示late。未核实日期／评级独立展示，不以采集时间补齐。
- 详解每批最多min(REPORT_MAX_ITEMS,50)，超额持久积压。事实覆盖与详解覆盖独立，只有相应归档成功才确认；新修订不会被旧确认消费。
- 每10条已保存详解补发，主动finalize_report(mode="supplement")可立即释放尾数，未主动调用则最后保存15分钟后释放。完整汇总仅归档，不重复推送。
- finalized不等于sent；投递开关关闭仍归档、排队。未配置渠道不算送达。SMTP接受不证明入箱，异常重试可能重复，接收端应按稳定消息ID去重。

```bash
docker compose exec -T web python -m vulintel.cli report-status
docker compose exec -T web python -m vulintel.cli report-volume --days 7 --severity critical
docker compose exec -T web python -m vulintel.cli status
docker compose logs --tail=100 publisher worker
docker compose exec -T web python -m vulintel.cli retry job <失败report任务ID>
docker compose exec -T web python -m vulintel.cli retry delivery <失败投递ID>
```

report-volume只读正式库规范日期，统一标识去重，列出新增、重要更新、积压、未知评级、日期缺口及来源覆盖，并分北京时间09/18时段。complete=false不能称全渠道准确日均；初始化未入库时0不等于公开漏洞没有新增。命令不采集、不创建报告、不发送。

临时渲染错误保留检查点并自动退避重试，最多8次；配置错误、文件损坏或持续失败明确阻塞。修复原因后再retry，不删除暂存文件。进程死亡由租约恢复；重复触发同slot复用报告。

查看进度可使用`screen -S vul-report-check`运行上述logs/status命令，Ctrl-A D离开，`screen -r vul-report-check`恢复。常驻任务由Compose和持久队列承担，screen不用于替代云端计划。

## 部署后无人值守验证

先完成[模拟验收](VALIDATION_v1.5.0.md)。真实渠道测试使用专用目标，不向生产收件人发测试。进行一次云端触发，记录事实报告和详解批次编号，确认无需人工批准；即使聊天结束也能完成事实版。验证令牌过期仍可刷新、本机关闭后任务运行，逐渠道核对分卷成功确认。

本地测试无法证明真实云端调度、OAuth刷新或邮件入箱。完成这些实测前不宣称生产无人值守发送已通过。
