# v1.4.1 热修复验证

日期：2026-10-25，Asia/Shanghai。

## 原因复现

对GitHub官方公共API执行三个不带令牌、每次仅一条结果的只读请求：

- 带微秒范围 `2026-10-18T05:10:03.138383Z..2026-10-25T05:10:03.138383Z`：HTTP422，响应明确为日期输入无效。
- 秒级范围 `2026-10-18T05:10:03Z..2026-10-25T05:10:03Z`：HTTP200。
- 仅日期范围 `2026-10-18..2026-10-25`：HTTP200。

只读检查CISA官方 `https://www.cisa.gov/cybersecurity-advisories/all.xml`：HTTP200，响应5,696,987字节，30条记录；其中Siemens SIMATIC S7 PLCs Web Server条目提取出的摘要正文为2,396,298字节。未执行公告代码，未将全文写入仓库，未修改生产数据。

## 本地验证

- 完整回归：**203 passed，41.00秒**，临时目录 `outputs/test-v141-full`。
- Ruff检查 `vulintel tests scripts`、`git diff --check`通过。
- Compose配置 `docker compose config --no-interpolate --no-env-resolution --quiet`通过。
- SHA256清单按Git规范LF文本计算，纳入热修复实现和文档。

专项覆盖首次published和后续modified的微秒转换、向外取整且保留内部精确窗口、保留before/after分页游标、正常2.4MB条目完整保存并继续扫描、超过8MiB原文完整隔离及下一条继续、隔离文件损坏检测、磁盘失败不推进游标、管理员下载认证及附件安全响应。

测试固定时钟下显式设置初始化来源next_run/updated_at，避免依赖实际执行时刻的数据库默认值。原有日期核实、初始化恢复、50条上限、积压、九工具认证、报告归档和模拟渠道确认回归通过。

## 边界

业务测试使用SQLite及模拟HTTP/投递，未发送真实邮件或Webhook。仅以上GitHub和CISA请求访问公开网络；未连接生产数据库、未重启生产服务、未重新清库、未修改现有初始化run_id或游标。

尚未构建镜像或启动PostgreSQL验证；部署后需确认服务版本1.4.1、原run_id不变、两个来源从原游标恢复。部署方式见 [升级说明](UPGRADE_v1.4.1.md)。
