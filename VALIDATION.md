# 验证记录

验证日期：2026-10-22（北京时间）。

## 已完成

| 检查 | 结果 |
| --- | --- |
| Python / 官方 MCP SDK | Python 3.12；mcp 2.3.0，完整依赖已锁定 |
| 自动测试 | **29 passed**，包括真实回环 HTTP 与官方 SDK 客户端 |
| 协议兼容 | 2025-03-26、2025-06-18、2025-11-25 初始化与 initialized 通知 |
| 工具发现 | 仅 health_check，正确声明只读、非破坏、幂等、无外部访问 |
| 正常调用 | 可省略标记、传 null、回传标记；UTC 时间和结构化输出正确 |
| 错误处理 | 拒绝错误类型、空串、换行、过长标记和未知工具 |
| 边界校验 | Host、Origin、16 KiB 请求体上限和 HTTPS 源配置 |
| 业务日志 | 成功结果含原标记、UTC 时间，HTTP 完成日志可核对 |
| Compose | docker compose config --quiet 通过 |
| Linux 镜像 | docker compose build 成功；pip 使用 --require-hashes 校验完整依赖 |
| 容器启动 | Compose 健康检查为 healthy |
| 实际容器调用 | 宿主机经 127.0.0.1:18877 调用、容器内部调用均 passed |
| 容器权限 | user=10001:10001，read_only=true |
| 清理 | 本次临时验证容器和网络已移除 |

本机 Docker 使用 Linux 引擎；未在你的 Debian 服务器上远程执行。
本机测试最初受 Windows 沙箱回环限制影响，已在获准的运行环境完成上述测试。

容器成功返回记录：

```json
{"service_name":"vul-mcp-check","service_version":"0.1.0","server_time_utc":"2026-10-22T03:57:02.521Z","marker":"container-regression-01"}
```

## 待部署后完成

- 你的服务器及 Nginx 配置、正式域名可达性和证书链。
- 在账号中添加自定义 MCP 并手动调用。
- 创建一次性云端任务，核对实际工具执行记录。
- 关闭个人电脑后，核对云端结果与服务器日志中的唯一标记。
- 确认无需人工批准后完成无人值守只读验收。

本交付没有创建自动化任务，也未安装账号插件或修改账号权限。
邮件、Webhook、OAuth 及无人值守写入不在本轮实现范围。
