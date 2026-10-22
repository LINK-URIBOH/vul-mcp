# MCP 云端接入验证版

只验证 Codex 云端是否能调用服务器，公开地址为 **https://vul.valna.cn/mcp**。
无身份验证，无数据库，无漏洞采集、报告存储、邮件或 Webhook。整个业务工具列表只有 `health_check`。

## 1. Debian / Docker 部署

将本目录上传到服务器，例如 `/opt/vul-mcp-check`。已有宿主机 Nginx 负责 HTTPS。

```bash
cd /opt/vul-mcp-check
cp .env.example .env
docker compose config --quiet
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8000/healthz
docker compose exec -T mcp python scripts/probe.py --marker debian-local-01
```

最后一个命令会发现工具、读取实时结果、核对标记和时间，并测试错误参数；成功输出 `"probe": "passed"`，失败退出码非零。服务器需校准时间，与检查机器相差超过 120 秒会失败。

默认仅发布 `127.0.0.1:8000`，不将应用端口暴露到公网。端口冲突时在 `.env` 调整 `HOST_PORT`，并同步改 Nginx 上游端口；容器内部仍用 8000。
默认域名已设置，不需要编辑代码。`PUBLIC_BASE_URL` 是 HTTPS **源地址**，不要包含 `/mcp`、查询参数或凭据。

应用容器以非 root 用户运行、根文件系统只读。标准错误输出包含 JSON 业务日志，Docker 保留最多 3 个 10 MB 日志文件；没有额外挂载业务数据卷。

## 2. Nginx 反代要求（由你配置）

参考 `nginx.example.conf`，它是需要合并的片段，不能原样覆盖已有证书配置。

- `limit_req_zone` 放在 `http {}`，`location = /mcp` 放在现有域名的 HTTPS `server {}`。
- `proxy_pass http://127.0.0.1:8000;` 不加尾部 `/`，保留路径 `/mcp`。
- 上游 Host 保持 `vul.valna.cn`。SDK 校验 Host 和存在的 Origin；不要改为 Docker 服务名，也不要删除 Origin 来绕过校验。
- 使用 HTTP/1.1，禁用代理缓冲和缓存；读写超时 60 秒，连接超时 5 秒。
- 完整转发 GET、POST、DELETE 及 MCP 请求头。此版本主要使用 POST + JSON 响应；GET 返回 405 在无状态模式下可能是正常行为，不能仅凭浏览器打开 URL 判断成功。
- 不添加 Basic Auth、浏览器验证码、跳转登录或 HTML 错误拦截；本轮 MCP 为“无需身份验证”。
- 示例按来源 IP 限流 5 请求/秒、突发 30，拒绝返回 429。云端可能共享出口 IP，遇到限流时根据日志调整阈值。
- `/healthz` 仅供本机和容器存活检查，不需要公网代理。

Nginx 生效后，从独立网络验证：

```bash
curl -i https://vul.valna.cn/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-06-18' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl-check","version":"1.0"}}}'
```

预期 HTTP 200，JSON 中包含 `result.serverInfo.name: "vul-mcp-check"`。
HTTP 421 检查 Host；403 检查 Origin；404 检查路径改写；502 检查容器端口；429 检查限流；证书错误应修复证书链。

还可从容器经公网域名执行完整检查：

```bash
docker compose exec -T mcp python scripts/probe.py \
  --url https://vul.valna.cn/mcp --marker public-probe-01
```

此项能验证域名和代理，但服务器自己访问成功仍不等于 OpenAI 云端已能访问。

## 3. 添加到 Codex 云端

在“插件 → 添加 → 添加自定义 MCP 服务器”填写：

| 字段 | 值 |
| --- | --- |
| 名称 | 漏洞情报接入测试 |
| 描述 | 只读连接测试：返回服务名称、UTC 时间及验证标记 |
| 连接 | 服务器 URL |
| URL | `https://vul.valna.cn/mcp` |
| 身份验证 | 无需身份验证 |

添加后在**云端聊天**选中该工具，手动发送以下指令：

> 调用“漏洞情报接入测试”的 health_check，marker 为 manual-20261022-01。必须实际调用工具，原样返回结构化结果。调用失败就报告失败，不要猜测服务器时间。

同时在服务器执行：

```bash
docker compose logs --since 10m mcp
```

日志中的 `event=health_check`、`outcome=ok`、标记和 UTC 时间应与云端结果匹配。标记只放公开测试字符串，不放个人信息或密钥。

## 4. 云端定时及关机验证

手动调用成功后，在同一个云端聊天创建**一次性**任务，安排到足够晚的未来时间（例如 10 分钟后），确认运行位置为**云端**、时区为 **Asia/Shanghai 或 Etc/GMT-8**。
此项目不会自行创建本地自动化；当前桌面端任务工具不能替代账号内的云端运行位置确认。

指令模板（把日期、时间和唯一标记换成实际值）：

> 请在北京时间 YYYY-MM-DD HH:mm 执行一次，不重复。使用“漏洞情报接入测试”调用 health_check，marker 固定为 cloud-YYYYMMDD-HHmm-01。必须实际调用工具，返回 service_name、service_version、server_time_utc、marker；调用失败请明确报告错误，不得使用示例结果或自行生成服务器时间。

随后关闭个人电脑，服务器保持在线。在计划时间后通过手机或其他设备核对：

1. 云端任务完成，未停在审批或等待输入状态。
2. 返回标记与本次任务完全相同。
3. 服务器日志存在相同标记和对应 UTC 时间（北京时间减 8 小时）。
4. HTTP 日志成功不够，必须有对应的 `health_check` 成功日志。

无身份验证时，任何人都能调用这个公开探针，日志本身不能证明调用方身份；需同时对照云端工具执行记录和本次唯一标记。
若任务要求批准，说明无人值守调用尚未通过，不能通过将写操作伪装成只读来规避。
验证后检查一次性任务已完成；如果界面实际建立了重复计划，暂停或删除该测试计划。

## 5. 工具契约与日志

`health_check(marker?: string | null)`：省略或 null 均可；非空标记只接受 1–128 位 ASCII 字母、数字、`.`、`_`、`:`、`-`，原样回传。
数字、布尔值、空字符串、换行和过长字符串返回 MCP 错误。
工具注解为只读、非破坏、幂等、无外部访问。每次返回时间不同，幂等指不会改变业务状态。

结果示例（时间仅为格式示意）：

```json
{
  "service_name": "vul-mcp-check",
  "service_version": "0.1.0",
  "server_time_utc": "2026-10-22T01:00:00.000Z",
  "marker": "cloud-20261022-0900-01"
}
```

成功日志示意：

```json
{"timestamp_utc":"2026-10-22T01:00:00.000Z","event":"health_check","outcome":"ok","result":{"service_name":"vul-mcp-check","service_version":"0.1.0","server_time_utc":"2026-10-22T01:00:00.000Z","marker":"cloud-20261022-0900-01"}}
```

另有 `http_request` 完成日志，记录请求时间、方法、状态和耗时，不记录请求头、IP 或整个请求体。非法参数可能在 SDK 中被拒绝，没有 `health_check` 成功日志是预期行为。
不要依赖日志永久保存；Docker 轮转会清除旧记录。

## 6. 开发、锁定与测试

需要 Python 3.12 和 uv。运行依赖完整版本及散列在 `requirements.lock`，开发环境及跨平台依赖在 `uv.lock`。

```bash
uv sync --frozen
uv run --frozen pytest -q
uv run --frozen python server.py
```

另开终端：

```bash
uv run --frozen python scripts/probe.py --marker local-sdk-01
```

开发启动会监听 0.0.0.0:8000；仅在可信本机环境使用。生产通过 Compose 将宿主机端口限制在 loopback。
测试包括旧协议初始化、工具列表与只读注解、标记回传、UTC 时间、日志、非法参数、Host/Origin、请求体限制和配置校验。SDK 客户端检查脚本同时验证当前 SDK 的自动协议协商。

依赖升级时重新锁定并运行测试，再导出生产锁文件：

```bash
uv lock --upgrade
uv sync --frozen
uv run --frozen pytest -q
uv export --frozen --no-dev --no-emit-project --format requirements-txt --output-file requirements.lock
```

官方 SDK 参考：[运行服务](https://py.sdk.modelcontextprotocol.io/run/)、[工具定义](https://py.sdk.modelcontextprotocol.io/servers/tools/)。

## 7. 完成边界

本地协议测试通过不等于已在你的服务器部署，也不等于已完成云端定时关机验证。实际验收结果见 `VALIDATION.md`。
本轮通过后再设计 OAuth、令牌续期和无人值守写入；只有这些也验证通过，才加入漏洞采集、存储、邮件和 Webhook。
