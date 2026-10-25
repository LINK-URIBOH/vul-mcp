# 漏洞情报正式版

当前版本 **v1.4.0**：支持显式清空漏洞和报告后，按固定近七天窗口分阶段初始化。候选先核实日期再进入正式库，OSV等来源按已发现精确编号补充，联网补证不阻塞报告；后续继续获取新公开漏洞和旧漏洞重要更新。保留账号、渠道配置和日期证据缓存，每批默认最多50条，超额持久待报。部署、重置边界与 `screen` 用法见 [v1.4.0 升级说明](UPGRADE_v1.4.0.md)，接口见 [报告接口说明](REPORT_API.md)。

独立于 `vul-mcp-check` 交付。本目录不包含生产密码、令牌、收件地址或 Webhook 目标。
Codex 云端执行分析；Debian 服务采集、去重、归档与投递。不需要额外模型 API，也不要求个人电脑开机。

## 组件与内存

| 服务 | 职责 | 容器内存上限 |
| --- | --- | --- |
| web | OAuth MCP、中文管理网页、报告任务入队 | 256 MB |
| worker | 串行采集、数据库任务队列、投递重试 | 384 MB |
| PostgreSQL | 独立业务及 Keycloak 数据库、独立账号 | 256 MB |
| Keycloak | OAuth/OIDC、PKCE、令牌刷新 | 768 MB，Java 堆384 MB |

上限合计1664 MB，需额外预留宿主机和已有 Nginx 的资源；不能把此数字当作整机占用保证。约2 GB环境应先执行 `RESOURCE_TEST.md`，若出现 OOM，优先把认证或数据库迁移到另一台服务器。没有 Redis，也没有独立前端运行服务。

## 1. 首次配置

默认使用新目录、新 Compose 项目和新端口；先不要替换现有验证版。

```bash
cd /opt/vul-intel
cp .env.example .env
chmod 600 .env
```

编辑 `.env`：

- `PUBLIC_BASE_URL=https://vul.valna.cn`，`ISSUER_URL=https://vul.valna.cn/auth/realms/vul`。
- `MCP_REDIRECT_URI`：填写自定义 MCP 高级 OAuth 界面实际显示的**准确 HTTPS 回调**，不要使用通配符。
- 默认应用回环端口8001、认证回环端口8081；若冲突，修改 `HOST_PORT`、`AUTH_PORT` 和 Nginx 上游。
- 按需完整填写 SMTP 或 Webhook，或同时配置两者；先保持 `DELIVERY_ENABLED=false`。凭据含 `$` 等字符时使用 dotenv 单引号，避免 Compose 插值。

然后用系统 Python 3 生成随机密码和 realm 文件，无需安装项目依赖：

```bash
python3 scripts/bootstrap.py
docker compose config --quiet
docker compose build web keycloak
docker compose up -d --wait
docker compose ps
curl --fail http://127.0.0.1:8001/healthz
```

第一次 Keycloak 初始化可能需要几分钟。脚本不会打印密码；在服务器本地安全读取 `.env` 中的 `ADMIN_USERNAME`、`ADMIN_PASSWORD`，不要将文件发到聊天。
以 root 运行初始化时会把 realm 文件交给 Keycloak 的 UID1000；非 root 部署需执行 `sudo chown 1000:0 secrets/realm.json` 并保持文件600权限。

`bootstrap.py` 拒绝覆盖已有 realm 文件。Keycloak 已有数据库时不会重新导入 realm，因此修改导入 JSON 不是更新线上配置的方式。后续通过受控 Keycloak 管理入口或管理 CLI 修改。
默认 Keycloak 管理员 `bootstrap-admin` 是初始化账号，请按 Keycloak 的流程建立持久管理账号并移除临时账号；业务网页登录使用单独的 `ADMIN_USERNAME`，两者职责不同。

业务数据库编号迁移在启动时执行并记录到 `schema_migrations`；当前为005（独立候选暂存和分阶段来源水位）。普通升级不清库。选择从零开始时，先停止旧修复脚本，再运行 `bash scripts/reset_recent.sh`，显式清空全部漏洞和报告，保留账号、配置及日期证据缓存。中断后同命令恢复；完成后重跑不会再次清库，另一次清库必须传 `--new-run`。旧历史修复入口不用于本版近七天初始化。不要手工调用 `create_all` 代替迁移。

## 2. Nginx 和 Cloudflare

将 `deploy/nginx.example.conf` 的片段合并到现有配置，由你维护证书。不要整份覆盖现有 Nginx 配置。

- `/mcp`、`/admin/`、`/static/` 和 `/.well-known/` 指向8001。
- `/auth/realms/`、`/auth/resources/` 指向8081；认证代理覆盖设置 `X-Forwarded-Proto=https`、Host及端口。
- Keycloak 管理控制台和健康接口默认不暴露公网。管理操作通过 SSH 端口转发访问回环服务，或使用容器内 `kcadm.sh`。
- Keycloak管理健康端口9000不发布；服务及数据库不直接发布到公网。
- 保留 MCP 请求头及 POST/GET/DELETE，关闭 MCP 缓冲、缓存，保持120秒代理读写超时，允许最大1 MiB请求。
- Cloudflare 对 MCP、认证及发现路径不得返回浏览器挑战页或缓存登录响应。只调整相关 API 路径，不停用整站保护。

正式上线需要同时切换上述路径，原无认证 `/mcp` 将变为受保护端点。保留原验证版目录作为回归依据，不并行在同一 URL 暴露两套 MCP。

验证：

```bash
curl -i https://vul.valna.cn/.well-known/oauth-protected-resource/mcp
curl -i -X POST https://vul.valna.cn/mcp -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

发现文档应返回200；未认证 MCP 应返回401和 `WWW-Authenticate`，这是正确行为。
管理网页为 `https://vul.valna.cn/admin/`，登录会话有效30分钟，Cookie为 Secure、HttpOnly、SameSite=Lax。退出管理页只结束该网页会话；Keycloak SSO及已授权连接需在认证服务中单独撤销。

## 3. 云端连接及自动投递验收

按 `CLOUD_TASK.md` 配置预注册的公共 OAuth 客户端 `vul-mcp`（`none`客户端认证、PKCE S256），明确请求读取、提交和投递权限及离线刷新。
管理网页使用独立的保密客户端 `vul-web`。服务验证签名、受众、签发者、有效期、管理员角色及工具权限。

先验证人工调用、权限不足拒绝、5分钟后的令牌刷新，再用固定的测试收件目标验证云端定时写入。
只有确认平台无需人工批准写操作、所有已配置渠道的测试目标正确后，才修改服务器：

```dotenv
DELIVERY_ENABLED=true
```

```bash
docker compose up -d --force-recreate web worker
```

开关关闭时，报告仍能归档并排队，工作进程不发送。启用开关会处理已有待发队列，请先在网页核对历史测试报告和固定目标。
不要因平台要求批准而把写操作标记成只读。当前交付不替你创建云端任务，不修改线上连接或 Cloudflare 规则。

## 4. 采集与报告行为

预置29个来源，见 `SOURCES.md`。采集按各源进度重叠回查48小时；采集窗口不等于报告公开窗口。每期以最近到期的北京时间09:00/18:00为截止，选择此前7×24小时内公开且未报告的记录，以及近期已利用证据、影响或修复的重要变化。普通抓取时间变化和重复来源收录不算新披露。
截止后才采集到的数据在后续报告中按相同规则判断。公开时间、上游更新时间、首次采集时间、实际变更时间及依据分别保留；KEV收录不冒充披露日期。日期未知另列待核实索引，窗口外历史数据保留检索。批次冻结修订水位和覆盖快照，采集更新不改写已选事实。

- 来源独立推进进度。部分记录成功、后续分页失败时，保留已写数据和失败状态，但不推进来源成功时间。
- CVE/GHSA/OSV别名合并；一篇公告提到多个 CVE 时，不把这些 CVE 错当作同一个漏洞的别名。
- 来源原文及版本条件完整保留，厂商回补补丁由云端分析按公告解释，不用上游版本号猜测发行版状态。
- 全部入选条目必须逐条中文详解，包括低危和未评分。按产品分组，组内优先展示已利用和高风险；未评分不等于低危。
- `REPORT_MAX_ITEMS=50` 限制每批详细分析量（配置取值1..10000，创建批次时冻结）。完整扫描候选后优先已利用、严重性高及等待时间长的记录，超额持久待报。过期候选以积压补报标注，原始日期和首次待报时间保留；日期待核实清单不占额度。归档后才确认覆盖，未完成分析和仅生成部分文件不算已报。
- 未完成批次优先恢复；准备中计数尚不确定，不是空报告。使用分页摘要及只读证据续页读取完整事实；配额不足时保留进度。
- open_report_batch快速创建任务；finalize_report幂等排队渲染。后台按检查点生成文件和分卷，全部成功后才统一finalized并激活投递；staged/rendering不是送达。
- HTML、Markdown、JSON、完整CSV及日期待核实CSV按报告UUID保存。网页和邮件共用结构化内容，旧自由文本摘要只供管理诊断。邮件在条目边界分卷，Webhook按条数及字节预算分批。
- 计数、窗口、覆盖状态由服务器生成。空批次显示“本批次未取得符合条件的记录”，说明窗口和缺口，不据此宣称公开漏洞没有新增。

云端分析包含中文漏洞说明、根因、触发前提、影响版本、攻击路径、修复方式、证据等级与引用；未知信息明确未公开或未确认。正式风险概述仅接受风险要点与修复优先级。服务校验结构和必填项，无法自动保证模型分析的真实性，重要处置仍需核对原始公告。
不执行利用代码，不扫描目标，不使用网页来源内容作为指令。

## 5. 邮件与 Webhook 投递

`DELIVERY_ENABLED` 是总开关。开启时至少配置一个完整渠道；SMTP 的 `SMTP_HOST`、`SMTP_FROM`、`SMTP_TO` 必填，`SMTP_USER` 和 `SMTP_PASSWORD` 同时填写（受信任免认证中继可同时留空）。Webhook 的 `WEBHOOK_URL`、`WEBHOOK_SECRET` 必须同时填写。某渠道未使用时清空其目标及凭据；SMTP 端口、TLS 模式、大小上限和 Webhook 分批条数可保留默认值。开启时仅填部分字段会明确报错，不静默忽略。

报告只为生成时完整配置的渠道创建队列，总开关关闭时仍可归档和排队；两渠道均未配置且总开关关闭时仅归档。重新配置渠道不为已完成报告自动补建任务。未配置渠道的历史队列保留并暂停，不增加尝试次数、不阻塞其他渠道；重新完整配置后，原待处理任务会恢复。已失败任务仍需人工重试，成功任务不会重发。管理页显示已配置渠道，MCP `get_delivery_status` 同时返回 `configured_channels` 和 `delivery_enabled`。

SMTP只允许STARTTLS或SSL，凭据不进入网页、MCP或报告。邮件正文和附件分卷，默认每封最大8 MB；单条极大公告超过单封分卷预算时会阻止完成并保留失败原因，调整 `SMTP_MAX_BYTES` 后恢复批次，不丢弃条目。

Webhook必须使用HTTPS，不跟随重定向。目标和签名密钥只能在服务器配置。消息头：

```text
X-Vul-Message-Id: <稳定的投递UUID>
X-Vul-Timestamp: <Unix秒>
X-Vul-Signature: sha256=<HMAC-SHA256>
```

签名输入是 `timestamp + "." + 原始请求体字节`。接收端先校验签名、时间窗口（建议5分钟）并按消息ID去重，再返回2xx确认。
新报告使用 `schema_version=2.0`，包含 `message_id`、`report_id`、`slot`、`part`、`parts`、结构化概述、覆盖快照和条目；完整字段与证据续页方式见 `REPORT_API.md`。旧队列保留原格式。
同一消息重试时ID和请求体不变，时间戳与签名重新生成。网络超时可能发生“已收到但确认丢失”，无法保证绝不重复；邮件使用稳定 Message-ID，Webhook仍必须接收端去重。

每个渠道及每个分卷独立保存状态。默认失败退避1、2、4、8分钟，最多5次；超过次数转为失败，网页/CLI可重试。成功渠道不会重发。进程崩溃的发送租约10分钟后恢复。
任务状态 `pending` 表示排队，不等于已送达；只有 `sent` 表示服务端收到成功确认。邮件 SMTP 接受不代表最终进入收件箱。

## 6. 管理和排障

网页提供工作台、漏洞索引与详情、报告归档、来源启停与补采、任务重试、投递记录。密钥及目标不在网页编辑。所有写操作需要登录与 CSRF，操作留有审计记录。

```bash
docker compose logs --since 30m web worker
docker compose exec -T web python -m vulintel.cli status
docker compose exec -T web python -m vulintel.cli collect nvd
docker compose exec -T web python -m vulintel.cli retry delivery <失败投递ID>
docker stats --no-stream
```

业务日志不输出JWT、SMTP密码或Webhook密钥。MCP和后台报告错误返回中文说明及追踪编号，日志记录阶段、耗时和脱敏堆栈；请求未到达服务端时需核对代理与云端限制。来源状态分别展示最近尝试、实际完成、正在执行任务及进度。数据源403/404展示失败，不被视为无漏洞。
查看404、502、401和403时分别检查路径/上游、容器状态、OAuth登录/令牌、角色和权限；同时核对Cloudflare安全事件。

## 7. 备份、恢复与升级

v1.0.1 的构建、备份、完整来源验收及回退步骤见 [UPGRADE_v1.0.1.md](UPGRADE_v1.0.1.md)。该版本修复采集响应重复解压、微软大文档读取和 OSV 索引连接问题；新增依赖 `ijson` 已按精确版本和 hash 锁定。

```bash
bash scripts/backup.sh /secure-backups/vul-YYYYMMDD
# 恢复会替换数据库，明确确认后执行：
bash scripts/restore.sh /secure-backups/vul-YYYYMMDD --confirm-replace
```

备份脚本暂时停止web、worker和Keycloak，导出两库和报告后恢复服务。数据库dump与报告包含私有分析/审计信息，按敏感备份保管；`.env`和realm导入文件另行加密备份。恢复前先备份当前状态，核对使用相同凭据和数据库版本，恢复后再验证OAuth与投递。
不要对生产执行 `docker compose down -v`，这会删除数据卷。

更新代码前备份、查看迁移说明，再构建并重启。依赖锁定在 `uv.lock` 与带hash的 `requirements.lock`；镜像引用及实测版本见 `VALIDATION.md`。

## 8. 开发与测试

```bash
uv sync --frozen
uv run --frozen pytest -q
uv run --frozen ruff check vulintel scripts tests
uv run --frozen python -m scripts.check_sources
```

上游抽样只验证当前网络中的一条记录或空窗口，不证明全量完整性。真实收件箱、你的Webhook、OpenAI账号OAuth续期与无人值守写入、线上Nginx和2 GB物理服务器长期运行，均需部署后验收，见 `VALIDATION.md` 和 `RESOURCE_TEST.md`。

参考：[OpenAI MCP认证](https://developers.openai.com/plugins/build/auth)、[Keycloak生产数据库](https://www.keycloak.org/server/db)、[OSV增量数据](https://google.github.io/osv.dev/data/)。
