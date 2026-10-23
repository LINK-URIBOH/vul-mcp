# 支持独立启用邮件或 Webhook

本次发布允许仅 SMTP、仅 HTTPS Webhook 或同时配置两者。没有新增 WebSocket 协议或第三方依赖，无数据库迁移。默认投递总开关仍关闭。

## 配置规则

- `DELIVERY_ENABLED=true` 时，至少完整配置一个渠道。某渠道部分填写时明确报错，防止漏填被误判为停用。
- SMTP 必填 `SMTP_HOST`、`SMTP_FROM`、`SMTP_TO`。`SMTP_USER` 和 `SMTP_PASSWORD` 同时填写；仅受信任的免认证中继可以同时留空。端口、TLS、单封大小按原配置。
- Webhook 必须同时填写 `WEBHOOK_URL`、`WEBHOOK_SECRET`，URL 仍要求 HTTPS。
- 不使用邮件时，将 SMTP_HOST、SMTP_FROM、SMTP_TO、SMTP_USER、SMTP_PASSWORD 全部留空；端口/TLS/大小保留默认值即可。不使用 Webhook 时，其 URL 和密钥同时留空。
- 总开关关闭时允许暂存未完成配置。完整配置的渠道仍可排队，但不发送；两者都未配置时，报告仅归档。

仅使用 126 邮箱 SSL 的示例（替换账号、授权码和收件地址）：

```dotenv
DELIVERY_ENABLED=true
SMTP_HOST=smtp.126.com
SMTP_PORT=465
SMTP_TLS=ssl
SMTP_USER=your-account@126.com
SMTP_PASSWORD='your-client-authorization-code'
SMTP_FROM=your-account@126.com
SMTP_TO=recipient@example.com
SMTP_MAX_BYTES=8000000
WEBHOOK_URL=
WEBHOOK_SECRET=
```

仅使用 Webhook 的示例（替换为固定接收服务及其约定密钥）：

```dotenv
DELIVERY_ENABLED=true
SMTP_HOST=
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=
SMTP_TO=
WEBHOOK_URL=https://receiver.example.com/vulnerability-reports
WEBHOOK_SECRET='replace-with-your-shared-secret'
WEBHOOK_BATCH_SIZE=50
```

## 报告与历史队列

报告完成时，仅为当时完整配置的渠道准备正文、附件或 Webhook 消息，不为未使用渠道生成任务。单独使用 Webhook 时不执行邮件分卷，不受邮件正文分卷预算约束。已完成报告保持幂等，后续新增渠道不会自动补发这些报告。

停用渠道的历史 `pending`、`failed` 或 `sending` 任务均保留；worker 不选择该渠道、不增加次数、不阻塞其他已配置渠道，也不将其标为已发送。重新完整配置后，待处理任务恢复；过期发送租约按原规则恢复，失败任务仍需人工重试。已发送任务不重复投递。

管理网页投递页显示已配置渠道及暂停说明。MCP `get_delivery_status` 保留原 `deliveries`，新增 `configured_channels`（email/webhook 列表）及 `delivery_enabled`（总开关）；工具数量及权限不变。云端任务以实际配置渠道核对送达，无任务不等于成功送达。

## 更新与验证

先保存旧镜像、Compose、`.env`，保护备份目录权限，再更新代码。沿用同一 Compose 项目、目录、密钥及数据卷，不重新初始化认证、不删除数据卷。

```bash
# 更新代码前，在原部署目录保存配置及镜像
umask 077
backup_dir=$(mktemp -d /root/vul-mcp-before-optional-channels-XXXXXXXX)
cp -a .env compose.yaml "$backup_dir/"
docker image tag vul-intel:1.0.2 vul-intel:rollback-before-optional-channels
echo "备份目录：$backup_dir"
```

更新代码并按所需渠道修改原 `.env` 后：

```bash
docker compose config --quiet
docker compose build web
docker compose up -d --no-deps --force-recreate web worker
docker compose ps
docker compose logs --since 10m --timestamps web worker
```

web、worker 共用 `vul-intel:1.0.3`；不用更新数据库和 Keycloak。仅改 `.env` 时也需要重新创建应用容器，普通 restart 不会重新载入 Compose 环境变量。

开启总开关前核对固定目标和历史队列，开启后已有已配置渠道的待处理任务可能立即发送。在测试目标完成一份报告，检查仅配置渠道生成任务、实际送达；单个渠道故障不影响另一渠道的配置和重试。生产凭据及邮件/Webhook 送达仍需你在服务器验收，本次交付不主动修改线上服务或发出通知。

## 回退

旧版要求开启推送时两渠道均配置。回退前先恢复备份的 `.env` 与 Compose，并确认旧配置满足该要求；若备份也只有单渠道，则先关闭 `DELIVERY_ENABLED` 再启动旧版，避免启动失败或错误投递。保留数据卷，无需数据库恢复。不要把当前单渠道配置直接用于旧版的开启状态。
