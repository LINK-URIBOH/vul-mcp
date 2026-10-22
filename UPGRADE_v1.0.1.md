# v1.0.1 升级与验收

本版本修复采集响应重复解压、微软 CVRF 文档超过 24 MiB、OSV 长时间保持索引连接的问题，增加有限重试、脱敏诊断日志和来源重试时间。业务数据库结构、MCP 工具和 OAuth 地址兼容 v1.0.0。

## 在旧版本目录备份

先在服务器**仍保留旧版 compose.yaml 和镜像**时执行以下命令。备份脚本会短暂停止 web、worker、Keycloak，完成后自动恢复。

```bash
cp compose.yaml compose.v1.0.0.rollback.yaml
docker image tag vul-intel:1.0.0 vul-intel:rollback-v1.0.0
bash scripts/backup.sh "/secure-backups/vul-before-v1.0.1-$(date +%Y%m%d-%H%M%S)"
```

另外保管现有 `.env` 和 `secrets/realm.json`。将 v1.0.1 文件覆盖到项目目录时保留这两个文件及已有数据卷，不重新运行初始化密钥脚本。若已提前覆盖 Compose，请先用保存的旧版配置完成备份；不能让备份脚本提前引用尚未构建的 v1.0.1 镜像。

## 构建并更新应用

```bash
docker compose build web
docker compose up -d --no-deps web worker
docker compose ps
docker compose logs --since 10m --timestamps web worker
```

web 和 worker 使用同一个 `vul-intel:1.0.1` 镜像。数据库和 Keycloak 使用已有服务及凭据。本次无需数据库迁移，不执行 `docker compose down -v`。

普通响应解压后上限为 24 MiB；微软 CVRF 文档与 OSV 索引上限为 64 MiB；OSV 编号清单上限为 16 MiB。临时文件在 `/data/.collector`，正常退出、异常和生成器取消时自动释放，不占用 32 MiB `/tmp`。需要为下载临时文件预留至少 80 MiB 可用卷空间。

## 只读来源验收

默认抽样近七天，每个来源取首条记录，单并发。`--source` 可以重复指定；`--full` 必须处理完整窗口；`--days` 为 1..100；`--workers` 为 1..4。小服务器保持单并发。

为避免在 2 GB 主机重复启动采集器，先停止 worker，再启动同镜像的临时检查进程。下面的退出处理会在检查成功或失败后恢复 worker：

```bash
(
  trap 'docker compose start worker' EXIT
  docker compose stop worker
  docker compose run --rm --no-deps -T worker python -m scripts.check_sources \
    --source nvd --source kev --source ghsa \
    --source apple --source android --source nodejs --source php \
    --source debian --source ubuntu --source msrc \
    --source osv-linux --source osv-android --source osv-debian --source osv-ubuntu \
    --source cisa-advisories --full --days 7 --workers 1 \
    > source-validation-v1.0.1.jsonl 2> source-validation-v1.0.1.stderr.log
)
```

检查不连接或写入业务数据库，也不发送邮件或 Webhook。标准输出为每源 JSON 行及 summary；标准错误包含每源开始、重试和约十五秒一次的处理进度。全窗口存在失败时返回 1；Ctrl+C 取消后释放临时文件，返回 130。`complete=false` 的抽样结果不能视为整源完成，`empty_window` 仅表示该窗口没有记录。

CISA 等官方源持续 403 时，验收该源的明确失败与退避状态，不将它记为成功或无新增，不自动接入镜像。完成只读检查后，恢复 worker 并在来源页逐个补采，确认真实数据库的成功时间推进和错误清除。

## 失败与日志含义

- 网络中断、超时、429、500、502、503、504：最多三次 GET 尝试，1 秒、2 秒退避加随机延迟。较短 Retry-After 按提示等待；超过 60 秒时延期当前来源，释放采集器继续处理其他来源。
- 403：本次不快速重试，至少一小时后自动重试；管理页仍可手工补采。
- 其他最终失败：十五分钟后重试。失败及重启不提前推进成功进度，已入库记录按来源编号幂等恢复。
- `collection_started`、`collection_progress`、`request_retry`、`collection_completed`、`collection_failed`：包含阶段、文档编号、HTTP 状态、尝试次数、已读字节、处理条数及耗时。记录处理期间约每十五秒输出进度。堆栈只含文件名、行号和函数名，不含异常原文、局部变量、请求头、查询参数或响应正文。
- 存活心跳每十五秒检查更新，下载和退避不会触发邮件/Webhook 投递；原有投递循环和分批投递行为保留。

来源页面显示下次采集/重试时间，报告继续标记启用来源中失败或过期的覆盖缺口，JSON coverage 保留停用状态。容器 healthy 只表示存活，仍需检查每源成功时间。

## 24 小时观察与回退

```bash
docker stats --no-stream
docker compose logs --since 24h --timestamps worker
```

验收：官方可达来源的完整窗口成功、成功时间持续前进；没有重复解压错误、非预期重启或 OOM；官方拒绝访问清楚可见；MCP、OAuth 登录、报告及投递通过回归。保留运行日志和来源检查结果。

若应用出现回归，在同目录使用升级前保存的 Compose 和旧镜像回退 web、worker：

```bash
docker compose -f compose.v1.0.0.rollback.yaml up -d --no-deps web worker
```

v1.0.1 未修改数据库结构，因此应用回退不需要恢复数据库。数据恢复仅在确有数据问题时单独执行，避免覆盖升级后正常产生的数据。
