# v1.0.2：CISA 公告请求兼容修复

本补丁基于 v1.0.1，只对 `cisa-advisories` 的 RSS 请求设置 `User-Agent: curl/8.0`。仍使用 HTTPX，不调用 curl 命令；其他来源保留原默认请求头。OAuth、MCP、报告、投递及数据库结构不变，不需要数据库迁移或重新生成密钥。

依据：2026-10-23 用户在生产 worker 容器使用同一 HTTPX 客户端做了两轮对照。原标识、简化标识和 Mozilla 兼容标识均为 403；`curl/8.0` 两轮均为 200，完整读取 5,692,234 字节，XML 有效且包含 30 条公告。此证据仅代表测试时的出口和上游状态，不保证长期可用。

## 1. 更新前保留回退材料

在服务器仍使用 v1.0.1 文件时执行，保留既有 Compose 项目名称和目录：

```bash
cp compose.yaml compose.v1.0.1.rollback.yaml
docker image tag vul-intel:1.0.1 vul-intel:rollback-v1.0.1
```

按现有备份流程备份数据库、报告及配置；保管 `.env` 和 `secrets/realm.json`。覆盖代码时保留这些配置及数据卷，不重新运行 bootstrap，不执行 `docker compose down -v`。若已提前覆盖 Compose，先从升级前备份取得旧配置，不用新配置伪造回退文件。

## 2. 构建与更新

将 v1.0.2 发布包内容覆盖到服务器原项目目录后执行：

```bash
docker compose config --quiet
docker compose build web
docker compose up -d --no-deps web worker
docker compose ps
docker compose logs --since 10m --timestamps worker
```

web、worker 共用 `vul-intel:1.0.2` 镜像。数据库和 Keycloak 无需更新。本补丁不改变 `DELIVERY_ENABLED`，也不创建报告、投递任务或云端计划。

## 3. 来源只读检查

为避免 2 GB 主机同时运行两个采集器，短暂停止 worker，使用同镜像检查并在退出后恢复。检查不连接业务数据库、不入库、不投递：

```bash
(
  trap 'docker compose start worker' EXIT
  docker compose stop worker
  docker compose run --rm --no-deps -T worker python -m scripts.check_sources \
    --source cisa-advisories --full --days 7 --workers 1 \
    > cisa-validation-v1.0.2.jsonl 2> cisa-validation-v1.0.2.stderr.log
)
cat cisa-validation-v1.0.2.jsonl
```

预期：该来源 `complete=true`、`result=record`，summary 的 `failed=0`；非零退出码或 `result=failed` 不计为通过。若该时间窗口确无条目，检查可返回 `empty_window`，需结合上游公告时间核对，不以零条替代当前已知公告的采集验收。

`--full --days 7` 表示完整处理本次返回的订阅并按七天窗口过滤；该 RSS 此前仅返回 30 条，不承诺提供完整七天历史。不得把订阅窗口成功解释为全量 CISA 历史公告完整。

## 4. 实际采集验收

1. 登录管理网页，在采集源页仅对 CISA 基础设施公告执行补采。
2. 核对 worker 的 `collection_completed`、实际入库记录、来源成功时间推进及错误清除；HTTP 200 本身不等于入库成功。
3. 再次补采：相同公告更新或复用原记录，不重复生成 SourceRecord；多 CVE 公告不把不同 CVE 合并成同一个编号别名。
4. 在下一次自动采集后复查成功时间、错误和容器状态；若再次 403，继续按原规则退避，不自动轮换 User-Agent。
5. 通过 MCP `health_check` 核对 `service_version=1.0.2`，通过 `get_source_status` 核对来源状态。

此验收不触发报告或邮件/Webhook；双渠道端到端验收仍单独进行。

## 5. 回退

保留原 `vul-intel:1.0.1` 标签，若出现应用回归，在同一目录运行：

```bash
docker compose -f compose.v1.0.1.rollback.yaml up -d --no-deps web worker
```

回退仅恢复应用，不恢复数据库或报告卷；上游对原 User-Agent 的 403 可能随回退恢复。不要覆盖升级后正常产生的数据。
