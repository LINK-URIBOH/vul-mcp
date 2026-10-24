# 采集来源和覆盖说明

来源地址固定在代码注册表，网页只能启停；不接受模型指定的任意URL。每个来源有独立成功时间、错误、重试时间。

| 来源 | 接入方式 | 覆盖 |
| --- | --- | --- |
| NVD/CVE | CVE API 2.0，按修改时间分页 | 操作系统、软件、设备、库及协议实现，保留CPE条件及评分来源 |
| CISA KEV | 官方JSON目录 | 已确认在野利用；近期新增和本地相关旧记录的利用状态更新 |
| GitHub Advisory | 官方REST分页 | 主流包生态；可配置GITHUB_TOKEN避免公共额度限制 |
| Microsoft MSRC | 官方CVRF API | Windows及微软产品，保留产品状态与修复条目 |
| Apple | 官方安全更新索引与公告正文 | macOS及Apple产品；公告中多CVE单独标为提及关系 |
| Android | 官方ASB索引与公告正文 | Android安全公告 |
| PSF | Python官方advisory-database归档 | CPython及标准库，按OSV格式读取 |
| Node.js / Go / PHP | 官方安全或发布feed | 运行时及安全发布；普通发布feed只取安全相关记录 |
| Debian / Ubuntu | 官方安全feed | 发行版公告及回补修复信息 |
| Cisco / Fortinet | 官方安全feed | 网络基础设备及安全产品 |
| CISA Advisories | 官方公告feed | 基础设施及厂商安全公告 |
| OSV（14个来源） | 按生态modified_id.csv流式增量，逐条JSON | npm、Packagist、Maven、PyPI、Go、Linux、Android、Debian、Ubuntu、Alpine、NuGet、crates.io、RubyGems、OSS-Fuzz |

上游覆盖不是全球完整漏洞集合；不同厂商可能延迟披露、修改网页结构或限制访问。来源失败不会回退成搜索摘要或编造记录。
OSV保留原生态名称和版本事件；初次7天以源修改时间查询，旧漏洞近期更新也会出现。
采集发现不等于近期公开。v1.3.0 的日期规则如下；原始值、字段、引用、时区和精度随判定保存。

| 来源或字段 | 日期含义与用途 |
| --- | --- |
| NVD `published`、CVE `cveMetadata.datePublished` | 数据库记录公开；不能直接当作漏洞首次公开 |
| CVE CNA `containers.cna.datePublic` | 明确披露日期证据；与可对应到漏洞的原始公告一起判定 |
| 全部OSV生态（含PSF）`published` | 来源条目公开；不因编号为CVE或生态名称而升级为披露日期 |
| GHSA `published_at` | 原始安全公告公开；`updated_at` 是独立的公告更新时间 |
| MSRC `RevisionHistory` | 仅描述明确为首次公开的修订可作公告公开证据；普通修订日期不适用 |
| Apple/Android | 明确公开元数据或带标签的公告日期；不从URL推断；多CVE公告日期不复制给各CVE |
| Node.js/Go/PHP/Debian/Ubuntu/Cisco/Fortinet/CISA RSS | 保留原始 `published`（公告公开）和 `updated`；多CVE公告仅为公告记录，不把CVE视为别名 |
| KEV `dateAdded`、NVD `cisaExploitAdd` | 已利用收录事件，不是漏洞首次公开 |
| 明确的修复 `Date` | 补丁/缓解发布时间，须有公开HTTPS依据 |
| 本库 `first_seen_at` / `change_observed_at` | 采集或观察时间；不能充当公开或重要变化发布时间 |

官方CVE补证固定访问 `https://cveawg.mitre.org/api/cve/{CVE}`，校验返回编号；仅解析日期和引用，不把后来取得的影响范围写入历史事实。原始公告补证只访问配置白名单内、由现有来源或CNA引用的HTTPS页面，且要求日期可对应到该CVE。结果缓存并限速，失败、无明确日期和冲突分别展示；未知不填采集时间。白名单为精确主机名，可用 `PUBLICATION_REFERENCE_HOSTS` 调整。

仅到日的记录保留原始日值。未知时区的日期使用保守区间（UTC前14小时至次日后12小时），不编造零点；区间跨筛选边界时进入待核实，不计已核实新增。只有能确认发生在窗口内的补丁、已利用收录、带日期的重要公告内容变化才推送为近期更新。维护重算不会制造维护当天的新事件。

历史RSS若只保留了旧适配器归一化的时间，无法还原原始时区和精度，不直接沿用为已核实公开或公告更新时间；旧Android从URL推断的日期也不沿用。通过CNA或原始公告重新补证，取不到证据则明确待核实。
网络协议类漏洞来自具体产品/实现公告；不把抽象协议名称直接等同于所有实现都受影响。

本次开发环境中GitHub Advisory与CISA公告feed曾返回403，其他来源抽样结果见验证记录。你的服务器需重新执行抽样并在管理页核对全量采集状态。
