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
采集发现不等于近期公开。RSS分别保存公开与更新时间；微软按漏洞条目最早公开修订日期；Apple/Android仅提取明确的公开元数据、标注日期或公告日期。无法证实的日期保留未知，报告另列待核实清单，不把首次发现当作披露。仅有日期的记录注明精度，窗口比较按UTC零点归一化。
KEV的dateAdded及NVD的CISA利用收录日期单列为已利用事件，不作为漏洞首次公开日期。影响范围、明确的补丁/缓解日期及已有来源修复内容变化可构成重要更新；来源重复收录、普通modified变化不构成新披露。旧数据回填复用已有官方事实，不访问任意地址，也不伪造未保存的历史版本或首次采集时间。
网络协议类漏洞来自具体产品/实现公告；不把抽象协议名称直接等同于所有实现都受影响。

本次开发环境中GitHub Advisory与CISA公告feed曾返回403，其他来源抽样结果见验证记录。你的服务器需重新执行抽样并在管理页核对全量采集状态。
