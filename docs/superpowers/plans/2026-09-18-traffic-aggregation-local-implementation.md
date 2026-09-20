# 流量聚合修复：本地实施结果与运维说明

日期：2026-09-18。对应 `2026-09-18-traffic-aggregation-repair-implementation-plan.md`。

当前交付为本地代码、测试、维护工具。没有提交、推送、操作 180 数据库或部署服务器。用户原有的模型超时输入上限 6000 改动保持原样。

## 1. 已实现的行为

| 范围 | 本地实现 |
|---|---|
| 接收一致性 | 直接推送与同步进入同一事务入口。MySQL 唯一键、按命中及聚合键加锁，有限死锁重试；相同命中重复传输不重复计数。同步失败不推进游标。 |
| 原始证据 | `traffic_event_hits` 保存完整有效输入，独立稳定 `hit-<64位摘要>`；不再只保存最近 200 条。身份缺失、非法时间、身份冲突保存为待核验接收记录。 |
| 证据补充 | ta_node 的同命中 `context_revision` 增加时保存不可变证据修订，不增加命中次数。同修订号、不同响应内容保留冲突记录。 |
| 生命周期 | 保留有向源 IP、目标 IP、类型分组；按发生时间判断相邻间隔，小于 30 分钟连通，达到 30 分钟分段。支持迟到、归档补传、桥接合并。 |
| 历史身份 | 桥接选择最早创建事件；创建时间相同时按 ID 排序。旧事件、报告和通报记录保留，列表隐藏别名，合并后待复核。 |
| 全量统计 | 分页扫描全部成员，精确计算五分钟半开窗口峰值。次数、首末时间和分布由一个版本产生，原子发布；更新期间使用上一发布版本。 |
| 流量口径 | 同包多规则分别计命中、只计一次物理包。可信累计计数按会话及计数周期高水位计算；缺零基线、身份或跨事件时，不输出伪精确实际流量。 |
| 证据查询 | 固定快照游标分页、按稳定命中 ID 查询、发生时间范围过滤、事件成员校验；保留旧附件入口，增加稳定命中附件入口，全量附件 ZIP。 |
| 模型输入 | 自动报告和工程师聊天共享 `EvidenceContext`；包含固定版本统计、扫描清单、压缩代表证据、真实命中 ID。响应与应用层摘要进入输入，完整数据保留在明细。 |
| 报告关联 | 消息保存快照版本及输入 manifest；生成期间有新数据则旧结果标记过期。点击报告中的命中 ID 可查看生成时的证据修订。 |
| 前端 | 命中弹窗读取分页接口，支持继续加载及完整明细；防止切换事件后旧响应覆盖、重复加载；展示统计更新、历史未核验、实际流量未核验与报告过期信息。 |
| 历史修复 | 独立 CLI 提供 audit/dry-run、apply、rollback、migrate。不能证明完整的数据仅标记质量，保留历史宣称次数；完整可核验记录才重建。历史重建不批量调用模型。 |

确定性统计不直接转换为攻击概率。模型继续进行协议语义、请求响应、时序和跨证据关联分析，输出危险攻击概率及逐条关键证据。概率属于研判估计，不冒充攻击成功概率。

## 2. 存储实现与计划的对应关系

本次采用少量物理表，避免在旧事件表增加多组业务列：

- `traffic_event_hits`：完整原始命中；二进制比较的 hit_id、dedup_key 唯一索引；事件/分组及发生时间索引。
- `traffic_hit_revisions`：相同命中的不可变补充证据，按源修订号唯一。
- `traffic_aggregation_records`：以 kind 区分 `segment`、`snapshot`、`revision`、`receipt`、`outbox`、`analysis_outbox`、`report_manifest`、`repair_batch`。
- `traffic_aggregation_locks`：InnoDB 事务锁行。
- `traffic_aggregation_migrations`：记录 `20260918_aggregation_v2` 迁移版本。

计划中的成员表采用“不可变原始事件归属 + segment.source_events + 命中序列水位”的等价表示。合并时不重写几十万条原始命中；快照固定来源集合、水位和证据修订水位，因此旧报告、旧游标不受补传或后续合并影响。

计划中的 stats、revision、outbox 等职责收敛到带 kind/group 索引的记录表，JSON 使用 LONGTEXT；不是分别创建一张物理表。旧 `events.context` 是兼容投影，仅保存少量身份预览、发布版本与统计摘要。完整规则/IOC 分布保存在快照，统计接口和月度汇总读取完整快照。投影压缩的分布有独立省略清单。

原始命中与修订不自动清理。保留时间和磁盘容量需要发布前按真实流量确定。当前实现未新增接收重试次数的完整运维仪表盘；重复/冲突状态通过接收响应与接收记录核验，不能用 hit 数推断原始传输次数。

## 3. 采集端字段契约

本地只读核对了 ta_node 的 `internal/detector/engine.go`、`internal/event/event.go`、`internal/correlation/tracker.go`：

- 源 `event_id` 由流首时刻、包时刻、序号、五元组及规则/IOC 身份生成，支持同包同规则重试识别。
- `context_revision` 是证据补充修订，`exchange`、请求/响应会发生补充，不能当新增命中。
- `packets/bytes/wire_bytes` 通常是累计观测值，不能按命中条数累加成真实流量。

接收时间优先级：`raw_packet.capture_time` → `capture_time` → `packet_time_usec` → `event_time` → `occurrence_time` → `time`。保存归一化发生时间、选用字段和完整原始输入；微秒 epoch 经过 JSON float64 解析后仍按整数微秒处理。

暂定拒绝 2000 年之前、缺失、非法或比服务器当前时间超前 5 分钟的发生时间，进入待核验接收区；生产探针时钟偏差仍需核验。原始输入保留了各时间字段，但目前没有单独的字段时间冲突汇总页面。

可信流量契约是显式 opt-in：`volume_mode=packet` 需要抓包时刻、包序号；`volume_mode=cumulative` 需要 session_id、counter_epoch、counter_zero_baseline=true、counter_started_at，且基线不早于该事件开始。现有节点未提供这些充分信息时显示“未核验”是预期结果。

当前事务入口支持本地事件数据库。启用远端 DeepSOC 转发模式时返回明确不支持错误，不宣称能跨远端接口完成本地事务。发布前必须核对目标部署采用本地存储模式。

## 4. API

主平台沿用现有鉴权中间件：

```text
GET /api/traffic/events/detail/:eventID/occurrences
GET /api/traffic/events/detail/:eventID/occurrences/:hitID
GET /api/traffic/events/detail/:eventID/occurrences/:hitID/evidence/:idx
```

分页参数：`limit` 默认 100、最大 200，`cursor`，`snapshot_version`，可选 `from`（含）和 `to`（不含）。后续页携带返回的游标，不更换版本和过滤条件。返回 `items/total/snapshot_version/next_cursor/statistics_quality`；`total_scope=snapshot` 表示 total 是整个快照的命中数，使用时间筛选时不等于匹配条数。

独立 HTTP 服务的明细入口为 `/api/events/detail/.../occurrences`，继续检查登录 token。主平台的附件权限与受控节点下载校验不变。新附件按命中关联，旧事件级附件序号不重排。

旧 `E-事件-O序号` 没有可证明的冻结映射时，返回“历史证据引用无法核验”，不指向当前数组的相同位置。完整原始明细弹窗按文本显示，不将原始 payload 当 HTML 执行。

模型摘要限制按字符预算实现，不是精确 tokenizer：最多选 48 个内容代表候选，再按完整 JSON 记录压缩到 6000 Unicode 字符；统计分布保留 Top 与被省略条数/命中数。manifest 记录实际扫描数量、选择 ID、版本、完整性和压缩说明。该限制只影响模型输入，不影响数据库保存。

## 5. 历史维护工具

从 `vulnscan-backend` 构建：

```powershell
go build -o traffic-aggregation-repair.exe ./traffic/cmd/aggregation-repair
```

Linux 编译同一路径，输出文件不带 `.exe`。工具置于 traffic/cmd 下以符合 Go internal 导入边界。

凭据只通过 `TRAFFIC_REPAIR_DSN` 环境变量提供。以下先在独立数据库副本执行；配置文件不需要替换。manifest 含原始事件内容，应按数据库备份保护。

```powershell
# 设置为副本连接，不能使用示例字面量。
$env:TRAFFIC_REPAIR_DSN = '<副本 MySQL DSN>'

# 默认只读，不迁移、不改事件、不调用模型；输出文件必须不存在。
.\traffic-aggregation-repair.exe --manifest audit.json

# 按某事件所属的完整有向分组形成一个批次，不随意截断相关事件。
.\traffic-aggregation-repair.exe --mode audit --event '<事件ID>' --manifest group-a.json

# 独立显式增量建表，重复执行安全；不重建旧数据。
.\traffic-aggregation-repair.exe --mode migrate

# 核对 manifest 后应用该批；再次应用同批不重复修改。
.\traffic-aggregation-repair.exe --mode apply --manifest group-a.json

# 从清单读取批次ID；回退仅允许该批之后未发生新修改。
$batch = (Get-Content group-a.json -Raw | ConvertFrom-Json).batch_id
.\traffic-aggregation-repair.exe --mode rollback --batch $batch
```

审阅 `declared_hits/available_hits/unique_hits/quality/reasons/corrected_archive_date/recoverable_hits`。184913 / 184713 冲突只作质量说明，绝不改成保存样本的 3 次或 200 次。

apply 验证清单 checksum 与每条事件当前状态摘要；任一冲突整批回滚，重新 audit。相同分组已经存在 v2 命中时，拒绝自动混合历史与新增链路。批次粒度为一次清单事务，可按分组逐批执行、停止后续批次；不是单次全库 apply 的后台暂停/续跑调度器。

rollback 保留不可变原始命中，将本批派生 segment 禁用，恢复原 context、归档、收敛、末次时间和审核状态；新增派生事件保留为隐藏历史身份。后台重建、收敛和证据修订不能重新激活已回退 segment。已回退的旧 manifest 不可重新 apply。

有后续新增命中、审核、报告或快照发布时拒绝回退覆盖。此时需要另行核验并补偿重建；当前 CLI 不自动执行这种补偿。运行修复时应暂停本批相关写入和派生 worker，先验证 apply/rollback，再恢复 worker。禁止恢复旧全库备份覆盖后续新增业务数据。

## 6. 本地验证记录

使用单独 MySQL 8.0.34，监听 127.0.0.1:33318；数据库名称以 `_test` 结尾。没有使用原有系统 MySQL 服务或生产数据库。

| 检查 | 结果 |
|---|---|
| `go test ./traffic/...`，包含显式本地 MySQL DSN | 通过；含 100 次并发重试及两个独立 OS 子进程、事务失败回滚、新连接重试 |
| 发生时间与生命周期 | 通过；顺序/逆序/乱序最终分段一致、30 分钟及微秒边界、迟到桥接、方向和设备作用域 |
| 快照/证据 | 通过；676 次同秒全量峰值、300 秒半开边界、固定游标并发补传、旧报告证据修订、跨事件命中隔离与报告失效 |
| 计量 | 通过；同包多规则、累计 100→150→150、乱序高水位、计数周期重置、跨事件未知基线 |
| 历史修复 | 通过；只读 audit、历史宣称数保留、checksum、并发编辑拒绝、重复 apply、原地恢复、拒绝覆盖后续修改 |
| 独立 HTTP 明细接口 | 通过；未登录/过期 token 401、登录成功、错误快照/游标与成员隔离 |
| `go build ./cmd/server`、维护工具构建 | 通过 |
| `node scripts/test-event-time.cjs` | 通过 |
| `node scripts/test-event-evidence.cjs` | 通过；运行实际 Vue 处理函数，验证分页、过时响应、重复点击、失败清理、按版本定位，编译相关模板 |
| `pnpm build:prod` | 通过 |
| `pnpm typecheck` | 未全量通过；资产、站点监测、权限等原有模块报错，本次涉及文件没有匹配报错 |
| `go test -race ...` | 未执行成功；Windows 当前 CGO 未启用/无配置好的 C 编译器，仍需 Linux CGO 环境检查 |

显式规模测试：`TRAFFIC_AGGREGATION_SCALE=1` 启用 `TestAggregationMySQLTwoHundredThousandHits`。本机 20 万条批量夹具插入约 29.70 秒，完整快照重建约 14.40 秒（首轮测量）。验证全量次数及峰值、首页及后续游标、投影大小。**这是数据库夹具和摘要验证，不是 HTTP 接收吞吐测试，也不等于生产压测验收。**

## 7. 发布前仍需完成的门槛

1. 使用部署探针真实 schema 与脱敏样本核对稳定 ID、发生时间、源命名空间、计量契约和时钟偏差；本地源码核对不能替代部署版本核对。
2. 用真实历史数据库副本重放 84 条基线及相邻事件差异，审阅历史分组修复计划。本地测试使用合成且脱敏的边界夹具，没有复制生产原始载荷。
3. Linux CGO 下运行 race；补足真实浏览器登录、登录过期、生成/停止、审核、通报、下载和归档端到端回归。组件处理函数测试不等于浏览器人工验收。
4. 在同机器测旧/新接收基线，以生产峰值两倍持续 30 分钟测 P95、积压回落、锁等待、RSS、磁盘增长；高基数规则/IOC/会话分布需要单独测量。仅分页读原始载荷并不意味着所有分布累积器都是常量内存。
5. 生成 Linux 镜像、SHA 与兼容回退镜像；备份并验证恢复，在隔离库和隔离端口验证。保持原 TOML、数据库、挂载和端口；暂停旧写入器再迁移切换，不能双写。
6. 实际上线后观察至少一个 30 分钟收敛窗口及一次归档；没有真实新流量则保留“接入待验证”。历史 apply 与新增接入切换分开。

上述发布/生产验收未执行，不能将本地改造解释为计划 P7 或生产修复全部完成。
