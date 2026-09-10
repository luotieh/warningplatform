# 流量事件双向聚合计划书（B1 无向五元组聚合为主，B2 flow_id 会话级为后续升级）

- 日期: 2026-08-20（决策确认: 2026-08-21）
- 状态: 决策已确认，待实施
- 范围:
  - 后端：`traffic/internal/service/event_mapping.go`（Fingerprint/聚合键）、`traffic/internal/service/services.go`（ProcessLyEvent/mergeOccurrence/buildOccurrence）、`traffic/internal/store`（event_maps 映射、ListEventsByTargetIP）、`traffic/event_service.go`（lyCompatibleEvent 展示）
  - 前端：事件列表列（端点对展示）、排行（端点活跃度）、命中明细（方向）
  - 数据：存量事件指纹映射重建（幂等、可回滚）
  - 后续升级（B2）：ta_node 推送 schema v1.7 新增 `flow_id`，聚合键切换（需节点侧配合）

## 1. 背景与问题

事件聚合键 `Fingerprint = sha256(src_ip | dst_ip | event_type)`（`event_mapping.go:29-42`）是**有向**的：`A→B` 与 `B→A` 指纹不同，各自建事件。同一会话双方向各命中检测时，事件列表出现两条"镜像"事件，导致：

- 列表噪音、威胁来源/受害目标排行被对向 IP 重复计数；
- 会话频次（`occurrence_count`）、总载荷（`total_payload_bytes`）按方向拆分；
- 资产关联事件数翻倍、AI 研判报告割裂、审核/通报需重复处理。

ta_node 推送（schema v1.6）中 `src_port/dst_port/proto/direction` 均为必填（见 `docs/event-push-api.md`），`session_summary` 本身描述双向会话；推送**无 `flow_id` 等会话标识**——这是选择 B1（五元组归一化，纯管理端可落地）而非 B2 的直接原因。

## 2. 目标

1. 同一会话（双向五元组 + 同类型）的命中合并为一条事件：频次、总载荷、证据、明细双向求和/汇总；
2. 不影响存量事件安全（映射重建幂等、可回滚），不影响幂等去重与收敛/归档链路；
3. **主视图无向化**：列表以"端点对"展示、方向信息下放明细（分布/时序），展示口径一致（含已上线的 IOC 受害目标交换——演进为标注式，验收语义不变）；
4. 为后续 B2（flow_id 会话级）预留切换点。

## 3. 方案选型结论

| 方案 | 结论 | 理由 |
|---|---|---|
| A 无向 IP 对 | **不采用** | 误并风险高：跨端口/跨服务/反向独立攻击会被合并，`occurrence_count` 口径失真，不具备生产可用性 |
| **B1 无向五元组（主方案）** | ✅ **采用** | 粒度接近真实会话，纯管理端改造，端口/proto 数据齐备（必填字段） |
| B2 flow_id 会话级 | **后续升级** | 语义最准，但依赖 ta_node schema v1.7 与节点排期，存量无法回溯 |
| D 展示层合并 | ✅ **P1 先行（已确认）** | 不动存储，快速去噪，与 B1 不冲突（见 §6） |

## 4. B1 详细设计

### 4.1 归一化聚合键

新增归一化函数（`event_mapping.go`），替换 `Fingerprint` 的 raw 拼接：

```
normalize(src_ip, src_port, dst_ip, dst_port, proto) → (left, right)
  1. IP 归一：strings.ToLower + netip.ParseAddr（失败退字符串比较）；
     IPv4-mapped IPv6（::ffff:1.2.3.4）先 Unmap，避免同一地址两种写法分裂；
  2. 端点比较：(ip, port) 字典序，小者为 left，大者为 right；IP 相同比端口；
  3. 聚合键 = sha256( left.ip | left.port | right.ip | right.port | proto | etype )
     etype 沿用现有 ToLower+TrimSpace 归一
```

- TCP/UDP 双向流五元组镜像对称（`A:pa→B:pb` 与 `B:pb→A:pa` 归一后一致）；单节点旁路/NAT 后采集均成立（节点看到的是转换后的对称五元组），仅非对称路由多节点分采集会破坏——属 B2 场景，B1 不做跨节点合并（`device_id` 不进入聚合键，现状即如此）；
- 语义：同五元组、不同时间 → 合并（维持现状的"多次命中收敛"）；同 IP 不同端口/协议 → 不合并（避免跨端口/跨服务的误并）；客户端动态端口新会话 → 新键不合并（正确）。

### 4.2 事件映射与存量兼容（关键设计）

现状：`event_maps` 以 fingerprint 为主键，INSERT IGNORE 去重（`store.go ReserveFingerprint/GetEventMap`，`services.go:34-35`）。

改造：**fingerprint → event_id 映射保持"多指纹指同一事件"能力**（一个事件可挂多个指纹）：

1. **新事件**：创建时写入"无向指纹 → event_id"（逻辑不变，只是指纹算法更换）；
2. **存量迁移**（一次性脚本，幂等）：
   - 遍历 `events`，按新算法计算每条事件的无向指纹；
   - 写入 `event_maps`（fingerprint=新指纹, deepsoc_event_id=存量事件ID）——**不修改事件内容**；
   - 冲突（同一无向指纹对应两个存量镜像事件）：保留"最后活跃/次数多"者为主事件；**副事件冻结（已确认 §9.2）：不删不改、不承接新命中**，仅等待自然收敛归档；
   - 执行前备份 `event_maps` 表；脚本可重复执行（INSERT IGNORE 语义）；
3. 此后任何方向的新推送，无向指纹命中 → `mergeOccurrence` 并入既有事件 ✓。

### 4.3 无向展示与 context 扩展（已确认 §9.1：主视图无向化，不设主方向）

**决策依据**：B1 五元组键合并出的事件本身就是单一会话（双向通信），强行指定"来源→目标"必然失真；方向语义的真正载体是「威胁语义方向」（IOC 侧 vs 受害侧）与「流向分布/时序」（ByDirection、occurrences[].direction），两者数据齐备，不依赖"主方向"概念。

- **列表主列**：`A ↔ B`（端点对），不区分来源/受害；辅以「命中方向分布」标签（如 入3/出5，取自 `quant_stats.ByDirection`）；
- **IOC 事件**：标注式——IOC 值所在侧 = 威胁方（情报命中标记），另一侧 = 受害方；已上线需求 2（受害目标不显示 IOC 规则 IP）的实现由"交换"演进为"标注"，**验收语义不变**；
- **规则命中事件**（无 IOC，如扫描）：方向分布标签表达"攻击源直觉"（如仅入向 8 次即知扫描源在另一端）；
- `context` 新增：
  - `involved_ips: [ip1, ip2, ...]`：全部命中涉及 IP 去重累积（供按任意侧查询/资产关联）；
  - （不设 `primary_src_ip/dst_ip`——无主方向概念）；
- `buildOccurrence`（`services.go:359-422`）为每条命中追加 `direction`（ly[`direction`]），明细弹窗可区分双向时序；
- `quant_stats`：`ByDirection` 已按每次命中累加（`quant_stats.go:95`）→ 方向分布标签直接可用；`SourceIPs/DestIPs` 同理由各方向命中各自累加，无需改。

### 4.4 合并逻辑改造（`mergeOccurrence`，`services.go:107-171`）

- 除现有累加逻辑外，补充：`involved_ips` 并入；
- **`occurrence_count` = 双向命中总次数（已确认 §9.3）**，报告/排行口径随之上线公告；
- 收敛窗口不变：`last_seen_at` 双向任一命中即刷新（现状已如此），30 分钟静默收敛、按日归档逻辑无需改动；
- `maxOccurrences=200` 截断、证据去重累积（`mergeEvidenceFiles`）不变。

### 4.5 下游适配

| 消费方 | 适配 |
|---|---|
| 列表展示 `lyCompatibleEvent`（`event_service.go:167+`） | 输出 `endpointA/endpointB` 端点对 + 方向分布 + IOC 侧标注；原 `attackDevice/victimDevice` 交换逻辑演进为标注式（需求 2 验收语义不变） |
| 前端列表/明细（LyEventTable、命中明细弹窗） | 主列 `A ↔ B` + 分布标签；明细弹窗展示每条命中 direction |
| 排行（前端 countByKey） | 「威胁来源/受害目标」→「**端点活跃度**」排行（每端点合并计数）；受害侧视图可用"非 IOC 侧/资产侧"过滤 |
| 资产月度总结 `ListEventsByTargetIP`（`mysql.go:375`） | 查询条件扩展：dst_ip/victim_target 匹配 **或** `involved_ips` 包含（JSON_CONTAINS）；月度统计不再漏反向命中 |
| AI 研判回传（前端 `buildAnalysisPayload` 用 src_ip/dst_ip） | 无需改：回传原始五元组 → 无向指纹仍命中同一事件（反而更稳） |
| 审核/通报（ReviewEvent） | 无需改：一次审核覆盖合并后的完整会话 |
| 资产字段/命中频次/总载荷（前端） | 无需改：数据已在合并事件上 |
| 证据聚合（EvidenceArchive） | 无需改：双向 PCAP 已在 occurrences 明细中累积 |

## 5. B2 后续升级设计（预留切换点）

1. **ta_node**：schema v1.7 推送新增 `flow_id`（同会话双向同 ID，建议复用现有会话标识生成逻辑）；`docs/event-push-api.md` 同步升级；
2. **管理端**：聚合键支持 `(flow_id, etype)` 模式（`Fingerprint` 增加 flow_id 分支）；无 `flow_id` 的旧事件/旧推送回退 B1 无向五元组键（双键兼容期）；
3. **切换**：配置项 `aggregate_key = "tuple5" | "flow_id"`，默认 tuple5；flow_id 覆盖率达到阈值后切换，观察期后可移除 B1 回退；
4. **不变量**：B1/B2 共用无向展示、`involved_ips`、`occurrences[].direction` 等 context 扩展，切换只影响指纹算法，下游零改动。

## 6. 实施计划（里程碑）

| 阶段 | 内容 | 产出/验证 |
|---|---|---|
| **P0 数据观测**（前置，只读） | 真实库统计镜像对占比/端口/类型分布（SQL 见 §10） | 必要性量化，确认 B1 参数（如是否需按 device_id 分组） |
| **P1 展示层合并（先行，已确认）** | 方案 D：列表/排行识别镜像行合并展示，标注"双向" | 快速去噪，可随时回退；与 B1 并存不冲突 |
| **P2 B1 核心** | 归一化函数 + Fingerprint 改造 + mergeOccurrence 双向累加 + context 扩展（involved_ips/occurrences.direction） | 单测：归一化（IPv4/IPv6/mapped、端口排序）、镜像推送合并为一条、频次/载荷双向求和 |
| **P3 存量映射迁移** | 迁移脚本（备份 event_maps → 重建无向指纹映射，幂等可重跑） | 迁移后新推送能命中存量事件；镜像冲突按 §9.2 副事件冻结 |
| **P4 下游适配** | ListEventsByTargetIP involved_ips 查询；lyCompatibleEvent 端点对/标注式；前端列表列与排行 | 集成测试：资产月度总结不漏反向命中；需求 2 验收回归（IOC IP 不出现在受害位置） |
| **P5 全量上线（已确认 §9.5）** | 直接全量启用 B1 无向键（不设灰度开关）；保留紧急回退手段（临时切回旧有向键的配置项，映射表保留两种指纹条目） | 上线后监控收敛/归档/审核链路无回归 |
| **B2（后续）** | 节点 schema v1.7 flow_id + 管理端双键兼容 + 切换 | 另行排期，本节设计为蓝图 |

## 7. 测试与验收清单

1. 归一化单元测试：IPv4/IPv6/大小写/IPv4-mapped/非法 IP/端口排序/同 IP 同端口（DNS 53↔53）；
2. 双向推送集成测试：同一会话 A→B 与 B→A（同五元组同类型）→ 合并为一条，occurrence_count=2、total_payload_bytes 求和、occurrences 两条各带 direction；
3. 不同端口/协议的同 IP 对 → 仍为两条（无误并）；
4. 存量迁移测试：预置镜像对 → 迁移后新推送命中主事件，副事件冻结（不承接新命中、不被删除）；
5. 资产月度总结：按 involved_ips 任一侧 IP 均能查到合并事件；
6. 展示回归：列表端点对 `A ↔ B` + 方向分布标签；IOC 事件标注威胁侧/受害侧（IOC 规则 IP 不出现在受害位置）；端点活跃度排行聚合正确；
7. 幂等回归：同 event_id 重复推送不重复计次；analysis_only 研判重推仍命中原事件；
8. 紧急回退演练：临时切回旧有向键，存量与新事件均正常。

## 8. 风险与回退

| 风险 | 缓解 |
|---|---|
| 存量指纹映射冲突（镜像对已存在） | 已确认副事件冻结（不删不改、不承接新命中），等待自然收敛归档 |
| occurrence_count 口径变化（双向求和）影响报告/排行 | 上线公告 + 报告文案注明"双向命中总次数"；P1 展示层先行可提前暴露口径争议 |
| 列表"来源→目标"改为"端点对"的运营习惯变化 | 方向分布标签（入/出次数）+ 明细时序保留方向信息；上线公告说明 |
| 排行语义变化（来源/受害 → 端点活跃度） | 已随无向展示决策确认；受害侧视图提供"非 IOC 侧/资产侧"过滤 |
| 端口复用跨时段误并 | 五元组已最小化；误并概率低，上线后监控异常频次事件 |
| 非对称路由/多节点导致漏并 | 属 B2 范围，B1 文档明示限制；不跨节点合并 |
| 迁移脚本故障 | 备份 + 幂等重跑 + 紧急回退（保留旧指纹映射条目） |

## 9. 决策记录（已确认 2026-08-21）

1. **主方向策略 → 不设主方向，主视图无向化**：列表端点对 `A ↔ B` + 方向分布标签；方向信息下放明细（occurrences[].direction、ByDirection、volume_role）；IOC 威胁语义以"标注式"表达（威胁侧/受害侧），需求 2 验收语义不变；
2. **存量镜像对 → 冻结**：仅映射重建，副事件不删不改、不承接新命中，等待自然收敛归档；
3. **频次口径 → 双向求和**：`occurrence_count` = 双向命中总次数；
4. **P1 展示层合并 → 先行**：作为第一阶段排期；
5. **上线方式 → 默认全量**：不设灰度开关，保留紧急回退配置项。

## 10. 附：数据观测 SQL（P0，只读）

```sql
-- 近 30 天事件按无向五元组+类型分组，统计"多方向并存"的镜像组合占比
SELECT LEAST(src, dst) AS ip1, GREATEST(src, dst) AS ip2, etype,
       COUNT(*) AS evt_cnt,
       COUNT(DISTINCT CONCAT(src,'>',dst)) AS dir_cnt,
       SUM(occ) AS total_hits
FROM (
  SELECT JSON_UNQUOTE(JSON_EXTRACT(context,'$.src_ip')) src,
         JSON_UNQUOTE(JSON_EXTRACT(context,'$.dst_ip')) dst,
         JSON_UNQUOTE(JSON_EXTRACT(context,'$.event_type')) etype,
         COALESCE(CAST(JSON_EXTRACT(context,'$.occurrence_count') AS UNSIGNED),1) occ,
         last_seen_at
  FROM events
  WHERE last_seen_at >= NOW() - INTERVAL 30 DAY
) t
GROUP BY ip1, ip2, etype
HAVING dir_cnt >= 2
ORDER BY total_hits DESC
LIMIT 100;
```

> 观测口径：`dir_cnt>=2` 即镜像组合；结合 `src_port/dst_port/proto` 是否一致可进一步判断 B1 五元组键能合并的比例，为 B1/B2 取舍提供数据依据。
