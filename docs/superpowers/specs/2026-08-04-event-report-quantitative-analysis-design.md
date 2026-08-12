# 事件报告量化分析逻辑设计（收敛终报 + 按需刷新 + 资产月度总结）

- 日期: 2026-08-04
- 分支: trafficanalysis
- 状态: 后端核心已落地，前端与报告渲染待跟进

## 1. 背景与问题

新报告模版（`docs/security_incident_report_template.md`）要求报告输出量化分析结果：

- `三、流量证据与IOC明细`：5 分钟内 12,847 次请求、32% 带 SQL 注入特征、1.2GB 响应外传等计数/占比/体量；
- `三.3 IOC有效性说明`：24 小时内触发 3 次、域名新注册等时间跨度与重复命中数据；
- `四、影响评估`：延迟、失败率、外传数据条数等业务影响指标；
- `五、处置建议`：基于量化阈值的立即行动项。

当前事件报告生成逻辑与这些需求存在结构性断层：

1. **首命中快照即终稿**：`ProcessLyEvent` 按「来源 IP + 目标 IP + 事件类型」聚合，首次命中创建事件并触发 `RunAgentWorkflowAsync` 生成 LLM 分析；后续同类命中只走 `mergeOccurrence` 累加次数、更新首末次时间与 occurrences，**不重跑分析**。
2. **幂等一刀切**：`RunAgentWorkflow` 用 `hasAgentWorkflowMessages` 判断"已分析即跳过"，前端"查看报告"的 `analysis_only` 重推也无法刷新既有报告。
3. **聚合数据未进 prompt**：分析 prompt 只包含首条命中的可观察对象与辅助上下文，`occurrence_count`、`first_time`、`last_time`、`occurrences` 等聚合字段没有实际渲染进 prompt，LLM 无量化数字可用。
4. **"最终频次"无闭环**：`aggregateIdleWindow`（10 分钟静默收敛）已在列表侧判定 `occurrence_count` 为最终频次，但收敛后没有动作生成终版报告。

## 2. 目标与非目标

### 2.1 目标

1. **量化指标确定性计算**：次数、体量、速率、分布等数字由规则引擎增量计算，不依赖 LLM，防止幻觉。
2. **收敛终报**：事件聚合收敛后自动生成一份基于最终量化数据的终版分析。
3. **按需手动刷新**：人工触发重分析，基于最新数据生成新版本报告。
4. **分析版本化**：初版/终版/手动刷新版本可区分、可追溯、可幂等。
5. **资产 IP 月度总结**：对已有资产 IP，每月对其一个月内所有落档报告做一次汇总分析。

### 2.2 非目标

- **阈值自动触发**（次数翻倍、新 IOC 出现等自动重跑）：用户明确砍掉，只保留收敛终报与手动刷新两个通道。
- 逐次命中实时分析：维持现有聚合语义，不做每次命中都调用 LLM。
- LLM 生成量化数字：所有数值一律来自量化引擎。

## 3. 决策约束（用户确认）

1. 第二层触发时机只保留 **收敛终报** 与 **按需手动刷新**，去掉阈值触发。
2. 分析做 **版本化**（初版 / 终版 / 手动刷新版本）。
3. 新增 **资产 IP 定期全报告分析**：对已有资产 IP，把该 IP 一个月内所有的落档报告做一次总结。

## 4. 总体方案

```
                    ┌─────────────────────────────────────────────┐
                    │         确定性量化引擎（quant_stats）        │
                    │  命中合并时增量累计：次数/体量/速率/分布/突发 │
                    └──────────────────────┬──────────────────────┘
                                           │ 快照
        ┌──────────────────────────────────┴──────────────────────────┐
        │                                                             │
  ┌─────▼──────────────┐                              ┌───────────────▼───────────┐
  │ 通道1：收敛终报      │                              │ 通道2：按需手动刷新          │
  │ 聚合收敛后自动触发    │                              │ 人工调接口强制重跑           │
  │ analysis_version=2  │                              │ analysis_version=3+        │
  └─────┬──────────────┘                              └───────────────┬───────────┘
        │                                                             │
        └───────────────────────┬─────────────────────────────────────┘
                                ▼
                   LLM 定性分析（结论/意图/处置叙事）
                   量化数字一律由 quant_stats 注入
                                │
                                ▼
                  报告模版渲染（TrafficEvidence/Iocs/Impact/…）

  独立通道：资产 IP 月度总结
    assets(ip) ──每月扫描──▶ 该 IP 近 30 天落档报告集合
                             ──聚合 quant_stats──▶ LLM 月度总结 ──▶ asset_report_summaries
```

## 5. 确定性量化引擎（quant_stats）

### 5.1 数据结构

`quant_stats` 随事件聚合增量维护，收敛后冻结为快照：

```go
type QuantStats struct {
    EventID         string            `json:"event_id"`
    WindowStart     string            `json:"window_start"`     // 首次命中时间
    WindowEnd       string            `json:"window_end"`       // 末次命中时间
    DurationSec     int64             `json:"duration_sec"`     // 收敛/冻结时计算
    OccurrenceCount int64             `json:"occurrence_count"` // 总命中次数
    UniqueSrcIPs    int               `json:"unique_src_ips"`
    UniqueDstIPs    int               `json:"unique_dst_ips"`
    TotalWireBytes  int64             `json:"total_wire_bytes"` // 在线字节合计
    TotalPackets    int64             `json:"total_packets"`
    RatePerMin      float64           `json:"rate_per_min"`     // 总次数/分钟
    ByRule          map[string]int64  `json:"by_rule"`          // 规则ID → 次数
    ByDirection     map[string]int64  `json:"by_direction"`     // inbound/outbound/lateral
    ByIOC           []IocHitStat      `json:"by_ioc"`           // IOC → 次数/首末次
    PeakWindow      PeakWindowStat    `json:"peak_window"`      // 最密集 5 分钟窗口
    UpdatedAt       string            `json:"updated_at"`
}

type IocHitStat struct {
    IOCValue  string `json:"ioc_value"`
    IOCType   string `json:"ioc_type"`
    Count     int64  `json:"count"`
    FirstSeen string `json:"first_seen"`
    LastSeen  string `json:"last_seen"`
}

type PeakWindowStat struct {
    StartTime string `json:"start_time"`
    EndTime   string `json:"end_time"`
    Count     int64  `json:"count"`
}
```

### 5.2 增量维护点

在 `mergeOccurrence`（`vulnscan-backend/traffic/internal/service/services.go`）中追加维护：

1. 累加 `occurrence_count`、`total_wire_bytes`、`total_packets`；
2. 更新 `window_start` / `window_end`；
3. `ByRule`：从事件 `rule_id` 计数；
4. `ByDirection`：从 `direction` 字段计数；
5. `ByIOC`：命中 `ioc_value` 时计数并记录首末次；
6. 突发窗口：对 occurrences 时间序列做滑动窗口（5 分钟）求最密集区间；
7. 置 `dirty=true`，供手动刷新判断"自上次分析后是否有增量"。

无 `wire_bytes` / `packets` / `direction` 的命中选择性省略对应指标，报告侧动态隐藏，不补 0。

### 5.3 存储

- 短期：写入事件 `context.quant_stats`（兼容现有 schema）；
- 中期：新增独立 JSON 列 `quant_stats`，避免 context 继续膨胀（现有 occurrences 已按 200 条截断）；
- 收敛冻结后不再随命中变化（收敛后新命中的事件按新聚合键处理）。

## 6. 分析版本化

### 6.1 版本语义

| analysis_version | kind | 触发 | 说明 |
| --- | --- | --- | --- |
| 1 | `initial` | 首次命中 | 现状快报，量化为首条快照，标注"待收敛后更新" |
| 2 | `final` | 聚合收敛 | 基于冻结 quant_stats 的终版，只生成一次 |
| 3+ | `manual` | 手动刷新 | 基于当前最新 quant_stats，每刷新一次 +1 |

### 6.2 幂等改造

`RunAgentWorkflow` 的 `hasAgentWorkflowMessages` 一刀切判断改为按 `(kind, version)` 判定：

- `initial`：已存在 version=1 则跳过；
- `final`：`aggregation_closed=false` 或已存在 version=2 则跳过；
- `manual`：不检查是否已分析，只检查 `agentWorkflowInflight`（同一事件同一时刻只跑一条）与冷却窗口。

`summaries` 表新增 `version`、`kind` 列，保留历史版本供追溯；事件表新增 `analysis_version`、`analysis_status`。

## 7. 触发通道

### 7.1 通道一：收敛终报

现状收敛判定是惰性的（列表查询时按 `last_seen_at` 计算），不落库。改造为：

1. 新增 `aggregation_closed` 布尔列，收敛时置 true；
2. 新增独立收敛扫描器（Ticker，间隔 1~2 分钟）：
   - 扫描 `aggregation_closed=false` 且 `now - last_seen_at >= aggregateIdleWindow` 的事件；
   - 置 `aggregation_closed=true`，冻结 `quant_stats`；
   - 若 `analysis_version < 2`，异步触发 `RunAgentWorkflow(kind=final, version=2)`。
3. 终版分析 prompt 注入冻结的 `quant_stats` 与 occurrences 聚合摘要，LLM 只写定性结论、影响判断、处置建议；
4. 生成 `kind=final` 的 summary 与专家消息，`analysis_version=2`。

延迟说明：终报发生在最后一次命中后 10 分钟，人工审核与报告导出通常发生在收敛之后，可接受。

### 7.2 通道二：按需手动刷新

新增接口：

```
POST /api/traffic/events/{eventID}/report/refresh
```

行为：

1. 事件不存在返回 404；
2. 该事件正在分析（inflight）返回"分析进行中"；
3. 冷却窗口（常量 `manualRefreshCooldown = 60s`）：距上次分析完成不足冷却时间则拒绝；
4. 基于**当前最新** `quant_stats` 与完整 occurrences 重新生成分析；
5. 新版本 = 当前 `analysis_version + 1`（`kind=manual`），保留历史 summary；
6. 未收敛事件也可手动刷新（版本号照常递增，但不算终版）；
7. 前端"查看报告"从 `analysis_only` 重推逐步迁移到该接口；`analysis_only` 保留为"未分析则补跑初版"的兼容语义。

### 7.3 通道三：资产 IP 月度总结（定期全报告分析）

#### 范围与周期

- 范围：traffic 侧启用资产（`asset_type=ip`，`status=1`）；按 `dst_ip` / `victim_target` 匹配事件；
- 周期：每月 1 日 02:00 全量扫描一次（常量 `assetMonthlyCron`，可用 30 天滚动窗口）；
- 窗口：目标 IP 近 30 天内**落档报告**。

#### "落档报告"定义

满足以下任一条件即视为落档：

- 事件已收敛（`aggregation_closed=true`）且 `analysis_version >= 2`（有终版分析）；
- 事件已推送通报处置且通报已关闭/归档（`circular_code` 非空且 incident 状态 closed）；
- 手动刷新的最新版本报告（`kind=manual`）视为已落档。

#### 生成流程

1. 扫描 `assets` 表取得全部启用 IP；
2. 对每个 IP 查询近 30 天落档报告集合（按事件收敛时间/终版生成时间归月）；
3. 聚合月度量化指标：
   - 事件总数、按严重级别分布、按攻击类型分布；
   - 攻击源 Top N、IOC Top N、命中规则 Top N；
   - 总次数、总体量（wire_bytes）、最活跃时段；
   - 处置状态分布（待处置/处置中/已关闭）；
4. 注入 LLM 生成月度总结叙事：风险趋势、重点事件、整改建议；
5. 落库 `asset_report_summaries`，支持导出为新模版报告（基础信息 + 事件概述 + 量化章节）。

#### 数据模型

```go
type AssetReportSummary struct {
    ID         string          `json:"id"`
    AssetID    string          `json:"asset_id"`
    AssetIP    string          `json:"asset_ip"`
    Period     string          `json:"period"`  // 2026-08
    WindowFrom string          `json:"window_from"`
    WindowTo   string          `json:"window_to"`
    EventCount int             `json:"event_count"`
    Stats      AssetMonthlyStats `json:"stats"`       // 确定性量化聚合
    Narrative  string          `json:"narrative"`     // LLM 月度总结
    Status     string          `json:"status"`        // pending/completed/failed
    CreatedAt  time.Time       `json:"created_at"`
}
```

月度总结同样遵循"数字确定性、叙事 LLM"原则：`Stats` 由规则引擎聚合，LLM 只写 `Narrative`。

## 8. 报告模版字段映射

| 模版字段 | 填充来源 |
| --- | --- |
| `TrafficEvidence.Type/Detail/Source/Confidence` | quant_stats（次数/体量/速率/突发窗口）+ 规则匹配 + ioc_evidence |
| `Iocs.Value/Match` | quant_stats.ByIOC + 情报源（ioc_source） |
| `IocValidity` | ByIOC 的首末次时间、重复触发次数、情报时效字段 |
| `Impact.Business`（延迟/失败率） | 站点监测/业务指标或人工确认，无数据则章节隐藏 |
| `Impact.DataRisk` | 外传方向（to_ioc/outbound）wire_bytes 合计、含敏感字段的应用样本 |
| `Impact.Intent` / 事件概述 / 核心结论 | LLM 终版/手动刷新分析 |
| `ImmediateActions` / `FollowupActions` | 阈值规则确定性生成（如速率 > N/分钟、体量 > X MB），LLM 可修正 |
| `Attachments` | 现有证据文件（evidence_file / evidence_images） |

## 9. 接口变更清单

### 9.1 traffic 模块

- `POST /api/traffic/events/{eventID}/report/refresh`：手动刷新分析；
- `GET /api/traffic/events/{eventID}/report`：返回最新版本报告（含 `analysis_version`、`quant_stats`）；
- `POST /api/traffic/assets/monthly-summary/run`：手动触发某资产 IP 月度总结；
- `GET /api/traffic/assets/{assetID}/monthly-summary?period=2026-08`：查询/导出月度总结。

### 9.2 incident 报告接口

- `PreviewIncidentReport` / `ExportIncidentReport` 读取事件侧 `quant_stats` 与最新分析版本；
- 报告数据契约（`IncidentReportData`）按既有模版建议新增 `TrafficEvidence`、`Iocs`、`IocValidity`、`Impact`、`ImmediateActions`、`FollowupActions`、`Attachments` 字段；
- 导出时标注分析版本与生成时间，未收敛事件显示"初版快报"标识。

### 9.3 前端

- 报告详情页展示分析版本、量化统计（命中频次弹窗复用现有 occurrences）；
- 新增"手动刷新分析"按钮，带冷却提示；
- 资产详情页新增"月度总结"入口。

## 10. Token 成本估算

按项目 `estimateTokens` 口径（CJK 0.7/字 ×1.1 保守系数）：

| 分析类型 | 输出估算 |
| --- | --- |
| 初版快报（version=1） | ~1,500 |
| 收敛终报（version=2） | ~1,900 |
| 手动刷新（version=3+） | ~1,900 |
| 资产 IP 月度总结 | ~2,500 ~ 3,500 |

- 单事件自动调用上限：初版 + 终版 = 2 次；
- 手动刷新受冷却窗口限制，正常操作频率下成本可控；
- 月度总结按资产数量线性增长，建议每次批量串行/限流执行。

## 11. 实施步骤

1. `quant_stats` 增量计算：改造 `mergeOccurrence`，补齐 ByRule/ByDirection/ByIOC/PeakWindow；
2. 事件表新增 `aggregation_closed`、`analysis_version`、`quant_stats` 列，`summaries` 表新增 `version`、`kind`；
3. 收敛扫描器：Ticker 扫描 + 冻结 quant_stats + 触发终版分析；
4. 版本化改造：`RunAgentWorkflow` 增加 `kind/version` 参数，替换 `hasAgentWorkflowMessages` 判断；
5. 手动刷新接口 + 冷却 + 前端按钮；
6. 资产月度总结：新增表、月度任务、聚合与 LLM 叙事、导出接口；
7. 报告模版字段对接：`IncidentReportData` 扩展 + 渲染填充；
8. 测试：合并命中后的量化正确性、收敛终报幂等、手动刷新版本递增、月度总结归月边界。

## 12. 风险与对策

| 风险 | 对策 |
| --- | --- |
| 事件长期活跃不收敛，终报迟迟不生成 | 手动刷新兜底；收敛窗口可配置 |
| 收敛扫描器与手动刷新并发触发 | inflight 互斥 + 版本号幂等 |
| 量化数据缺失（无 wire_bytes/packets） | 指标省略，报告章节动态隐藏 |
| 月度总结任务量大、LLM 调用多 | 串行限流、失败重试、可手动补跑 |
| 手动刷新产生大量历史版本 | 保留最近 N 版（如 10 版），更早版本可清理 |
| 应用层计数（如 12,847 次请求指向某接口）依赖 ta_node 聚合 | 一期用现有字段近似统计，二期由 ta_node 下发按规则/端点聚合数据 |
