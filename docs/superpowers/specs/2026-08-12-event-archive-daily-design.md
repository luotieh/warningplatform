# 事件列表按日归档与当日工作视图设计（Spec，待确认）

- 日期: 2026-08-12
- 状态: 已确认（含收敛逻辑核查），待实施
- 范围: 流量事件列表/总览/搜索的“当日视图 + 按日归档”

## 1. 现状分析

### 1.1 数据链路

```
ta_node ──push──▶ events 表（聚合：src_ip+dst_ip+event_type 合并为一条）
                        │
                        ▼
GET /api/traffic/events/list
   → Store.ListEvents()：SELECT ... FROM events ORDER BY created_at DESC（无 LIMIT/无条件）
                        │
                        ▼
前端 lyStore.loadEvents() 全量拉入内存
   → 事件列表/搜索/总览排行/时间分布全部客户端过滤与分页
```

### 1.2 存在的问题

1. **全量拉取**：`ListEvents()` 无分页、无过滤、无上限（[mysql.go](/home/yt/projects/warning-platform/vulnscan-backend/traffic/internal/store/mysql.go:185)），事件越多单次响应越大；
2. **前端全量计算**：列表筛选、排行、时间分布都在浏览器内对全量数据做 `filter/count`，数据量大时页面卡顿；
3. **列表无时间边界**：事件列表默认展示全部历史，无法快速聚焦“今天发生了什么”；
4. **无归档概念**：所有事件（含已收敛、已处置、已驳回）与今日事件混在一起。

### 1.3 已有可复用能力

- 聚合事件有明确生命周期：`last_seen_at`（最近命中时刻）、`aggregation_closed`（已收敛）、静默超时收敛扫描（`ScanConverged` 每 1 分钟执行）；
- 月度总结已实现“异步任务 + job_id 进度查询”模式，可复用到每日归档任务；
- events 表已有 `created_at DESC` 索引，可扩展归档日索引。

## 2. 结论：需要归档，但建议“逻辑归档 + 默认当日视图”

不建议物理删除/物理迁移（本期）：

- 聚合事件在收敛前会**持续合并更新**（`mergeOccurrence` 改写 `last_seen_at/occurrence_count`），物理迁走未收敛事件会破坏聚合；
- 历史事件仍被月度总结、报告下载、通报处置（circular_code）、审核记录引用；
- messages/tasks 等表通过 `event_id` 外键关联，物理迁移成本高、风险大。

推荐：

- 事件表新增“归档日”标记（`archive_date`），**已收敛且不再活跃**的事件按自然日标记；
- 事件列表默认只显示“今日工作视图”（未归档 + 今日活跃/新增）；
- 历史内容通过“归档”入口按日浏览；
- 列表接口改造为服务端分页/过滤，从根上解决全量拉取。

## 3. 设计

### 3.1 数据模型

`events` 表新增：

```sql
ALTER TABLE events
  ADD COLUMN archive_date DATE NULL COMMENT '归档日（Asia/Shanghai 自然日，NULL=未归档/今日视图）',
  ADD KEY idx_events_archive_date (archive_date, created_at DESC);
```

新增归档任务表（复用月度任务模式）：

```sql
CREATE TABLE IF NOT EXISTS archive_jobs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  job_id VARCHAR(64) UNIQUE NOT NULL,
  period DATE NOT NULL COMMENT '归档目标日',
  status VARCHAR(32) NOT NULL DEFAULT 'running', -- running/success/failed
  total INTEGER NOT NULL DEFAULT 0,
  processed INTEGER NOT NULL DEFAULT 0,
  error TEXT NOT NULL,
  created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 3.2 归档口径（关键决策，见 §5）

已确认口径 A：**按“活跃日”归档**

```
归档条件（每日任务）：
  aggregation_closed = 1
  AND last_seen_at < 今日 00:00（Asia/Shanghai）
  AND archive_date IS NULL
→ archive_date = last_seen_at 所在自然日
```

- 未收敛事件（可能继续合并）即使发生在昨天，也保留在今日工作视图，避免漏处置；
- 已收敛的旧事件按最后活跃日归档，历史可追溯。

备选口径：

- B：按 `created_at < 今日` 归档（简单，但未收敛/未处置事件会从工作视图消失）；
- C：按 `first_time` 归档（语义直观，但活跃事件也会被归档）。

**收敛后新命中的重新打开（实施必做）**

现状：`mergeOccurrence` 不会重置 `aggregation_closed`。已收敛事件若再次收到同聚合键命中，
`occurrence_count` 会继续累加，但收敛标记保持 true，导致“最终频次”失真。
归档实施时必须同步修复：合并命中时若事件已收敛，则
`aggregation_closed=false` 且 `archive_date=NULL`（从归档日回到当日视图）。

### 3.3 列表接口改造（服务端分页/过滤）

```
GET /api/traffic/events/list
  ?scope=today|archive
  &date=YYYY-MM-DD        # scope=archive 时必填
  &page=1&page_size=20
  &level=&keyword=&asset=&starttime=&endtime=

响应：
{
  "items": [LY 兼容事件...],
  "total": n,
  "page": 1,
  "page_size": 20
}
```

- 默认 `scope=today`：`archive_date IS NULL`（未归档）；
- `scope=archive&date=`：`archive_date = date`；
- 过滤条件下推 SQL（严重级别、关键字、来源/目标、时间范围、资产关联），
  避免全表扫描后在内存过滤；
- 排序保持 `created_at DESC, id DESC`；
- 保留详情/搜索接口可查全量历史（搜索不默认限制归档范围）。

### 3.4 每日归档任务

- 每日 00:10（Asia/Shanghai）定时触发，**不提供手动触发入口**；
- 任务幂等：`archive_date IS NULL` 条件保证重跑不重复；
- 批量执行（如每次 500 条，循环至完成），记录 job_id/进度/错误；
- 任务前确保收敛扫描已跑过（现有 `ScanConverged` 每 1 分钟执行）；
- 提供 `GET /api/traffic/archive/jobs/:jobID` 查询进度；

### 3.5 前端

- 事件列表默认“今日视图”，页头提供“归档”切换（日期选择，按日浏览历史）；
- 分页/筛选改为服务端模式（保留现有严重级别、时间范围、关键字/IP、资产筛选 UI）；
- 总览统计、时间分布、排行默认基于今日视图，可切换“近 7 日/归档日”；
- 搜索页保持全量搜索（跨归档范围），结果可跳转详情。

## 4. 预期收益

- 今日列表响应体积与查询时间稳定（不再随历史总量增长）；
- 总览/排行/时间分布计算量显著下降；
- “今天发生了什么”一眼可见，历史按日可查；
- 数据不丢失、聚合不破坏、月度总结/通报/审核不受影响。

## 5. 已确认决策

1. 归档口径：A——按“最后活跃日 + 仅已收敛”逻辑归档；
2. 今日视图包含未收敛的历史事件（`archive_date IS NULL` 即今日视图，未收敛不归档）；
3. 列表接口默认只提供当日视图（服务端分页/过滤），归档按日经 `scope=archive&date=` 查询；
4. 归档仅每日定时（00:10 Asia/Shanghai），无手动触发；
5. 全局搜索默认全量（跨归档范围）。

## 5.1 收敛逻辑核查结论

核查结果（`traffic/internal/service/analysis_scheduler.go`、`event_service.go`）：

1. 收敛窗口当前为 **10 分钟**（`ConvergenceIdleWindow = 10 * time.Minute`），**不是 30 分钟**；
   已确认实施时调整为 **30 分钟**（`ConvergenceIdleWindow = 30 * time.Minute`）；
2. 收敛扫描每 1 分钟执行一次（`traffic.go` 后台 ticker），对**每个事件**统一生效：
   `aggregation_closed=0` 且 `last_seen_at < now-10min` 即收敛，与事件类型、严重级别、处置状态无关；
3. 收敛动作：置 `aggregation_closed=true` + 冻结 quant_stats；若 `analysis_version<2` 异步触发收敛终报；
4. 单轮扫描 `LIMIT 500`：若未收敛事件积压超过 500/分钟，收敛会有延迟（大流量下需关注）；
5. 收敛后新命中不会重置收敛标记（见 §3.2 的“重新打开”修复项）；
6. 列表侧 `isFinal` 展示与后台扫描共用同一 10 分钟窗口。

收敛窗口参数已确认：调整为 **30 分钟**，同步影响列表侧 `isFinal` 展示与收敛终报判定。

## 6. 验收清单（确认后执行）

1. 今日视图：仅返回未归档事件，分页/筛选服务端生效；
2. 归档任务：昨日事件归档成功，job 状态与进度可查，重跑幂等；
3. 归档页：按日期浏览历史事件，详情/报告/PCAP 下载正常；
4. 未收敛旧事件不归档，仍出现在今日视图；
5. 总览统计按今日/归档范围正确；
6. 全量回归：事件推送、聚合、审核、月度总结不受影响。
