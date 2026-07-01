# 搜索页资产化 + 结果表复用事件列表 设计

- 日期：2026-07-01
- 分支：`trafficanalysis`
- 约束：**仅修改流量分析前端**——`vulnscan-frontend/apps/web/src/views/ly/**`（事件列表、搜索页、新增共享组件）。不动后端、不动其它前端模块。

## 1. 背景与目标

流量分析「总览 → 搜索」页（`views/ly/search/index.vue`，`/ly/search` 重定向至此）当前：
- 搜索表单：设备ID(devid) / 关键字 / 起止时间。
- 结果列：ID / 事件类型 / 描述 / 等级 / 处理状态 / 操作(查看)。

目标：
1. 把「设备ID」搜索栏改为**资产搜索**（下拉选已登记资产，按事件威胁来源/受害目标关联过滤）。
2. 搜索结果列表与**事件列表完全同步**（同列、同操作：查看报告/审核/驳回、命中明细弹窗、审核状态列）。
3. 旧结果列**仅保留「描述」**，其余替换为事件列表风格的列。

实现方式：把事件列表的**表格部分抽成共享组件 `LyEventTable`**，事件列表页与搜索页都渲染它，从而真正"同步"。

## 2. 关键决策（已与用户确认）

1. 资产搜索控件 = **下拉选已登记资产**（`lyAssetList`，值=资产地址），按 `assetMatchesEvent`（威胁来源或受害目标任一命中）过滤结果。
2. 结果表 = **完全复用事件列表**（含 查看报告/审核通过/驳回、命中明细弹窗、审核状态列），额外保留「描述」列。
3. 旧结果列 ID/等级/处理状态/旧操作 全去掉，仅保留「描述」。
4. `autoAnalyze`：事件列表 = true（保留现有挂载即批量预分析）；**搜索页 = false**（不在挂载时批量调 LLM，改由点「查看报告」按需分析）。

## 3. 共享组件 `LyEventTable.vue`

路径：`vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`。

**Props：**
- `rows: Array<Record<string, any>>` — 已筛选好的事件行（NormalizedLyEvent）。
- `showDesc?: boolean`（默认 false）— 为 true 时在列中插入「描述」列（`key: 'desc'`，ellipsis+tooltip；位置置于「事件类型」之后）。
- `autoAnalyze?: boolean`（默认 false）— 为 true 时组件挂载后对 `rows` 顺序批量预分析（等价现事件列表的 `analyzeHistorySequentially`）。
- `pageSize?: number`（默认 10）。

**从事件列表迁入组件（原样迁移，不改逻辑）：**
- 状态：`analyzingIds`、report 弹窗(`reportVisible/reportEventId/reportContext`)、命中明细(`occVisible/occRows/occColumns`)。
- 方法：`buildAnalysisPayload`、`ensureAnalysis`、`analyzeHistorySequentially`、`openAiDetail`、`reviewStatusMeta`、`reviewEvent`、`buildOccRows`、`openOccurrences`。
- 列定义 `columns`（事件类型/威胁来源/受害目标/严重程度/命中频次含明细/分析状态/审核状态/发生时间/操作），`showDesc` 时插入「描述」列。
- 内置分页（`page/pageSize` + `paginate(rows,...)`）。
- 模板中的 `ReportModal` 与命中明细 `NModal`。
- 依赖 `useLyStore`(仅 loading 展示可选)、`useUserStore`(审核 reviewedBy)、`lyEventPushToAi`、`lyEventReview`、`message`、`utils/ly` 的 `formatBytes/formatTimestamp/paginate`。

**分页归属**：由组件内部管理（每个使用方传全量已筛选 `rows`，组件负责分页与 `NPagination`）。

**auto 分析**：`onMounted` 时若 `autoAnalyze` 为 true，`void analyzeHistorySequentially()`（遍历 `props.rows`）。

## 4. 事件列表页 `views/ly/event/list/index.vue`

- 保留：筛选区（处理状态/活跃/资产/排行 toggle 与排行卡）、`baseRows/filteredRows`、`assetOptions/loadAssets`、`rankFilter/clearRankFilter` 等。
- 移除：迁入 `LyEventTable` 的所有表格/行为/弹窗代码与相关 import。
- 表格区替换为：`<LyEventTable :rows="filteredRows" :auto-analyze="true" />`。
- 行为与现状一致（自动预分析、审核、命中明细、查看报告均保留）。
- `onMounted` 保留 `loadEvents()` 与 `loadAssets()`；`analyzeHistorySequentially` 交由组件（autoAnalyze）执行，页面不再直接调用。

## 5. 搜索页 `views/ly/search/index.vue`

- 表单：删除「设备ID」`NInput`，新增「资产」`NSelect`（`form.asset` 存资产地址；选项来自 `lyAssetList`，label=`名称（地址）`，value=`address`；clearable+filterable）。保留 关键字 + 起止时间。
- `runSearch`：现有 `lyEventSearch(query)`（保留 keyword/时间参数）→ `normalizeLyEvents` → 现有 keyword 前端过滤 → **若 `form.asset` 非空再按 `assetMatchesEvent({address: form.asset}, item)` 过滤**。结果存 `state.rows`。
  - 说明：后端 `lyEventSearch` 不识别资产参数，资产过滤在前端做（与事件列表一致）。query 不再传 devid。
- 结果区替换为：`<LyEventTable :rows="state.rows" :show-desc="true" :auto-analyze="false" />`（去掉旧 `columns`、旧 `NDataTable`、旧分页——分页由组件内置）。
- `onMounted` 深链：保留 keyword/时间自动检索；`devid` 相关读取删除，改读 `q.asset`（可选，从事件列表「查看」或资产页跳转带入）。

## 6. 组件复用后的 import 去重

- 事件列表页移除仅表格用到的 import（`NModal`、`ReportModal`、`lyEventPushToAi`、`lyEventReview`、`useUserStore`、`formatBytes`、`formatTimestamp` 等——凡迁入组件的）。保留筛选/排行/资产仍需的（`NSelect/NCheckbox/NTag/countByKey/paginate?`）。`paginate` 若页面不再直接用则移除。
- 搜索页移除旧 `columns` 相关 import（`NDataTable` 若不再直接用则移除；`h`、`paginate`、`normalizeLyEvents` 视情况）。

## 7. 测试

- typecheck：三个文件（组件 + 两页）无新增类型错误。
- 手工验证（重点防事件列表回归）：
  - 事件列表：类型/威胁来源/受害目标/严重程度/命中频次(明细弹窗)/分析状态/审核状态/发生时间/操作(查看报告·审核·驳回) 全部与改动前一致；排行筛选、资产筛选、处理状态/活跃筛选、分页正常；挂载自动预分析仍生效。
  - 搜索页：资产下拉出现且可筛选；选资产+关键字+时间检索后，结果表与事件列表一致（含描述列）；点查看报告/审核可用；不自动批量分析。

## 8. 不做的事（YAGNI）

- 不改后端、不加后端资产查询参数（资产过滤前端做）。
- 不把分页/筛选状态在两页间共享（各页独立）。
- 不改事件列表现有筛选/排行逻辑（仅把表格抽走）。
- 不做搜索页的排行卡/资产 toggle（那是事件列表的；搜索页只加资产下拉）。
