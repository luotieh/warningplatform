# 事件/搜索列表视觉增强（LyEventTable）设计

- 日期：2026-07-02
- 分支：`trafficanalysis`
- 约束：**仅修改 `vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`**（事件列表与搜索页共用此组件，改一处两处生效）。不动其它文件、不改后端。

## 1. 背景与目标

事件列表/搜索结果当前是朴素 naive-ui 表格，视觉「过于简陋」。在**保持单行表格布局与全部交互不变**的前提下做视觉增强（方案 C：改动最小）。图标用项目既有的 `IconifyIcon`（`@vben/icons`，lucide 图标集）。

## 2. 关键决策（已与用户确认）

- 方向 = 增强单行表格（不改为卡片/双行）。
- 操作列保持三个文字按钮（查看报告/审核通过/驳回），交互零变化。
- 纯呈现层：不改列数据来源、分页、AI 报告/审核/命中明细逻辑。
- 搜索页 `showDesc` 的「描述」列保留。

## 3. 具体增强项（均在 LyEventTable.vue）

### 3.1 严重程度 + 行左色条
- 列渲染：彩色圆点（CSS span）+ 文字。色彩映射：`极高→红(#d03050)`、`高→橙(#f0a020)`、`中→蓝(#2080f0)`、`低/其它→灰(#909399)`。
- 整行左侧加**严重程度色条**：`NDataTable :row-class-name`，返回 `sev-critical|sev-high|sev-medium|sev-low`；`<style>` 里 `:deep(.n-data-table-tr.sev-xxx .n-data-table-td:first-child){ box-shadow: inset 3px 0 <色> }`（或 border-left），使危急事件一眼可辨。
- 抽出 `severityMeta(levelText)` 返回 `{ color, key }` 供列与行类共用（DRY）。

### 3.2 来源 → 目标（合并列）
- 把「威胁来源」「受害目标」两列**合并为一列**`来源 → 目标`（minWidth 260）。
- 渲染：等宽字体，来源色 `#d03050`、目标色 `#2080f0`，中间 `h(IconifyIcon, { icon: 'lucide:move-right' })` 箭头；缺一侧显示 `-`。

### 3.3 事件类型图标
- 类型文字前加 `IconifyIcon`，按 `row.type` 映射 lucide 图标，未知回退 `lucide:shield-alert`。映射（覆盖 utils/ly 的 EVENT_TYPE_MAP 键，取常见者，其余走回退）：
  - `port_scan|ip_scan|scan → lucide:radar`
  - `dns|dns_tun → lucide:globe`
  - `frn_trip → lucide:arrow-up-right`
  - `mining → lucide:pickaxe`
  - `black → lucide:ban`；`ti → lucide:crosshair`；`dga → lucide:shuffle`；`icmp_tun → lucide:waves`；`mo → lucide:radar`；`cap → lucide:package-search`；`sus → lucide:alert-triangle`；`srv → lucide:server`
  - 其它 → `lucide:shield-alert`
- 图标颜色随严重程度（复用 severityMeta.color）或统一中性色（择一，实现取中性 `#909399` 以免与严重列重复视觉）。

### 3.4 命中频次
- 高频/多发（`row.hitFrequencyLevel` 为 error/warning）前加 `lucide:zap` 图标；保留收敛状态 tag 与「明细」按钮。单次不加图标。

### 3.5 分析状态 / 审核状态 → 圆角 pill
- 由现在的小方 tag 改为带前置圆点的圆角 pill：`NTag { round: true, bordered: true }` + 前置一个彩色 `●`（CSS span）。
- 颜色沿用现有语义：分析 completed→success/processing→warning/failed·llm_config_required→error/其它→default(待分析)；审核 approved→success/rejected→error/pending_review→warning/—→default。文案不变。

### 3.6 行/表样式
- `NDataTable` 开启 `:single-line="false"` 保持；增加行 hover 高亮、行高更舒展（td 垂直 padding 略增）、细分隔线、表头字重加粗。通过组件 `<style scoped>` + `:deep()` 实现，不影响其它页面表格。

### 3.7 保持不变
- 列：事件类型（含图标）/ [描述(showDesc)] / 来源→目标 / 严重程度 / 命中频次 / 分析状态 / 审核状态 / 发生时间 / 操作。
- 操作三按钮、命中明细弹窗、ReportModal、分页、props（rows/showDesc/autoAnalyze/loading/pageSize）、所有事件处理函数逻辑不变。

## 4. 实现要点

- `import { IconifyIcon } from '@vben/icons';`
- 图标在 render 中用 `h(IconifyIcon, { icon, style: '...' })`；与文字用 flex 容器包裹对齐。
- 严重程度/状态圆点用内联 `h('span', { class: 'dot', style: 'background:<色>' })` + scoped `.dot` 基础样式（圆、8px、inline-block、margin-right）。
- 色条 row-class-name 与 severityMeta 共用同一色值来源，避免不一致。

## 5. 测试

- typecheck：`pnpm --filter @vben/web-template run typecheck`，`views/ly/event/components` 无新增类型错误。
- 手工：事件列表与搜索页表格呈现新样式（严重色条/来源→目标箭头/类型图标/频次⚡/状态 pill/hover）；所有操作（查看报告/审核/驳回/命中明细/分页/排行·资产筛选）功能不变；搜索页描述列在。

## 6. 不做的事（YAGNI）

- 不改为卡片/双行布局；不折叠操作为下拉菜单。
- 不改后端、不改其它页面或组件、不动列数据来源与交互逻辑。
- 不引入新图标依赖（复用 `@vben/icons` 的 IconifyIcon）。
