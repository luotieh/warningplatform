# 事件/搜索列表视觉增强（LyEventTable）Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 增强共享组件 LyEventTable 的单行表格视觉（严重色条/来源→目标箭头/类型图标/频次⚡/状态 pill/hover），事件列表与搜索页同时生效；交互与逻辑零变化。

**Architecture:** 只改 `LyEventTable.vue`：加 IconifyIcon + severityMeta/typeIcon/rowClass 辅助；重写 `columns` computed（合并来源→目标、加图标与 pill）；NDataTable 加 `:row-class-name`；加 scoped CSS。

**Tech Stack:** Vue3 + naive-ui + `@vben/icons`（IconifyIcon/lucide）。

## Global Constraints

- **仅修改** `vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`。不动其它文件、不改后端。
- 纯呈现层：不改列数据来源、分页、AI 报告/审核/命中明细逻辑与 props。
- 图标复用 `import { IconifyIcon } from '@vben/icons';`（勿引入新依赖）。
- 保留列：事件类型/[描述(showDesc)]/来源→目标/严重程度/命中频次/分析状态/审核状态/发生时间/操作(三按钮)。
- 前端 typecheck：`pnpm --filter @vben/web-template run typecheck`。

---

### Task 1: LyEventTable 视觉增强

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`

**Interfaces:**
- Produces（组件内私有）：`severityMeta(levelText)`, `typeIcon(type)`, `rowClass(row)`, `TYPE_ICONS`。

- [ ] **Step 1: 加 import 与辅助函数**

`<script setup>` 顶部 import 增加：

```ts
import { IconifyIcon } from '@vben/icons';
```

在 `columns` 定义之前新增辅助（放在 reviewEvent 之后、columns 之前）：

```ts
function severityMeta(levelText?: string): { color: string; key: string } {
  switch (levelText) {
    case '极高': return { color: '#d03050', key: 'critical' };
    case '高': return { color: '#f0a020', key: 'high' };
    case '中': return { color: '#2080f0', key: 'medium' };
    default: return { color: '#909399', key: 'low' };
  }
}

const TYPE_ICONS: Record<string, string> = {
  scan: 'lucide:radar', port_scan: 'lucide:radar', ip_scan: 'lucide:radar', mo: 'lucide:radar',
  dns: 'lucide:globe', dns_tun: 'lucide:globe',
  frn_trip: 'lucide:arrow-up-right',
  mining: 'lucide:pickaxe',
  black: 'lucide:ban', ti: 'lucide:crosshair', dga: 'lucide:shuffle',
  icmp_tun: 'lucide:waves', cap: 'lucide:package-search',
  sus: 'lucide:triangle-alert', srv: 'lucide:server',
};
function typeIcon(type?: string): string {
  return TYPE_ICONS[String(type ?? '')] ?? 'lucide:shield-alert';
}

function rowClass(row: Record<string, any>): string {
  return `sev-${severityMeta(row.levelText).key}`;
}
```

- [ ] **Step 2: 重写 columns computed**

把现有 `const columns = computed(() => [ ... ]);` 整体替换为下面版本（保留所有 render 内的处理逻辑，仅调整呈现；操作列、命中明细按钮、时间区间、分析/审核语义均不变）：

```ts
const columns = computed(() => [
  {
    title: '事件类型',
    key: 'typeText',
    minWidth: 150,
    render: (row: Record<string, any>) =>
      h('div', { style: 'display:flex;align-items:center;gap:6px' }, [
        h(IconifyIcon, { icon: typeIcon(row.type), style: 'font-size:16px;color:#909399;flex:none' }),
        h('span', row.typeText || '-'),
      ]),
  },
  ...(props.showDesc
    ? [{ title: '描述', key: 'desc', minWidth: 200, ellipsis: { tooltip: true } }]
    : []),
  {
    title: '来源 → 目标',
    key: 'flow',
    minWidth: 260,
    render: (row: Record<string, any>) =>
      h('div', { style: 'display:flex;align-items:center;gap:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace' }, [
        h('span', { style: 'color:#d03050' }, row.attackDevice || '-'),
        h(IconifyIcon, { icon: 'lucide:move-right', style: 'font-size:15px;color:#909399;flex:none' }),
        h('span', { style: 'color:#2080f0' }, row.victimDevice || '-'),
      ]),
  },
  {
    title: '严重程度',
    key: 'levelText',
    width: 110,
    render: (row: Record<string, any>) => {
      const m = severityMeta(row.levelText);
      return h('div', { style: 'display:flex;align-items:center;gap:6px' }, [
        h('span', { class: 'ly-dot', style: `background:${m.color}` }),
        h('span', row.levelText || '-'),
      ]);
    },
  },
  {
    title: '命中频次',
    key: 'hitFrequencyText',
    width: 240,
    render: (row: Record<string, any>) => {
      const high = row.hitFrequencyLevel === 'error' || row.hitFrequencyLevel === 'warning';
      const children: any[] = [
        h(NTag, { size: 'small', round: true, type: row.hitFrequencyLevel || 'default' }, {
          default: () =>
            high
              ? h('span', { style: 'display:inline-flex;align-items:center;gap:2px' }, [
                  h(IconifyIcon, { icon: 'lucide:zap' }),
                  row.hitFrequencyText || '单次',
                ])
              : (row.hitFrequencyText || '单次'),
        }),
      ];
      if (row.aggregationStatusText) {
        children.push(
          h(NTag, { size: 'small', round: true, type: row.isFinal ? 'success' : 'info', style: 'margin-left:4px' }, { default: () => row.aggregationStatusText }),
        );
      }
      if (Array.isArray(row.occurrences) && row.occurrences.length > 0) {
        children.push(
          h(NButton, { text: true, size: 'small', type: 'primary', style: 'margin-left:8px', onClick: () => openOccurrences(row) }, { default: () => '明细' }),
        );
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;align-items:center;gap:4px' }, children);
    },
  },
  {
    title: '分析状态',
    key: 'analysisStatusText',
    width: 130,
    render: (row: Record<string, any>) => {
      const analyzing = state.analyzingIds.has(String(row.id));
      const status = analyzing ? 'processing' : row.analysisStatus;
      const type = status === 'completed' ? 'success' : status === 'failed' || status === 'llm_config_required' ? 'error' : status === 'processing' ? 'warning' : 'default';
      const text = analyzing ? '分析中' : row.analysisStatusText || '待分析';
      return h(NTag, { size: 'small', round: true, bordered: true, type }, { default: () => text });
    },
  },
  {
    title: '审核状态',
    key: 'review_status',
    width: 150,
    render: (row: Record<string, any>) => {
      const meta = reviewStatusMeta(row);
      const tags = [h(NTag, { size: 'small', round: true, bordered: true, type: meta.type as any }, { default: () => meta.text })];
      if (row.circular_code) {
        tags.push(h(NTag, { size: 'small', round: true, type: 'info', style: 'margin-left:4px' }, { default: () => row.circular_code }));
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;gap:4px' }, tags);
    },
  },
  {
    title: '发生时间',
    key: 'startTimeText',
    minWidth: 180,
    render: (row: Record<string, any>) => {
      const n = Number(row.eventCount || 1);
      if (n > 1 && row.lastTimeText && row.lastTimeText !== row.firstTimeText) {
        return h('span', `${row.firstTimeText} ~ ${row.lastTimeText}`);
      }
      return h('span', row.firstTimeText || row.startTimeText || '-');
    },
  },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    render: (row: Record<string, any>) => {
      const canReview = row.analysisStatus === 'completed';
      const reviewed = row.review_status === 'approved';
      return h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, { text: true, type: 'success', loading: state.analyzingIds.has(String(row.id)), onClick: () => openAiDetail(row) }, { default: () => '查看报告' }),
          h(NButton, { text: true, type: 'primary', disabled: !canReview || reviewed, onClick: () => reviewEvent(row, 'approve') }, { default: () => '审核通过' }),
          h(NButton, { text: true, type: 'error', disabled: !canReview || reviewed, onClick: () => reviewEvent(row, 'reject') }, { default: () => '驳回' }),
        ],
      });
    },
  },
]);
```

- [ ] **Step 3: 模板加 row-class-name + CSS**

模板里 `NDataTable`（表格那一个，非命中明细弹窗内的）加 `:row-class-name="rowClass"`：

```vue
    <NDataTable :columns="columns" :data="pagedRows" :loading="props.loading" :bordered="false" size="small" :row-class-name="rowClass" />
```

`<style scoped>` 追加：

```css
.ly-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; flex: none; }
:deep(.n-data-table-tr.sev-critical .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #d03050; }
:deep(.n-data-table-tr.sev-high .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #f0a020; }
:deep(.n-data-table-tr.sev-medium .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #2080f0; }
:deep(.n-data-table-tr.sev-low .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #909399; }
:deep(.n-data-table-td) { padding-top: 10px; padding-bottom: 10px; }
:deep(.n-data-table-th) { font-weight: 600; }
```

- [ ] **Step 4: typecheck**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template run typecheck`
Expected: `src/views/ly/event/components/` 无新增类型错误（存量无关模块错误忽略）。

- [ ] **Step 5: 手工验证**

事件列表与搜索页表格呈现新样式：类型带图标、来源→目标带箭头且颜色区分、严重程度圆点 + 整行左色条、命中频次高频带⚡、分析/审核为圆角 pill、行距更舒展；所有操作（查看报告/审核/驳回/命中明细/分页/排行·资产筛选）功能不变；搜索页描述列在。

- [ ] **Step 6: 提交**

```bash
git add vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue
git commit -m "feat(traffic-frontend): 事件/搜索列表视觉增强(严重色条/来源→目标/图标/pill)"
```

---

## Self-Review

**1. Spec coverage:** §3.1 严重+色条→Step 1/2/3；§3.2 来源→目标→Step 2；§3.3 类型图标→Step 1/2；§3.4 频次⚡→Step 2；§3.5 状态 pill→Step 2；§3.6 行样式→Step 3；§3.7 保持不变（操作/明细/分页/props/描述列）→Step 2 原样保留。✓

**2. Placeholder scan:** 无 TBD；columns 与 CSS 给完整代码，helpers 完整。✓

**3. Type consistency:** `severityMeta/typeIcon/rowClass/TYPE_ICONS` Step 1 定义、Step 2/3 使用一致；`IconifyIcon` 用 `h(IconifyIcon, { icon })`（与 site-monitor 等既有用法一致）；render 内引用的 `state.analyzingIds/openOccurrences/openAiDetail/reviewEvent/reviewStatusMeta` 均为组件既有成员，未改签名。✓
