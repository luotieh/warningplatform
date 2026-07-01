# 搜索页资产化 + 结果表复用事件列表 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 把事件列表表格抽成共享组件 `LyEventTable`，事件列表页复用它（行为不变）；搜索页把「设备ID」改为「资产下拉」并用同一组件展示结果（含描述列，不自动批量分析）。

**Architecture:** 新增 `views/ly/event/components/LyEventTable.vue`（表格+行为+弹窗+分页，props: rows/showDesc/autoAnalyze/loading/pageSize）。事件列表页保留筛选/排行、表格换成组件（autoAnalyze=true）。搜索页表单资产化、结果按资产过滤、用组件（showDesc=true, autoAnalyze=false）。

**Tech Stack:** Vue3 + naive-ui（vben admin）。

## Global Constraints

- **仅修改流量分析前端**：`vulnscan-frontend/apps/web/src/views/ly/**`（新增组件 + 事件列表页 + 搜索页）。不动后端、不动其它模块。
- 分支：`trafficanalysis`。
- 事件列表抽取后**行为必须与现状一致**（列/操作/命中明细/审核/自动预分析/排行与资产筛选/分页）。
- 搜索页 `autoAnalyze=false`（不在挂载时批量调 LLM）。
- 前端 typecheck：`pnpm --filter @vben/web-template run typecheck`（vitest 环境不可用，本功能靠 typecheck + 手工验证）。

---

### Task 1: 抽取 LyEventTable 组件并改造事件列表页

新建共享表格组件，事件列表页改用它，保持行为不变。

**Files:**
- Create: `vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`
- Modify: `vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue`

**Interfaces:**
- Produces: 组件 `LyEventTable`，props `{ rows: Record<string,any>[]; showDesc?: boolean; autoAnalyze?: boolean; loading?: boolean; pageSize?: number }`。内部管理分页、AI 报告、审核、命中明细弹窗。

- [ ] **Step 1: 新建 LyEventTable.vue（完整内容）**

写入 `vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`：

```vue
<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref, watch } from 'vue';

import { NButton, NDataTable, NModal, NPagination, NSpace, NTag } from 'naive-ui';

import { useUserStore } from '@vben/stores';

import { lyEventPushToAi, lyEventReview } from '#/api/ly';
import { message } from '#/adapter/naive';
import { formatBytes, formatTimestamp, paginate } from '#/utils/ly';

import ReportModal from '../detail/components/ReportModal.vue';

defineOptions({ name: 'LyEventTable' });

const props = withDefaults(
  defineProps<{
    rows: Record<string, any>[];
    showDesc?: boolean;
    autoAnalyze?: boolean;
    loading?: boolean;
    pageSize?: number;
  }>(),
  { showDesc: false, autoAnalyze: false, loading: false, pageSize: 10 },
);

const userStore = useUserStore();

const reportVisible = ref(false);
const reportEventId = ref('');
const reportContext = ref<Record<string, any>>({});

const state = reactive({
  analyzingIds: new Set<string>(),
  page: 1,
  pageSize: props.pageSize,
});

const pagedRows = computed(() => paginate(props.rows, state.page, state.pageSize));

watch(
  () => props.rows.length,
  () => {
    const max = Math.max(1, Math.ceil(props.rows.length / state.pageSize));
    if (state.page > max) state.page = max;
  },
);

const occVisible = ref(false);
const occRows = ref<Array<{ idx: number; time: string; size: string; packets: string }>>([]);

function buildOccRows(occ: any[]) {
  return (occ || []).map((o, i) => {
    const item = typeof o === 'string' ? { time: o } : (o ?? {});
    return {
      idx: i + 1,
      time: formatTimestamp(item.time) || '-',
      size: item.wire_bytes == null ? '-' : formatBytes(item.wire_bytes),
      packets: item.packets == null ? '-' : String(item.packets),
    };
  });
}

function openOccurrences(row: Record<string, any>) {
  occRows.value = buildOccRows(row.occurrences || []);
  occVisible.value = true;
}

const occColumns = [
  { title: '序号', key: 'idx', width: 70 },
  { title: '命中时间', key: 'time', minWidth: 180 },
  { title: '数据包大小', key: 'size', width: 120 },
  { title: '包数', key: 'packets', width: 90 },
];

function buildAnalysisPayload(row: Record<string, any>) {
  return {
    detail_type: String(row.type || '').toUpperCase(),
    duration: row.durationText || '',
    event_level: row.levelText || '',
    event_type: String(row.type || ''),
    event_type_name: row.type === 'mo' ? '追踪事件' : row.typeText || '',
    id: `#${row.id}`,
    is_active: row.aliveText || '',
    method: row.show_model || '',
    occurrence_time: row.startTimeText || '',
    hit_frequency: row.hitFrequencyText || '单次',
    hit_count: Number(row.eventCount || 1),
    first_time: row.firstTimeText || '',
    last_time: row.lastTimeText || '',
    is_final: Boolean(row.isFinal),
    aggregation_status: row.isFinal ? 'closed' : 'active',
    analysis_only: true,
    rule_desc: row.desc || '',
    threat_source: row.attackDevice || '',
    victim_target: row.victimDevice || '',
  };
}

async function ensureAnalysis(row: Record<string, any>) {
  const rowId = String(row.id);
  if (!rowId || state.analyzingIds.has(rowId)) {
    return String(row.event_id || row.deepsoc_event_id || row.id || '');
  }
  if (row.analysisStatus === 'completed' && (row.event_id || row.deepsoc_event_id)) {
    return String(row.event_id || row.deepsoc_event_id);
  }
  state.analyzingIds.add(rowId);
  state.analyzingIds = new Set(state.analyzingIds);
  try {
    const res = await lyEventPushToAi(buildAnalysisPayload(row));
    const data = res?.data && typeof res.data === 'object' ? res.data : res;
    const deepflowEventId = String(data?.deepsoc_event_id || data?.event_id || row.event_id || row.id || '');
    row.event_id = deepflowEventId;
    row.deepsoc_event_id = deepflowEventId;
    row.analysisStatus = 'completed';
    row.analysisStatusText = '已生成';
    return deepflowEventId;
  } catch (error) {
    row.analysisStatus = 'failed';
    row.analysisStatusText = '分析失败';
    throw error;
  } finally {
    state.analyzingIds.delete(rowId);
    state.analyzingIds = new Set(state.analyzingIds);
  }
}

async function analyzeHistorySequentially() {
  for (const row of props.rows || []) {
    if (row.analysisStatus === 'completed') continue;
    try {
      await ensureAnalysis(row);
    } catch {
      // 保留行级状态，继续处理后续历史事件。
    }
  }
}

async function openAiDetail(row: Record<string, any>) {
  const payload = { ...buildAnalysisPayload(row) };
  const eventId = String(row.id);
  let deepflowEventId = '';
  try {
    deepflowEventId = await ensureAnalysis(row);
  } catch (error) {
    message.error(error instanceof Error ? error.message : '报告尚未生成，请检查服务和LLM配置');
    return;
  }
  reportEventId.value = deepflowEventId || eventId;
  reportContext.value = { ...payload };
  reportVisible.value = true;
}

function reviewStatusMeta(row: Record<string, any>): { text: string; type: string } {
  const map: Record<string, { text: string; type: string }> = {
    approved: { text: '已通过', type: 'success' },
    rejected: { text: '已驳回', type: 'error' },
    pending_review: { text: '待审核', type: 'warning' },
  };
  if (row.review_status && map[row.review_status]) return map[row.review_status]!;
  if (row.analysisStatus === 'completed') return map.pending_review!;
  return { text: '—', type: 'default' };
}

async function reviewEvent(row: Record<string, any>, action: 'approve' | 'reject') {
  const eventId = String(row.event_id || row.deepsoc_event_id || row.id || '');
  if (!eventId) {
    message.error('事件尚未生成分析，无法审核');
    return;
  }
  if (row.analysisStatus !== 'completed') {
    message.error('仅 AI 分析完成的事件可审核');
    return;
  }
  try {
    const res = await lyEventReview({ eventId, action, reviewedBy: userStore.userInfo?.realName || userStore.userInfo?.username || '' });
    row.review_status = res?.review_status || (action === 'approve' ? 'approved' : 'rejected');
    if (res?.circular_code) row.circular_code = res.circular_code;
    message.success(action === 'approve' ? `已推送通报处置${res?.circular_code ? '：' + res.circular_code : ''}` : '已驳回');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '审核失败');
  }
}

const columns = computed(() => [
  { title: '事件类型', key: 'typeText', minWidth: 120 },
  ...(props.showDesc
    ? [{ title: '描述', key: 'desc', minWidth: 200, ellipsis: { tooltip: true } }]
    : []),
  { title: '威胁来源', key: 'attackDevice', minWidth: 160 },
  { title: '受害目标', key: 'victimDevice', minWidth: 160 },
  {
    title: '严重程度',
    key: 'levelText',
    width: 100,
    render: (row: Record<string, any>) => h(NTag, { size: 'small', type: row.levelText === '极高' ? 'error' : row.levelText === '高' ? 'warning' : 'default' }, { default: () => row.levelText }),
  },
  {
    title: '命中频次',
    key: 'hitFrequencyText',
    width: 240,
    render: (row: Record<string, any>) => {
      const tags = [
        h(NTag, { size: 'small', type: row.hitFrequencyLevel || 'default' }, { default: () => row.hitFrequencyText || '单次' }),
      ];
      if (row.aggregationStatusText) {
        tags.push(h(NTag, { size: 'small', type: row.isFinal ? 'success' : 'info', style: 'margin-left:4px' }, { default: () => row.aggregationStatusText }));
      }
      if (Array.isArray(row.occurrences) && row.occurrences.length > 0) {
        tags.push(h(NButton, { text: true, size: 'small', type: 'primary', style: 'margin-left:8px', onClick: () => openOccurrences(row) }, { default: () => '明细' }));
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;align-items:center;gap:4px' }, tags);
    },
  },
  {
    title: '分析状态',
    key: 'analysisStatusText',
    width: 120,
    render: (row: Record<string, any>) => {
      const analyzing = state.analyzingIds.has(String(row.id));
      const status = analyzing ? 'processing' : row.analysisStatus;
      const type = status === 'completed' ? 'success' : status === 'failed' || status === 'llm_config_required' ? 'error' : status === 'processing' ? 'warning' : 'default';
      const text = analyzing ? '分析中' : row.analysisStatusText || '待分析';
      return h(NTag, { size: 'small', type }, { default: () => text });
    },
  },
  {
    title: '审核状态',
    key: 'review_status',
    width: 140,
    render: (row: Record<string, any>) => {
      const meta = reviewStatusMeta(row);
      const tags = [h(NTag, { size: 'small', type: meta.type as any }, { default: () => meta.text })];
      if (row.circular_code) {
        tags.push(h(NTag, { size: 'small', type: 'info', style: 'margin-left:4px' }, { default: () => row.circular_code }));
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

onMounted(() => {
  if (props.autoAnalyze) void analyzeHistorySequentially();
});
</script>

<template>
  <div>
    <NDataTable :columns="columns" :data="pagedRows" :loading="props.loading" :bordered="false" size="small" />
    <div class="pager-wrap">
      <NPagination v-model:page="state.page" v-model:page-size="state.pageSize" :item-count="props.rows.length" show-size-picker :page-sizes="[10, 20, 50, 100]" />
    </div>

    <ReportModal v-model:visible="reportVisible" :event-id="reportEventId" :context="reportContext" />

    <NModal v-model:show="occVisible" preset="card" title="命中明细" style="width: 640px; max-width: 90vw">
      <NDataTable :columns="occColumns" :data="occRows" size="small" :max-height="420" :bordered="false" />
    </NModal>
  </div>
</template>

<style scoped>
.pager-wrap { display: flex; justify-content: flex-end; margin-top: 12px; }
</style>
```

- [ ] **Step 2: 改造事件列表页 `list/index.vue`**

删除已迁入组件的代码，改用组件。具体：

1. **import 区**：删除 `NDataTable`、`NModal`、`NPagination`（如果仅表格用）从 naive-ui import（保留 `NButton, NCard, NCheckbox, NSelect, NSpace, NTag`）；删除 `import { useUserStore } from '@vben/stores';`、`import { lyEventPushToAi, lyEventReview } from '#/api/ly';`、`import ReportModal from '../detail/components/ReportModal.vue';`；把 `import { countByKey, formatBytes, formatTimestamp, paginate } from '#/utils/ly';` 改为 `import { countByKey } from '#/utils/ly';`（页面不再直接用 paginate/formatBytes/formatTimestamp）。新增：`import LyEventTable from '../components/LyEventTable.vue';`。`h` 若不再使用则从 `vue` import 移除（页面 render 已迁走）。保留 `computed, onMounted, reactive, ref, watch`（watch 若不再用可移除——见下）。

2. **删除脚本块**：删除 `const userStore = ...`；`reportVisible/reportEventId/reportContext`；`occVisible/occRows/buildOccRows/openOccurrences/occColumns`；`buildAnalysisPayload/ensureAnalysis/analyzeHistorySequentially/openAiDetail/reviewStatusMeta/reviewEvent`；整个 `const columns = [...]`；`const pagedRows = ...`。`state` 里删除 `analyzingIds/page/pageSize`（仅保留 `proc_status/is_alive/rankKey/rankValue`）。删除 `watch(filteredRows, ...)` 那个夹逼分页的 watch（分页移入组件）。

3. **保留**：`route/lyStore`；`assets/selectedAsset/onlyAssetRelated/assetOptions/loadAssets`；`baseRows/filteredRows`；`attackRank/victimRank/typeRank`；`RANK_LABELS/isRankActive/rankFilter/clearRankFilter`。

4. **onMounted** 改为（去掉 analyze 调用，交给组件）：
```ts
onMounted(async () => {
  if (!lyStore.events.length) {
    await lyStore.loadEvents();
  }
  void loadAssets();
});
```

5. **模板**：把「搜索结果」那张 `NCard`（含 `NDataTable`/`NPagination`）以及 `ReportModal`、命中明细 `NModal` 整块删除，替换为：
```vue
      <NCard size="small">
        <LyEventTable :rows="filteredRows" :auto-analyze="true" :loading="lyStore.loading" />
      </NCard>
```
（保留其上方的「事件排行筛选」NCard 与筛选 NCard 不变。）

6. **style**：`.pager-wrap` 若模板不再使用可删除（分页在组件内）；其余样式保留。

- [ ] **Step 3: typecheck**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template run typecheck`
Expected: `src/views/ly/event/` 无新增类型错误（存量无关模块错误忽略）。

- [ ] **Step 4: 手工验证事件列表零回归**

启动平台，事件列表：列（类型/威胁来源/受害目标/严重程度/命中频次+明细/分析状态/审核状态/发生时间/操作）与改动前一致；查看报告/审核通过/驳回、命中明细弹窗、排行筛选(toggle+高亮+清除)、资产筛选、处理状态/活跃筛选、分页、挂载自动预分析 均正常。

- [ ] **Step 5: 提交**

```bash
git add vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue
git commit -m "refactor(traffic-frontend): 抽取 LyEventTable 组件，事件列表复用"
```

---

### Task 2: 搜索页资产化 + 复用 LyEventTable

设备ID → 资产下拉；结果按资产过滤；结果表用 LyEventTable(showDesc, autoAnalyze=false)。

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/views/ly/search/index.vue`

**Interfaces:**
- Consumes: Task 1 组件 `LyEventTable`；`lyAssetList`（`#/api/ly/assets`）；`assetMatchesEvent`（`#/utils/ly-asset`）。

- [ ] **Step 1: 改造 search/index.vue（完整内容）**

写入 `vulnscan-frontend/apps/web/src/views/ly/search/index.vue`：

```vue
<script lang="ts" setup>
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';

import {
  NButton,
  NCard,
  NDatePicker,
  NForm,
  NFormItem,
  NInput,
  NSelect,
  NSpace,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { lyEventSearch } from '#/api/ly';
import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import { normalizeLyEvents } from '#/utils/ly';
import { assetMatchesEvent } from '#/utils/ly-asset';
import LyEventTable from '../event/components/LyEventTable.vue';

defineOptions({ name: 'LySearch' });

const route = useRoute();

const form = reactive({
  asset: '',
  keyword: '',
  starttime: null as null | number,
  endtime: null as null | number,
});

const assets = ref<LyAsset[]>([]);
const assetOptions = computed(() =>
  assets.value.map((a) => ({ label: `${a.name}（${a.address}）`, value: a.address })),
);

const state = reactive({
  loading: false,
  searched: false,
  rows: [] as Record<string, any>[],
});

async function loadAssets() {
  try {
    assets.value = (await lyAssetList()) || [];
  } catch {
    assets.value = [];
  }
}

async function runSearch() {
  state.loading = true;
  state.searched = true;
  try {
    const query: Record<string, any> = { keyword: form.keyword || undefined };
    if (form.starttime) query.starttime = Math.floor(form.starttime / 1000);
    if (form.endtime) query.endtime = Math.floor(form.endtime / 1000);
    const res = await lyEventSearch(query);
    const rows = Array.isArray(res) ? res : [];
    const keyword = String(form.keyword || '').trim().toLowerCase();
    const asset = form.asset;
    state.rows = normalizeLyEvents(rows).filter((item) => {
      if (keyword && !JSON.stringify(item).toLowerCase().includes(keyword)) return false;
      if (asset && !assetMatchesEvent({ address: asset }, item)) return false;
      return true;
    });
  } catch (error) {
    console.error('[ly] 搜索失败', error);
    message.error('搜索失败，请检查后端服务');
    state.rows = [];
  } finally {
    state.loading = false;
  }
}

function startSearch() {
  runSearch();
}

function resetSearch() {
  form.asset = '';
  form.keyword = '';
  form.starttime = null;
  form.endtime = null;
}

onMounted(() => {
  void loadAssets();
  const q = route.query as Record<string, any>;
  form.asset = String(q.asset ?? '');
  form.keyword = String(q.keyword ?? '');
  const startSec = Number(q.starttime);
  const endSec = Number(q.endtime);
  form.starttime = q.starttime && !Number.isNaN(startSec) ? startSec * 1000 : null;
  form.endtime = q.endtime && !Number.isNaN(endSec) ? endSec * 1000 : null;
  if (q.asset || q.keyword || q.starttime || q.endtime) {
    runSearch();
  }
});
</script>

<template>
  <div class="ly-page">
    <NCard title="全局搜索引擎" size="small" class="search-card">
      <NForm label-placement="left" label-width="90">
        <div class="form-grid">
          <NFormItem label="资产">
            <NSelect
              v-model:value="form.asset"
              clearable
              filterable
              placeholder="选择已登记资产"
              :options="assetOptions"
              class="full-input"
            />
          </NFormItem>
          <NFormItem label="关键字">
            <NInput v-model:value="form.keyword" placeholder="可选" />
          </NFormItem>
          <NFormItem label="开始时间">
            <NDatePicker v-model:value="form.starttime" type="datetime" clearable placeholder="选择开始时间" class="full-input" />
          </NFormItem>
          <NFormItem label="结束时间">
            <NDatePicker v-model:value="form.endtime" type="datetime" clearable placeholder="选择结束时间" class="full-input" />
          </NFormItem>
        </div>
      </NForm>
      <NSpace justify="center">
        <NButton type="primary" :loading="state.loading" @click="startSearch">搜索</NButton>
        <NButton @click="resetSearch">重置</NButton>
      </NSpace>
    </NCard>

    <NCard v-if="state.searched" class="result-card" title="搜索结果" size="small">
      <LyEventTable :rows="state.rows" :show-desc="true" :auto-analyze="false" :loading="state.loading" />
    </NCard>
  </div>
</template>

<style scoped>
.ly-page { min-height: 100%; padding: 16px; }
.search-card { margin-bottom: 16px; }
.form-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 0 16px; }
.full-input { width: 100%; }
.result-card :deep(.n-card__content) { padding: 18px; }
@media (max-width: 640px) {
  .ly-page { padding: 12px; }
  .form-grid { grid-template-columns: 1fr; }
}
</style>
```

- [ ] **Step 2: typecheck**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web-template run typecheck`
Expected: `src/views/ly/search/` 无新增类型错误。

- [ ] **Step 3: 手工验证**

总览 → 搜索 tab：表单第一项为「资产」下拉（选项来自已登记资产），不再有「设备ID」；选资产 + 关键字 + 时间后点搜索 → 结果表与事件列表一致（类型/威胁来源/受害目标/严重程度/命中频次+明细/分析状态/审核状态/发生时间/操作）且含「描述」列；点查看报告/审核可用；结果**不自动批量分析**（分析状态初始为待分析，点查看报告才生成）。从资产页/事件列表带 `?asset=` 跳入时自动检索。

- [ ] **Step 4: 提交**

```bash
git add vulnscan-frontend/apps/web/src/views/ly/search/index.vue
git commit -m "feat(traffic-frontend): 搜索页设备ID改为资产下拉，结果表复用 LyEventTable"
```

---

## Self-Review

**1. Spec coverage:**
- §3 LyEventTable 组件（props/迁移内容/内置分页/auto 分析）→ Task 1 Step 1。✓
- §4 事件列表页改造（保留筛选/排行，表格换组件，autoAnalyze=true，onMounted 去 analyze）→ Task 1 Step 2/4。✓
- §5 搜索页（资产下拉替 devid、资产过滤、组件 showDesc+autoAnalyze=false、深链读 asset）→ Task 2 Step 1。✓
- §6 import 去重 → Task 1 Step 2.1、Task 2 Step 1（整文件重写）。✓
- §7 测试（typecheck + 手工零回归/搜索）→ Task 1 Step 3/4、Task 2 Step 2/3。✓
- §8 YAGNI（不改后端/不共享状态/不改排行逻辑/搜索不加排行卡）→ 计划未涉及。✓

**2. Placeholder scan:** 无 TBD/TODO；组件与搜索页给完整文件内容，事件列表页为精确删除/替换指令（针对现有文件）。✓

**3. Type consistency:**
- `LyEventTable` props（rows/showDesc/autoAnalyze/loading/pageSize）— Task 1 定义、事件列表(rows/auto-analyze/loading)与搜索页(rows/show-desc/auto-analyze/loading)使用，一致。✓
- `assetMatchesEvent({address})` — Task 2 使用，签名与既有 `#/utils/ly-asset` 一致（前序功能已建）。✓
- `lyAssetList/LyAsset`、`normalizeLyEvents`、`lyEventSearch` — 均既有导出，签名不变。✓
- ReportModal 相对路径：组件在 `event/components/`，`../detail/components/ReportModal.vue` 正确（与 `event/list/` 同级 detail）。✓
