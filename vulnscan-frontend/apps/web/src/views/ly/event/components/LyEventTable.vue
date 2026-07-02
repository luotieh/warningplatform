<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref, watch } from 'vue';

import { NButton, NDataTable, NModal, NPagination, NSpace, NTag } from 'naive-ui';

import { IconifyIcon } from '@vben/icons';
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

// 行集变化（筛选切换/新检索/刷新）时回到第 1 页，等价旧事件列表点排行即重置分页的行为。
watch(
  () => props.rows,
  () => {
    state.page = 1;
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

onMounted(() => {
  if (props.autoAnalyze) void analyzeHistorySequentially();
});
</script>

<template>
  <div>
    <NDataTable :columns="columns" :data="pagedRows" :loading="props.loading" :bordered="false" size="small" :row-class-name="rowClass" />
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
.ly-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; flex: none; }
:deep(.n-data-table-tr.sev-critical .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #d03050; }
:deep(.n-data-table-tr.sev-high .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #f0a020; }
:deep(.n-data-table-tr.sev-medium .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #2080f0; }
:deep(.n-data-table-tr.sev-low .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #909399; }
:deep(.n-data-table-td) { padding-top: 10px; padding-bottom: 10px; }
:deep(.n-data-table-th) { font-weight: 600; }
</style>
