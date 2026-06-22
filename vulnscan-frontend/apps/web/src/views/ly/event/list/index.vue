<script lang="ts" setup>
import { h, onMounted, reactive, ref, computed, watch } from 'vue';
import { useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NPagination,
  NSelect,
  NSpace,
  NTag,
} from 'naive-ui';

import { lyEventPushToAi } from '#/api/ly';
import { message } from '#/adapter/naive';
import { useLyStore } from '#/store/ly';
import { countByKey, paginate } from '#/utils/ly';

import ReportModal from '../detail/components/ReportModal.vue';

defineOptions({ name: 'LyEventList' });

const router = useRouter();
const lyStore = useLyStore();

// 查看报告弹窗（替代原来的整页跳转）
const reportVisible = ref(false);
const reportEventId = ref('');
const reportContext = ref<Record<string, any>>({});
const state = reactive({
  analyzingIds: new Set<string>(),
  page: 1,
  pageSize: 10,
  proc_status: '',
  is_alive: '' as '' | 'false' | 'true',
});

const filteredRows = computed(() => {
  return (lyStore.events || []).filter((item) => {
    if (state.proc_status && item.proc_status !== state.proc_status) return false;
    if (state.is_alive) {
      const alive = String(item.is_alive) === state.is_alive;
      if (!alive) return false;
    }
    return true;
  });
});
const pagedRows = computed(() => paginate(filteredRows.value, state.page, state.pageSize));
const attackRank = computed(() => countByKey(filteredRows.value, 'attackDevice').slice(0, 8));
const victimRank = computed(() => countByKey(filteredRows.value, 'victimDevice').slice(0, 8));
const typeRank = computed(() => countByKey(filteredRows.value, 'typeText').slice(0, 8));

watch(filteredRows, () => {
  const max = Math.max(1, Math.ceil(filteredRows.value.length / state.pageSize));
  if (state.page > max) state.page = max;
});

function rankFilter(key: string, value: string) {
  if (key === 'typeText') {
    const row = (lyStore.events || []).find((item) => item.typeText === value);
    if (row) router.push({ path: '/ly/search', query: { keyword: row.type } });
    return;
  }
  router.push({ path: '/ly/search', query: { keyword: value } });
}

function buildAnalysisPayload(row: Record<string, any>) {
  return {
    detail_type: String(row.type || '').toUpperCase(),
    duration: row.durationText || '',
    event_level: row.levelText || '',
    // event_type 必须是稳定的“类型代码”(用于聚合指纹)，中文标签另放 event_type_name；
    // 否则研判重推会因“标签≠代码”算出不同指纹、被错误新建为重复事件。
    event_type: String(row.type || ''),
    event_type_name: row.type === 'mo' ? '追踪事件' : row.typeText || '',
    id: `#${row.id}`,
    is_active: row.aliveText || '',
    method: row.show_model || '',
    occurrence_time: row.startTimeText || '',
    // 命中频次取代原 processing_status：描述是否在某段时间内多次命中，
    // 并附结构化聚合字段供后续分析使用。
    hit_frequency: row.hitFrequencyText || '单次',
    hit_count: Number(row.eventCount || 1),
    first_time: row.firstTimeText || '',
    last_time: row.lastTimeText || '',
    is_final: Boolean(row.isFinal),
    aggregation_status: row.isFinal ? 'closed' : 'active',
    // 标记为研判复用请求：后端据此不把本次重推计为一次新命中（避免虚增频次/重置收敛）
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
  for (const row of lyStore.events || []) {
    if (row.analysisStatus === 'completed') continue;
    try {
      await ensureAnalysis(row);
    } catch {
      // 保留行级状态，继续处理后续历史事件。
    }
  }
}

async function openAiDetail(row: Record<string, any>) {
  const payload = {
    ...buildAnalysisPayload(row),
  };
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

const columns = [
  { title: '事件类型', key: 'typeText', minWidth: 120 },
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
    width: 200,
    render: (row: Record<string, any>) => {
      const tags = [
        h(
          NTag,
          { size: 'small', type: row.hitFrequencyLevel || 'default' },
          { default: () => row.hitFrequencyText || '单次' },
        ),
      ];
      if (row.aggregationStatusText) {
        tags.push(
          h(
            NTag,
            {
              size: 'small',
              type: row.isFinal ? 'success' : 'info',
              style: 'margin-left:4px',
            },
            { default: () => row.aggregationStatusText },
          ),
        );
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;gap:4px' }, tags);
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
    width: 120,
    render: (row: Record<string, any>) => h(NButton, {
      text: true,
      type: 'success',
      loading: state.analyzingIds.has(String(row.id)),
      onClick: () => openAiDetail(row),
    }, { default: () => '查看报告' }),
  },
];

onMounted(async () => {
  if (!lyStore.events.length) {
    await lyStore.loadEvents();
  }
  void analyzeHistorySequentially();
});
</script>

<template>
  <div class="ly-page">
    <NSpace vertical :size="12">
      <NCard title="事件排行筛选" size="small">
        <div class="rank-grid">
          <div>
            <div class="rank-title">威胁来源</div>
            <NSpace>
              <NTag v-for="item in attackRank" :key="item.name" size="small" @click="rankFilter('attackDevice', item.name)">
                {{ item.name }} ({{ item.value }})
              </NTag>
            </NSpace>
          </div>
          <div>
            <div class="rank-title">受害目标</div>
            <NSpace>
              <NTag v-for="item in victimRank" :key="item.name" size="small" type="success" @click="rankFilter('victimDevice', item.name)">
                {{ item.name }} ({{ item.value }})
              </NTag>
            </NSpace>
          </div>
          <div>
            <div class="rank-title">事件类型</div>
            <NSpace>
              <NTag v-for="item in typeRank" :key="item.name" size="small" type="warning" @click="rankFilter('typeText', item.name)">
                {{ item.name }} ({{ item.value }})
              </NTag>
            </NSpace>
          </div>
        </div>
      </NCard>

      <NCard size="small">
        <NSpace>
          <NSelect v-model:value="state.proc_status" clearable placeholder="处理状态" :options="[{ label: '未处理', value: 'unprocessed' }, { label: '已处理', value: 'processed' }, { label: '已确认', value: 'assigned' }]" style="width: 160px" />
          <NSelect v-model:value="state.is_alive" clearable placeholder="活跃状态" :options="[{ label: '活跃', value: 'true' }, { label: '不活跃', value: 'false' }]" style="width: 160px" />
          <NButton type="primary" @click="lyStore.loadEvents()">刷新</NButton>
        </NSpace>
      </NCard>

      <NCard size="small">
        <NDataTable :columns="columns" :data="pagedRows" :loading="lyStore.loading" :bordered="false" size="small" />
        <div class="pager-wrap">
          <NPagination v-model:page="state.page" v-model:page-size="state.pageSize" :item-count="filteredRows.length" show-size-picker :page-sizes="[10, 20, 50, 100]" />
        </div>
      </NCard>
    </NSpace>

    <ReportModal
      v-model:visible="reportVisible"
      :event-id="reportEventId"
      :context="reportContext"
    />
  </div>
</template>

<style scoped>
.ly-page { padding: 12px; }
.rank-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
.rank-title { margin-bottom: 8px; font-weight: 600; }
.pager-wrap { display: flex; justify-content: flex-end; margin-top: 12px; }
</style>
