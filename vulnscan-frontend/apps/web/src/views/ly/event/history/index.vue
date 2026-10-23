<script lang="ts" setup>
import { computed, onUnmounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { NAlert, NButton, NCard, NInput, NModal, NPagination, NSelect, NSpace, NTag } from 'naive-ui';
import { lyAssetList, type LyAsset } from '#/api/ly/assets';
import { deepflowGetEventsPage, deepflowGenerateHistoryReport, deepflowListHistoryReports, deepflowGetHistoryReport, type HistoryReportListItem, type HistoryComprehensiveReport } from '#/api/ly/deepflow';
import { markdownToHtml } from '#/utils/markdown';
import { normalizeLyEvents } from '#/utils/ly';
import { eventAssetNames } from '#/utils/ly-asset';
import LyEventTable from '../components/LyEventTable.vue';

defineOptions({ name: 'LyEventHistory' });
const route = useRoute();
const form = reactive({ ioc: '', type: '', victim: '', mode: 'same' });
const query = ref<Record<string, any> | null>(null);
const rows = ref<Record<string, any>[]>([]);
const assets = ref<LyAsset[]>([]);
const page = ref(1);
const pageSize = ref(20);
const total = ref(0);
const loading = ref(false);
const error = ref('');
const report = ref<HistoryComprehensiveReport | null>(null);
const reportVisible = ref(false);
const reportLoading = ref(false);
const reportError = ref('');
let reportRequestId = 0;
const savedReports = ref<HistoryReportListItem[]>([]);
const savedReportId = ref<string | null>(null);
const archiveError = ref('');
const archiveLoading = ref(false);
let archiveRequestId = 0;
const savedReportOptions = computed(() => savedReports.value.map((item) => ({
  value: item.report_id, label: `${item.generated_at} · ${item.event_count} 个事件`,
})));

async function loadSavedReports() {
  const id = ++archiveRequestId;
  if (!query.value) return;
  archiveLoading.value = true;
  archiveError.value = '';
  try {
    const result = await deepflowListHistoryReports({ ...query.value });
    if (id === archiveRequestId) savedReports.value = result;
  } catch (cause) {
    if (id === archiveRequestId) archiveError.value = cause instanceof Error ? cause.message : '已保存报告查询失败';
  } finally {
    if (id === archiveRequestId) archiveLoading.value = false;
  }
}

async function openSavedReport() {
  if (!savedReportId.value || reportLoading.value) return;
  const id = ++reportRequestId;
  reportVisible.value = true;
  reportLoading.value = true;
  reportError.value = '';
  try {
    const result = await deepflowGetHistoryReport(savedReportId.value);
    if (id === reportRequestId) report.value = result;
  } catch (cause) {
    if (id === reportRequestId) reportError.value = cause instanceof Error ? cause.message : '读取报告失败';
  } finally {
    if (id === reportRequestId) reportLoading.value = false;
  }
}

async function generateReport() {
  if (!query.value || reportLoading.value) return;
  const id = ++reportRequestId;
  const scope = { ...query.value };
  reportVisible.value = true;
  reportLoading.value = true;
  reportError.value = '';
  try {
    const result = await deepflowGenerateHistoryReport(scope);
    if (id !== reportRequestId) return;
    report.value = result;
    savedReportId.value = result.report_id;
    void loadSavedReports();
  } catch (cause) {
    if (id === reportRequestId) reportError.value = cause instanceof Error ? cause.message : '综合报告生成失败';
  } finally {
    if (id === reportRequestId) reportLoading.value = false;
  }
}

function downloadReport() {
  if (!report.value) return;
  const s = report.value.snapshot;
  const text = `# 历史事件综合报告\n\nIOC：${s.scope.ioc_value}\n被攻击方：${s.scope.victim || '全部'}\n生成时间：${s.generated_at}\n事件数：${s.event_count}\n\n${report.value.markdown}\n\n## 统计快照与来源索引\n\n\`\`\`json\n${JSON.stringify(s, null, 2)}\n\`\`\`\n`;
  const url = URL.createObjectURL(new Blob([text], { type: 'text/markdown;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = '历史事件综合报告.md';
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
let requestId = 0;
const displayRows = computed(() => rows.value.map((row) => ({
  ...row, assetText: eventAssetNames(row, assets.value).join('、') || '未登记',
})));

async function loadHistory() {
  if (!query.value) return;
  const id = ++requestId;
  loading.value = true;
  error.value = '';
  try {
    const params = { ...query.value, scope: 'all', page: page.value, page_size: pageSize.value };
    let result = await deepflowGetEventsPage(params);
    if (id !== requestId) return;
    const maxPage = Math.max(1, Math.ceil(result.total / pageSize.value));
    if (page.value > maxPage) {
      page.value = maxPage;
      result = await deepflowGetEventsPage({ ...params, page: maxPage });
      if (id !== requestId) return;
    }
    rows.value = normalizeLyEvents(result.items);
    total.value = result.total;
  } catch (cause) {
    if (id !== requestId) return;
    rows.value = [];
    total.value = 0;
    error.value = cause instanceof Error ? cause.message : '历史事件查询失败';
  } finally {
    if (id === requestId) loading.value = false;
  }
}

function search() {
  // 默认范围必须同时指定 IOC 和被攻击方，缺少目标时不静默放宽范围。
  if (!form.ioc.trim() || (form.mode === 'same' && !form.victim.trim())) return;
  ++reportRequestId;
  reportLoading.value = false;
  reportVisible.value = false;
  report.value = null;
  query.value = {
    ioc_value: form.ioc.trim(),
    ioc_type: form.type.trim(),
    ...(form.mode === 'same' ? { victim: form.victim.trim() } : {}),
  };
  savedReports.value = [];
  savedReportId.value = null;
  void loadSavedReports();
  page.value = 1;
  void loadHistory();
}

watch(() => [route.query.ioc_value, route.query.ioc_type, route.query.victim], () => {
  ++archiveRequestId;
  archiveLoading.value = false;
  savedReports.value = [];
  savedReportId.value = null;
  archiveError.value = '';
  ++reportRequestId;
  reportLoading.value = false;
  reportVisible.value = false;
  report.value = null;
  ++requestId;
  loading.value = false;
  query.value = null;
  rows.value = [];
  total.value = 0;
  error.value = '';
  form.ioc = typeof route.query.ioc_value === 'string' ? route.query.ioc_value : '';
  form.type = typeof route.query.ioc_type === 'string' ? route.query.ioc_type : '';
  form.victim = typeof route.query.victim === 'string' ? route.query.victim : '';
  form.mode = 'same';
  search();
}, { immediate: true });

function changeMode() { search(); }
function changePage(value: number) { page.value = value; void loadHistory(); }
function changePageSize(value: number) { pageSize.value = value; page.value = 1; void loadHistory(); }

void lyAssetList().then((result) => { assets.value = result || []; }).catch(() => {});
onUnmounted(() => { ++requestId; ++reportRequestId; ++archiveRequestId; });
</script>

<template>
  <div class="history-page">
    <NSpace vertical :size="12">
      <NCard title="IOC 历史事件查询" size="small">
        <NSpace>
          <NInput v-model:value="form.ioc" clearable placeholder="IOC 命中值（精确匹配）" style="width: 280px" @keyup.enter="search" />
          <NInput v-model:value="form.type" clearable placeholder="IOC 类型（可选）" style="width: 160px" @keyup.enter="search" />
          <NSelect
            v-model:value="form.mode"
            :options="[{ label: '同 IOC、同被攻击方', value: 'same' }, { label: '该 IOC 所有事件', value: 'all' }]"
            style="width: 220px"
            @update:value="changeMode"
          />
          <NInput v-model:value="form.victim" :disabled="form.mode === 'all'" clearable placeholder="被攻击方 IP / 域名" style="width: 240px" @keyup.enter="search" />
          <NButton type="primary" :loading="loading" :disabled="!form.ioc.trim() || (form.mode === 'same' && !form.victim.trim())" @click="search">查询</NButton>
        </NSpace>
        <p class="history-hint">查询全部时间，包含已归档事件及当前事件。默认仅查看同 IOC、同被攻击方；可切换查看该 IOC 所有事件。</p>
        <NSpace v-if="query">
          <NTag type="info">IOC：{{ query.ioc_value }}</NTag>
          <NTag v-if="query.ioc_type">类型：{{ query.ioc_type }}</NTag>
          <NTag>{{ query.victim ? `被攻击方：${query.victim}` : '全部被攻击方' }}</NTag>
        </NSpace>
      </NCard>
      <NAlert v-if="error" type="error">{{ error }}</NAlert>
      <NAlert v-else-if="!query" type="info">请输入 IOC 和被攻击方，或选择“该 IOC 所有事件”后查询。</NAlert>
      <NCard v-if="query" :title="`历史事件（${total}）`" size="small">
        <template #header-extra>
          <NSpace>
            <NButton v-if="report" @click="reportVisible = true">查看综合报告</NButton>
            <NButton type="primary" :loading="reportLoading" :disabled="loading || !total || !!error" @click="generateReport">生成综合报告</NButton>
          </NSpace>
        </template>
        <p class="history-hint">基于当前查询范围的全部历史事件生成，覆盖所有分页；重点分析整体活动特征、趋势与风险走向。</p>
        <NSpace align="center" style="margin-bottom: 12px">
          <NSelect v-model:value="savedReportId" :options="savedReportOptions" :loading="archiveLoading" clearable placeholder="选择已保存的综合报告" style="width: 360px; max-width: 80vw" />
          <NButton :disabled="!savedReportId || reportLoading" @click="openSavedReport">打开已保存报告</NButton>
          <NButton :loading="archiveLoading" @click="loadSavedReports">刷新报告列表</NButton>
        </NSpace>
        <NAlert v-if="archiveError" type="warning" style="margin-bottom: 12px">{{ archiveError }}</NAlert>
        <LyEventTable :rows="displayRows" :loading="loading" :assets="assets" />
        <div class="history-pager">
          <NPagination :page="page" :page-size="pageSize" :item-count="total" show-size-picker :page-sizes="[20, 50, 100]" @update:page="changePage" @update:page-size="changePageSize" />
        </div>
      </NCard>
    </NSpace>
    <NModal v-model:show="reportVisible" preset="card" title="历史事件综合报告" style="width: min(1000px, 94vw)">
      <NAlert v-if="reportLoading" type="info">正在加载综合报告；新报告生成可能需要较长时间，请稍候……</NAlert>
      <NAlert v-else-if="reportError" type="error">{{ reportError }}</NAlert>
      <template v-if="report && !reportLoading && !reportError">
        <NSpace align="center">
          <NTag type="info">IOC：{{ report.snapshot.scope.ioc_value }}</NTag>
          <NTag>{{ report.snapshot.scope.victim || '全部被攻击方' }}</NTag>
          <NTag>{{ report.snapshot.event_count }} 个事件</NTag>
          <NButton @click="downloadReport">下载报告及统计快照</NButton>
        </NSpace>
        <p class="history-hint">生成时间：{{ report.snapshot.generated_at }}。统计基于已保存的事件记录，IOC 命中不等于成功连接；报告可下载保存。</p>
        <div class="history-report-body" v-html="markdownToHtml(report.markdown)"></div>
        <details v-if="report.snapshot.connection_features"><summary>查看按日实际保存的活动明细统计</summary>
          <p>以下为保存的命中数，不是成功连接数。部分或不可用明细不会补零。</p>
          <div v-for="day in report.snapshot.connection_features.daily_observed_activity" :key="day.date">{{ day.date }}：{{ day.observed_hits }} 次保存命中，{{ day.active_events }} 个活跃事件</div>
          <p v-for="boundary in report.snapshot.connection_features.boundaries" :key="boundary">{{ boundary }}</p>
        </details>
        <details><summary>查看每日新聚合事件数（辅助统计）</summary>
          <div v-for="day in report.snapshot.daily_event_starts" :key="day.date">{{ day.date }}：{{ day.event_starts }}</div>
        </details>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.history-page { padding: 12px; }
.history-hint { color: #808080; font-size: 13px; margin: 12px 0; }
.history-pager { display: flex; justify-content: flex-end; padding-top: 12px; }
.history-report-body { overflow-wrap: anywhere; line-height: 1.8; max-height: 65vh; overflow-y: auto; padding: 16px 0; }
.history-report-body :deep(h2) { font-size: 18px; font-weight: 600; margin: 18px 0 10px; }
.history-report-body :deep(p), .history-report-body :deep(ul), .history-report-body :deep(ol) { margin: 10px 0; }
.history-report-body :deep(ul), .history-report-body :deep(ol) { padding-left: 24px; list-style: revert; }
</style>
