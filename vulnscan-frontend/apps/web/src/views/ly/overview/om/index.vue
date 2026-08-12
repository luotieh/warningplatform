<script lang="ts" setup>
import { computed, h, onMounted, reactive, watch } from 'vue';
import { useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NFlex,
  NPagination,
  NStatistic,
  NTag,
} from 'naive-ui';

import { useLyStore } from '#/store/ly';
import { countByKey, paginate } from '#/utils/ly';

defineOptions({ name: 'LyOverviewOM' });

const router = useRouter();
const lyStore = useLyStore();

const pagerAttack = reactive({ page: 1, pageSize: 10 });
const pagerVictim = reactive({ page: 1, pageSize: 10 });
const pagerTimeline = reactive({ page: 1, pageSize: 10 });
const pagerReview = reactive({ page: 1, pageSize: 10 });
const pagerAnalysis = reactive({ page: 1, pageSize: 10 });

const allEvents = computed(() => lyStore.events ?? []);
// 待审核：review_status 为空或 pending_review（已通过/已驳回不计入）
const reviewPendingEvents = computed(() =>
  allEvents.value.filter(
    (item) => !item.review_status || item.review_status === 'pending_review',
  ),
);
// 待分析：尚未生成报告（analysis_status = pending）
const pendingAnalysisEvents = computed(() =>
  allEvents.value.filter((item) => item.analysis_status === 'pending'),
);
const attackRank = computed(() => countByKey(allEvents.value, 'attackDevice'));
const victimRank = computed(() => countByKey(allEvents.value, 'victimDevice'));
// 事件时间分布：按天（YYYY-MM-DD）聚合，避免精确到秒导致看不出分布效果。
const timelineRows = computed(() => {
  const buckets = new Map<string, { time: string; type: string; count: number }>();
  for (const item of allEvents.value) {
    const date = String(item.startTimeText ?? '').slice(0, 10);
    if (!date) continue;
    const type = item.typeText || '-';
    const key = `${date}|${type}`;
    const current = buckets.get(key) ?? { time: date, type, count: 0 };
    current.count += 1;
    buckets.set(key, current);
  }
  return [...buckets.values()].sort(
    (a, b) => b.time.localeCompare(a.time) || a.type.localeCompare(b.type),
  );
});

const attackData = computed(() => paginate(attackRank.value, pagerAttack.page, pagerAttack.pageSize));
const victimData = computed(() => paginate(victimRank.value, pagerVictim.page, pagerVictim.pageSize));
const timelineData = computed(() => paginate(timelineRows.value, pagerTimeline.page, pagerTimeline.pageSize));
const reviewData = computed(() => paginate(reviewPendingEvents.value, pagerReview.page, pagerReview.pageSize));
const analysisData = computed(() => paginate(pendingAnalysisEvents.value, pagerAnalysis.page, pagerAnalysis.pageSize));

watch([attackRank, victimRank, timelineRows, reviewPendingEvents, pendingAnalysisEvents], () => {
  const fit = (pager: { page: number; pageSize: number }, total: number) => {
    const max = Math.max(1, Math.ceil(total / pager.pageSize));
    if (pager.page > max) pager.page = max;
  };
  fit(pagerAttack, attackRank.value.length);
  fit(pagerVictim, victimRank.value.length);
  fit(pagerTimeline, timelineRows.value.length);
  fit(pagerReview, reviewPendingEvents.value.length);
  fit(pagerAnalysis, pendingAnalysisEvents.value.length);
});

const rankColumns = [
  { title: '对象', key: 'name' },
  { title: '次数', key: 'value', width: 90 },
];

const timelineColumns = [
  { title: '日期', key: 'time', minWidth: 140 },
  { title: '事件类型', key: 'type', width: 120 },
  { title: '数量', key: 'count', width: 90 },
];

const eventWorkColumns = [
  { title: '规则描述', key: 'desc', ellipsis: { tooltip: true } },
  { title: '威胁来源', key: 'attackDevice', width: 180 },
  {
    title: '操作',
    key: 'actions',
    width: 120,
    render: () =>
      h(
        NButton,
        {
          size: 'small',
          text: true,
          type: 'primary',
          onClick: () => router.push('/ly/event/list'),
        },
        { default: () => '查看' },
      ),
  },
];

onMounted(async () => {
  if (!lyStore.events.length) {
    await lyStore.loadEvents();
  }
});
</script>

<template>
  <div class="ly-page-grid">
    <NFlex :size="12" vertical>
      <NCard title="事件概览" size="small">
        <NFlex :size="12">
          <NStatistic label="事件总数" :value="allEvents.length" />
          <NStatistic label="待审核" :value="reviewPendingEvents.length" />
          <NStatistic label="待分析" :value="pendingAnalysisEvents.length" />
          <NStatistic label="威胁来源" :value="attackRank.length" />
          <NStatistic label="受害目标" :value="victimRank.length" />
        </NFlex>
      </NCard>

      <div class="ly-grid-2">
        <NCard title="主机排行（威胁来源）" size="small">
          <NDataTable :columns="rankColumns" :data="attackData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerAttack.page" v-model:page-size="pagerAttack.pageSize" :item-count="attackRank.length" show-size-picker :page-sizes="[10, 20, 50]" />
          </div>
        </NCard>
        <NCard title="主机排行（受害目标）" size="small">
          <NDataTable :columns="rankColumns" :data="victimData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerVictim.page" v-model:page-size="pagerVictim.pageSize" :item-count="victimRank.length" show-size-picker :page-sizes="[10, 20, 50]" />
          </div>
        </NCard>
      </div>

      <div class="ly-grid-2">
        <NCard title="事件时间分布" size="small">
          <NDataTable :columns="timelineColumns" :data="timelineData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerTimeline.page" v-model:page-size="pagerTimeline.pageSize" :item-count="timelineRows.length" show-size-picker :page-sizes="[10, 20, 50]" />
          </div>
        </NCard>
        <NCard title="审核（待审核事件）" size="small">
          <template #header-extra>
            <NTag type="warning" size="small">待审核 {{ reviewPendingEvents.length }}</NTag>
          </template>
          <NDataTable :columns="eventWorkColumns" :data="reviewData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerReview.page" v-model:page-size="pagerReview.pageSize" :item-count="reviewPendingEvents.length" show-size-picker :page-sizes="[10, 20, 50]" />
          </div>
        </NCard>
        <NCard title="待分析事件" size="small">
          <template #header-extra>
            <NTag type="info" size="small">待分析 {{ pendingAnalysisEvents.length }}</NTag>
          </template>
          <NDataTable :columns="eventWorkColumns" :data="analysisData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerAnalysis.page" v-model:page-size="pagerAnalysis.pageSize" :item-count="pendingAnalysisEvents.length" show-size-picker :page-sizes="[10, 20, 50]" />
          </div>
        </NCard>
      </div>
    </NFlex>
  </div>
</template>

<style scoped>
.ly-page-grid {
  padding: 12px;
}

.ly-grid-2 {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}

.pager-wrap {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
</style>
