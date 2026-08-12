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

const pagerAttack = reactive({ page: 1, pageSize: 8 });
const pagerVictim = reactive({ page: 1, pageSize: 8 });
const pagerTimeline = reactive({ page: 1, pageSize: 10 });
const pagerPending = reactive({ page: 1, pageSize: 8 });

const allEvents = computed(() => lyStore.events ?? []);
const pendingEvents = computed(() =>
  allEvents.value.filter((item) => item.proc_status === 'unprocessed'),
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
const pendingData = computed(() => paginate(pendingEvents.value, pagerPending.page, pagerPending.pageSize));

watch([attackRank, victimRank, timelineRows, pendingEvents], () => {
  const fit = (pager: { page: number; pageSize: number }, total: number) => {
    const max = Math.max(1, Math.ceil(total / pager.pageSize));
    if (pager.page > max) pager.page = max;
  };
  fit(pagerAttack, attackRank.value.length);
  fit(pagerVictim, victimRank.value.length);
  fit(pagerTimeline, timelineRows.value.length);
  fit(pagerPending, pendingEvents.value.length);
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

const pendingColumns = [
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
          <NStatistic label="待处理" :value="pendingEvents.length" />
          <NStatistic label="威胁来源" :value="attackRank.length" />
          <NStatistic label="受害目标" :value="victimRank.length" />
        </NFlex>
      </NCard>

      <div class="ly-grid-2">
        <NCard title="主机排行（威胁来源）" size="small">
          <NDataTable :columns="rankColumns" :data="attackData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerAttack.page" v-model:page-size="pagerAttack.pageSize" :item-count="attackRank.length" show-size-picker :page-sizes="[8, 16, 24]" />
          </div>
        </NCard>
        <NCard title="主机排行（受害目标）" size="small">
          <NDataTable :columns="rankColumns" :data="victimData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerVictim.page" v-model:page-size="pagerVictim.pageSize" :item-count="victimRank.length" show-size-picker :page-sizes="[8, 16, 24]" />
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
        <NCard title="工作台（待处理事件）" size="small">
          <template #header-extra>
            <NTag type="warning" size="small">未处理 {{ pendingEvents.length }}</NTag>
          </template>
          <NDataTable :columns="pendingColumns" :data="pendingData" :bordered="false" size="small" />
          <div class="pager-wrap">
            <NPagination v-model:page="pagerPending.page" v-model:page-size="pagerPending.pageSize" :item-count="pendingEvents.length" show-size-picker :page-sizes="[8, 16, 24]" />
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
