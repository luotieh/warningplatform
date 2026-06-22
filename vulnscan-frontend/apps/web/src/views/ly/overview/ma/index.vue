<script lang="ts" setup>
import { computed, h, onMounted, reactive, watch } from 'vue';

import { NCard, NDataTable, NPagination, NStatistic, NTag } from 'naive-ui';

import { useLyStore } from '#/store/ly';
import { paginate } from '#/utils/ly';

defineOptions({ name: 'LyOverviewMA' });

const lyStore = useLyStore();
const devicePager = reactive({ page: 1, pageSize: 10 });
const eventPager = reactive({ page: 1, pageSize: 10 });

// 告警规则统计与「事件列表」同源：按事件类型聚合 lyStore.events 的命中数量，
// 而非读 lyStore.eventRules(/config?type=event 通用 KV) 或 /rules(管理端常无规则文件)。
const eventSummary = computed(() => {
  const map = new Map<string, number>();
  (lyStore.events || []).forEach((item) => {
    const key = String(item.typeText || item.type || 'unknown');
    map.set(key, (map.get(key) || 0) + 1);
  });
  return Array.from(map.entries())
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count);
});

// 「告警规则」统计卡展示已触发的规则类型数（与事件列表的类型分布一致）。
const ruleTotal = computed(() => eventSummary.value.length);

// 与「节点配置」页保持一致：节点信息同时包含采集节点(device)与分析融合节点(proxy)，
// 否则当节点以 proxy 类型注册时，总览节点表会为空。
const deviceRows = computed(() =>
  [...(lyStore.device || []), ...(lyStore.proxy || [])].map((item) => ({
    ...item,
    address: item.address ?? item.addr ?? item.ip ?? '-',
    port: item.port ?? parseMeta(item.meta).port ?? '-',
    status: normalizeStatus(item.status),
  })),
);

const deviceData = computed(() =>
  paginate(deviceRows.value, devicePager.page, devicePager.pageSize),
);
const eventData = computed(() =>
  paginate(eventSummary.value, eventPager.page, eventPager.pageSize),
);

watch([() => deviceRows.value.length, eventSummary], () => {
  const fit = (pager: { page: number; pageSize: number }, total: number) => {
    const max = Math.max(1, Math.ceil(total / pager.pageSize));
    if (pager.page > max) pager.page = max;
  };
  fit(devicePager, deviceRows.value.length);
  fit(eventPager, eventSummary.value.length);
});

const deviceColumns = [
  { title: 'ID', key: 'id', width: 80 },
  { title: '名称', key: 'name', minWidth: 180 },
  { title: '地址', key: 'address', minWidth: 220 },
  { title: '端口', key: 'port', width: 90 },
  {
    title: '状态',
    key: 'status',
    width: 110,
    render: (row: Record<string, any>) => {
      const tag = statusTag(row.status);
      return h(NTag, { size: 'small', type: tag.type }, { default: () => tag.text });
    },
  },
];

const eventColumns = [
  { title: '事件类型', key: 'type', minWidth: 180 },
  { title: '事件数量', key: 'count', width: 140, align: 'right' as const },
];

onMounted(async () => {
  await Promise.all([
    lyStore.device.length ? Promise.resolve() : lyStore.loadConfigs(),
    lyStore.events.length ? Promise.resolve() : lyStore.loadEvents(),
  ]);
});

function parseMeta(value: any) {
  if (!value) return {};
  if (typeof value === 'object') return value;
  try {
    return JSON.parse(value);
  } catch {
    return {};
  }
}

function normalizeStatus(value: any) {
  const raw = String(value ?? '').toLowerCase();
  if (['connected', 'online', 'ready', 'running', 'success'].includes(raw)) return 'online';
  if (['warn', 'warning', 'degraded'].includes(raw)) return 'warning';
  if (['disabled', 'stopped'].includes(raw)) return 'disabled';
  if (['disconnected', 'down', 'failed', 'offline', 'error'].includes(raw)) return 'offline';
  return raw || 'unknown';
}

function statusTag(value: any) {
  const status = normalizeStatus(value);
  const map: Record<string, { text: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
    disabled: { text: '停用', type: 'default' },
    offline: { text: '离线', type: 'error' },
    online: { text: '在线', type: 'success' },
    unknown: { text: '未知', type: 'info' },
    warning: { text: '异常', type: 'warning' },
  };
  return map[status] ?? { text: status, type: 'info' };
}
</script>

<template>
  <div class="ly-page">
    <div class="overview-stack">
      <div class="stats-grid">
        <NCard class="stat-card" size="small">
          <NStatistic label="节点" :value="deviceRows.length" />
        </NCard>
        <NCard class="stat-card" size="small">
          <NStatistic label="用户" :value="lyStore.userList.length" />
        </NCard>
        <NCard class="stat-card" size="small">
          <NStatistic label="告警规则" :value="ruleTotal" />
        </NCard>
        <NCard class="stat-card" size="small">
          <NStatistic label="追踪目标" :value="lyStore.mo.length" />
        </NCard>
      </div>

      <NCard class="table-card" title="节点信息" size="small">
        <NDataTable
          :columns="deviceColumns"
          :data="deviceData"
          :bordered="false"
          size="small"
          class="overview-table"
        />
        <div class="pager-wrap">
          <NPagination
            v-model:page="devicePager.page"
            v-model:page-size="devicePager.pageSize"
            :item-count="deviceRows.length"
            show-size-picker
            :page-sizes="[10, 20, 50]"
          />
        </div>
      </NCard>

      <NCard class="table-card" title="告警规则统计" size="small">
        <NDataTable
          :columns="eventColumns"
          :data="eventData"
          :bordered="false"
          size="small"
          class="overview-table"
        />
        <div class="pager-wrap">
          <NPagination
            v-model:page="eventPager.page"
            v-model:page-size="eventPager.pageSize"
            :item-count="eventSummary.length"
            show-size-picker
            :page-sizes="[10, 20, 50]"
          />
        </div>
      </NCard>
    </div>
  </div>
</template>

<style scoped>
.ly-page {
  min-height: 100%;
  padding: 16px;
}

.overview-stack {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}

.stat-card {
  min-height: 84px;
}

.table-card :deep(.n-card-header) {
  min-height: 54px;
  padding: 16px 18px;
  border-bottom: 1px solid var(--n-border-color);
}

.table-card :deep(.n-card__content) {
  padding: 16px 18px 14px;
}

.overview-table {
  min-height: 96px;
}

.pager-wrap {
  display: flex;
  justify-content: flex-end;
  padding-top: 10px;
}

@media (max-width: 1024px) {
  .stats-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
}

@media (max-width: 640px) {
  .ly-page {
    padding: 12px;
  }

  .stats-grid {
    grid-template-columns: 1fr;
  }
}
</style>
