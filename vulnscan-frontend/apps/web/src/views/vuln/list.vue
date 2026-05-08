<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NInput,
  NSelect,
  NSpace,
  NTag,
  NPopconfirm,
  NStatistic,
  NGrid,
  NGridItem,
  NDropdown,
  useMessage,
} from 'naive-ui';
import { useRouter } from 'vue-router';

import {
  getVulnList,
  getVulnStats,
  deleteVuln,
  markFixed,
  markIgnored,
  reopenVuln,
  type Vulnerability,
} from '#/api/vuln';

defineOptions({ name: 'VulnList' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<Vulnerability[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const severityFilter = ref<string | null>(null);
const statusFilter = ref<string | null>(null);
const stats = ref<Record<string, any> | null>(null);

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
  { label: '信息', value: 'info' },
];

const statusOptions = [
  { label: '待修复', value: 'open' },
  { label: '已修复', value: 'fixed' },
  { label: '已忽略', value: 'ignored' },
];

const sevLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};
const sevColors: Record<string, { bg: string; fg: string }> = {
  critical: { bg: '#fff1f0', fg: '#cf1322' },
  high: { bg: '#fff7e6', fg: '#d46b08' },
  medium: { bg: '#fffbe6', fg: '#d4b106' },
  low: { bg: '#f6ffed', fg: '#389e0d' },
  info: { bg: '#f0f5ff', fg: '#1890ff' },
};
const statusLabels: Record<string, string> = {
  open: '待修复', fixed: '已修复', ignored: '已忽略', reopened: '已重开',
};
const statusTypes: Record<string, string> = {
  open: 'error', fixed: 'success', ignored: 'default', reopened: 'warning',
};

const columns = computed(() => [
  {
    title: '漏洞', key: 'title', minWidth: 260,
    render: (row: Vulnerability) => h('div', { style: 'cursor: pointer; line-height: 1.5', onClick: () => router.push(`/vuln/${row.id}`) }, [
      h('div', { style: 'font-size: 13px; font-weight: 600; color: #1890ff' }, row.title),
      row.description ? h('div', { style: 'font-size: 11px; color: #888; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 400px', title: row.description }, row.description) : null,
    ]),
  },
  {
    title: '严重程度', key: 'severity', width: 90, align: 'center' as const,
    render: (row: Vulnerability) => {
      const sc = sevColors[row.severity] ?? { bg: '#f5f5f5', fg: '#999' };
      return h('span', { style: `padding: 3px 10px; border-radius: 4px; font-size: 12px; font-weight: 600; background: ${sc.bg}; color: ${sc.fg}` }, sevLabels[row.severity] ?? row.severity);
    },
  },
  {
    title: '状态', key: 'status', width: 80,
    render: (row: Vulnerability) => h(NTag, { size: 'small', type: (statusTypes[row.status] || 'default') as any, bordered: false }, () => statusLabels[row.status] ?? row.status),
  },
  { title: '目标', key: 'target', width: 160, ellipsis: { tooltip: true } },
  {
    title: '关联资产', key: 'asset_id', width: 90, align: 'center' as const,
    render: (row: Vulnerability) => row.asset_id
      ? h(NButton, { size: 'tiny', text: true, type: 'info', onClick: () => router.push(`/asset/ledger?id=${row.asset_id}`) }, () => '查看')
      : h('span', { style: 'color: #ccc' }, '-'),
  },
  {
    title: 'CVE', key: 'cve_ids', width: 140,
    render: (row: Vulnerability) => {
      if (!row.cve_ids?.length) return h('span', { style: 'color: #ccc' }, '-');
      return h(NSpace, { size: 4 }, () => row.cve_ids!.slice(0, 2).map((c) => h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => c)));
    },
  },
  { title: '模块', key: 'module_id', width: 110, ellipsis: { tooltip: true } },
  { title: '发现时间', key: 'first_seen_at', width: 150 },
  {
    title: '操作', key: 'actions', width: 120, fixed: 'right' as const,
    render: (row: Vulnerability) => h(NSpace, { size: 4 }, () => {
      const items: any[] = [];
      if (row.status === 'open' || row.status === 'reopened') {
        items.push(h(NButton, { size: 'tiny', type: 'success', secondary: true, onClick: () => handleMarkFixed(row.id) }, () => '修复'));
        items.push(h(NButton, { size: 'tiny', secondary: true, onClick: () => handleMarkIgnored(row.id) }, () => '忽略'));
      }
      if (row.status === 'fixed' || row.status === 'ignored') {
        items.push(h(NButton, { size: 'tiny', type: 'warning', secondary: true, onClick: () => handleReopen(row.id) }, () => '重开'));
      }
      items.push(h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'),
        default: () => '确定删除？',
      }));
      return items;
    }),
  },
]);

async function fetchData() {
  loading.value = true;
  try {
    const result = await getVulnList({
      page: page.value,
      page_size: pageSize.value,
      keyword: keyword.value || undefined,
      severity: severityFilter.value || undefined,
      status: statusFilter.value || undefined,
    });
    data.value = result.items ?? [];
    total.value = result.total ?? 0;
  } finally {
    loading.value = false;
  }
}

async function fetchStats() {
  try {
    stats.value = await getVulnStats() as any;
  } catch { /* silent */ }
}

async function handleDelete(id: string) {
  try {
    await deleteVuln(id);
    message.success('已删除');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

async function handleMarkFixed(id: string) {
  try {
    await markFixed(id);
    message.success('已标记修复');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleMarkIgnored(id: string) {
  try {
    await markIgnored(id);
    message.success('已标记忽略');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleReopen(id: string) {
  try {
    await reopenVuln(id);
    message.success('已重新打开');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

onMounted(() => {
  fetchData();
  fetchStats();
});
</script>

<template>
  <div style="padding: 16px">
    <NCard v-if="stats" size="small" style="margin-bottom: 16px">
      <NGrid :cols="6" :x-gap="12">
        <NGridItem>
          <NStatistic label="总数" :value="(stats as any)?.total ?? 0" tabular-nums />
        </NGridItem>
        <NGridItem>
          <NStatistic label="严重" tabular-nums>
            <template #prefix>
              <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#cf1322;margin-right:4px" />
            </template>
            {{ (stats as any)?.critical ?? 0 }}
          </NStatistic>
        </NGridItem>
        <NGridItem>
          <NStatistic label="高危" tabular-nums>
            <template #prefix>
              <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#d46b08;margin-right:4px" />
            </template>
            {{ (stats as any)?.high ?? 0 }}
          </NStatistic>
        </NGridItem>
        <NGridItem>
          <NStatistic label="中危" tabular-nums>
            <template #prefix>
              <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#d4b106;margin-right:4px" />
            </template>
            {{ (stats as any)?.medium ?? 0 }}
          </NStatistic>
        </NGridItem>
        <NGridItem>
          <NStatistic label="低危" tabular-nums>
            <template #prefix>
              <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#389e0d;margin-right:4px" />
            </template>
            {{ (stats as any)?.low ?? 0 }}
          </NStatistic>
        </NGridItem>
        <NGridItem>
          <NStatistic label="信息" tabular-nums>
            <template #prefix>
              <span style="display:inline-block;width:10px;height:10px;border-radius:50%;background:#1890ff;margin-right:4px" />
            </template>
            {{ (stats as any)?.info ?? 0 }}
          </NStatistic>
        </NGridItem>
      </NGrid>
    </NCard>

    <NCard title="漏洞列表" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect
            v-model:value="severityFilter"
            :options="severityOptions"
            placeholder="严重程度"
            size="small"
            style="width: 120px"
            clearable
            @update:value="() => { page = 1; fetchData(); }"
          />
          <NSelect
            v-model:value="statusFilter"
            :options="statusOptions"
            placeholder="状态"
            size="small"
            style="width: 100px"
            clearable
            @update:value="() => { page = 1; fetchData(); }"
          />
          <NInput v-model:value="keyword" placeholder="搜索漏洞..." size="small" clearable style="width: 200px" @keyup.enter="() => { page = 1; fetchData(); }" @clear="() => { page = 1; fetchData(); }" />
          <NButton size="small" type="primary" @click="() => { page = 1; fetchData(); }">搜索</NButton>
        </NSpace>
      </template>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :bordered="false"
        size="small"
        striped
        :scroll-x="1000"
        :pagination="{
          page: page,
          pageSize: pageSize,
          itemCount: total,
          showSizePicker: true,
          pageSizes: [20, 50, 100],
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>
  </div>
</template>
