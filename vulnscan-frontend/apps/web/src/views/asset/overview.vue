<script lang="ts" setup>
import type { DataTableColumns, TreeOption } from 'naive-ui';

import { h, onMounted, reactive, ref } from 'vue';

import type { Asset } from '#/api/asset';

import { getAssetList, getAssetStats } from '#/api/asset';
import { getOrganizeTree } from '#/api/assetmgr';
import { createTask } from '#/api/task';

import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NGrid,
  NGridItem,
  NPopconfirm,
  NSpace,
  NStatistic,
  NTag,
  NTree,
  useMessage,
} from 'naive-ui';

defineOptions({ name: 'AssetOverview' });

interface OrgItem {
  id: string;
  name: string;
  parent_id?: string;
}

const message = useMessage();
const loading = ref(false);
const treeLoading = ref(false);
const selectedOrgId = ref<null | string>(null);
const selectedOrgName = ref('全部组织');
const orgTree = ref<TreeOption[]>([]);
const data = ref<Asset[]>([]);
const showDetail = ref(false);
const detailItem = ref<Asset | null>(null);

const stats = ref({
  keyAssets: 0,
  online: 0,
  riskHigh: 0,
  total: 0,
  withVulns: 0,
});

const lifecycleMap: Record<
  string,
  {
    label: string;
    type: 'default' | 'error' | 'info' | 'success' | 'warning';
  }
> = {
  confirmed: { label: '已确认', type: 'info' },
  decommission: { label: '退役中', type: 'warning' },
  discovered: { label: '已发现', type: 'default' },
  offline: { label: '已下线', type: 'error' },
  operating: { label: '运行中', type: 'success' },
  registered: { label: '已登记', type: 'info' },
};

const pagination = reactive({
  itemCount: 0,
  onChange: (page: number) => {
    pagination.page = page;
    fetchList();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    fetchList();
  },
  page: 1,
  pageSize: 20,
  pageSizes: [10, 20, 50],
  showSizePicker: true,
});

function getAssetName(row: Asset) {
  return row.system_name || row.name || '-';
}

function getAssetTarget(row: Asset) {
  if (row.url) return row.url;
  if (row.domain) return row.port ? `${row.domain}:${row.port}` : row.domain;
  return row.ipv4 || row.address || '';
}

const columns: DataTableColumns<Asset> = [
  {
    ellipsis: { tooltip: true },
    key: 'system_name',
    render: (row) => getAssetName(row),
    title: '系统名称',
    width: 180,
  },
  {
    ellipsis: { tooltip: true },
    key: 'address',
    title: '地址',
    width: 180,
  },
  {
    key: 'type',
    render: (row) => row.type || '-',
    title: '类型',
    width: 100,
  },
  {
    key: 'lifecycle_state',
    render: (row) => {
      const item = lifecycleMap[row.lifecycle_state ?? ''];
      return item
        ? h(NTag, { size: 'small', type: item.type }, () => item.label)
        : '-';
    },
    title: '状态',
    width: 100,
  },
  {
    key: 'risk_score',
    render: (row) => {
      const score = row.risk_score ?? 0;
      const className =
        score >= 70
          ? 'risk-score risk-score--high'
          : score >= 40
            ? 'risk-score risk-score--medium'
            : 'risk-score risk-score--low';
      return h('span', { class: className }, String(score));
    },
    title: '风险分',
    width: 90,
  },
  {
    key: 'vuln_count',
    render: (row) => row.vuln_count ?? 0,
    title: '漏洞',
    width: 80,
  },
  {
    ellipsis: { tooltip: true },
    key: 'responsible_user_name',
    render: (row) => row.responsible_user_name || '-',
    title: '责任人',
    width: 120,
  },
  {
    fixed: 'right',
    key: 'actions',
    render: (row) =>
      h(NSpace, { size: 8 }, () => [
        h(
          NPopconfirm,
          {
            onPositiveClick: () => onScan(row),
          },
          {
            default: () => `确认扫描 ${getAssetTarget(row) || getAssetName(row)}？`,
            trigger: () =>
              h(NButton, { size: 'small', type: 'warning' }, () => '扫描'),
          },
        ),
        h(
          NButton,
          {
            onClick: () => {
              detailItem.value = row;
              showDetail.value = true;
            },
            size: 'small',
            type: 'info',
          },
          () => '详情',
        ),
      ]),
    title: '操作',
    width: 150,
  },
];

function buildTree(items: OrgItem[]): TreeOption[] {
  const map = new Map<string, TreeOption>();
  const roots: TreeOption[] = [];

  for (const item of items) {
    map.set(item.id, { children: [], key: item.id, label: item.name });
  }

  for (const item of items) {
    const node = map.get(item.id);
    if (!node) continue;
    if (item.parent_id && map.has(item.parent_id)) {
      map.get(item.parent_id)?.children?.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots.map(pruneTreeNode);
}

function pruneTreeNode(node: TreeOption): TreeOption {
  if (node.children?.length) {
    return { ...node, children: node.children.map(pruneTreeNode) };
  }
  return { key: node.key, label: node.label };
}

function findTreeLabel(nodes: TreeOption[], key: string): null | string {
  for (const node of nodes) {
    if (node.key === key) return String(node.label ?? '');
    if (node.children) {
      const result = findTreeLabel(node.children, key);
      if (result) return result;
    }
  }
  return null;
}

async function fetchStats() {
  try {
    const res = await getAssetStats();
    if (!res) return;
    stats.value = {
      keyAssets: 0,
      online: res.active ?? 0,
      riskHigh: 0,
      total: res.total ?? 0,
      withVulns: res.with_vulns ?? 0,
    };
  } catch {
    // 统计信息非关键数据，失败时保留当前展示。
  }
}

async function fetchTree() {
  treeLoading.value = true;
  try {
    const res = await getOrganizeTree();
    const body = (res as any)?.data ?? res;
    const items: OrgItem[] = body?.data ?? body ?? [];
    orgTree.value = [
      { children: buildTree(items), key: '__all__', label: '全部组织' },
    ];
  } catch {
    orgTree.value = [{ key: '__all__', label: '全部组织' }];
  } finally {
    treeLoading.value = false;
  }
}

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = {
      page: pagination.page,
      page_size: pagination.pageSize,
    };
    if (selectedOrgId.value && selectedOrgId.value !== '__all__') {
      params.organize_id = selectedOrgId.value;
    }
    const res = await getAssetList(params);
    data.value = res.items ?? [];
    pagination.itemCount = res.total ?? 0;
  } catch {
    message.error('获取资产失败');
  } finally {
    loading.value = false;
  }
}

function onSelectOrg(keys: string[]) {
  const key = keys[0] ?? null;
  selectedOrgId.value = key;
  selectedOrgName.value = key
    ? (findTreeLabel(orgTree.value, key) ?? '全部组织')
    : '全部组织';
  pagination.page = 1;
  fetchList();
  fetchStats();
}

async function onScan(row: Asset) {
  const target = getAssetTarget(row);
  if (!target) {
    message.warning('当前资产缺少可扫描地址');
    return;
  }
  try {
    await createTask({ name: `扫描-${getAssetName(row)}`, targets: [target] });
    message.success('扫描任务已创建');
  } catch {
    message.error('创建扫描任务失败');
  }
}

onMounted(() => {
  fetchTree();
  fetchList();
  fetchStats();
});
</script>

<template>
  <div class="asset-overview-page">
    <NCard class="asset-overview-page__tree" size="small" title="组织结构">
      <NTree
        v-if="orgTree.length"
        :data="orgTree"
        :default-expanded-keys="['__all__']"
        :loading="treeLoading"
        :selected-keys="selectedOrgId ? [selectedOrgId] : []"
        block-line
        @update:selected-keys="onSelectOrg"
      />
      <NEmpty v-else description="暂无组织数据" />
    </NCard>

    <div class="asset-overview-page__main">
      <NCard size="small" :title="`${selectedOrgName} - 资产概况`">
        <NGrid :cols="5" :x-gap="16" responsive="screen">
          <NGridItem>
            <NStatistic label="资产总数" :value="stats.total">
              <template #suffix>个</template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="在线资产" :value="stats.online">
              <template #prefix><span class="stat-dot stat-dot--success" /></template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="关键资产" :value="stats.keyAssets">
              <template #prefix><span class="stat-symbol stat-symbol--primary">★</span></template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="高风险" :value="stats.riskHigh">
              <template #prefix><span class="stat-symbol stat-symbol--danger">▲</span></template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="有漏洞" :value="stats.withVulns">
              <template #prefix><span class="stat-symbol stat-symbol--warning">⚠</span></template>
            </NStatistic>
          </NGridItem>
        </NGrid>
      </NCard>

      <NCard class="asset-overview-page__table" size="small" title="资产列表">
        <NDataTable
          :bordered="false"
          :columns="columns"
          :data="data"
          :loading="loading"
          :pagination="pagination"
          :scroll-x="960"
          remote
          size="small"
          striped
        />
      </NCard>
    </div>

    <NDrawer v-model:show="showDetail" :width="480">
      <NDrawerContent :title="detailItem ? getAssetName(detailItem) : '资产详情'">
        <NDescriptions
          v-if="detailItem"
          :column="1"
          bordered
          label-placement="left"
          size="small"
        >
          <NDescriptionsItem label="名称">{{ getAssetName(detailItem) }}</NDescriptionsItem>
          <NDescriptionsItem label="地址">{{ detailItem.address || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="域名">{{ detailItem.domain || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="IPv4">{{ detailItem.ipv4 || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="类型">{{ detailItem.type || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="风险分">
            <span
              :class="[
                'risk-score',
                (detailItem.risk_score ?? 0) >= 70
                  ? 'risk-score--high'
                  : (detailItem.risk_score ?? 0) >= 40
                    ? 'risk-score--medium'
                    : 'risk-score--low',
              ]"
            >
              {{ detailItem.risk_score ?? 0 }}
            </span>
          </NDescriptionsItem>
          <NDescriptionsItem label="漏洞数">{{ detailItem.vuln_count ?? 0 }}</NDescriptionsItem>
          <NDescriptionsItem label="生命周期">
            {{ lifecycleMap[detailItem.lifecycle_state ?? '']?.label || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem label="责任人">
            {{ detailItem.responsible_user_name || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem label="最近扫描">
            {{ detailItem.last_scan_at || '-' }}
          </NDescriptionsItem>
          <NDescriptionsItem label="备注">{{ detailItem.remark || '-' }}</NDescriptionsItem>
        </NDescriptions>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>

<style scoped>
.asset-overview-page {
  display: flex;
  gap: 16px;
  height: calc(100vh - 100px);
  padding: 16px;
  color: hsl(var(--foreground));
  background: hsl(var(--background-deep));
}

.asset-overview-page__tree {
  width: 260px;
  flex-shrink: 0;
  overflow: auto;
}

.asset-overview-page__main {
  display: flex;
  flex: 1;
  flex-direction: column;
  gap: 16px;
  min-width: 0;
  overflow: auto;
}

.asset-overview-page__table {
  flex: 1;
  min-height: 0;
}

.asset-overview-page :deep(.n-card) {
  color: hsl(var(--foreground));
  background: hsl(var(--card));
  border-color: hsl(var(--border));
}

.asset-overview-page :deep(.n-card-header),
.asset-overview-page :deep(.n-card__content),
.asset-overview-page :deep(.n-statistic),
.asset-overview-page :deep(.n-tree) {
  color: hsl(var(--foreground));
}

.asset-overview-page :deep(.n-statistic .n-statistic__label),
.asset-overview-page :deep(.n-empty__description) {
  color: hsl(var(--muted-foreground));
}

.asset-overview-page :deep(.n-data-table) {
  color: hsl(var(--foreground));
  background: hsl(var(--card));
}

.asset-overview-page :deep(.n-data-table-th) {
  color: hsl(var(--foreground));
  background: hsl(var(--accent));
}

.asset-overview-page :deep(.n-data-table-td) {
  color: hsl(var(--foreground));
  background: hsl(var(--card));
  border-color: hsl(var(--border));
}

.asset-overview-page :deep(.n-data-table-tr--striped .n-data-table-td) {
  background: hsl(var(--accent-lighter));
}

.asset-overview-page :deep(.n-tree-node-content:hover),
.asset-overview-page :deep(.n-tree-node-content--selected) {
  color: hsl(var(--foreground));
  background: hsl(var(--accent));
}

.stat-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  margin-right: 4px;
  border-radius: 50%;
}

.stat-dot--success {
  background: #18a058;
}

.stat-symbol {
  margin-right: 4px;
  font-size: 18px;
  line-height: 1;
}

.stat-symbol--danger {
  color: #d03050;
}

.stat-symbol--primary {
  color: #2080f0;
}

.stat-symbol--warning {
  color: #f0a020;
}

.risk-score {
  font-weight: 700;
}

.risk-score--high {
  color: #d03050;
}

.risk-score--low {
  color: #18a058;
}

.risk-score--medium {
  color: #f0a020;
}
</style>
