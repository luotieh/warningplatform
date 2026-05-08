<script lang="ts" setup>
import { h, onMounted, reactive, ref, watch } from 'vue';
import {
  NButton, NCard, NDataTable, NDescriptions, NDescriptionsItem, NDrawer, NDrawerContent,
  NEmpty, NGrid, NGridItem, NPopconfirm, NSpace, NStatistic, NTag, NTree, useMessage,
} from 'naive-ui';
import type { TreeOption } from 'naive-ui';
import type { Asset, AssetStats } from '#/api/asset';
import { getAssetList, getAssetStats } from '#/api/asset';
import { getOrganizeTree } from '#/api/assetmgr';
import { createTask } from '#/api/task';

defineOptions({ name: 'AssetOverview' });

const message = useMessage();
const loading = ref(false);
const treeLoading = ref(false);
const selectedOrgId = ref<null | string>(null);
const selectedOrgName = ref('全部组织');
const orgTree = ref<TreeOption[]>([]);
const data = ref<Asset[]>([]);
const showDetail = ref(false);
const detailItem = ref<Asset | null>(null);

const stats = ref({ total: 0, online: 0, keyAssets: 0, riskHigh: 0, withVulns: 0 });

async function fetchStats() {
  try {
    const res = await getAssetStats();
    if (res) {
      stats.value = {
        total: res.total ?? 0,
        online: res.active ?? 0,
        keyAssets: 0,
        riskHigh: 0,
        withVulns: res.with_vulns ?? 0,
      };
    }
  } catch { /* stats are non-critical */ }
}

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const lifecycleMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  discovered: { label: '已发现', type: 'default' }, confirmed: { label: '已确认', type: 'info' },
  registered: { label: '已登记', type: 'info' }, operating: { label: '运营中', type: 'success' },
  decommission: { label: '退役中', type: 'warning' }, offline: { label: '已下线', type: 'error' },
};

const columns = [
  { title: '系统名称', key: 'system_name', width: 180, ellipsis: { tooltip: true },
    render: (row: Asset) => row.system_name || row.name },
  { title: '地址', key: 'address', width: 160, ellipsis: { tooltip: true } },
  { title: '类型', key: 'type', width: 80 },
  { title: '状态', key: 'lifecycle_state', width: 80,
    render: (row: Asset) => { const m = lifecycleMap[row.lifecycle_state ?? '']; return m ? h(NTag, { size: 'small', type: m.type }, () => m.label) : '-'; } },
  { title: '风险分', key: 'risk_score', width: 70,
    render: (row: Asset) => {
      const s = row.risk_score ?? 0;
      return h('span', { style: { fontWeight: 'bold', color: s >= 70 ? '#d03050' : s >= 40 ? '#f0a020' : '#18a058' } }, String(s));
    } },
  { title: '漏洞', key: 'vuln_count', width: 60 },
  { title: '责任人', key: 'responsible_user_name', width: 80 },
  { title: '操作', key: 'actions', width: 140, fixed: 'right' as const,
    render: (row: Asset) => h(NSpace, { size: 4 }, () => [
      h(NPopconfirm, { onPositiveClick: () => onScan(row) }, {
        trigger: () => h(NButton, { size: 'small', type: 'warning' }, () => '扫描'),
        default: () => `扫描 ${row.address}？`,
      }),
      h(NButton, { size: 'small', type: 'info', onClick: () => { detailItem.value = row; showDetail.value = true; } }, () => '详情'),
    ]),
  },
];

interface OrgItem { id: string; parent_id: string; name: string; [k: string]: any }

function buildTree(items: OrgItem[]): TreeOption[] {
  const map = new Map<string, TreeOption>();
  const roots: TreeOption[] = [];
  for (const item of items) {
    map.set(item.id, { key: item.id, label: item.name, children: [] });
  }
  for (const item of items) {
    const node = map.get(item.id)!;
    if (item.parent_id && map.has(item.parent_id)) {
      map.get(item.parent_id)!.children!.push(node);
    } else {
      roots.push(node);
    }
  }
  function prune(nodes: TreeOption[]): TreeOption[] {
    return nodes.map(n => n.children?.length ? { ...n, children: prune(n.children) } : { key: n.key, label: n.label });
  }
  return prune(roots);
}

async function fetchTree() {
  treeLoading.value = true;
  try {
    const res = await getOrganizeTree();
    const body = (res as any)?.data ?? res;
    const items: OrgItem[] = body?.data ?? body ?? [];
    orgTree.value = [{ key: '__all__', label: '全部组织', children: buildTree(items) }];
  } catch { orgTree.value = [{ key: '__all__', label: '全部组织' }]; }
  finally { treeLoading.value = false; }
}

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize };
    if (selectedOrgId.value && selectedOrgId.value !== '__all__') {
      params.organize_id = selectedOrgId.value;
    }
    const res = await getAssetList(params);
    data.value = res.items ?? [];
    pagination.itemCount = res.total ?? 0;
  } catch { message.error('获取资产失败'); }
  finally { loading.value = false; }
}

function onSelectOrg(keys: string[]) {
  const key = keys[0] ?? null;
  selectedOrgId.value = key;
  const findLabel = (nodes: TreeOption[], k: string): string | null => {
    for (const n of nodes) {
      if (n.key === k) return n.label as string;
      if (n.children) { const r = findLabel(n.children, k); if (r) return r; }
    }
    return null;
  };
  selectedOrgName.value = key ? (findLabel(orgTree.value, key) ?? '全部组织') : '全部组织';
  pagination.page = 1;
  fetchList();
  fetchStats();
}

async function onScan(row: Asset) {
  const target = row.url || (row.domain ? (row.port ? `${row.domain}:${row.port}` : row.domain) : (row.ipv4 || row.address));
  try {
    await createTask({ name: `扫描-${row.system_name || row.name}`, targets: [target] });
    message.success('扫描任务已创建');
  } catch { message.error('创建失败'); }
}

onMounted(() => { fetchTree(); fetchList(); fetchStats(); });
</script>

<template>
  <div style="padding: 16px; display: flex; gap: 16px; height: calc(100vh - 100px)">
    <!-- 左侧组织树 -->
    <NCard size="small" style="width: 260px; flex-shrink: 0; overflow: auto" title="组织结构">
      <NTree
        v-if="orgTree.length"
        :data="orgTree"
        block-line
        :default-expanded-keys="['__all__']"
        :selected-keys="selectedOrgId ? [selectedOrgId] : []"
        @update:selected-keys="onSelectOrg"
      />
      <NEmpty v-else description="暂无组织数据" />
    </NCard>

    <!-- 右侧内容 -->
    <div style="flex: 1; overflow: auto; display: flex; flex-direction: column; gap: 16px">
      <!-- 统计卡片 -->
      <NCard size="small" :title="`${selectedOrgName} — 资产概况`">
        <NGrid :cols="5" :x-gap="16">
          <NGridItem>
            <NStatistic label="资产总数" :value="stats.total">
              <template #suffix>个</template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="在线资产" :value="stats.online">
              <template #prefix><span style="color: #18a058">●</span></template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="关键资产" :value="stats.keyAssets">
              <template #prefix><span style="color: #2080f0">★</span></template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="高风险" :value="stats.riskHigh">
              <template #prefix><span style="color: #d03050">▲</span></template>
            </NStatistic>
          </NGridItem>
          <NGridItem>
            <NStatistic label="有漏洞" :value="stats.withVulns">
              <template #prefix><span style="color: #f0a020">⚠</span></template>
            </NStatistic>
          </NGridItem>
        </NGrid>
      </NCard>

      <!-- 资产列表 -->
      <NCard size="small" title="资产列表" style="flex: 1">
        <NDataTable
          :columns="columns" :data="data" :loading="loading"
          :pagination="pagination" :bordered="false" :scroll-x="960"
          size="small" striped remote
        />
      </NCard>
    </div>

    <!-- 详情抽屉 -->
    <NDrawer v-model:show="showDetail" :width="480">
      <NDrawerContent :title="detailItem?.system_name || detailItem?.name || '资产详情'">
        <NDescriptions v-if="detailItem" label-placement="left" bordered :column="1" size="small">
          <NDescriptionsItem label="名称">{{ detailItem.system_name || detailItem.name }}</NDescriptionsItem>
          <NDescriptionsItem label="地址">{{ detailItem.address }}</NDescriptionsItem>
          <NDescriptionsItem label="域名">{{ detailItem.domain || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="IPv4">{{ detailItem.ipv4 || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="类型">{{ detailItem.type }}</NDescriptionsItem>
          <NDescriptionsItem label="风险分">
            <span :style="{ fontWeight: 'bold', color: (detailItem.risk_score ?? 0) >= 70 ? '#d03050' : (detailItem.risk_score ?? 0) >= 40 ? '#f0a020' : '#18a058' }">
              {{ detailItem.risk_score ?? 0 }}
            </span>
          </NDescriptionsItem>
          <NDescriptionsItem label="漏洞数">{{ detailItem.vuln_count ?? 0 }}</NDescriptionsItem>
          <NDescriptionsItem label="生命周期">{{ lifecycleMap[detailItem.lifecycle_state ?? '']?.label || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="责任人">{{ detailItem.responsible_user_name || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="最近扫描">{{ detailItem.last_scan_at || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="备注">{{ detailItem.remark || '-' }}</NDescriptionsItem>
        </NDescriptions>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
