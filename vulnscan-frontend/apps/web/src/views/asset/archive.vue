<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import { getArchiveDetail, getArchiveList, getOrganizeTree, type AssetArchiveSnapshot } from '#/api/assetmgr';
import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NSpace,
  NTag,
  NTreeSelect,
  useMessage,
} from 'naive-ui';

defineOptions({ name: 'AssetArchive' });

const message = useMessage();
const loading = ref(false);
const detailLoading = ref(false);
const data = ref<AssetArchiveSnapshot[]>([]);
const detail = ref<AssetArchiveSnapshot | null>(null);
const organizeTreeOptions = ref<any[]>([]);
const drawer = ref(false);
const searchForm = reactive({ keyword: '', organize_id: '' });

const pagination = reactive({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50],
  onChange: (page: number) => {
    pagination.page = page;
    fetchList();
  },
  onUpdatePageSize: (pageSize: number) => {
    pagination.pageSize = pageSize;
    pagination.page = 1;
    fetchList();
  },
});

const columns = [
  {
    title: '归档状态',
    key: 'status',
    width: 110,
    render: (row: AssetArchiveSnapshot) => h(NTag, { size: 'small' }, () => row.status || 'archived'),
  },
  { title: '系统名称', key: 'asset_name', width: 180, ellipsis: { tooltip: true } },
  { title: '访问地址', key: 'address', minWidth: 220, ellipsis: { tooltip: true } },
  { title: '资产所属单位', key: 'organize_id', width: 150, ellipsis: { tooltip: true } },
  { title: '资产ID', key: 'asset_id', width: 170, ellipsis: { tooltip: true } },
  { title: '批次', key: 'batch_id', width: 150, ellipsis: { tooltip: true } },
  { title: '归档人', key: 'archived_by', width: 120 },
  { title: '归档时间', key: 'archived_at', width: 170 },
  {
    title: '操作',
    key: 'actions',
    width: 90,
    fixed: 'right' as const,
    render: (row: AssetArchiveSnapshot) => h(NButton, { size: 'tiny', onClick: () => showDetail(row) }, () => '详情'),
  },
];

function normalizeTree(nodes: any[] = []): any[] {
  return nodes.map((node) => ({
    label: node.name || node.organize_name || node.label || node.id,
    key: node.id || node.organize_id || node.key || node.value,
    children: normalizeTree(node.children ?? []),
  })).filter((node) => node.label && node.key);
}

async function fetchList() {
  loading.value = true;
  try {
    const res = await getArchiveList({
      page: pagination.page,
      page_size: pagination.pageSize,
      ...searchForm,
    });
    const body = (res as any)?.data ?? res;
    data.value = body?.data ?? [];
    pagination.itemCount = body?.count ?? 0;
  } catch {
    message.error('获取归档列表失败');
  } finally {
    loading.value = false;
  }
}

async function showDetail(row: AssetArchiveSnapshot) {
  drawer.value = true;
  detailLoading.value = true;
  try {
    detail.value = await getArchiveDetail(row.id);
  } catch {
    message.error('获取归档详情失败');
  } finally {
    detailLoading.value = false;
  }
}

async function loadOrganizeTree() {
  try {
    const res = await getOrganizeTree();
    const nodes = Array.isArray(res) ? res : ((res as any)?.data ?? (res as any)?.items ?? []);
    organizeTreeOptions.value = normalizeTree(nodes);
  } catch {
    organizeTreeOptions.value = [];
  }
}

function resetSearch() {
  Object.assign(searchForm, { keyword: '', organize_id: '' });
  pagination.page = 1;
  fetchList();
}

onMounted(() => {
  fetchList();
  loadOrganizeTree();
});
</script>

<template>
  <div class="asset-workspace">
    <NCard title="资产归档查询" size="small">
      <NForm inline label-placement="left" :show-feedback="false" class="asset-toolbar">
        <NFormItem label="关键词">
          <NInput v-model:value="searchForm.keyword" clearable placeholder="系统名称 / 地址" />
        </NFormItem>
        <NFormItem label="所属单位">
          <NTreeSelect
            v-model:value="searchForm.organize_id"
            clearable
            filterable
            :options="organizeTreeOptions"
            placeholder="选择单位"
          />
        </NFormItem>
        <NFormItem>
          <NSpace :size="8">
            <NButton type="primary" @click="fetchList">查询</NButton>
            <NButton @click="resetSearch">重置</NButton>
          </NSpace>
        </NFormItem>
      </NForm>

      <NDataTable
        remote
        striped
        size="small"
        :bordered="false"
        :columns="columns"
        :data="data"
        :loading="loading"
        :pagination="pagination"
        :scroll-x="1420"
      />
    </NCard>

    <NDrawer v-model:show="drawer" :width="720">
      <NDrawerContent title="归档快照" :native-scrollbar="false">
        <NDescriptions v-if="detail" label-placement="left" bordered size="small" :column="1">
          <NDescriptionsItem label="系统名称">{{ detail.asset_name || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="访问地址">{{ detail.address || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="资产所属单位">{{ detail.organize_id || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="资产ID">{{ detail.asset_id }}</NDescriptionsItem>
          <NDescriptionsItem label="核验任务">{{ detail.task_id }}</NDescriptionsItem>
          <NDescriptionsItem label="归档时间">{{ detail.archived_at || '-' }}</NDescriptionsItem>
        </NDescriptions>
        <NDataTable
          v-if="detail?.snapshot?.asset"
          class="snapshot-table"
          size="small"
          :bordered="false"
          :pagination="false"
          :columns="[
            { title: '字段', key: 'label', width: 150 },
            { title: '内容', key: 'value', ellipsis: { tooltip: true } },
          ]"
          :data="[
            { label: '备案编号', value: detail.snapshot.asset.filing_cert_number || '-' },
            { label: 'ICP备案', value: detail.snapshot.asset.icp_filing_number || '-' },
            { label: '资产分类', value: detail.snapshot.asset.asset_family || '-' },
            { label: '等保等级', value: detail.snapshot.asset.security_protection_level || '-' },
            { label: '建设单位', value: detail.snapshot.asset.construction_org_id || '-' },
            { label: '运维单位', value: detail.snapshot.asset.operation_org_id || '-' },
            { label: '负责人', value: detail.snapshot.asset.responsible_user_name || '-' },
          ]"
        />
        <div v-else-if="detailLoading" class="empty-text">加载中</div>
        <div v-else class="empty-text">暂无快照明细</div>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>

<style scoped>
.asset-workspace {
  padding: 16px;
}

.asset-toolbar {
  margin-bottom: 16px;
}

.asset-toolbar :deep(.n-input),
.asset-toolbar :deep(.n-tree-select) {
  width: 210px;
}

.snapshot-table {
  margin-top: 16px;
}

.empty-text {
  color: var(--text-color-3);
  padding: 24px 0;
  text-align: center;
}
</style>
