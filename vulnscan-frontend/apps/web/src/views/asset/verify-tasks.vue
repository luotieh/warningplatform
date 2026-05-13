<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey } from 'naive-ui';

import { computed, h, onMounted, reactive, ref } from 'vue';

import { getAssetList, type Asset } from '#/api/asset';
import {
  archiveVerifyTask,
  confirmVerifyTask,
  createVerifyTasks,
  forwardVerifyTask,
  getConstructionList,
  getIamOrganizeTree,
  getVerifyTaskList,
  getVerifyTaskLogs,
  receiveVerifyTask,
  rejectVerifyTask,
  returnVerifyTask,
  type AssetVerifyOplog,
  type AssetVerifyTask,
} from '#/api/assetmgr';
import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSelect,
  NSpace,
  NTag,
  NTreeSelect,
  useMessage,
} from 'naive-ui';

defineOptions({ name: 'AssetVerifyTasks' });

const message = useMessage();

const loading = ref(false);
const assetLoading = ref(false);
const logLoading = ref(false);

const data = ref<AssetVerifyTask[]>([]);
const assetOptions = ref<Asset[]>([]);
const selectedAssetIds = ref<DataTableRowKey[]>([]);
const logs = ref<AssetVerifyOplog[]>([]);
const organizeTreeOptions = ref<any[]>([]);
const organizeNameMap = ref<Record<string, string>>({});
const constructionOrgNameMap = ref<Record<string, string>>({});

const logDrawer = ref(false);
const createModal = ref(false);
const actionModal = ref(false);
const confirmModal = ref(false);
const actionType = ref<'forward' | 'reject'>('forward');
const activeTask = ref<AssetVerifyTask | null>(null);
const pendingAction = ref<'archive' | 'confirm' | 'receive' | 'return' | ''>('');

const searchForm = reactive({ keyword: '', status: '', owner_organize_id: '' });
const assetSearchForm = reactive({ keyword: '', organize_id: '' });
const createForm = reactive({ target_organize_id: '', source_type: 'manual', remark: '' });
const actionForm = reactive({ target_organize_id: '', reject_reason: '', remark: '' });

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

const selectedAssets = computed(() => {
  const selected = new Set(selectedAssetIds.value.map(String));
  return assetOptions.value.filter((item) => selected.has(item.id));
});

const statusMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  pending_dispatch: { label: '待下发', type: 'default' },
  pending_receive: { label: '待接收', type: 'warning' },
  pending_verify: { label: '待核验', type: 'info' },
  confirmed: { label: '已确认', type: 'success' },
  rejected: { label: '已驳回', type: 'error' },
  returned: { label: '已退回', type: 'warning' },
  forwarded: { label: '已转发', type: 'info' },
  archived: { label: '已归档', type: 'default' },
};

const actionMap: Record<string, string> = {
  create: '创建',
  dispatch: '下发',
  receive: '接收',
  verify_confirm: '确认',
  verify_reject: '驳回',
  forward: '转发',
  return: '退回',
  archive: '归档',
  reactivate: '重新激活',
};

const sourceMap: Record<string, string> = {
  discovery: '探测发现',
  import: '导入',
  manual: '手工录入',
  scan: '扫描',
};

const statusOptions = Object.entries(statusMap).map(([value, item]) => ({ label: item.label, value }));
const sourceOptions = Object.entries(sourceMap).map(([value, label]) => ({ label, value }));

function normalizeTree(nodes: any[] = []): any[] {
  return nodes
    .map((node) => {
      const value = String(node.id ?? node.organize_id ?? node.value ?? '');
      const label = node.name ?? node.organize_name ?? node.label ?? value;
      return {
        label,
        value,
        children: normalizeTree(node.children ?? []),
      };
    })
    .filter((node) => node.label && node.value);
}

function flattenTree(nodes: any[] = [], result: Record<string, string> = {}) {
  nodes.forEach((node) => {
    if (node.value) {
      result[String(node.value)] = node.label;
    }
    flattenTree(node.children ?? [], result);
  });
  return result;
}

function parseListBody<T>(res: unknown): { count: number; data: T[] } {
  const body = (res as any)?.data ?? res;
  return {
    count: Number(body?.count ?? body?.total ?? 0),
    data: body?.data ?? body?.items ?? [],
  };
}

function displayName(value?: string, map: Record<string, string> = organizeNameMap.value) {
  if (!value) return '-';
  return map[value] ?? value;
}

function displaySource(value?: string) {
  if (!value) return '-';
  return sourceMap[value] ?? value;
}

function displayStatus(value?: string) {
  if (!value) return '-';
  return statusMap[value]?.label ?? value;
}

function renderStatus(row: AssetVerifyTask) {
  const item = statusMap[row.status] ?? { label: row.status, type: 'default' as const };
  return h(NTag, { bordered: false, size: 'small', type: item.type }, () => item.label);
}

function getForwardActionText(row?: AssetVerifyTask | null) {
  return row?.status === 'pending_dispatch' ? '下发' : '转发';
}

function renderMuted(value?: string) {
  return h('span', { class: value ? 'cell-text' : 'cell-text cell-text--empty' }, value || '-');
}

const columns: DataTableColumns<AssetVerifyTask> = [
  { title: '状态', key: 'status', width: 96, render: renderStatus },
  {
    title: '资产',
    key: 'asset_name',
    minWidth: 220,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(row.asset_name || row.address),
  },
  { title: '访问地址', key: 'address', minWidth: 220, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.address) },
  {
    title: '资产所属单位',
    key: 'owner_organize_id',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(displayName(row.owner_organize_id)),
  },
  {
    title: '当前处理单位',
    key: 'current_organize_id',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(displayName(row.current_organize_id)),
  },
  {
    title: '建设单位',
    key: 'construction_org_id',
    minWidth: 150,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(displayName(row.construction_org_id, constructionOrgNameMap.value)),
  },
  {
    title: '运维单位',
    key: 'operation_org_id',
    minWidth: 150,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(displayName(row.operation_org_id, constructionOrgNameMap.value)),
  },
  { title: '来源', key: 'source_type', width: 100, render: (row) => renderMuted(displaySource(row.source_type)) },
  { title: '更新时间', key: 'updated_at', width: 170, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.updated_at) },
  {
    title: '操作',
    key: 'actions',
    width: 330,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 6, wrap: false }, () => [
        h(NButton, { size: 'tiny', disabled: !['pending_receive', 'forwarded'].includes(row.status), onClick: () => runSimple(row, 'receive') }, () => '接收'),
        h(NButton, { size: 'tiny', type: 'primary', disabled: row.status !== 'pending_verify', onClick: () => runSimple(row, 'confirm') }, () => '确认'),
        h(NButton, { size: 'tiny', disabled: !['pending_dispatch', 'pending_receive', 'pending_verify'].includes(row.status), onClick: () => openAction(row, 'forward') }, () => getForwardActionText(row)),
        h(NButton, { size: 'tiny', type: 'warning', disabled: !['pending_receive', 'pending_verify', 'forwarded'].includes(row.status), onClick: () => runSimple(row, 'return') }, () => '退回'),
        h(NButton, { size: 'tiny', type: 'error', disabled: !['pending_receive', 'pending_verify'].includes(row.status), onClick: () => openAction(row, 'reject') }, () => '驳回'),
        h(NButton, { size: 'tiny', disabled: !['confirmed', 'rejected', 'returned'].includes(row.status), onClick: () => runSimple(row, 'archive') }, () => '归档'),
        h(NButton, { size: 'tiny', onClick: () => showLogs(row) }, () => '日志'),
      ]),
  },
];

const assetColumns: DataTableColumns<Asset> = [
  { type: 'selection', width: 44 },
  { title: '系统名称', key: 'name', minWidth: 180, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.name || row.address) },
  { title: '访问地址', key: 'address', minWidth: 220, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.address) },
  {
    title: '资产所属单位',
    key: 'organize_id',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(displayName(row.organize_id)),
  },
  { title: '系统类型', key: 'system_type', width: 120, render: (row) => renderMuted(row.system_type) },
];

const logColumns: DataTableColumns<AssetVerifyOplog> = [
  { title: '动作', key: 'action', width: 110, render: (row) => renderMuted(actionMap[row.action] ?? row.action) },
  { title: '原状态', key: 'from_status', width: 110, render: (row) => renderMuted(displayStatus(row.from_status)) },
  { title: '新状态', key: 'to_status', width: 110, render: (row) => renderMuted(displayStatus(row.to_status)) },
  {
    title: '目标单位',
    key: 'target_organize_id',
    minWidth: 160,
    ellipsis: { tooltip: true },
    render: (row) => renderMuted(displayName(row.target_organize_id)),
  },
  { title: '操作人', key: 'operator', width: 130, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.operator) },
  { title: '备注', key: 'remark', minWidth: 180, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.remark) },
  { title: '时间', key: 'created_at', width: 170, ellipsis: { tooltip: true }, render: (row) => renderMuted(row.created_at) },
];

async function fetchList() {
  loading.value = true;
  try {
    const res = await getVerifyTaskList({
      page: pagination.page,
      page_size: pagination.pageSize,
      ...searchForm,
    });
    const body = parseListBody<AssetVerifyTask>(res);
    data.value = body.data;
    pagination.itemCount = body.count;
  } catch {
    message.error('获取核验任务失败');
  } finally {
    loading.value = false;
  }
}

async function fetchAssets() {
  assetLoading.value = true;
  try {
    const res = await getAssetList({
      keyword: assetSearchForm.keyword,
      organize_id: assetSearchForm.organize_id,
      page: 1,
      page_size: 50,
    });
    assetOptions.value = res.items;
  } catch {
    message.error('获取资产列表失败');
  } finally {
    assetLoading.value = false;
  }
}

async function loadOrganizeTree() {
  try {
    const res = await getIamOrganizeTree();
    const nodes = Array.isArray(res) ? res : ((res as any)?.data ?? (res as any)?.items ?? []);
    const options = normalizeTree(nodes);
    organizeTreeOptions.value = options;
    organizeNameMap.value = flattenTree(options);
  } catch {
    organizeTreeOptions.value = [];
    organizeNameMap.value = {};
  }
}

async function loadConstructionOrgs() {
  try {
    const res = await getConstructionList({ page: 1, page_size: 1000 });
    const body = parseListBody<{ id: string; name: string }>(res);
    constructionOrgNameMap.value = Object.fromEntries(body.data.map((item) => [item.id, item.name]));
  } catch {
    constructionOrgNameMap.value = {};
  }
}

async function submitCreate() {
  if (selectedAssetIds.value.length === 0) {
    message.warning('请选择需要核验的资产');
    return;
  }
  try {
    await createVerifyTasks({
      asset_ids: selectedAssetIds.value.map(String),
      source_type: createForm.source_type,
      target_organize_id: createForm.target_organize_id,
      remark: createForm.remark,
    });
    message.success('已创建核验任务');
    createModal.value = false;
    selectedAssetIds.value = [];
    fetchList();
  } catch {
    message.error('创建核验任务失败');
  }
}

function openAction(row: AssetVerifyTask, type: 'forward' | 'reject') {
  activeTask.value = row;
  actionType.value = type;
  Object.assign(actionForm, { target_organize_id: '', reject_reason: '', remark: '' });
  actionModal.value = true;
}

async function submitAction() {
  if (!activeTask.value) return;
  try {
    if (actionType.value === 'forward') {
      if (!actionForm.target_organize_id) {
        message.warning('请选择目标单位');
        return;
      }
      await forwardVerifyTask(activeTask.value.id, {
        target_organize_id: actionForm.target_organize_id,
        remark: actionForm.remark,
      });
      message.success(activeTask.value.status === 'pending_dispatch' ? '已下发' : '已转发');
    } else {
      await rejectVerifyTask(activeTask.value.id, {
        reject_reason: actionForm.reject_reason,
        remark: actionForm.remark,
      });
      message.success('已驳回');
    }
    actionModal.value = false;
    fetchList();
  } catch {
    message.error('操作失败');
  }
}

function runSimple(row: AssetVerifyTask, type: 'archive' | 'confirm' | 'receive' | 'return') {
  activeTask.value = row;
  pendingAction.value = type;
  confirmModal.value = true;
}

function getActionText(type = pendingAction.value) {
  if (!type) return '处理';
  const actionTextMap: Record<'archive' | 'confirm' | 'receive' | 'return', string> = {
    archive: '归档',
    confirm: '确认',
    receive: '接收',
    return: '退回',
  };
  return actionTextMap[type];
}

function getActiveTaskTitle() {
  const task = activeTask.value;
  return task?.asset_name || task?.address || '该资产';
}

async function submitSimpleAction() {
  if (!activeTask.value || !pendingAction.value) return;
  await runTaskAction(activeTask.value, pendingAction.value);
  confirmModal.value = false;
  pendingAction.value = '';
}

async function runTaskAction(row: AssetVerifyTask, type: 'archive' | 'confirm' | 'receive' | 'return') {
  try {
    if (type === 'receive') await receiveVerifyTask(row.id);
    if (type === 'confirm') await confirmVerifyTask(row.id);
    if (type === 'return') await returnVerifyTask(row.id);
    if (type === 'archive') await archiveVerifyTask(row.id);
    message.success('操作成功');
    fetchList();
  } catch {
    message.error('操作失败');
  }
}

async function showLogs(row: AssetVerifyTask) {
  activeTask.value = row;
  logDrawer.value = true;
  logLoading.value = true;
  try {
    const res = await getVerifyTaskLogs(row.id, { page: 1, page_size: 100 });
    logs.value = parseListBody<AssetVerifyOplog>(res).data;
  } catch {
    message.error('获取流转日志失败');
  } finally {
    logLoading.value = false;
  }
}

function resetSearch() {
  Object.assign(searchForm, { keyword: '', owner_organize_id: '', status: '' });
  pagination.page = 1;
  fetchList();
}

function openCreateModal() {
  Object.assign(createForm, { target_organize_id: '', source_type: 'manual', remark: '' });
  Object.assign(assetSearchForm, { keyword: '', organize_id: '' });
  selectedAssetIds.value = [];
  assetOptions.value = [];
  createModal.value = true;
  fetchAssets();
}

onMounted(() => {
  fetchList();
  loadOrganizeTree();
  loadConstructionOrgs();
});
</script>

<template>
  <div class="asset-workspace">
    <NCard title="资产核验任务" size="small" :bordered="false">
      <template #header-extra>
        <NButton type="primary" size="small" @click="openCreateModal">新建任务</NButton>
      </template>

      <NForm inline label-placement="left" :show-feedback="false" class="asset-toolbar">
        <NFormItem label="关键词">
          <NInput v-model:value="searchForm.keyword" clearable placeholder="系统名称 / 访问地址" @keyup.enter="fetchList" />
        </NFormItem>
        <NFormItem label="状态">
          <NSelect v-model:value="searchForm.status" clearable :options="statusOptions" placeholder="全部状态" />
        </NFormItem>
        <NFormItem label="所属单位">
          <NTreeSelect
            v-model:value="searchForm.owner_organize_id"
            clearable
            filterable
            :options="organizeTreeOptions"
            placeholder="全部单位"
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
        :scroll-x="1760"
      />
    </NCard>

    <NModal v-model:show="createModal" preset="dialog" title="新建核验任务" class="verify-task-modal">
      <NForm label-placement="left" label-width="96" class="modal-form">
        <NFormItem label="选择资产" required>
          <div class="asset-picker">
            <NSpace :size="8" class="asset-picker-toolbar">
              <NInput
                v-model:value="assetSearchForm.keyword"
                clearable
                placeholder="系统名称 / 访问地址"
                @keyup.enter="fetchAssets"
              />
              <NTreeSelect
                v-model:value="assetSearchForm.organize_id"
                clearable
                filterable
                :options="organizeTreeOptions"
                placeholder="资产所属单位"
              />
              <NButton type="primary" @click="fetchAssets">查询资产</NButton>
            </NSpace>
            <NDataTable
              size="small"
              remote
              :bordered="false"
              :columns="assetColumns"
              :data="assetOptions"
              :loading="assetLoading"
              :pagination="false"
              :row-key="(row: Asset) => row.id"
              :checked-row-keys="selectedAssetIds"
              :scroll-x="900"
              @update:checked-row-keys="(keys: DataTableRowKey[]) => selectedAssetIds = keys"
            />
            <div class="selection-tip">
              已选择 {{ selectedAssetIds.length }} 个资产
              <template v-if="selectedAssets.length > 0">
                ：{{ selectedAssets.map((item) => item.name || item.address).join('、') }}
              </template>
            </div>
          </div>
        </NFormItem>
        <NFormItem label="数据来源">
          <NSelect v-model:value="createForm.source_type" :options="sourceOptions" />
        </NFormItem>
        <NFormItem label="目标单位">
          <NTreeSelect
            v-model:value="createForm.target_organize_id"
            clearable
            filterable
            :options="organizeTreeOptions"
            placeholder="未选择则使用资产所属单位"
          />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="createForm.remark" type="textarea" :rows="2" placeholder="可填写下发说明或核验要求" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="createModal = false">取消</NButton>
          <NButton type="primary" @click="submitCreate">创建</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal
      v-model:show="actionModal"
      preset="dialog"
      :title="actionType === 'forward' ? `${getForwardActionText(activeTask)}核验任务` : '驳回核验任务'"
      style="width: 480px"
    >
      <NForm label-placement="left" label-width="90" class="modal-form">
        <NFormItem v-if="actionType === 'forward'" label="目标单位" required>
          <NTreeSelect
            v-model:value="actionForm.target_organize_id"
            clearable
            filterable
            :options="organizeTreeOptions"
            :placeholder="activeTask?.status === 'pending_dispatch' ? '选择负责确认资产归属的 IAM 单位' : '选择 IAM 单位'"
          />
        </NFormItem>
        <NFormItem v-if="actionType === 'reject'" label="驳回原因">
          <NInput v-model:value="actionForm.reject_reason" type="textarea" :rows="3" placeholder="请说明资产信息无法确认的原因" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="actionForm.remark" type="textarea" :rows="2" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="actionModal = false">取消</NButton>
          <NButton type="primary" @click="submitAction">确定</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal
      v-model:show="confirmModal"
      preset="dialog"
      :title="`${getActionText()}核验任务`"
      :positive-text="getActionText()"
      negative-text="取消"
      @positive-click="submitSimpleAction"
    >
      确定要{{ getActionText() }}“{{ getActiveTaskTitle() }}”的核验任务吗？
    </NModal>

    <NDrawer v-model:show="logDrawer" :width="760">
      <NDrawerContent :title="`流转日志${activeTask?.asset_name ? ` - ${activeTask.asset_name}` : ''}`">
        <NDataTable
          size="small"
          :bordered="false"
          :columns="logColumns"
          :data="logs"
          :loading="logLoading"
          :pagination="false"
          :scroll-x="980"
        />
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
.asset-toolbar :deep(.n-select),
.asset-toolbar :deep(.n-tree-select) {
  width: 220px;
}

.modal-form {
  margin-top: 14px;
}

.asset-picker {
  width: 100%;
}

.asset-picker-toolbar {
  margin-bottom: 12px;
}

.asset-picker-toolbar :deep(.n-input),
.asset-picker-toolbar :deep(.n-tree-select) {
  width: 240px;
}

.selection-tip {
  display: block;
  margin-top: 10px;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  color: var(--n-text-color-3);
  white-space: nowrap;
}

.cell-text--empty {
  color: var(--n-text-color-3);
}

:global(.verify-task-modal.n-modal) {
  width: min(920px, calc(100vw - 32px));
}
</style>
