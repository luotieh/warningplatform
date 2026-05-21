<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey, TreeOption } from 'naive-ui';

import { computed, h, onMounted, onUnmounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import {
  createDiscoveryProbe,
  getDiscoveryCandidates,
  getDiscoveryProbe,
  getDiscoveryProbeList,
  importDiscoveryCandidates,
  rejectDiscoveryCandidates,
  syncDiscoveryCandidates,
  verifyDiscoveryCandidates,
  type AssetDiscoveryCandidate,
  type AssetDiscoveryProbe,
} from '#/api/asset/discovery';
import { getOrganizeTree } from '#/api/assetmgr';
import { buildOrgTreeOptions } from '#/views/asset/ledger/utils';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSelect,
  NSpace,
  NTag,
  NText,
  NTreeSelect,
  useMessage,
} from 'naive-ui';

defineOptions({ name: 'AssetDiscoveryPage' });

const message = useMessage();
const router = useRouter();

const probeLoading = ref(false);
const candidateLoading = ref(false);
const creating = ref(false);
const actionLoading = ref(false);

const probes = ref<AssetDiscoveryProbe[]>([]);
const candidates = ref<AssetDiscoveryCandidate[]>([]);
const activeProbe = ref<AssetDiscoveryProbe | null>(null);
const selectedCandidateKeys = ref<DataTableRowKey[]>([]);

const createModal = ref(false);
const candidateModal = ref(false);
const verifyModal = ref(false);
const verifySubmitting = ref(false);
const orgTreeOptions = ref<TreeOption[]>([]);
const orgTreeLoading = ref(false);
const verifyForm = reactive({
  targetOrganizeId: '' as string | null,
  remark: '',
});
const importRemark = ref('');

const searchForm = reactive({ keyword: '', status: '' });
const candidateFilter = reactive({ status: '', keyword: '' });

const portsMode = ref<'preset' | 'custom'>('preset');

const createForm = reactive({
  name: '',
  targets_text: '',
  ports_preset: 'top1000',
  ports_custom: '22,80,443,3389,8080',
  timeout_ms: 800,
});

/** 发现超时过短会导致大量主机被判为不存活，建议 ≥500ms */
const timeoutMsMin = 200;
const timeoutMsMax = 10000;

const probePagination = reactive({
  page: 1,
  pageSize: 20,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 20, 50],
  onChange: (page: number) => {
    probePagination.page = page;
    fetchProbes();
  },
  onUpdatePageSize: (pageSize: number) => {
    probePagination.pageSize = pageSize;
    probePagination.page = 1;
    fetchProbes();
  },
});

const candidatePagination = reactive({
  page: 1,
  pageSize: 50,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [20, 50, 100],
  onChange: (page: number) => {
    candidatePagination.page = page;
    fetchCandidates();
  },
  onUpdatePageSize: (pageSize: number) => {
    candidatePagination.pageSize = pageSize;
    candidatePagination.page = 1;
    fetchCandidates();
  },
});

const portsOptions = [
  { label: '常用 1000 端口', value: 'top1000' },
  { label: '常用 100 端口', value: 'top100' },
  { label: '全端口 (较慢)', value: 'full' },
];

function formatPortsPreset(raw?: string) {
  const p = (raw ?? '').trim();
  if (!p) return '-';
  if (p === 'top100' || p === 'top1000' || p === 'full') {
    return portsOptions.find((o) => o.value === p)?.label ?? p;
  }
  return p.length > 36 ? `${p.slice(0, 36)}…` : p;
}

const probeStatusMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  pending: { label: '待启动', type: 'default' },
  running: { label: '探测中', type: 'info' },
  completed: { label: '已完成', type: 'success' },
  failed: { label: '失败', type: 'error' },
  cancelled: { label: '已取消', type: 'warning' },
};

const candidateStatusMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  pending: { label: '待下发核验', type: 'warning' },
  verified: { label: '已下发核验', type: 'info' },
  rejected: { label: '已驳回', type: 'error' },
  imported: { label: '已入库', type: 'success' },
  in_library: { label: '已在库', type: 'success' },
};

let pollTimer: ReturnType<typeof setInterval> | null = null;

const selectedCandidateIds = computed(() => selectedCandidateKeys.value.map(String));

const selectedCandidates = computed(() =>
  candidates.value.filter((c) => selectedCandidateIds.value.includes(c.id)),
);

const canDispatchVerify = computed(
  () =>
    selectedCandidates.value.length > 0 &&
    selectedCandidates.value.every(
      (c) => c.status === 'pending' && !c.in_asset_library,
    ),
);

const canImportSelected = computed(
  () =>
    selectedCandidates.value.length > 0 &&
    selectedCandidates.value.every((c) => c.status === 'verified' && !c.in_asset_library),
);

const probeColumns: DataTableColumns<AssetDiscoveryProbe> = [
  { title: '任务名称', key: 'name', minWidth: 160, ellipsis: { tooltip: true } },
  {
    title: '状态',
    key: 'status',
    width: 100,
    render: (row) => {
      const m = probeStatusMap[row.status] ?? { label: row.status, type: 'default' as const };
      return h(NTag, { size: 'small', type: m.type }, () => m.label);
    },
  },
  { title: '目标数', key: 'target_count', width: 80 },
  {
    title: '候选',
    key: 'candidate_total',
    width: 120,
    render: (row) =>
      `${row.candidate_total} / 待核${row.pending_count} / 入库${row.imported_count}`,
  },
  {
    title: '存活/端口',
    key: 'alive_hosts',
    width: 100,
    render: (row) => `${row.alive_hosts ?? 0} / ${row.open_ports ?? 0}`,
  },
  {
    title: '端口策略',
    key: 'ports_preset',
    width: 140,
    ellipsis: { tooltip: true },
    render: (row) => formatPortsPreset(row.ports_preset),
  },
  {
    title: '创建时间',
    key: 'created_at',
    width: 170,
    render: (row) => (row.created_at ? row.created_at.replace('T', ' ').slice(0, 19) : '-'),
  },
  {
    title: '操作',
    key: 'actions',
    width: 200,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 4 }, () => [
        h(
          NButton,
          {
            size: 'small',
            quaternary: true,
            type: 'primary',
            onClick: () => openCandidates(row),
          },
          () => '候选资产',
        ),
        row.task_id
          ? h(
              NButton,
              {
                size: 'small',
                quaternary: true,
                onClick: () => router.push(`/scan/task/${row.task_id}`),
              },
              () => '扫描详情',
            )
          : null,
      ]),
  },
];

const candidateColumns: DataTableColumns<AssetDiscoveryCandidate> = [
  {
    type: 'selection',
    disabled: (row) => row.status === 'in_library' || row.in_asset_library,
  },
  { title: '地址', key: 'address', minWidth: 150 },
  {
    title: '存活',
    key: 'alive',
    width: 64,
    render: (row) => (row.alive ? '是' : '-'),
  },
  {
    title: '台账单位',
    key: 'existing_organize_name',
    minWidth: 140,
    ellipsis: { tooltip: true },
    render: (row) => {
      if (row.status === 'in_library' || row.in_asset_library) {
        return row.existing_organize_name || row.existing_organize_id || '—';
      }
      return '—';
    },
  },
  {
    title: '核验单位',
    key: 'target_organize_name',
    width: 120,
    ellipsis: { tooltip: true },
    render: (row) => row.target_organize_name || '—',
  },
  {
    title: '状态',
    key: 'status',
    width: 110,
    render: (row) => {
      const status =
        row.in_asset_library && row.status === 'pending' ? 'in_library' : row.status;
      const m = candidateStatusMap[status] ?? { label: status, type: 'default' as const };
      return h(NTag, { size: 'small', type: m.type }, () => m.label);
    },
  },
  { title: '说明', key: 'title', minWidth: 140, ellipsis: { tooltip: true } },
];

async function loadOrgTree() {
  orgTreeLoading.value = true;
  try {
    const tree = await getOrganizeTree();
    orgTreeOptions.value = buildOrgTreeOptions(Array.isArray(tree) ? tree : []);
  } catch {
    orgTreeOptions.value = [];
  } finally {
    orgTreeLoading.value = false;
  }
}

function openVerifyModal() {
  if (!canDispatchVerify.value) {
    message.warning('请仅选择「待下发核验」且未在台账中的候选');
    return;
  }
  verifyForm.targetOrganizeId = null;
  verifyForm.remark = '';
  verifyModal.value = true;
}

async function submitVerifyDispatch() {
  if (!activeProbe.value) return;
  if (!verifyForm.targetOrganizeId) {
    message.warning('请选择核验目标单位');
    return;
  }
  verifySubmitting.value = true;
  try {
    const res = await verifyDiscoveryCandidates(activeProbe.value.id, {
      ids: selectedCandidateIds.value,
      target_organize_id: verifyForm.targetOrganizeId,
      remark: verifyForm.remark.trim() || undefined,
    });
    message.success(
      `已向「${res.target_organize_name ?? '目标单位'}」下发核验 ${res.updated ?? 0} 条，可在核验任务中跟进`,
    );
    verifyModal.value = false;
    selectedCandidateKeys.value = [];
    await refreshActiveProbe();
    await fetchCandidates();
    await fetchProbes();
  } catch (e: any) {
    message.error(e?.message ?? '下发核验失败');
  } finally {
    verifySubmitting.value = false;
  }
}

async function fetchProbes() {
  probeLoading.value = true;
  try {
    const { items, total } = await getDiscoveryProbeList({
      page: probePagination.page,
      page_size: probePagination.pageSize,
      keyword: searchForm.keyword || undefined,
      status: searchForm.status || undefined,
    });
    probes.value = items;
    probePagination.itemCount = total;
  } catch (e: any) {
    message.error(e?.message ?? '加载探测任务失败');
  } finally {
    probeLoading.value = false;
  }
}

async function fetchCandidates() {
  if (!activeProbe.value?.id) return;
  candidateLoading.value = true;
  try {
    const { items, total } = await getDiscoveryCandidates(activeProbe.value.id, {
      page: candidatePagination.page,
      page_size: candidatePagination.pageSize,
      status: candidateFilter.status || undefined,
      keyword: candidateFilter.keyword || undefined,
    });
    candidates.value = Array.isArray(items) ? items : [];
    candidatePagination.itemCount = total;
    if (total > 0 && candidates.value.length === 0) {
      message.warning('候选列表解析异常，请点「从扫描结果同步」或刷新页面');
    }
  } catch (e: any) {
    message.error(e?.message ?? '加载候选资产失败');
  } finally {
    candidateLoading.value = false;
  }
}

async function refreshActiveProbe() {
  if (!activeProbe.value?.id) return;
  try {
    activeProbe.value = await getDiscoveryProbe(activeProbe.value.id);
    const idx = probes.value.findIndex((p) => p.id === activeProbe.value?.id);
    if (idx >= 0 && activeProbe.value) {
      probes.value[idx] = activeProbe.value;
    }
  } catch {
    /* ignore poll errors */
  }
}

function startPoll() {
  stopPoll();
  pollTimer = setInterval(async () => {
    if (!activeProbe.value || activeProbe.value.status !== 'running') {
      if (activeProbe.value?.status === 'running') {
        await refreshActiveProbe();
      }
      return;
    }
    await refreshActiveProbe();
    await fetchCandidates();
    if (activeProbe.value?.status !== 'running') {
      await fetchProbes();
    }
  }, 5000);
}

function stopPoll() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

async function openCandidates(row: AssetDiscoveryProbe) {
  activeProbe.value = row;
  selectedCandidateKeys.value = [];
  candidatePagination.page = 1;
  candidateModal.value = true;
  await refreshActiveProbe();
  await fetchCandidates();
  if (
    activeProbe.value?.status === 'completed' ||
    activeProbe.value?.status === 'partial'
  ) {
    try {
      await syncDiscoveryCandidates(activeProbe.value.id);
      await refreshActiveProbe();
      await fetchCandidates();
    } catch {
      /* 同步失败时保留已加载的候选列表 */
    }
  }
  if (row.status === 'running' || activeProbe.value?.status === 'running') {
    startPoll();
  }
}

function closeCandidateModal() {
  candidateModal.value = false;
  stopPoll();
}

async function handleCreate() {
  const text = createForm.targets_text.trim();
  if (!text) {
    message.warning('请填写探测目标');
    return;
  }
  const custom = createForm.ports_custom.trim();
  if (portsMode.value === 'custom' && !custom) {
    message.warning('请填写自定义端口');
    return;
  }
  creating.value = true;
  try {
    const res = await createDiscoveryProbe({
      name: createForm.name.trim() || undefined,
      targets_text: text,
      ports_preset: portsMode.value === 'preset' ? createForm.ports_preset : undefined,
      ports_custom: portsMode.value === 'custom' ? custom : undefined,
      timeout_ms: Number(createForm.timeout_ms) || 800,
    });
    message.success(`探测已启动，展开 ${res.expanded ?? res.probe?.target_count ?? 0} 个目标`);
    createModal.value = false;
    createForm.targets_text = '';
    createForm.name = '';
    await fetchProbes();
    if (res.probe) {
      openCandidates(res.probe);
    }
  } catch (e: any) {
    const detail =
      e?.response?.data?.msg ??
      e?.response?.data?.err ??
      e?.message ??
      '创建探测失败';
    message.error(detail);
  } finally {
    creating.value = false;
  }
}

async function handleSync() {
  if (!activeProbe.value) return;
  actionLoading.value = true;
  try {
    const res = await syncDiscoveryCandidates(activeProbe.value.id);
    message.success(`已同步 ${res.synced ?? 0} 条候选`);
    await refreshActiveProbe();
    await fetchCandidates();
    await fetchProbes();
  } catch (e: any) {
    message.error(e?.message ?? '同步失败');
  } finally {
    actionLoading.value = false;
  }
}

async function runCandidateAction(action: 'reject' | 'import') {
  if (!activeProbe.value) return;
  const ids = selectedCandidateIds.value;
  if (!ids.length) {
    message.warning('请先选择候选资产');
    return;
  }
  if (action === 'import' && !canImportSelected.value) {
    const hasInLib = selectedCandidates.value.some((c) => c.in_asset_library);
    message.warning(
      hasInLib
        ? '所选候选已在资产库中，无需重复入库'
        : '仅可将「已下发核验」且未在库中的候选入库',
    );
    return;
  }
  actionLoading.value = true;
  try {
    const remark = action === 'import' ? importRemark.value.trim() || undefined : undefined;
    if (action === 'reject') {
      const res = await rejectDiscoveryCandidates(activeProbe.value.id, ids, remark);
      message.success(`已驳回 ${res.updated ?? 0} 条`);
    } else {
      const res = await importDiscoveryCandidates(activeProbe.value.id, ids, remark);
      message.success(`已按核验单位入库 ${res.imported ?? 0} 条，跳过 ${res.skipped ?? 0} 条`);
    }
    selectedCandidateKeys.value = [];
    await refreshActiveProbe();
    await fetchCandidates();
    await fetchProbes();
  } catch (e: any) {
    message.error(e?.message ?? '操作失败');
  } finally {
    actionLoading.value = false;
  }
}

onMounted(() => {
  fetchProbes();
  loadOrgTree();
});

onUnmounted(() => {
  stopPoll();
});
</script>

<template>
  <div class="p-4 flex flex-col gap-4">
    <NCard title="资产探测" size="small">
      <template #header-extra>
        <NSpace>
          <NButton type="primary" @click="createModal = true">新建探测</NButton>
          <NButton :loading="probeLoading" @click="fetchProbes">刷新</NButton>
        </NSpace>
      </template>
      <NSpace class="mb-3" wrap>
        <NInput
          v-model:value="searchForm.keyword"
          clearable
          placeholder="任务名称 / 目标"
          style="width: 220px"
          @keyup.enter="fetchProbes"
        />
        <NSelect
          v-model:value="searchForm.status"
          clearable
          placeholder="状态"
          style="width: 140px"
          :options="[
            { label: '探测中', value: 'running' },
            { label: '已完成', value: 'completed' },
            { label: '失败', value: 'failed' },
          ]"
        />
        <NButton @click="fetchProbes">查询</NButton>
      </NSpace>
      <NText depth="3" class="block mb-3 text-sm">
        在此创建与管理资产探测任务（与「漏洞扫描 → 任务列表」分离）。支持 IP、域名、CIDR 与自定义端口；完成后在「候选资产」中核验入库。历史漏扫中的资产探测任务会在刷新列表时自动同步到此页。
      </NText>
      <NDataTable
        :columns="probeColumns"
        :data="probes"
        :loading="probeLoading"
        :pagination="probePagination"
        :row-key="(row: AssetDiscoveryProbe) => row.id"
        remote
      />
    </NCard>

    <NModal v-model:show="createModal" preset="card" title="新建资产探测" style="width: 560px">
      <NForm label-placement="left" label-width="100">
        <NFormItem label="任务名称">
          <NInput v-model:value="createForm.name" placeholder="可选" />
        </NFormItem>
        <NFormItem label="探测目标" required>
          <NInput
            v-model:value="createForm.targets_text"
            type="textarea"
            :rows="6"
            placeholder="每行一个：IP、域名或 CIDR（如 192.168.1.0/24）"
          />
        </NFormItem>
        <NFormItem label="端口范围">
          <NSpace vertical style="width: 100%">
            <NSelect
              v-model:value="portsMode"
              :options="[
                { label: '预设端口组', value: 'preset' },
                { label: '自定义端口', value: 'custom' },
              ]"
            />
            <NSelect
              v-if="portsMode === 'preset'"
              v-model:value="createForm.ports_preset"
              :options="portsOptions"
            />
            <NInput
              v-else
              v-model:value="createForm.ports_custom"
              placeholder="逗号分隔或范围，如 22,80,443,3389,8000-8100"
            />
          </NSpace>
        </NFormItem>
        <NFormItem label="发现超时(ms)">
          <NInput v-model:value="createForm.timeout_ms" :allow-input="(v: string) => /^\d*$/.test(v)" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="createModal = false">取消</NButton>
          <NButton type="primary" :loading="creating" @click="handleCreate">开始探测</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal
      v-model:show="candidateModal"
      preset="card"
      :title="`候选资产 — ${activeProbe?.name ?? ''}`"
      class="discovery-candidate-modal"
      :style="{ width: 'min(920px, 92vw)' }"
      :content-style="{ maxHeight: 'min(78vh, 680px)' }"
      @after-leave="closeCandidateModal"
    >
      <div class="discovery-candidate-modal__body">
      <NSpace class="mb-2" wrap align="center" size="small">
        <NTag v-if="activeProbe" :type="probeStatusMap[activeProbe.status]?.type ?? 'default'">
          {{ probeStatusMap[activeProbe.status]?.label ?? activeProbe.status }}
        </NTag>
        <NText depth="3">目标 {{ activeProbe?.target_count ?? 0 }} · 候选 {{ activeProbe?.candidate_total ?? 0 }}</NText>
        <NInput
          v-model:value="candidateFilter.keyword"
          clearable
          placeholder="地址 / 服务"
          style="width: 160px"
          size="small"
        />
        <NSelect
          v-model:value="candidateFilter.status"
          clearable
          placeholder="候选状态"
          size="small"
          style="width: 120px"
          :options="[
            { label: '待下发核验', value: 'pending' },
            { label: '已在库', value: 'in_library' },
            { label: '已下发核验', value: 'verified' },
            { label: '已驳回', value: 'rejected' },
            { label: '已入库', value: 'imported' },
          ]"
        />
        <NButton size="small" @click="fetchCandidates">筛选</NButton>
        <NButton size="small" :loading="actionLoading" @click="handleSync">从扫描结果同步</NButton>
        <NButton size="small" quaternary type="primary" @click="router.push('/asset/verify-tasks')">
          核验任务
        </NButton>
      </NSpace>
      <NText depth="3" class="discovery-candidate-modal__hint">
        新发现主机需下发核验后入库；状态「已在库」表示台账中已有，无需重复操作。
      </NText>
      <NSpace class="mb-2" wrap size="small">
        <NButton
          size="small"
          type="info"
          :disabled="!canDispatchVerify"
          @click="openVerifyModal"
        >
          下发核验
        </NButton>
        <NButton
          size="small"
          :loading="actionLoading"
          :disabled="!selectedCandidateIds.length"
          @click="runCandidateAction('reject')"
        >
          驳回
        </NButton>
        <NInput
          v-model:value="importRemark"
          placeholder="入库备注（可选）"
          size="small"
          style="width: 200px"
        />
        <NButton
          size="small"
          type="primary"
          :loading="actionLoading"
          :disabled="!canImportSelected"
          @click="runCandidateAction('import')"
        >
          入库到资产库
        </NButton>
      </NSpace>
      <div class="discovery-candidate-modal__table-wrap">
        <NDataTable
          v-model:checked-row-keys="selectedCandidateKeys"
          :columns="candidateColumns"
          :data="candidates"
          :loading="candidateLoading"
          :pagination="candidatePagination"
          :row-key="(row: AssetDiscoveryCandidate) => row.id"
          :scroll-x="720"
          :max-height="400"
          size="small"
          remote
        />
      </div>
      </div>
    </NModal>

    <NModal
      v-model:show="verifyModal"
      preset="card"
      title="下发核验"
      style="width: min(620px, calc(100vw - 32px))"
    >
      <NForm label-placement="top">
        <NFormItem label="核验目标单位" required>
          <NTreeSelect
            v-model:value="verifyForm.targetOrganizeId"
            filterable
            clearable
            default-expand-all
            key-field="key"
            label-field="label"
            children-field="children"
            :options="orgTreeOptions"
            :loading="orgTreeLoading"
            placeholder="请选择接收核验的单位"
          />
        </NFormItem>
        <NFormItem :label="`备注（本次 ${selectedCandidateIds.length} 条候选）`">
          <NInput
            v-model:value="verifyForm.remark"
            type="textarea"
            :rows="3"
            placeholder="下发说明，将随核验任务流转"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="verifyModal = false">取消</NButton>
          <NButton type="primary" :loading="verifySubmitting" @click="submitVerifyDispatch">
            确认下发
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.discovery-candidate-modal__body {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.discovery-candidate-modal__hint {
  display: block;
  font-size: 12px;
  line-height: 1.5;
  margin: 0;
}

.discovery-candidate-modal__table-wrap {
  min-height: 200px;
}
</style>
