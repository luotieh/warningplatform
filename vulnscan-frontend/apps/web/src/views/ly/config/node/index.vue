<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref, watch } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NInputNumber,
  NModal,
  NPagination,
  NSelect,
  NSpace,
  NTag,
  useMessage,
} from 'naive-ui';

import { lyConfigSave, lyNodeTestConnection } from '#/api/ly';
import { useLyStore } from '#/store/ly';
import { paginate } from '#/utils/ly';

defineOptions({ name: 'LyConfigNode' });

const message = useMessage();
const lyStore = useLyStore();
const state = reactive({ page: 1, pageSize: 10 });
const testingKeys = ref(new Set<string>());
const checkingAll = ref(false);

const modalVisible = ref(false);
const modalMode = ref<'add' | 'mod'>('add');
const form = reactive<Record<string, any>>({
  agentid: '',
  comment: '',
  devid: '',
  flowtype: 'netflow',
  id: undefined,
  interface: '',
  ip: '',
  name: '',
  node_type: 'device',
  port: 19090,
  protocol: 'http',
  status: 'unknown',
  version: 'ta_node',
});

const typeOptions = [
  { label: '采集节点', value: 'device' },
  { label: '分析融合节点', value: 'proxy' },
];
const protocolOptions = [
  { label: 'HTTP', value: 'http' },
  { label: 'HTTPS', value: 'https' },
  { label: 'TCP', value: 'tcp' },
];
const statusOptions = [
  { label: '未知', value: 'unknown' },
  { label: '在线', value: 'online' },
  { label: '异常', value: 'warning' },
  { label: '离线', value: 'offline' },
  { label: '停用', value: 'disabled' },
];

const rows = computed<Record<string, any>[]>(() => [
  ...normalizeRows(lyStore.device, 'device'),
  ...normalizeRows(lyStore.proxy, 'proxy'),
]);
const pagedRows = computed(() => paginate(rows.value, state.page, state.pageSize));

watch(rows, () => {
  const max = Math.max(1, Math.ceil(rows.value.length / state.pageSize));
  if (state.page > max) state.page = max;
});

function normalizeRows(source: Record<string, any>[], type: 'device' | 'proxy') {
  return (source || []).map((item) => {
    const meta = parseMeta(item.meta);
    const protocol = item.protocol ?? meta.protocol ?? 'http';
    const port = Number(item.port ?? meta.port ?? (protocol === 'https' ? 443 : 19090));
    return {
      ...item,
      agentid: item.agentid ?? meta.agentid ?? '',
      comment: item.comment ?? meta.comment ?? item.description ?? item.desc ?? '',
      flowtype: item.flowtype ?? meta.flowtype ?? '',
      interface: item.interface ?? meta.interface ?? '',
      last_test_at: item.last_test_at ?? meta.last_test_at ?? '',
      last_test_message: item.last_test_message ?? meta.last_test_message ?? '',
      node_type: type,
      port,
      protocol,
      row_key: `${type}-${item.id ?? item.devid ?? item.ip ?? item.name}`,
      status: normalizeStatus(item.status),
      typeText: type === 'device' ? '采集节点' : '分析融合节点',
    };
  });
}

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
    standby: { text: '待命', type: 'info' },
    unknown: { text: '未知', type: 'info' },
    warning: { text: '异常', type: 'warning' },
  };
  return map[status] ?? { text: status, type: 'info' };
}

function resetForm(row?: Record<string, any>) {
  Object.assign(form, {
    agentid: row?.agentid ?? '',
    comment: row?.comment ?? '',
    devid: row?.devid ?? '',
    flowtype: row?.flowtype || 'netflow',
    id: row?.id,
    interface: row?.interface ?? '',
    ip: row?.ip ?? '',
    name: row?.name ?? '',
    node_type: row?.node_type ?? 'device',
    port: Number(row?.port ?? 19090),
    protocol: row?.protocol ?? 'http',
    status: row?.status ?? 'unknown',
    version: row?.version ?? 'ta_node',
  });
}

function onAdd(type: 'device' | 'proxy' = 'device') {
  modalMode.value = 'add';
  resetForm({ node_type: type, port: 19090, protocol: 'http' });
  modalVisible.value = true;
}

function onEdit(row: Record<string, any>) {
  modalMode.value = 'mod';
  resetForm(row);
  modalVisible.value = true;
}

function buildPayload(row: Record<string, any>) {
  const target = row.node_type === 'device' ? 'device' : 'proxy';
  const endpoint = normalizeEndpoint(row.ip, row.port, row.protocol);
  return {
    agentid: row.agentid,
    comment: row.comment,
    description: row.comment,
    devid: row.devid || undefined,
    flowtype: row.flowtype,
    id: row.id,
    interface: row.interface,
    ip: endpoint.ip,
    name: row.name,
    node_type: target,
    port: endpoint.port,
    protocol: endpoint.protocol,
    status: row.status,
    target,
    type: 'agent',
    version: row.version,
  };
}

function normalizeEndpoint(ip: any, port: any, protocol: any) {
  const raw = String(ip ?? '').trim();
  const fallbackProtocol = String(protocol || 'http').toLowerCase();
  const fallbackPort = Number(port || (fallbackProtocol === 'https' ? 443 : 19090));
  try {
    const withScheme = raw.includes('://') ? raw : `${fallbackProtocol}://${raw}`;
    const url = new URL(withScheme);
    return {
      ip: url.hostname || raw,
      port: Number(url.port || fallbackPort),
      protocol: url.protocol.replace(':', '') || fallbackProtocol,
    };
  } catch {
    const match = raw.match(/^([^:]+):(\d+)$/);
    if (match) {
      return {
        ip: match[1],
        port: Number(match[2]),
        protocol: fallbackProtocol,
      };
    }
    return {
      ip: raw,
      port: fallbackPort,
      protocol: fallbackProtocol,
    };
  }
}

async function submitForm() {
  if (!form.name) {
    message.warning('请输入节点名称');
    return;
  }
  if (!form.ip) {
    message.warning('请输入节点 IP');
    return;
  }
  if (!form.port) {
    message.warning('请输入节点端口');
    return;
  }

  await lyConfigSave({
    ...buildPayload(form),
    op: modalMode.value,
  });
  await lyStore.loadConfigs();
  modalVisible.value = false;
  message.success('操作成功');
}

async function deleteRow(row: Record<string, any>) {
  if (!window.confirm('确认删除当前节点？')) return;
  await lyConfigSave({
    ...buildPayload(row),
    op: 'del',
  });
  await lyStore.loadConfigs();
  message.success('操作成功');
}

async function testRow(row: Record<string, any>) {
  const key = row.row_key;
  testingKeys.value.add(key);
  testingKeys.value = new Set(testingKeys.value);
  try {
    const result = (await lyNodeTestConnection(buildPayload(row))) as Record<
      string,
      any
    >;
    if (result?.reachable) {
      await lyConfigSave({
        ...buildPayload(row),
        last_test_at: result.tested_at,
        last_test_message: result.message,
        op: 'mod',
        status: result.status || 'online',
      });
      message.success(`连接成功：${result.message || 'reachable'}`);
    } else {
      await lyConfigSave({
        ...buildPayload(row),
        last_test_at: result?.tested_at,
        last_test_message: result?.message,
        op: 'mod',
        status: result?.status || 'offline',
      });
      message.error(`连接失败：${result?.message || 'unreachable'}`);
    }
    await lyStore.loadConfigs();
  } finally {
    testingKeys.value.delete(key);
    testingKeys.value = new Set(testingKeys.value);
  }
}

// 进入页面 / 点击刷新时主动检测所有节点的在线情况，而不是读取数据库中的旧状态。
// 后端在 op=test 时会实时探测节点并把最新状态写回数据库，这里并发探测全部节点后再统一拉取一次。
async function checkAllNodes() {
  if (checkingAll.value) return;
  checkingAll.value = true;
  try {
    // 先确保拿到最新的节点列表
    await lyStore.loadConfigs();
    const targets = rows.value;
    if (!targets.length) return;

    testingKeys.value = new Set(targets.map((row) => row.row_key));
    let online = 0;
    let offline = 0;
    await Promise.all(
      targets.map(async (row) => {
        try {
          const result = (await lyNodeTestConnection(buildPayload(row))) as Record<
            string,
            any
          >;
          if (result?.reachable) online += 1;
          else offline += 1;
        } catch {
          offline += 1;
        } finally {
          testingKeys.value.delete(row.row_key);
          testingKeys.value = new Set(testingKeys.value);
        }
      }),
    );
    // 后端探测时已写回最新状态，重新拉取以刷新表格
    await lyStore.loadConfigs();
    message.info(`节点检测完成：在线 ${online}，离线/异常 ${offline}`);
  } finally {
    testingKeys.value = new Set();
    checkingAll.value = false;
  }
}

async function refreshAll() {
  await checkAllNodes();
}

function formatTime(value: any) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

const columns = [
  { title: '类型', key: 'typeText', width: 120 },
  { title: '名称', key: 'name', minWidth: 160 },
  { title: 'IP', key: 'ip', minWidth: 150 },
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
  { title: '最后测试', key: 'last_test_at', minWidth: 180, render: (row: Record<string, any>) => formatTime(row.last_test_at) },
  { title: '测试结果', key: 'last_test_message', minWidth: 180, ellipsis: { tooltip: true } },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    fixed: 'right' as const,
    render: (row: Record<string, any>) =>
      h(NSpace, { size: 8 }, () => [
        h(
          NButton,
          {
            loading: testingKeys.value.has(row.row_key),
            text: true,
            type: 'success',
            onClick: () => testRow(row),
          },
          { default: () => '测试连接' },
        ),
        h(
          NButton,
          { text: true, type: 'primary', onClick: () => onEdit(row) },
          { default: () => '编辑' },
        ),
        h(
          NButton,
          { text: true, type: 'error', onClick: () => deleteRow(row) },
          { default: () => '删除' },
        ),
      ]),
  },
];

onMounted(async () => {
  // 进入页面即主动确认所有节点的在线情况，而非展示历史状态
  await checkAllNodes();
});
</script>

<template>
  <div class="ly-page">
    <NCard class="content-card" size="small">
      <NSpace class="toolbar">
        <NButton type="primary" @click="onAdd('device')">新增采集节点</NButton>
        <NButton type="primary" secondary @click="onAdd('proxy')">
          新增分析融合节点
        </NButton>
        <NButton :loading="checkingAll" @click="refreshAll">刷新并检测</NButton>
      </NSpace>

      <NDataTable
        :columns="columns"
        :data="pagedRows"
        :bordered="true"
        size="small"
      />
      <div class="pager-wrap">
        <NPagination
          v-model:page="state.page"
          v-model:page-size="state.pageSize"
          :item-count="rows.length"
          show-size-picker
          show-quick-jumper
          :page-sizes="[10, 20, 50, 100]"
        />
      </div>
    </NCard>

    <NModal
      v-model:show="modalVisible"
      preset="card"
      :title="modalMode === 'add' ? '新增节点' : '编辑节点'"
      class="node-modal"
      :mask-closable="false"
    >
      <NForm label-placement="left" label-width="96">
        <div class="form-grid">
          <NFormItem label="节点类型">
            <NSelect v-model:value="form.node_type" :options="typeOptions" />
          </NFormItem>
          <NFormItem label="节点名称">
            <NInput v-model:value="form.name" />
          </NFormItem>
          <NFormItem v-if="form.node_type === 'device'" label="设备编号">
            <NInput v-model:value="form.devid" placeholder="留空则自动生成" />
          </NFormItem>
          <NFormItem v-else label="版本">
            <NInput v-model:value="form.version" />
          </NFormItem>
          <NFormItem label="IP 地址">
            <NInput v-model:value="form.ip" />
          </NFormItem>
          <NFormItem label="端口">
            <NInputNumber v-model:value="form.port" :min="1" :max="65535" />
          </NFormItem>
          <NFormItem label="协议">
            <NSelect v-model:value="form.protocol" :options="protocolOptions" />
          </NFormItem>
          <NFormItem label="状态">
            <NSelect v-model:value="form.status" :options="statusOptions" />
          </NFormItem>
          <NFormItem v-if="form.node_type === 'device'" label="流类型">
            <NInput v-model:value="form.flowtype" />
          </NFormItem>
          <NFormItem v-if="form.node_type === 'device'" label="采集网卡">
            <NInput v-model:value="form.interface" />
          </NFormItem>
          <NFormItem label="关联代理">
            <NInput v-model:value="form.agentid" placeholder="可选" />
          </NFormItem>
          <NFormItem class="form-wide" label="备注">
            <NInput v-model:value="form.comment" type="textarea" :rows="3" />
          </NFormItem>
        </div>
      </NForm>
      <template #footer>
        <div class="modal-footer">
          <NButton @click="modalVisible = false">取消</NButton>
          <NButton type="primary" @click="submitForm">确定</NButton>
        </div>
      </template>
    </NModal>
  </div>
</template>

<style scoped>
.ly-page {
  min-height: 100%;
  padding: 16px;
}

.content-card :deep(.n-card__content) {
  padding: 18px;
}

.toolbar {
  margin-bottom: 12px;
}

.pager-wrap {
  display: flex;
  justify-content: flex-end;
  padding-top: 12px;
}

.form-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 0 16px;
}

.form-wide {
  grid-column: 1 / -1;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 12px;
}

:global(.node-modal) {
  width: min(760px, 94vw);
}

@media (max-width: 720px) {
  .ly-page {
    padding: 12px;
  }

  .form-grid {
    grid-template-columns: 1fr;
  }
}
</style>
