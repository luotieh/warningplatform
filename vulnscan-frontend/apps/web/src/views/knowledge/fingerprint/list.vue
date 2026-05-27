<script lang="ts" setup>
import { h, onMounted, ref, computed } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NDivider,
  NDrawer,
  NDrawerContent,
  NDescriptions,
  NDescriptionsItem,
  NInput,
  NInputNumber,
  NModal,
  NForm,
  NFormItem,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
} from 'naive-ui';

import {
  getFingerprintList,
  createFingerprint,
  updateFingerprint,
  deleteFingerprint,
  type ServiceFingerprint,
} from '#/api/fingerprint';

defineOptions({ name: 'FingerprintManage' });

const message = useMessage();
const loading = ref(false);
const data = ref<ServiceFingerprint[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const protocolFilter = ref<string | null>(null);

const showEditor = ref(false);
const editorMode = ref<'create' | 'edit'>('create');
const editingId = ref('');
const saving = ref(false);
const editorForm = ref({
  name: '', service: '', protocol: 'tcp', probe_type: 'passive',
  probe_data: '', match_type: 'regex', match_rule: '', version_expr: '',
  priority: 50, ports: '', description: '', status: 'active',
  http_paths: '', http_headers: '', http_method: 'GET', http_match_body: false,
  tls_match_cn: false, tls_match_san: false, tls_match_org: false,
  tls_match_issuer: false, tls_match_expiry: false, tls_match_self_sign: false,
  probe_chain: '', probe_chain_next: '',
});

const showDetail = ref(false);
const detailItem = ref<ServiceFingerprint | null>(null);

const protocolOpts = [
  { label: 'TCP', value: 'tcp' },
  { label: 'UDP', value: 'udp' },
];
const probeOpts = [
  { label: '被动', value: 'passive' },
  { label: '主动', value: 'active' },
];
const matchOpts = [
  { label: '正则', value: 'regex' },
  { label: '关键词', value: 'word' },
  { label: '十六进制', value: 'hex' },
  { label: 'HTTP Header', value: 'header' },
  { label: 'HTTP Path', value: 'path' },
  { label: 'TLS 证书', value: 'tls' },
];
const statusOpts = [
  { label: '启用', value: 'active' },
  { label: '停用', value: 'disabled' },
  { label: '草稿', value: 'draft' },
];
const httpMethodOpts = [
  { label: 'GET', value: 'GET' },
  { label: 'POST', value: 'POST' },
  { label: 'HEAD', value: 'HEAD' },
  { label: 'OPTIONS', value: 'OPTIONS' },
];

const columns = computed(() => [
  {
    title: '名称', key: 'name', minWidth: 160,
    render: (row: ServiceFingerprint) => h('a', { style: 'color: #1890ff; cursor: pointer', onClick: () => { detailItem.value = row; showDetail.value = true; } }, row.name),
  },
  {
    title: '服务', key: 'service', width: 100,
    render: (row: ServiceFingerprint) => h(NTag, { size: 'small', type: 'info', bordered: false }, () => row.service),
  },
  { title: '协议', key: 'protocol', width: 60 },
  {
    title: '探测', key: 'probe_type', width: 70,
    render: (row: ServiceFingerprint) => h(NTag, { size: 'small', type: row.probe_type === 'active' ? 'warning' : 'default', bordered: false }, () => row.probe_type === 'active' ? '主动' : '被动'),
  },
  { title: '匹配', key: 'match_type', width: 60 },
  { title: '优先级', key: 'priority', width: 60 },
  { title: '端口', key: 'ports', width: 100, ellipsis: { tooltip: true } },
  {
    title: '状态', key: 'status', width: 70,
    render: (row: ServiceFingerprint) => h(NTag, { type: row.status === 'active' ? 'success' : 'default', size: 'small', bordered: false }, () => row.status === 'active' ? '启用' : row.status === 'draft' ? '草稿' : '停用'),
  },
  {
    title: '操作', key: 'actions', width: 120, fixed: 'right' as const,
    render: (row: ServiceFingerprint) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', type: 'info', secondary: true, onClick: () => openEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'),
        default: () => '确定删除？',
      }),
    ]),
  },
]);

async function fetchData() {
  loading.value = true;
  try {
    const result = await getFingerprintList({
      page: page.value, page_size: pageSize.value,
      keyword: keyword.value || undefined,
      protocol: protocolFilter.value || undefined,
    });
    data.value = result.items ?? [];
    total.value = result.total ?? 0;
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  editorMode.value = 'create';
  editingId.value = '';
  editorForm.value = { name: '', service: '', protocol: 'tcp', probe_type: 'passive', probe_data: '', match_type: 'regex', match_rule: '', version_expr: '', priority: 50, ports: '', description: '', status: 'active', http_paths: '', http_headers: '', http_method: 'GET', http_match_body: false, tls_match_cn: false, tls_match_san: false, tls_match_org: false, tls_match_issuer: false, tls_match_expiry: false, tls_match_self_sign: false, probe_chain: '', probe_chain_next: '' };
  showEditor.value = true;
}

function openEdit(row: ServiceFingerprint) {
  editorMode.value = 'edit';
  editingId.value = row.id;
  editorForm.value = {
    name: row.name, service: row.service, protocol: row.protocol,
    probe_type: row.probe_type, probe_data: row.probe_data ?? '',
    match_type: row.match_type, match_rule: row.match_rule,
    version_expr: row.version_expr ?? '', priority: row.priority,
    ports: row.ports ?? '', description: row.description ?? '',
    status: row.status,
    http_paths: row.http_paths ?? '', http_headers: row.http_headers ?? '',
    http_method: row.http_method ?? 'GET', http_match_body: row.http_match_body ?? false,
    tls_match_cn: row.tls_match_cn ?? false, tls_match_san: row.tls_match_san ?? false,
    tls_match_org: row.tls_match_org ?? false, tls_match_issuer: row.tls_match_issuer ?? false,
    tls_match_expiry: row.tls_match_expiry ?? false, tls_match_self_sign: row.tls_match_self_sign ?? false,
    probe_chain: row.probe_chain ?? '', probe_chain_next: row.probe_chain_next ?? '',
  };
  showEditor.value = true;
}

async function handleSave() {
  if (!editorForm.value.name || !editorForm.value.match_rule) { message.warning('名称和匹配规则不能为空'); return; }
  saving.value = true;
  try {
    if (editorMode.value === 'create') {
      await createFingerprint(editorForm.value as any);
      message.success('创建成功');
    } else {
      await updateFingerprint(editingId.value, editorForm.value as any);
      message.success('更新成功');
    }
    showEditor.value = false;
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '保存失败');
  } finally {
    saving.value = false;
  }
}

async function handleDelete(id: string) {
  try {
    await deleteFingerprint(id);
    message.success('已删除');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="识别指纹" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect v-model:value="protocolFilter" :options="protocolOpts" placeholder="协议" size="small" style="width: 90px" clearable @update:value="() => { page = 1; fetchData(); }" />
          <NInput v-model:value="keyword" placeholder="搜索服务/名称..." size="small" clearable style="width: 180px" @keyup.enter="() => { page = 1; fetchData(); }" />
          <NButton size="small" type="primary" @click="() => { page = 1; fetchData(); }">搜索</NButton>
          <NButton size="small" @click="openCreate">新建</NButton>
        </NSpace>
      </template>

      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped :scroll-x="900" :pagination="{ page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20, 50, 100], onUpdatePage: (p: number) => { page = p; fetchData(); }, onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); } }" />
    </NCard>

    <!-- Editor Modal -->
    <NModal v-model:show="showEditor" :title="editorMode === 'create' ? '新建指纹规则' : '编辑指纹规则'" preset="card" style="width: 720px">
      <NForm label-placement="left" label-width="90" size="small">
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0 16px">
          <NFormItem label="名称"><NInput v-model:value="editorForm.name" placeholder="规则名称" /></NFormItem>
          <NFormItem label="服务"><NInput v-model:value="editorForm.service" placeholder="如 ssh, mysql, http" /></NFormItem>
          <NFormItem label="协议"><NSelect v-model:value="editorForm.protocol" :options="protocolOpts" /></NFormItem>
          <NFormItem label="探测方式"><NSelect v-model:value="editorForm.probe_type" :options="probeOpts" /></NFormItem>
          <NFormItem label="匹配方式"><NSelect v-model:value="editorForm.match_type" :options="matchOpts" /></NFormItem>
          <NFormItem label="优先级"><NInputNumber v-model:value="editorForm.priority" :min="0" :max="100" /></NFormItem>
        </div>
        <NFormItem label="匹配规则"><NInput v-model:value="editorForm.match_rule" placeholder="正则表达式或字符串" style="font-family: monospace" /></NFormItem>
        <NFormItem label="版本提取"><NInput v-model:value="editorForm.version_expr" placeholder="版本号提取正则（可选）" style="font-family: monospace" /></NFormItem>
        <NFormItem v-if="editorForm.probe_type === 'active'" label="探测数据"><NInput v-model:value="editorForm.probe_data" type="textarea" :rows="3" placeholder="主动发送的探测包（可选）" style="font-family: monospace" /></NFormItem>
        <NFormItem label="适用端口"><NInput v-model:value="editorForm.ports" placeholder="如 22,2222 或留空适用所有" /></NFormItem>
        <NFormItem label="状态"><NSelect v-model:value="editorForm.status" :options="statusOpts" /></NFormItem>

        <!-- HTTP 深度识别 -->
        <NDivider title-placement="left">HTTP 深度识别</NDivider>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0 16px">
          <NFormItem label="HTTP 方法"><NSelect v-model:value="editorForm.http_method" :options="httpMethodOpts" /></NFormItem>
          <NFormItem label="匹配响应体"><NSwitch v-model:value="editorForm.http_match_body" /></NFormItem>
        </div>
        <NFormItem label="HTTP 路径"><NInput v-model:value="editorForm.http_paths" placeholder="多路径用逗号分隔，如 /admin/,/login" style="font-family: monospace" /></NFormItem>
        <NFormItem label="HTTP 请求头"><NInput v-model:value="editorForm.http_headers" placeholder="格式 Key:Value,Key2:Value2" style="font-family: monospace" /></NFormItem>

        <!-- TLS 证书分析 -->
        <NDivider title-placement="left">TLS 证书分析</NDivider>
        <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0 16px">
          <NFormItem label="匹配 CN"><NSwitch v-model:value="editorForm.tls_match_cn" /></NFormItem>
          <NFormItem label="匹配 SAN"><NSwitch v-model:value="editorForm.tls_match_san" /></NFormItem>
          <NFormItem label="匹配组织"><NSwitch v-model:value="editorForm.tls_match_org" /></NFormItem>
          <NFormItem label="匹配颁发者"><NSwitch v-model:value="editorForm.tls_match_issuer" /></NFormItem>
          <NFormItem label="匹配过期"><NSwitch v-model:value="editorForm.tls_match_expiry" /></NFormItem>
          <NFormItem label="自签名"><NSwitch v-model:value="editorForm.tls_match_self_sign" /></NFormItem>
        </div>

        <!-- 探测链 -->
        <NDivider title-placement="left">探测链</NDivider>
        <NFormItem label="下一步指纹"><NInput v-model:value="editorForm.probe_chain_next" placeholder="下一步探测的指纹 ID" /></NFormItem>

        <NFormItem label="描述"><NInput v-model:value="editorForm.description" type="textarea" :rows="2" placeholder="可选描述" /></NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showEditor = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="handleSave">{{ editorMode === 'create' ? '创建' : '保存' }}</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Detail Drawer -->
    <NDrawer v-model:show="showDetail" :width="640">
      <NDrawerContent v-if="detailItem" :title="detailItem.name">
        <NDescriptions label-placement="left" bordered :column="2" size="small">
          <NDescriptionsItem label="服务">{{ detailItem.service }}</NDescriptionsItem>
          <NDescriptionsItem label="协议">{{ detailItem.protocol }}</NDescriptionsItem>
          <NDescriptionsItem label="探测方式">{{ detailItem.probe_type === 'active' ? '主动' : '被动' }}</NDescriptionsItem>
          <NDescriptionsItem label="匹配方式">{{ detailItem.match_type }}</NDescriptionsItem>
          <NDescriptionsItem label="优先级">{{ detailItem.priority }}</NDescriptionsItem>
          <NDescriptionsItem label="状态">{{ detailItem.status === 'active' ? '启用' : '停用' }}</NDescriptionsItem>
          <NDescriptionsItem :span="2" label="适用端口">{{ detailItem.ports || '全部' }}</NDescriptionsItem>
          <NDescriptionsItem :span="2" label="匹配规则">
            <code style="font-size: 12px; background: #f5f5f5; padding: 4px 8px; border-radius: 4px">{{ detailItem.match_rule }}</code>
          </NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.version_expr" :span="2" label="版本提取">
            <code style="font-size: 12px; background: #f5f5f5; padding: 4px 8px; border-radius: 4px">{{ detailItem.version_expr }}</code>
          </NDescriptionsItem>
          <NDescriptionsItem v-if="detailItem.probe_data" :span="2" label="探测数据">
            <pre style="font-size: 12px; background: #f5f5f5; padding: 8px; border-radius: 4px; margin: 0">{{ detailItem.probe_data }}</pre>
          </NDescriptionsItem>

          <!-- HTTP 深度识别 -->
          <template v-if="detailItem.http_paths || detailItem.http_headers">
            <NDescriptionsItem label="HTTP 方法">{{ detailItem.http_method || 'GET' }}</NDescriptionsItem>
            <NDescriptionsItem label="匹配响应体">{{ detailItem.http_match_body ? '是' : '否' }}</NDescriptionsItem>
            <NDescriptionsItem v-if="detailItem.http_paths" :span="2" label="HTTP 路径">
              <code style="font-size: 12px; background: #f5f5f5; padding: 4px 8px; border-radius: 4px">{{ detailItem.http_paths }}</code>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="detailItem.http_headers" :span="2" label="HTTP 请求头">
              <code style="font-size: 12px; background: #f5f5f5; padding: 4px 8px; border-radius: 4px">{{ detailItem.http_headers }}</code>
            </NDescriptionsItem>
          </template>

          <!-- TLS 证书分析 -->
          <template v-if="detailItem.tls_match_cn || detailItem.tls_match_san || detailItem.tls_match_org || detailItem.tls_match_issuer || detailItem.tls_match_expiry || detailItem.tls_match_self_sign">
            <NDescriptionsItem label="匹配 CN">{{ detailItem.tls_match_cn ? '是' : '否' }}</NDescriptionsItem>
            <NDescriptionsItem label="匹配 SAN">{{ detailItem.tls_match_san ? '是' : '否' }}</NDescriptionsItem>
            <NDescriptionsItem label="匹配组织">{{ detailItem.tls_match_org ? '是' : '否' }}</NDescriptionsItem>
            <NDescriptionsItem label="匹配颁发者">{{ detailItem.tls_match_issuer ? '是' : '否' }}</NDescriptionsItem>
            <NDescriptionsItem label="匹配过期">{{ detailItem.tls_match_expiry ? '是' : '否' }}</NDescriptionsItem>
            <NDescriptionsItem label="自签名">{{ detailItem.tls_match_self_sign ? '是' : '否' }}</NDescriptionsItem>
          </template>

          <!-- 探测链 -->
          <NDescriptionsItem v-if="detailItem.probe_chain_next" :span="2" label="下一步指纹">
            <code style="font-size: 12px; background: #f5f5f5; padding: 4px 8px; border-radius: 4px">{{ detailItem.probe_chain_next }}</code>
          </NDescriptionsItem>

          <NDescriptionsItem v-if="detailItem.description" :span="2" label="描述">{{ detailItem.description }}</NDescriptionsItem>
        </NDescriptions>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
