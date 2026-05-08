<script lang="ts" setup>
import { h, onMounted, reactive, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NDescriptions, NDescriptionsItem, NDrawer, NDrawerContent,
  NForm, NFormItem, NGrid, NGridItem, NInput, NInputNumber, NModal, NPopconfirm,
  NSelect, NSpace, NSwitch, NTabPane, NTabs, NTag, NUpload, useMessage,
} from 'naive-ui';
import type { UploadFileInfo } from 'naive-ui';
import { NStatistic } from 'naive-ui';
import { useRouter } from 'vue-router';
import type { Asset } from '#/api/asset';
import { createAsset, deleteAsset, getAssetList, importAssets, updateAsset } from '#/api/asset';
import { createTask } from '#/api/task';
import { requestClient } from '#/api/request';

defineOptions({ name: 'AssetLedger' });

const router = useRouter();
const message = useMessage();
const loading = ref(false);
const data = ref<Asset[]>([]);
const checkedKeys = ref<string[]>([]);
const showModal = ref(false);
const showDetail = ref(false);
const showImport = ref(false);
const importLoading = ref(false);
const editingId = ref<null | string>(null);
const detailItem = ref<Asset | null>(null);
const sendingToMonitor = ref(false);
const monitorResultVisible = ref(false);
const monitorResult = ref<any>(null);
const showBatchEdit = ref(false);
const batchEditLoading = ref(false);
const batchEditForm = reactive({
  field: '' as string,
  value: '' as string,
});
const exportLoading = ref(false);

const pagination = reactive({
  page: 1, pageSize: 20, itemCount: 0, showSizePicker: true, pageSizes: [10, 20, 50, 100],
  onChange: (p: number) => { pagination.page = p; fetchList(); },
  onUpdatePageSize: (ps: number) => { pagination.pageSize = ps; pagination.page = 1; fetchList(); },
});

const searchForm = reactive({
  keyword: '', data_number: '', system_type: undefined as string | undefined,
  security_protection_level: undefined as string | undefined,
  lifecycle_state: undefined as string | undefined, data_source: undefined as string | undefined,
});

const formData = reactive({
  name: '', type: 'server', address: '', port: 0, domain: '', ipv4: '', url: '', protocol: '',
  service: '', version: '', os: '', data_number: '', system_name: '', system_type: '',
  is_online: true, is_key: false, security_protection_level: '', filing_cert_number: '',
  icp_filing_number: '', construction_org_id: '', operation_org_id: '', data_source: 'manual_import',
  responsible_user_name: '', remark: '', tags: [] as string[],
});

const systemTypeOptions = [
  { label: '网站', value: 'url' }, { label: '应用系统', value: 'application' },
  { label: '数据库', value: 'database' }, { label: '服务器', value: 'server' },
  { label: '网络设备', value: 'network' }, { label: '安全设备', value: 'security' },
];
const securityOptions = [
  { label: '一级', value: 'level1' }, { label: '二级', value: 'level2' },
  { label: '三级', value: 'level3' }, { label: '四级', value: 'level4' }, { label: '五级', value: 'level5' },
];
const sourceOptions = [
  { label: '手动导入', value: 'manual_import' }, { label: '自动探测', value: 'auto_detect' },
  { label: '外部集成', value: 'external' },
];
const lifecycleOptions = [
  { label: '已发现', value: 'discovered' }, { label: '已确认', value: 'confirmed' },
  { label: '已登记', value: 'registered' }, { label: '运营中', value: 'operating' },
  { label: '退役中', value: 'decommission' }, { label: '已下线', value: 'offline' },
];

const systemTypeMap: Record<string, string> = Object.fromEntries(systemTypeOptions.map(o => [o.value, o.label]));
const securityMap: Record<string, string> = Object.fromEntries(securityOptions.map(o => [o.value, o.label]));
const sourceMap: Record<string, string> = Object.fromEntries(sourceOptions.map(o => [o.value, o.label]));
const lifecycleMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  discovered: { label: '已发现', type: 'default' }, confirmed: { label: '已确认', type: 'info' },
  registered: { label: '已登记', type: 'info' }, operating: { label: '运营中', type: 'success' },
  decommission: { label: '退役中', type: 'warning' }, offline: { label: '已下线', type: 'error' },
};

const columns = [
  { type: 'selection' as const, width: 50 },
  { title: '数据编号', key: 'data_number', width: 130, ellipsis: { tooltip: true } },
  { title: '系统名称', key: 'system_name', width: 160, ellipsis: { tooltip: true },
    render: (row: Asset) => row.system_name || row.name },
  { title: '地址', key: 'address', width: 160, ellipsis: { tooltip: true } },
  { title: '系统类型', key: 'system_type', width: 100,
    render: (row: Asset) => systemTypeMap[row.system_type ?? ''] || row.type },
  { title: '保护等级', key: 'security_protection_level', width: 90,
    render: (row: Asset) => row.security_protection_level
      ? h(NTag, { size: 'small', type: 'info' }, () => securityMap[row.security_protection_level!] || row.security_protection_level)
      : '-' },
  { title: '生命周期', key: 'lifecycle_state', width: 90,
    render: (row: Asset) => { const m = lifecycleMap[row.lifecycle_state ?? '']; return m ? h(NTag, { size: 'small', type: m.type }, () => m.label) : '-'; } },
  { title: '风险分', key: 'risk_score', width: 70,
    render: (row: Asset) => h('span', { style: { color: (row.risk_score ?? 0) >= 70 ? '#d03050' : (row.risk_score ?? 0) >= 40 ? '#f0a020' : '#18a058' } }, String(row.risk_score ?? 0)) },
  { title: '漏洞', key: 'vuln_count', width: 60,
    render: (row: Asset) => (row.vuln_count ?? 0) > 0
      ? h(NTag, { size: 'small', type: 'error', bordered: false }, () => String(row.vuln_count))
      : h('span', { style: 'color: #ccc' }, '0') },
  { title: '责任人', key: 'responsible_user_name', width: 80 },
  { title: '数据来源', key: 'data_source', width: 80,
    render: (row: Asset) => sourceMap[row.data_source ?? ''] || row.data_source || '-' },
  { title: '操作', key: 'actions', width: 230, fixed: 'right' as const,
    render: (row: Asset) => h(NSpace, { size: 4 }, () => [
      h(NPopconfirm, { onPositiveClick: () => onScan(row) }, {
        trigger: () => h(NButton, { size: 'small', type: 'warning' }, () => '扫描'),
        default: () => `对 ${row.address} 发起漏洞扫描？`,
      }),
      h(NButton, { size: 'small', type: 'info', onClick: () => onDetail(row) }, () => '详情'),
      h(NButton, { size: 'small', onClick: () => onEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => onDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => '确认删除？',
      }),
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: pagination.page, page_size: pagination.pageSize, ...searchForm };
    const res = await getAssetList(params);
    data.value = res.items ?? [];
    pagination.itemCount = res.total ?? 0;
  } catch { message.error('获取资产台账失败'); }
  finally { loading.value = false; }
}

function onSearch() { pagination.page = 1; fetchList(); }
function onReset() {
  Object.assign(searchForm, { keyword: '', data_number: '', system_type: undefined, security_protection_level: undefined, lifecycle_state: undefined, data_source: undefined });
  onSearch();
}

function resetForm() {
  Object.assign(formData, {
    name: '', type: 'server', address: '', port: 0, domain: '', ipv4: '', url: '', protocol: '',
    service: '', version: '', os: '', data_number: '', system_name: '', system_type: '',
    is_online: true, is_key: false, security_protection_level: '', filing_cert_number: '',
    icp_filing_number: '', construction_org_id: '', operation_org_id: '', data_source: 'manual_import',
    responsible_user_name: '', remark: '', tags: [],
  });
}

function onAdd() { editingId.value = null; resetForm(); showModal.value = true; }

function onEdit(row: Asset) {
  editingId.value = row.id;
  Object.assign(formData, {
    name: row.name, type: row.type, address: row.address, port: row.port ?? 0,
    domain: row.domain ?? '', ipv4: row.ipv4 ?? '', url: row.url ?? '', protocol: row.protocol ?? '',
    service: row.service ?? '', version: row.version ?? '', os: row.os ?? '',
    data_number: row.data_number ?? '', system_name: row.system_name ?? '', system_type: row.system_type ?? '',
    is_online: row.is_online ?? true, is_key: row.is_key ?? false,
    security_protection_level: row.security_protection_level ?? '',
    filing_cert_number: row.filing_cert_number ?? '', icp_filing_number: row.icp_filing_number ?? '',
    construction_org_id: row.construction_org_id ?? '', operation_org_id: row.operation_org_id ?? '',
    data_source: row.data_source ?? 'manual_import',
    responsible_user_name: row.responsible_user_name ?? '', remark: row.remark ?? '',
    tags: row.tags ?? [],
  });
  showModal.value = true;
}

const detailVulns = ref<any[]>([]);
const detailMonitorTasks = ref<any[]>([]);

async function onDetail(row: Asset) {
  detailItem.value = row;
  detailVulns.value = [];
  detailMonitorTasks.value = [];
  showDetail.value = true;
  try {
    const res: any = await requestClient.get(`/asset/detail/${row.id}`);
    const body = res?.data ?? res;
    detailVulns.value = body?.asset_vulns ?? [];
    detailMonitorTasks.value = body?.monitor_tasks ?? [];
  } catch { /* detail enrichment is non-critical */ }
}

async function onSave() {
  if (!formData.name || !formData.address) { message.warning('请填写名称和地址'); return; }
  try {
    if (editingId.value) { await updateAsset(editingId.value, formData as any); message.success('更新成功'); }
    else { await createAsset(formData as any); message.success('创建成功'); }
    showModal.value = false; fetchList();
  } catch { message.error('操作失败'); }
}

async function onDelete(id: string) {
  try { await deleteAsset(id); message.success('删除成功'); fetchList(); }
  catch { message.error('删除失败'); }
}

async function onBatchDelete() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  for (const id of checkedKeys.value) { await deleteAsset(id).catch(() => {}); }
  checkedKeys.value = []; message.success('批量删除完成'); fetchList();
}

function buildTarget(row: Asset): string {
  if (row.url) return row.url;
  if (row.domain) return row.port ? `${row.domain}:${row.port}` : row.domain;
  if (row.ipv4) return row.port ? `${row.ipv4}:${row.port}` : row.ipv4;
  return row.port ? `${row.address}:${row.port}` : row.address;
}

async function onScan(row: Asset) {
  try {
    await createTask({
      name: `扫描-${row.system_name || row.name}`,
      targets: [buildTarget(row)],
    });
    message.success('扫描任务已创建，请到扫描中心查看');
  } catch { message.error('创建扫描任务失败'); }
}

async function onBatchScan() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  const selected = data.value.filter(a => checkedKeys.value.includes(a.id));
  const targets = selected.map(buildTarget);
  try {
    await createTask({
      name: `批量扫描-${targets.length}个资产`,
      targets,
    });
    message.success(`已创建扫描任务，包含 ${targets.length} 个目标`);
  } catch { message.error('创建扫描任务失败'); }
}

async function onImportUpload(options: { file: UploadFileInfo }) {
  const rawFile = options.file.file;
  if (!rawFile) return;
  importLoading.value = true;
  try {
    const res: any = await importAssets(rawFile);
    const body = res?.data ?? res;
    const imported = body?.data?.imported ?? body?.imported ?? 0;
    message.success(`成功导入 ${imported} 条资产`);
    showImport.value = false;
    fetchList();
  } catch { message.error('导入失败，请检查文件格式'); }
  finally { importLoading.value = false; }
}

async function downloadTemplate() {
  try {
    const blob = await requestClient.download<Blob>('/asset/import/template');
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'asset_import_template.xlsx';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch {
    message.error('下载模板失败');
  }
}

async function onSendToMonitor() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  sendingToMonitor.value = true;
  try {
    const res: any = await requestClient.post('/monitor/tasks/from-assets', {
      asset_ids: checkedKeys.value,
    });
    monitorResult.value = res?.data ?? res;
    monitorResultVisible.value = true;
    checkedKeys.value = [];
    message.success(`创建了 ${monitorResult.value?.success ?? 0} 个监测任务`);
  } catch (e: any) {
    message.error(e?.msg || '发送到站点监控失败');
  } finally {
    sendingToMonitor.value = false;
  }
}

const batchEditFieldOptions = [
  { label: '系统类型', value: 'system_type' },
  { label: '保护等级', value: 'security_protection_level' },
  { label: '生命周期', value: 'lifecycle_state' },
  { label: '数据来源', value: 'data_source' },
  { label: '责任人', value: 'responsible_user_name' },
  { label: '状态(1活跃/0不活跃)', value: 'status' },
  { label: '是否关键资产', value: 'is_key' },
  { label: '备注', value: 'remark' },
];
const batchEditValueOptions: Record<string, { label: string; value: string }[]> = {
  system_type: systemTypeOptions,
  security_protection_level: securityOptions,
  lifecycle_state: lifecycleOptions,
  data_source: sourceOptions,
  status: [{ label: '活跃', value: '1' }, { label: '不活跃', value: '0' }],
  is_key: [{ label: '是', value: 'true' }, { label: '否', value: 'false' }],
};

function openBatchEdit() {
  if (!checkedKeys.value.length) { message.warning('请先选择资产'); return; }
  batchEditForm.field = '';
  batchEditForm.value = '';
  showBatchEdit.value = true;
}

async function onBatchEditConfirm() {
  if (!batchEditForm.field || !batchEditForm.value) { message.warning('请选择字段和值'); return; }
  batchEditLoading.value = true;
  let val: any = batchEditForm.value;
  if (batchEditForm.field === 'status') val = Number(val);
  if (batchEditForm.field === 'is_key') val = val === 'true';
  try {
    const res: any = await requestClient.post('/asset/batch-update', {
      ids: checkedKeys.value,
      updates: { [batchEditForm.field]: val },
    });
    const affected = res?.data?.affected ?? res?.affected ?? 0;
    message.success(`已更新 ${affected} 条资产`);
    showBatchEdit.value = false;
    checkedKeys.value = [];
    fetchList();
  } catch { message.error('批量编辑失败'); }
  finally { batchEditLoading.value = false; }
}

async function onExport() {
  exportLoading.value = true;
  try {
    const params: Record<string, string> = { format: 'csv' };
    if (searchForm.keyword) params.keyword = searchForm.keyword;
    if (searchForm.system_type) params.system_type = searchForm.system_type;
    if (searchForm.security_protection_level) params.security_protection_level = searchForm.security_protection_level;
    if (searchForm.lifecycle_state) params.lifecycle_state = searchForm.lifecycle_state;
    if (searchForm.data_source) params.data_source = searchForm.data_source;

    const blob = await requestClient.download<Blob>('/asset/export', { params });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `assets_${new Date().toISOString().slice(0, 10)}.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch {
    message.error('导出失败');
  } finally {
    exportLoading.value = false;
  }
}

onMounted(fetchList);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="资产台账" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NButton type="primary" size="small" @click="onAdd">登记资产</NButton>
          <NButton size="small" @click="showImport = true">导入</NButton>
          <NButton size="small" :loading="exportLoading" @click="onExport">导出</NButton>
          <NButton size="small" :disabled="!checkedKeys.length" @click="openBatchEdit">
            批量编辑{{ checkedKeys.length ? ` (${checkedKeys.length})` : '' }}
          </NButton>
          <NPopconfirm @positive-click="onBatchScan">
            <template #trigger><NButton type="warning" size="small" :disabled="!checkedKeys.length">批量扫描</NButton></template>
            对选中的资产发起漏洞扫描？
          </NPopconfirm>
          <NButton type="info" size="small" :loading="sendingToMonitor" :disabled="!checkedKeys.length" @click="onSendToMonitor">
            发送监控{{ checkedKeys.length ? ` (${checkedKeys.length})` : '' }}
          </NButton>
          <NPopconfirm @positive-click="onBatchDelete">
            <template #trigger><NButton type="error" size="small" :disabled="!checkedKeys.length">批量删除</NButton></template>
            确认删除选中的资产？
          </NPopconfirm>
        </NSpace>
      </template>

      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="关键词"><NInput v-model:value="searchForm.keyword" placeholder="名称/地址" clearable style="width: 160px" /></NFormItem>
        <NFormItem label="编号"><NInput v-model:value="searchForm.data_number" placeholder="数据编号" clearable style="width: 130px" /></NFormItem>
        <NFormItem label="类型"><NSelect v-model:value="searchForm.system_type" :options="systemTypeOptions" placeholder="全部" clearable style="width: 110px" /></NFormItem>
        <NFormItem label="等保"><NSelect v-model:value="searchForm.security_protection_level" :options="securityOptions" placeholder="全部" clearable style="width: 90px" /></NFormItem>
        <NFormItem label="状态"><NSelect v-model:value="searchForm.lifecycle_state" :options="lifecycleOptions" placeholder="全部" clearable style="width: 100px" /></NFormItem>
        <NFormItem><NSpace :size="8"><NButton type="primary" @click="onSearch">查询</NButton><NButton @click="onReset">重置</NButton></NSpace></NFormItem>
      </NForm>

      <NDataTable v-model:checked-row-keys="checkedKeys" :columns="columns" :data="data" :loading="loading"
        :pagination="pagination" :row-key="(row: Asset) => row.id" :bordered="false" :scroll-x="1350" size="small" striped remote />
    </NCard>

    <!-- 登记/编辑 -->
    <NModal v-model:show="showModal" preset="dialog" :title="editingId ? '编辑资产' : '资产登记'" style="width: 780px">
      <NForm label-placement="left" label-width="100" style="margin-top: 16px">
        <NGrid :cols="2" :x-gap="16">
          <NGridItem><NFormItem label="资产名称" required><NInput v-model:value="formData.name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="系统名称"><NInput v-model:value="formData.system_name" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="地址" required><NInput v-model:value="formData.address" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="端口"><NInputNumber v-model:value="formData.port" :min="0" :max="65535" style="width: 100%" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="域名"><NInput v-model:value="formData.domain" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="IPv4"><NInput v-model:value="formData.ipv4" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="URL"><NInput v-model:value="formData.url" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="协议"><NInput v-model:value="formData.protocol" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="系统类型"><NSelect v-model:value="formData.system_type" :options="systemTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="资产类型"><NSelect v-model:value="formData.type" :options="systemTypeOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="数据编号"><NInput v-model:value="formData.data_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="保护等级"><NSelect v-model:value="formData.security_protection_level" :options="securityOptions" clearable /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="是否在线"><NSwitch v-model:value="formData.is_online" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="是否关键"><NSwitch v-model:value="formData.is_key" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="等保证号"><NInput v-model:value="formData.filing_cert_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="ICP备案号"><NInput v-model:value="formData.icp_filing_number" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="数据来源"><NSelect v-model:value="formData.data_source" :options="sourceOptions" /></NFormItem></NGridItem>
          <NGridItem><NFormItem label="责任人"><NInput v-model:value="formData.responsible_user_name" /></NFormItem></NGridItem>
          <NGridItem span="2"><NFormItem label="备注"><NInput v-model:value="formData.remark" type="textarea" :rows="2" /></NFormItem></NGridItem>
        </NGrid>
      </NForm>
      <template #action><NSpace><NButton @click="showModal = false">取消</NButton><NButton type="primary" @click="onSave">确认</NButton></NSpace></template>
    </NModal>

    <!-- 详情抽屉 -->
    <NDrawer v-model:show="showDetail" :width="600">
      <NDrawerContent :title="detailItem?.system_name || detailItem?.name || '资产详情'">
        <NTabs v-if="detailItem" type="line" size="small">
          <NTabPane name="info" tab="基本信息">
            <NDescriptions label-placement="left" bordered :column="1" size="small">
              <NDescriptionsItem label="ID">{{ detailItem.id }}</NDescriptionsItem>
              <NDescriptionsItem label="名称">{{ detailItem.name }}</NDescriptionsItem>
              <NDescriptionsItem label="系统名称">{{ detailItem.system_name || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="地址">{{ detailItem.address }}</NDescriptionsItem>
              <NDescriptionsItem label="域名">{{ detailItem.domain || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="IPv4">{{ detailItem.ipv4 || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="端口">{{ detailItem.port || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="系统类型">{{ systemTypeMap[detailItem.system_type ?? ''] || detailItem.type }}</NDescriptionsItem>
              <NDescriptionsItem label="保护等级">{{ securityMap[detailItem.security_protection_level ?? ''] || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="数据编号">{{ detailItem.data_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="生命周期">{{ lifecycleMap[detailItem.lifecycle_state ?? '']?.label || detailItem.lifecycle_state || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="风险分">{{ detailItem.risk_score ?? 0 }}</NDescriptionsItem>
              <NDescriptionsItem label="漏洞数">{{ detailItem.vuln_count ?? 0 }}</NDescriptionsItem>
              <NDescriptionsItem label="责任人">{{ detailItem.responsible_user_name || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="数据来源">{{ sourceMap[detailItem.data_source ?? ''] || detailItem.data_source || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="等保证号">{{ detailItem.filing_cert_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="ICP备案">{{ detailItem.icp_filing_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="最近扫描">{{ detailItem.last_scan_at || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="SSL到期">{{ detailItem.ssl_expires_at || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="创建时间">{{ detailItem.created_at }}</NDescriptionsItem>
              <NDescriptionsItem label="备注">{{ detailItem.remark || '-' }}</NDescriptionsItem>
            </NDescriptions>
          </NTabPane>
          <NTabPane name="vulns" tab="关联漏洞">
            <div v-if="detailVulns.length === 0" style="padding: 20px; text-align: center; color: #999">暂无关联漏洞</div>
            <NDataTable v-else :data="detailVulns" :bordered="false" size="small" :columns="[
              { title: '漏洞', key: 'title', ellipsis: { tooltip: true } },
              { title: '严重度', key: 'severity', width: 70 },
              { title: '状态', key: 'status', width: 70 },
              { title: '时间', key: 'created_at', width: 150 },
            ]" :max-height="400" />
            <NButton v-if="detailVulns.length > 0" text type="info" style="margin-top: 8px" @click="router.push(`/vuln/list?asset_id=${detailItem.id}`)">查看全部漏洞 →</NButton>
          </NTabPane>
          <NTabPane name="monitor" tab="关联监控">
            <div v-if="detailMonitorTasks.length === 0" style="padding: 20px; text-align: center; color: #999">暂无关联监控任务</div>
            <NDataTable v-else :data="detailMonitorTasks" :bordered="false" size="small" :columns="[
              { title: '任务名', key: 'task_name', ellipsis: { tooltip: true } },
              { title: '首页', key: 'target_homepage', width: 180, ellipsis: { tooltip: true } },
              { title: '状态', key: 'enabled', width: 60, render: (row: any) => row.enabled ? '启用' : '停用' },
            ]" :max-height="400" />
            <NButton v-if="detailMonitorTasks.length > 0" text type="info" style="margin-top: 8px" @click="router.push('/monitor/tasks')">查看监控任务 →</NButton>
          </NTabPane>
        </NTabs>
      </NDrawerContent>
    </NDrawer>

    <!-- 批量编辑弹窗 -->
    <NModal v-model:show="showBatchEdit" preset="dialog" title="批量编辑" style="width: 460px">
      <div style="margin-top: 12px">
        <p style="margin-bottom: 12px; color: #666">将对选中的 {{ checkedKeys.length }} 个资产进行统一修改。</p>
        <NForm label-placement="left" label-width="80" :show-feedback="false">
          <NFormItem label="修改字段">
            <NSelect v-model:value="batchEditForm.field" :options="batchEditFieldOptions" placeholder="选择字段" />
          </NFormItem>
          <NFormItem label="目标值" style="margin-top: 12px">
            <NSelect v-if="batchEditValueOptions[batchEditForm.field]" v-model:value="batchEditForm.value" :options="batchEditValueOptions[batchEditForm.field]" placeholder="选择值" />
            <NInput v-else v-model:value="batchEditForm.value" placeholder="输入值" />
          </NFormItem>
        </NForm>
      </div>
      <template #action>
        <NSpace>
          <NButton @click="showBatchEdit = false">取消</NButton>
          <NButton type="primary" :loading="batchEditLoading" @click="onBatchEditConfirm">确认修改</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 导入弹窗 -->
    <NModal v-model:show="showImport" preset="dialog" title="导入资产" style="width: 500px">
      <div style="margin-top: 16px">
        <p style="margin-bottom: 12px; color: #666">支持 .csv 和 .xlsx 格式，请按模板填写数据后上传。</p>
        <NSpace vertical :size="16">
          <NButton text type="primary" @click="downloadTemplate">下载导入模板 (xlsx)</NButton>
          <NUpload
            :max="1"
            accept=".csv,.xlsx,.xls"
            :custom-request="({ file }: any) => onImportUpload({ file })"
            :show-file-list="false"
          >
            <NButton type="primary" :loading="importLoading">{{ importLoading ? '导入中...' : '选择文件上传' }}</NButton>
          </NUpload>
        </NSpace>
      </div>
    </NModal>

    <!-- 发送到站点监控结果 -->
    <NModal v-model:show="monitorResultVisible" preset="card" title="发送到站点监控" style="width: 540px">
      <template v-if="monitorResult">
        <NGrid :cols="3" :x-gap="8" style="margin-bottom: 12px">
          <NGridItem><NCard size="small"><NStatistic label="成功创建" :value="monitorResult.success ?? 0" /></NCard></NGridItem>
          <NGridItem><NCard size="small"><NStatistic label="已存在跳过" :value="monitorResult.skipped ?? 0" /></NCard></NGridItem>
          <NGridItem><NCard size="small"><NStatistic label="失败" :value="monitorResult.failed ?? 0" /></NCard></NGridItem>
        </NGrid>
        <NDataTable
          v-if="monitorResult.details?.length"
          :columns="[
            { title: '资产', key: 'asset_name', ellipsis: { tooltip: true } },
            {
              title: '结果',
              key: 'status',
              width: 100,
              render: (row: any) => h(NTag, { type: row.status === 'success' ? 'success' : row.status === 'skipped' ? 'warning' : 'error', size: 'small' }, () => row.status === 'success' ? '成功' : row.status === 'skipped' ? '跳过' : '失败'),
            },
            { title: '说明', key: 'reason', ellipsis: { tooltip: true } },
          ]"
          :data="monitorResult.details"
          :bordered="false"
          size="small"
          :max-height="300"
        />
      </template>
      <template #action><NButton @click="monitorResultVisible = false">关闭</NButton></template>
    </NModal>
  </div>
</template>
