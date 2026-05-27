<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';
import { computed, h, onMounted, ref } from 'vue';
import { useRoute } from 'vue-router';

import {
  NButton, NCard, NDataTable, NDrawer, NDrawerContent, NEmpty,
  NForm, NFormItem, NInput, NInputNumber, NModal, NPopconfirm,
  NSelect, NSpace, NSwitch, NTabPane, NTabs, NTag, NText, NSpin,
  useMessage,
} from 'naive-ui';

import {
  getDataLibList, getDataLibEntries, createDataLib,
  deleteDataLib, addDataLibEntry, updateDataLibEntry, deleteDataLibEntry,
  importDataLib, exportDataLibUrl, clearDataLib,
  type DataLibrary, type DataLibraryEntry,
} from '#/api/datalib';


defineOptions({ name: 'DataLibManage' });

const message = useMessage();
const activeTab = ref('dict');

const categoryOptions = [
  { label: 'SQL注入', value: 'sqli' }, { label: '跨站脚本(XSS)', value: 'xss' },
  { label: 'CRLF注入', value: 'crlf' }, { label: '命令注入', value: 'cmdi' },
  { label: '路径遍历', value: 'lfi' }, { label: 'SSRF', value: 'ssrf' },
  { label: '模板注入(SSTI)', value: 'ssti' }, { label: 'XXE注入', value: 'xxe' },
  { label: 'NoSQL注入', value: 'nosqli' }, { label: 'JWT安全', value: 'jwt' },
  { label: 'XML-RPC', value: 'xmlrpc' }, { label: '点击劫持', value: 'clickjacking' },
  { label: 'HTTP请求走私', value: 'http_smuggling' }, { label: '子域接管', value: 'subdomain_takeover' },
  { label: '文件上传', value: 'file_upload' }, { label: '反序列化', value: 'deserialization' },
  { label: '认证绕过', value: 'auth_bypass' }, { label: '开放重定向', value: 'open_redirect' },
  { label: '目录遍历', value: 'dir_traversal' }, { label: 'Host头注入', value: 'host_header' },
];
const categoryLabels: Record<string, string> = Object.fromEntries(categoryOptions.map(o => [o.value, o.label]));

// ═══════════════════════════════════
// Tab 1: 扫描字典
// ═══════════════════════════════════
const dictLoading = ref(false);
const dictData = ref<DataLibrary[]>([]);
const dictTotal = ref(0);
const dictPage = ref(1);
const dictPageSize = ref(20);
const dictKeyword = ref('');
const dictTypeFilter = ref<string | null>(null);

const dictTypeOptions = [
  { label: '子域名', value: 'subdomain' },
  { label: '目录路径', value: 'dirpath' },
  { label: '用户名', value: 'username' },
  { label: '密码', value: 'password' },
  { label: 'User-Agent', value: 'useragent' },
  { label: '自定义', value: 'custom' },
];
const dictTypeLabels: Record<string, string> = {
  subdomain: '子域名', dirpath: '目录路径', username: '用户名',
  password: '密码', useragent: 'UA', custom: '自定义',
};

const showDictCreateModal = ref(false);
const dictCreateForm = ref({ name: '', type: 'custom', description: '' });
const showImportModal = ref(false);
const importLibId = ref('');
const importText = ref('');
const importing = ref(false);

const showDrawer = ref(false);
const currentLib = ref<DataLibrary | null>(null);
const entries = ref<DataLibraryEntry[]>([]);
const entryTotal = ref(0);
const entryPage = ref(1);
const entryLoading = ref(false);
const newEntryValue = ref('');

const dictColumns = computed<DataTableColumns<DataLibrary>>(() => [
  { title: '名称', key: 'name', minWidth: 160, ellipsis: { tooltip: true } },
  { title: '类型', key: 'type', width: 100, render: (row) => h(NTag, { size: 'small', bordered: false, type: 'info' }, () => dictTypeLabels[row.type] ?? row.type) },
  { title: '描述', key: 'description', minWidth: 200, ellipsis: { tooltip: true } },
  { title: '条目数', key: 'entry_count', width: 80 },
  { title: '状态', key: 'status', width: 80, render: (row) => h(NTag, { size: 'small', type: row.status === 'active' ? 'success' : 'default', bordered: false }, () => row.status === 'active' ? '启用' : '停用') },
  { title: '创建时间', key: 'created_at', width: 150 },
  { title: '操作', key: 'actions', width: 220, fixed: 'right' as const, render: (row) => h(NSpace, { size: 4 }, () => [
    h(NButton, { size: 'tiny', type: 'info', secondary: true, onClick: () => openDrawer(row) }, () => '查看条目'),
    h(NButton, { size: 'tiny', secondary: true, onClick: () => openImport(row.id) }, () => '导入'),
    h(NButton, { size: 'tiny', secondary: true, onClick: () => window.open(exportDataLibUrl(row.id), '_blank') }, () => '导出'),
    h(NPopconfirm, { onPositiveClick: () => handleDeleteLib(row.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'), default: () => '确定删除？' }),
  ]) },
]);

async function fetchDictList() {
  dictLoading.value = true;
  try {
    const result = await getDataLibList({
      page: dictPage.value, page_size: dictPageSize.value,
      keyword: dictKeyword.value || undefined,
      type: dictTypeFilter.value || undefined,
      exclude_types: dictTypeFilter.value ? undefined : 'config,pattern,payload',
    });
    dictData.value = result.items;
    dictTotal.value = result.total;
  } finally { dictLoading.value = false; }
}

async function handleCreateDict() {
  try {
    await createDataLib(dictCreateForm.value);
    message.success('创建成功');
    showDictCreateModal.value = false;
    dictCreateForm.value = { name: '', type: 'custom', description: '' };
    await fetchDictList();
  } catch (e: any) { message.error(e?.message || '创建失败'); }
}

async function handleDeleteLib(id: string) {
  try { await deleteDataLib(id); message.success('已删除'); await fetchDictList(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}

function openImport(id: string) { importLibId.value = id; importText.value = ''; showImportModal.value = true; }

async function handleImport() {
  if (!importText.value.trim()) return;
  importing.value = true;
  try {
    await importDataLib(importLibId.value, importText.value);
    message.success('导入成功');
    showImportModal.value = false;
    await fetchDictList();
    if (currentLib.value?.id === importLibId.value) await fetchEntries();
  } catch (e: any) { message.error(e?.message || '导入失败'); }
  finally { importing.value = false; }
}

async function openDrawer(lib: DataLibrary) {
  currentLib.value = lib; showDrawer.value = true; entryPage.value = 1; await fetchEntries();
}

async function fetchEntries() {
  if (!currentLib.value) return;
  entryLoading.value = true;
  try {
    const result = await getDataLibEntries(currentLib.value.id, { page: entryPage.value, page_size: 50 });
    entries.value = result.items; entryTotal.value = result.total;
  } finally { entryLoading.value = false; }
}

async function handleAddEntry() {
  if (!currentLib.value || !newEntryValue.value.trim()) return;
  try {
    await addDataLibEntry(currentLib.value.id, { value: newEntryValue.value.trim(), enabled: true });
    newEntryValue.value = ''; await fetchEntries(); await fetchDictList();
  } catch (e: any) { message.error(e?.message || '添加失败'); }
}

async function handleDeleteEntry(entryId: string) {
  if (!currentLib.value) return;
  try { await deleteDataLibEntry(currentLib.value.id, entryId); await fetchEntries(); await fetchDictList(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}

async function handleClear() {
  if (!currentLib.value) return;
  try { await clearDataLib(currentLib.value.id); message.success('已清空'); await fetchEntries(); await fetchDictList(); }
  catch (e: any) { message.error(e?.message || '清空失败'); }
}

// ═══════════════════════════════════
// Tab 2: Payload（含检测模式 + 扫描配置子 tab）
// ═══════════════════════════════════
const payloadLoading = ref(false);
const payloadData = ref<DataLibrary[]>([]);
const payloadTotal = ref(0);
const payloadPage = ref(1);
const payloadPageSize = ref(20);
const payloadKeyword = ref('');
const payloadCategoryFilter = ref<string | null>(null);

const payloadColumns = computed<DataTableColumns<DataLibrary>>(() => [
  { title: '名称', key: 'name', minWidth: 160, ellipsis: { tooltip: true } },
  { title: '分类', key: 'category', width: 100, render: (row) => h(NTag, { size: 'small', bordered: false, type: 'info' }, () => categoryLabels[row.category] ?? row.category) },
  { title: '描述', key: 'description', minWidth: 200, ellipsis: { tooltip: true } },
  { title: '条目数', key: 'entry_count', width: 80 },
  { title: '状态', key: 'status', width: 80, render: (row) => h(NTag, { size: 'small', type: row.status === 'active' ? 'success' : 'default', bordered: false }, () => row.status === 'active' ? '启用' : '停用') },
  { title: '操作', key: 'actions', width: 180, fixed: 'right' as const, render: (row) => h(NSpace, { size: 4 }, () => [
    h(NButton, { size: 'tiny', type: 'info', secondary: true, onClick: () => openPayloadDrawer(row) }, () => '查看'),
    h(NPopconfirm, { onPositiveClick: () => handleDeletePayloadLib(row.id) }, { trigger: () => h(NButton, { size: 'tiny', type: 'error', text: true }, () => '删除'), default: () => '确定删除？' }),
  ]) },
]);

async function fetchPayloadList() {
  payloadLoading.value = true;
  try {
    const result = await getDataLibList({
      page: payloadPage.value, page_size: payloadPageSize.value,
      keyword: payloadKeyword.value || undefined,
      type: 'payload',
      category: payloadCategoryFilter.value || undefined,
    });
    payloadData.value = result.items;
    payloadTotal.value = result.total;
  } finally { payloadLoading.value = false; }
}

async function handleDeletePayloadLib(id: string) {
  try { await deleteDataLib(id); message.success('已删除'); await fetchPayloadList(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}

// Payload 抽屉（含 3 个子 tab：Payload / 检测模式 / 扫描配置）
const showPayloadDrawer = ref(false);
const currentPayloadLib = ref<DataLibrary | null>(null);
const drawerTab = ref('payload');

// Payload 条目
const payloadEntries = ref<DataLibraryEntry[]>([]);
const payloadEntryTotal = ref(0);
const payloadEntryPage = ref(1);
const payloadEntryLoading = ref(false);
const showPayloadEntryModal = ref(false);
const payloadEntryForm = ref<Partial<DataLibraryEntry>>({});
const payloadEntryMode = ref<'create' | 'edit'>('create');

// Pattern 条目（同 category 的 pattern 库）
const patternLib = ref<DataLibrary | null>(null);
const patternEntries = ref<DataLibraryEntry[]>([]);
const patternEntryTotal = ref(0);
const patternEntryPage = ref(1);
const patternEntryLoading = ref(false);
const showPatternEntryModal = ref(false);
const patternEntryForm = ref<Partial<DataLibraryEntry>>({});
const patternEntryMode = ref<'create' | 'edit'>('create');

// Config 条目（同 category 的 config 库）
const configLib = ref<DataLibrary | null>(null);
const configEntries = ref<DataLibraryEntry[]>([]);
const configEntryTotal = ref(0);
const configEntryPage = ref(1);
const configEntryLoading = ref(false);
const showConfigEntryModal = ref(false);
const configEntryForm = ref<Partial<DataLibraryEntry>>({});
const configEntryMode = ref<'create' | 'edit'>('create');

async function openPayloadDrawer(lib: DataLibrary) {
  currentPayloadLib.value = lib;
  drawerTab.value = 'payload';
  showPayloadDrawer.value = true;
  payloadEntryPage.value = 1;
  patternEntryPage.value = 1;
  configEntryPage.value = 1;
  patternLib.value = null;
  configLib.value = null;
  await fetchPayloadEntries();
  fetchRelatedLib('pattern', lib.category);
  fetchRelatedLib('config', lib.category);
}

async function fetchRelatedLib(type: 'pattern' | 'config', category: string) {
  try {
    const result = await getDataLibList({ type, category, page: 1, page_size: 1 });
    const lib = result.items[0] ?? null;
    if (type === 'pattern') {
      patternLib.value = lib;
      if (lib) await fetchPatternEntries(); else { patternEntries.value = []; patternEntryTotal.value = 0; }
    } else {
      configLib.value = lib;
      if (lib) await fetchConfigEntries(); else { configEntries.value = []; configEntryTotal.value = 0; }
    }
  } catch { /* ignore */ }
}

async function fetchPayloadEntries() {
  if (!currentPayloadLib.value) return;
  payloadEntryLoading.value = true;
  try {
    const result = await getDataLibEntries(currentPayloadLib.value.id, { page: payloadEntryPage.value, page_size: 50 });
    payloadEntries.value = result.items; payloadEntryTotal.value = result.total;
  } finally { payloadEntryLoading.value = false; }
}

function openPayloadEntryCreate() {
  payloadEntryMode.value = 'create';
  payloadEntryForm.value = { enabled: true, priority: 0 };
  showPayloadEntryModal.value = true;
}
function openPayloadEntryEdit(entry: DataLibraryEntry) {
  payloadEntryMode.value = 'edit';
  payloadEntryForm.value = { ...entry };
  showPayloadEntryModal.value = true;
}
async function handleSavePayloadEntry() {
  if (!currentPayloadLib.value) return;
  try {
    if (payloadEntryMode.value === 'create') {
      await addDataLibEntry(currentPayloadLib.value.id, payloadEntryForm.value);
      message.success('创建成功');
    } else {
      await updateDataLibEntry(currentPayloadLib.value.id, payloadEntryForm.value.id!, payloadEntryForm.value);
      message.success('更新成功');
    }
    showPayloadEntryModal.value = false;
    await fetchPayloadEntries(); await fetchPayloadList();
  } catch (e: any) { message.error(e?.message || '保存失败'); }
}
async function handleDeletePayloadEntry(entryId: string) {
  if (!currentPayloadLib.value) return;
  try { await deleteDataLibEntry(currentPayloadLib.value.id, entryId); await fetchPayloadEntries(); await fetchPayloadList(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}

// Pattern 条目操作
async function fetchPatternEntries() {
  if (!patternLib.value) return;
  patternEntryLoading.value = true;
  try {
    const result = await getDataLibEntries(patternLib.value.id, { page: patternEntryPage.value, page_size: 50 });
    patternEntries.value = result.items; patternEntryTotal.value = result.total;
  } finally { patternEntryLoading.value = false; }
}
function openPatternEntryCreate() {
  patternEntryMode.value = 'create';
  patternEntryForm.value = { enabled: true };
  showPatternEntryModal.value = true;
}
function openPatternEntryEdit(entry: DataLibraryEntry) {
  patternEntryMode.value = 'edit';
  patternEntryForm.value = { ...entry };
  showPatternEntryModal.value = true;
}
async function handleSavePatternEntry() {
  if (!patternLib.value) return;
  try {
    if (patternEntryMode.value === 'create') {
      await addDataLibEntry(patternLib.value.id, patternEntryForm.value);
      message.success('创建成功');
    } else {
      await updateDataLibEntry(patternLib.value.id, patternEntryForm.value.id!, patternEntryForm.value);
      message.success('更新成功');
    }
    showPatternEntryModal.value = false;
    await fetchPatternEntries();
  } catch (e: any) { message.error(e?.message || '保存失败'); }
}
async function handleDeletePatternEntry(entryId: string) {
  if (!patternLib.value) return;
  try { await deleteDataLibEntry(patternLib.value.id, entryId); await fetchPatternEntries(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}

// Config 条目操作
async function fetchConfigEntries() {
  if (!configLib.value) return;
  configEntryLoading.value = true;
  try {
    const result = await getDataLibEntries(configLib.value.id, { page: configEntryPage.value, page_size: 50 });
    configEntries.value = result.items; configEntryTotal.value = result.total;
  } finally { configEntryLoading.value = false; }
}
function openConfigEntryCreate() {
  configEntryMode.value = 'create';
  configEntryForm.value = { enabled: true };
  showConfigEntryModal.value = true;
}
function openConfigEntryEdit(entry: DataLibraryEntry) {
  configEntryMode.value = 'edit';
  configEntryForm.value = { ...entry };
  showConfigEntryModal.value = true;
}
async function handleSaveConfigEntry() {
  if (!configLib.value) return;
  try {
    if (configEntryMode.value === 'create') {
      await addDataLibEntry(configLib.value.id, configEntryForm.value);
      message.success('创建成功');
    } else {
      await updateDataLibEntry(configLib.value.id, configEntryForm.value.id!, configEntryForm.value);
      message.success('更新成功');
    }
    showConfigEntryModal.value = false;
    await fetchConfigEntries();
  } catch (e: any) { message.error(e?.message || '保存失败'); }
}
async function handleDeleteConfigEntry(entryId: string) {
  if (!configLib.value) return;
  try { await deleteDataLibEntry(configLib.value.id, entryId); await fetchConfigEntries(); }
  catch (e: any) { message.error(e?.message || '删除失败'); }
}


onMounted(() => {
  const route = useRoute();
  const tab = route.query.tab as string;
  if (tab && ['dict', 'payload'].includes(tab)) {
    activeTab.value = tab;
  }
  fetchDictList();
  fetchPayloadList();
});

const headerExtraSlot = 'header-extra';
</script>

<template>
  <div style="padding: 16px">
    <NCard size="small">
      <NTabs v-model:value="activeTab" type="line" animated>
        <!-- Tab 1: 枚举字典 -->
        <NTabPane name="dict" tab="枚举字典">
          <NSpace align="center" justify="space-between" class="mb-3">
            <NSpace :size="8" align="center">
              <NSelect v-model:value="dictTypeFilter" :options="dictTypeOptions" placeholder="字典类型" size="small" style="width: 120px" clearable @update:value="() => { dictPage = 1; fetchDictList(); }" />
              <NInput v-model:value="dictKeyword" placeholder="搜索..." size="small" clearable style="width: 180px" @keyup.enter="() => { dictPage = 1; fetchDictList(); }" />
              <NButton size="small" type="primary" @click="() => { dictPage = 1; fetchDictList(); }">搜索</NButton>
            </NSpace>
            <NButton size="small" type="primary" @click="showDictCreateModal = true">新建字典</NButton>
          </NSpace>
          <NDataTable :columns="dictColumns" :data="dictData" :loading="dictLoading" :bordered="false" size="small" striped :scroll-x="900" :pagination="{ page: dictPage, pageSize: dictPageSize, itemCount: dictTotal, showSizePicker: true, pageSizes: [20, 50, 100], onUpdatePage: (p: number) => { dictPage = p; fetchDictList(); }, onUpdatePageSize: (s: number) => { dictPageSize = s; dictPage = 1; fetchDictList(); } }" />
        </NTabPane>

        <!-- Tab 2: 漏洞载荷 (Payload) -->
        <NTabPane name="payload" tab="漏洞载荷">
          <NSpace align="center" justify="space-between" class="mb-3">
            <NSpace :size="8" align="center">
              <NSelect v-model:value="payloadCategoryFilter" :options="categoryOptions" placeholder="全部分类" size="small" style="width: 130px" clearable @update:value="() => { payloadPage = 1; fetchPayloadList(); }" />
              <NInput v-model:value="payloadKeyword" placeholder="搜索..." size="small" clearable style="width: 180px" @keyup.enter="() => { payloadPage = 1; fetchPayloadList(); }" />
              <NButton size="small" type="primary" @click="() => { payloadPage = 1; fetchPayloadList(); }">搜索</NButton>
            </NSpace>
          </NSpace>
          <NDataTable :columns="payloadColumns" :data="payloadData" :loading="payloadLoading" :bordered="false" size="small" striped :scroll-x="900" :pagination="{ page: payloadPage, pageSize: payloadPageSize, itemCount: payloadTotal, showSizePicker: true, pageSizes: [20, 50, 100], onUpdatePage: (p: number) => { payloadPage = p; fetchPayloadList(); }, onUpdatePageSize: (s: number) => { payloadPageSize = s; payloadPage = 1; fetchPayloadList(); } }" />
        </NTabPane>

      </NTabs>
    </NCard>

    <!-- 扫描字典新建弹窗 -->
    <NModal v-model:show="showDictCreateModal" preset="card" title="新建字典" style="width: 480px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称"><NInput v-model:value="dictCreateForm.name" placeholder="字典名称" /></NFormItem>
        <NFormItem label="类型"><NSelect v-model:value="dictCreateForm.type" :options="dictTypeOptions" /></NFormItem>
        <NFormItem label="描述"><NInput v-model:value="dictCreateForm.description" type="textarea" placeholder="可选描述" :rows="3" /></NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showDictCreateModal = false">取消</NButton>
          <NButton type="primary" :disabled="!dictCreateForm.name" @click="handleCreateDict">创建</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 导入弹窗 -->
    <NModal v-model:show="showImportModal" preset="card" title="批量导入" style="width: 560px">
      <NText depth="3" style="font-size: 12px; margin-bottom: 8px; display: block">每行一个条目，空行和 # 开头的行将被忽略，自动去重</NText>
      <NInput v-model:value="importText" type="textarea" placeholder="每行一个条目..." :rows="12" style="font-family: monospace" />
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showImportModal = false">取消</NButton>
          <NButton type="primary" :loading="importing" :disabled="!importText.trim()" @click="handleImport">导入</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 扫描字典条目抽屉 -->
    <NDrawer v-model:show="showDrawer" :width="600">
      <NDrawerContent :title="`${currentLib?.name ?? ''} - 条目管理`">
        <template #[headerExtraSlot]>
          <NSpace :size="8">
            <NButton size="tiny" @click="openImport(currentLib?.id ?? '')">批量导入</NButton>
            <NPopconfirm @positive-click="handleClear">
              <template #trigger><NButton size="tiny" type="error">清空</NButton></template>
              确定清空所有条目？
            </NPopconfirm>
          </NSpace>
        </template>
        <NSpace style="margin-bottom: 12px">
          <NInput v-model:value="newEntryValue" placeholder="输入新条目..." size="small" style="width: 360px" @keyup.enter="handleAddEntry" />
          <NButton size="small" type="primary" :disabled="!newEntryValue.trim()" @click="handleAddEntry">添加</NButton>
        </NSpace>
        <NText depth="3" style="font-size: 12px; margin-bottom: 8px; display: block">共 {{ entryTotal }} 条</NText>
        <NSpin :show="entryLoading">
          <div v-if="entries.length === 0 && !entryLoading"><NEmpty description="暂无条目" /></div>
          <div v-else style="max-height: calc(100vh - 260px); overflow-y: auto">
            <div v-for="entry in entries" :key="entry.id" style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; border-bottom: 1px solid #f0f0f0; font-family: monospace; font-size: 13px">
              <span style="flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="entry.value">{{ entry.value }}</span>
              <NButton text type="error" size="tiny" style="flex-shrink: 0; margin-left: 8px" @click="handleDeleteEntry(entry.id)">删除</NButton>
            </div>
          </div>
        </NSpin>
        <div v-if="entryTotal > 50" style="margin-top: 12px; text-align: center">
          <NButton size="tiny" :disabled="entryPage <= 1" @click="() => { entryPage--; fetchEntries(); }">上一页</NButton>
          <NText style="margin: 0 8px; font-size: 12px">{{ entryPage }} / {{ Math.ceil(entryTotal / 50) }}</NText>
          <NButton size="tiny" :disabled="entryPage >= Math.ceil(entryTotal / 50)" @click="() => { entryPage++; fetchEntries(); }">下一页</NButton>
        </div>
      </NDrawerContent>
    </NDrawer>

    <!-- Payload 抽屉（含子 tab） -->
    <NDrawer v-model:show="showPayloadDrawer" :width="750">
      <NDrawerContent :title="`${currentPayloadLib?.name ?? ''} (${categoryLabels[currentPayloadLib?.category ?? ''] ?? ''})`">
        <NTabs v-model:value="drawerTab" type="line" size="small">
          <!-- 子 Tab: Payload 条目 -->
          <NTabPane name="payload" tab="漏洞载荷">
            <NSpace justify="space-between" align="center" style="margin-bottom: 8px">
              <NText depth="3" style="font-size: 12px">共 {{ payloadEntryTotal }} 条</NText>
              <NButton size="tiny" type="primary" @click="openPayloadEntryCreate">新建</NButton>
            </NSpace>
            <NSpin :show="payloadEntryLoading">
              <div v-if="payloadEntries.length === 0 && !payloadEntryLoading"><NEmpty description="暂无条目" /></div>
              <div v-else style="max-height: calc(100vh - 240px); overflow-y: auto">
                <div v-for="entry in payloadEntries" :key="entry.id" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-bottom: 1px solid #f0f0f0; font-size: 13px">
                  <div style="flex: 1; min-width: 0">
                    <div style="font-weight: 500">{{ entry.name || '-' }}</div>
                    <div style="font-family: monospace; color: #666; overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="entry.value">{{ entry.value }}</div>
                  </div>
                  <NTag v-if="entry.type" size="small">{{ entry.type }}</NTag>
                  <NButton text size="tiny" @click="openPayloadEntryEdit(entry)">编辑</NButton>
                  <NButton text type="error" size="tiny" @click="handleDeletePayloadEntry(entry.id)">删除</NButton>
                </div>
              </div>
            </NSpin>
            <div v-if="payloadEntryTotal > 50" style="margin-top: 12px; text-align: center">
              <NButton size="tiny" :disabled="payloadEntryPage <= 1" @click="() => { payloadEntryPage--; fetchPayloadEntries(); }">上一页</NButton>
              <NText style="margin: 0 8px; font-size: 12px">{{ payloadEntryPage }} / {{ Math.ceil(payloadEntryTotal / 50) }}</NText>
              <NButton size="tiny" :disabled="payloadEntryPage >= Math.ceil(payloadEntryTotal / 50)" @click="() => { payloadEntryPage++; fetchPayloadEntries(); }">下一页</NButton>
            </div>
          </NTabPane>

          <!-- 子 Tab: 检测模式 -->
          <NTabPane name="pattern" tab="检测模式">
            <template v-if="patternLib">
              <NSpace justify="space-between" align="center" style="margin-bottom: 8px">
                <NText depth="3" style="font-size: 12px">共 {{ patternEntryTotal }} 条</NText>
                <NButton size="tiny" type="primary" @click="openPatternEntryCreate">新建</NButton>
              </NSpace>
              <NSpin :show="patternEntryLoading">
                <div v-if="patternEntries.length === 0 && !patternEntryLoading"><NEmpty description="暂无条目" /></div>
                <div v-else style="max-height: calc(100vh - 240px); overflow-y: auto">
                  <div v-for="entry in patternEntries" :key="entry.id" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-bottom: 1px solid #f0f0f0; font-size: 13px">
                    <div style="flex: 1; min-width: 0">
                      <div style="font-weight: 500">{{ entry.name || '-' }}</div>
                      <div style="font-family: monospace; color: #666; overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="entry.value">{{ entry.value }}</div>
                    </div>
                    <NButton text size="tiny" @click="openPatternEntryEdit(entry)">编辑</NButton>
                    <NButton text type="error" size="tiny" @click="handleDeletePatternEntry(entry.id)">删除</NButton>
                  </div>
                </div>
              </NSpin>
              <div v-if="patternEntryTotal > 50" style="margin-top: 12px; text-align: center">
                <NButton size="tiny" :disabled="patternEntryPage <= 1" @click="() => { patternEntryPage--; fetchPatternEntries(); }">上一页</NButton>
                <NText style="margin: 0 8px; font-size: 12px">{{ patternEntryPage }} / {{ Math.ceil(patternEntryTotal / 50) }}</NText>
                <NButton size="tiny" :disabled="patternEntryPage >= Math.ceil(patternEntryTotal / 50)" @click="() => { patternEntryPage++; fetchPatternEntries(); }">下一页</NButton>
              </div>
            </template>
            <NEmpty v-else description="该分类暂无检测模式库" />
          </NTabPane>

          <!-- 子 Tab: 扫描配置 -->
          <NTabPane name="config" tab="扫描配置">
            <template v-if="configLib">
              <NSpace justify="space-between" align="center" style="margin-bottom: 8px">
                <NText depth="3" style="font-size: 12px">共 {{ configEntryTotal }} 条</NText>
                <NButton size="tiny" type="primary" @click="openConfigEntryCreate">新建</NButton>
              </NSpace>
              <NSpin :show="configEntryLoading">
                <div v-if="configEntries.length === 0 && !configEntryLoading"><NEmpty description="暂无条目" /></div>
                <div v-else style="max-height: calc(100vh - 240px); overflow-y: auto">
                  <div v-for="entry in configEntries" :key="entry.id" style="display: flex; align-items: center; gap: 8px; padding: 8px 10px; border-bottom: 1px solid #f0f0f0; font-size: 13px">
                    <div style="flex: 1; min-width: 0">
                      <div style="font-weight: 500">{{ entry.name || '-' }}</div>
                      <div style="font-family: monospace; color: #666; overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="entry.value">{{ entry.value }}</div>
                    </div>
                    <NTag v-if="entry.enabled" size="small" type="success">启用</NTag>
                    <NTag v-else size="small">停用</NTag>
                    <NButton text size="tiny" @click="openConfigEntryEdit(entry)">编辑</NButton>
                    <NButton text type="error" size="tiny" @click="handleDeleteConfigEntry(entry.id)">删除</NButton>
                  </div>
                </div>
              </NSpin>
              <div v-if="configEntryTotal > 50" style="margin-top: 12px; text-align: center">
                <NButton size="tiny" :disabled="configEntryPage <= 1" @click="() => { configEntryPage--; fetchConfigEntries(); }">上一页</NButton>
                <NText style="margin: 0 8px; font-size: 12px">{{ configEntryPage }} / {{ Math.ceil(configEntryTotal / 50) }}</NText>
                <NButton size="tiny" :disabled="configEntryPage >= Math.ceil(configEntryTotal / 50)" @click="() => { configEntryPage++; fetchConfigEntries(); }">下一页</NButton>
              </div>
            </template>
            <NEmpty v-else description="该分类暂无扫描配置库" />
          </NTabPane>
        </NTabs>
      </NDrawerContent>
    </NDrawer>

    <!-- Payload 条目编辑弹窗 -->
    <NModal v-model:show="showPayloadEntryModal" preset="card" :title="payloadEntryMode === 'create' ? '新建漏洞载荷' : '编辑漏洞载荷'" style="width: 600px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称"><NInput v-model:value="payloadEntryForm.name" placeholder="载荷名称" /></NFormItem>
        <NFormItem label="载荷内容"><NInput v-model:value="payloadEntryForm.value" type="textarea" :rows="3" placeholder="载荷内容" /></NFormItem>
        <NFormItem label="类型"><NInput v-model:value="payloadEntryForm.type" placeholder="error/boolean/time/union" /></NFormItem>
        <NFormItem label="标签"><NInput v-model:value="payloadEntryForm.tags" placeholder="逗号分隔" /></NFormItem>
        <NFormItem label="优先级"><NInputNumber v-model:value="payloadEntryForm.priority" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="payloadEntryForm.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showPayloadEntryModal = false">取消</NButton>
          <NButton type="primary" @click="handleSavePayloadEntry">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Pattern 条目编辑弹窗 -->
    <NModal v-model:show="showPatternEntryModal" preset="card" :title="patternEntryMode === 'create' ? '新建检测模式' : '编辑检测模式'" style="width: 600px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称"><NInput v-model:value="patternEntryForm.name" placeholder="pattern 名称" /></NFormItem>
        <NFormItem label="正则模式"><NInput v-model:value="patternEntryForm.value" type="textarea" :rows="4" placeholder="正则表达式" /></NFormItem>
        <NFormItem label="标签"><NInput v-model:value="patternEntryForm.tags" placeholder="逗号分隔" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="patternEntryForm.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showPatternEntryModal = false">取消</NButton>
          <NButton type="primary" @click="handleSavePatternEntry">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Config 条目编辑弹窗 -->
    <NModal v-model:show="showConfigEntryModal" preset="card" :title="configEntryMode === 'create' ? '新建配置项' : '编辑配置项'" style="width: 500px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="配置键"><NInput v-model:value="configEntryForm.name" placeholder="config_key" /></NFormItem>
        <NFormItem label="配置值"><NInput v-model:value="configEntryForm.value" type="textarea" :rows="3" placeholder="配置值" /></NFormItem>
        <NFormItem label="启用"><NSwitch v-model:value="configEntryForm.enabled" /></NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showConfigEntryModal = false">取消</NButton>
          <NButton type="primary" @click="handleSaveConfigEntry">保存</NButton>
        </NSpace>
      </template>
    </NModal>

  </div>
</template>
