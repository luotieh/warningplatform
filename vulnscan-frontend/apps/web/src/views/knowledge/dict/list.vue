<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type { FileLibrary, WordLibrary } from '#/api/sitemonitor';

import { computed, h, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
  NEmpty,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NTabPane,
  NTabs,
  NTag,
  NText,
  NSpin,
  useMessage,
} from 'naive-ui';

import { dialog } from '#/adapter/naive';

import {
  getDictList,
  getDictEntries,
  createDict,
  deleteDict,
  addDictEntry,
  deleteDictEntry,
  importDict,
  clearDict,
  exportDict,
  type Dictionary,
  type DictionaryEntry,
} from '#/api/dict';

import {
  createFileLibrary,
  createWordLibrary,
  deleteFileLibrary,
  deleteWordLibrary,
  getFileLibraryList,
  getWordLibraryList,
  updateFileLibrary,
  updateWordLibrary,
} from '#/api/sitemonitor';

import dayjs from 'dayjs';

defineOptions({ name: 'DictManage' });

const message = useMessage();
const router = useRouter();
const activeTab = ref('scan');

// ═══════════════════════════════════
// Tab 1: 扫描字典
// ═══════════════════════════════════
const loading = ref(false);
const data = ref<Dictionary[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const typeFilter = ref<string | null>(null);

const typeOptions = [
  { label: '子域名', value: 'subdomain' },
  { label: '目录路径', value: 'dirpath' },
  { label: '用户名', value: 'username' },
  { label: '密码', value: 'password' },
  { label: 'User-Agent', value: 'useragent' },
  { label: '自定义', value: 'custom' },
];

const typeLabels: Record<string, string> = {
  subdomain: '子域名', dirpath: '目录路径', username: '用户名',
  password: '密码', useragent: 'UA', custom: '自定义',
};

const showCreateModal = ref(false);
const createForm = ref({ name: '', type: 'custom', description: '' });

const showImportModal = ref(false);
const importDictId = ref('');
const importText = ref('');
const importing = ref(false);

const showDrawer = ref(false);
const currentDict = ref<Dictionary | null>(null);
const entries = ref<DictionaryEntry[]>([]);
const entryTotal = ref(0);
const entryPage = ref(1);
const entryLoading = ref(false);
const newEntryValue = ref('');

const columns = computed(() => [
  { title: '名称', key: 'name', minWidth: 160, ellipsis: { tooltip: true } },
  {
    title: '类型', key: 'type', width: 100,
    render: (row: Dictionary) => h(NTag, { size: 'small', bordered: false, type: 'info' }, () => typeLabels[row.type] ?? row.type),
  },
  { title: '描述', key: 'description', minWidth: 200, ellipsis: { tooltip: true } },
  { title: '条目数', key: 'entry_count', width: 80 },
  {
    title: '状态', key: 'status', width: 80,
    render: (row: Dictionary) => h(NTag, { size: 'small', type: row.status === 'active' ? 'success' : 'default', bordered: false }, () => row.status === 'active' ? '启用' : '停用'),
  },
  { title: '创建时间', key: 'created_at', width: 150 },
  {
    title: '操作', key: 'actions', width: 220, fixed: 'right' as const,
    render: (row: Dictionary) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', type: 'info', secondary: true, onClick: () => openDrawer(row) }, () => '查看条目'),
      h(NButton, { size: 'tiny', secondary: true, onClick: () => openImport(row.id) }, () => '导入'),
      h(NButton, { size: 'tiny', secondary: true, onClick: () => window.open(exportDict(row.id), '_blank') }, () => '导出'),
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
    const result = await getDictList({
      page: page.value, page_size: pageSize.value,
      keyword: keyword.value || undefined,
      type: typeFilter.value || undefined,
    });
    data.value = result.items;
    total.value = result.total;
  } finally {
    loading.value = false;
  }
}

async function handleCreate() {
  try {
    await createDict(createForm.value);
    message.success('创建成功');
    showCreateModal.value = false;
    createForm.value = { name: '', type: 'custom', description: '' };
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '创建失败');
  }
}

async function handleDelete(id: string) {
  try {
    await deleteDict(id);
    message.success('已删除');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

function openImport(id: string) {
  importDictId.value = id;
  importText.value = '';
  showImportModal.value = true;
}

async function handleImport() {
  if (!importText.value.trim()) return;
  importing.value = true;
  try {
    await importDict(importDictId.value, importText.value);
    message.success('导入成功');
    showImportModal.value = false;
    await fetchData();
    if (currentDict.value?.id === importDictId.value) {
      await fetchEntries();
    }
  } catch (e: any) {
    message.error(e?.message || '导入失败');
  } finally {
    importing.value = false;
  }
}

async function openDrawer(dict: Dictionary) {
  currentDict.value = dict;
  showDrawer.value = true;
  entryPage.value = 1;
  await fetchEntries();
}

async function fetchEntries() {
  if (!currentDict.value) return;
  entryLoading.value = true;
  try {
    const result = await getDictEntries(currentDict.value.id, { page: entryPage.value, page_size: 50 });
    entries.value = result.items;
    entryTotal.value = result.total;
  } finally {
    entryLoading.value = false;
  }
}

async function handleAddEntry() {
  if (!currentDict.value || !newEntryValue.value.trim()) return;
  try {
    await addDictEntry(currentDict.value.id, { value: newEntryValue.value.trim() });
    newEntryValue.value = '';
    await fetchEntries();
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '添加失败');
  }
}

async function handleDeleteEntry(entryId: string) {
  if (!currentDict.value) return;
  try {
    await deleteDictEntry(currentDict.value.id, entryId);
    await fetchEntries();
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

async function handleClear() {
  if (!currentDict.value) return;
  try {
    await clearDict(currentDict.value.id);
    message.success('已清空');
    await fetchEntries();
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '清空失败');
  }
}

// ═══════════════════════════════════
// Tab 2: 敏感词库
// ═══════════════════════════════════
const wordLoading = ref(false);
const wordList = ref<WordLibrary[]>([]);
const safeWordList = computed(() => Array.isArray(wordList.value) ? wordList.value : []);
const wordPage = ref(1);
const wordPageSize = ref(10);
const wordTotal = ref(0);
const wordSearch = ref('');

async function fetchWordList() {
  wordLoading.value = true;
  try {
    const res = await getWordLibraryList({ index: wordPage.value, name: wordSearch.value, size: wordPageSize.value });
    wordList.value = res.data || [];
    wordTotal.value = (res as any).count || 0;
  } catch { wordList.value = []; }
  finally { wordLoading.value = false; }
}

const wordColumns = computed<DataTableColumns<WordLibrary>>(() => [
  { key: 'name', title: '词库名称', minWidth: 160 },
  { key: 'description', title: '描述', minWidth: 200, ellipsis: { tooltip: true } },
  {
    key: 'created_at', title: '创建时间', minWidth: 160,
    render: (row) => row.created_at ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss') : '-',
  },
  {
    key: 'op', title: '操作', width: 280, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, () => [
      h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => router.push(`/knowledge/dict/word/${row.id}`) }, { default: () => '详情' }),
      h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => openLibDialog('word', row) }, { default: () => '编辑' }),
      h(NButton, { text: true, type: 'error', size: 'small', onClick: () => handleDeleteWord(row) }, { default: () => '删除' }),
    ]),
  },
]);

function handleDeleteWord(row: WordLibrary) {
  dialog.warning({
    title: '提示', content: `确认删除词库「${row.name}」？删除后不可恢复`,
    positiveText: '确认删除', negativeText: '取消',
    onPositiveClick: async () => {
      try { await deleteWordLibrary(row.id); message.success('删除成功'); fetchWordList(); }
      catch (e: any) { message.error(e?.msg || '删除失败'); }
    },
  });
}

// ═══════════════════════════════════
// Tab 3: 敏感文件库
// ═══════════════════════════════════
const fileLoading = ref(false);
const fileList = ref<FileLibrary[]>([]);
const safeFileList = computed(() => Array.isArray(fileList.value) ? fileList.value : []);
const filePage = ref(1);
const filePageSize = ref(10);
const fileTotal = ref(0);
const fileSearch = ref('');

async function fetchFileList() {
  fileLoading.value = true;
  try {
    const res = await getFileLibraryList({ index: filePage.value, name: fileSearch.value, size: filePageSize.value });
    fileList.value = res.data || [];
    fileTotal.value = (res as any).count || 0;
  } catch { fileList.value = []; }
  finally { fileLoading.value = false; }
}

const fileColumns = computed<DataTableColumns<FileLibrary>>(() => [
  { key: 'name', title: '文件库名称', minWidth: 160 },
  { key: 'description', title: '描述', minWidth: 200, ellipsis: { tooltip: true } },
  {
    key: 'created_at', title: '创建时间', minWidth: 160,
    render: (row) => row.created_at ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss') : '-',
  },
  {
    key: 'op', title: '操作', width: 280, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, () => [
      h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => router.push(`/knowledge/dict/file/${row.id}`) }, { default: () => '详情' }),
      h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => openLibDialog('file', row) }, { default: () => '编辑' }),
      h(NButton, { text: true, type: 'error', size: 'small', onClick: () => handleDeleteFile(row) }, { default: () => '删除' }),
    ]),
  },
]);

function handleDeleteFile(row: FileLibrary) {
  dialog.warning({
    title: '提示', content: `确认删除文件库「${row.name}」？`,
    positiveText: '确认删除', negativeText: '取消',
    onPositiveClick: async () => {
      try { await deleteFileLibrary(row.id); message.success('删除成功'); fetchFileList(); }
      catch (e: any) { message.error(e?.msg || '删除失败'); }
    },
  });
}

// ═══════════════════════════════════
// 敏感词库/文件库 共享新增编辑弹窗
// ═══════════════════════════════════
const libDialogVisible = ref(false);
const libDialogTitle = ref('');
const libDialogType = ref<'file' | 'word'>('word');
const libForm = ref({ id: '', isEdit: false, name: '', description: '' });
const libSubmitting = ref(false);

function openLibDialog(type: 'file' | 'word', row?: FileLibrary | WordLibrary) {
  libDialogType.value = type;
  if (row) {
    libDialogTitle.value = type === 'word' ? '编辑词库' : '编辑文件库';
    libForm.value = { isEdit: true, id: row.id, name: row.name, description: row.description };
  } else {
    libDialogTitle.value = type === 'word' ? '新增词库' : '新增文件库';
    libForm.value = { isEdit: false, id: '', name: '', description: '' };
  }
  libDialogVisible.value = true;
}

async function handleLibSubmit() {
  if (!libForm.value.name.trim()) { message.warning('请填写名称'); return; }
  libSubmitting.value = true;
  try {
    const payload = { name: libForm.value.name, description: libForm.value.description };
    if (libDialogType.value === 'word') {
      libForm.value.isEdit ? await updateWordLibrary(libForm.value.id, payload) : await createWordLibrary(payload);
    } else {
      libForm.value.isEdit ? await updateFileLibrary(libForm.value.id, payload) : await createFileLibrary(payload);
    }
    message.success(libForm.value.isEdit ? '更新成功' : '创建成功');
    libDialogVisible.value = false;
    libDialogType.value === 'word' ? fetchWordList() : fetchFileList();
  } catch (e: any) { message.error(e?.msg || '操作失败'); }
  finally { libSubmitting.value = false; }
}

function handleTabChange(tab: string) {
  activeTab.value = tab;
}

onMounted(() => {
  fetchData();
  fetchWordList();
  fetchFileList();
});

const headerExtraSlot = 'header-extra';
</script>

<template>
  <div style="padding: 16px">
    <NCard size="small">
      <NTabs :value="activeTab" type="line" animated @update:value="handleTabChange">
        <!-- Tab 1: 扫描字典 -->
        <NTabPane name="scan" tab="扫描字典">
          <NSpace align="center" justify="space-between" class="mb-3">
            <NSpace :size="8" align="center">
              <NSelect
                v-model:value="typeFilter"
                :options="typeOptions"
                placeholder="字典类型"
                size="small"
                style="width: 120px"
                clearable
                @update:value="() => { page = 1; fetchData(); }"
              />
              <NInput v-model:value="keyword" placeholder="搜索..." size="small" clearable style="width: 180px" @keyup.enter="() => { page = 1; fetchData(); }" />
              <NButton size="small" type="primary" @click="() => { page = 1; fetchData(); }">搜索</NButton>
            </NSpace>
            <NButton size="small" type="primary" @click="showCreateModal = true">新建字典</NButton>
          </NSpace>

          <NDataTable
            :columns="columns"
            :data="data"
            :loading="loading"
            :bordered="false"
            size="small"
            striped
            :scroll-x="900"
            :pagination="{
              page, pageSize, itemCount: total, showSizePicker: true, pageSizes: [20, 50, 100],
              onUpdatePage: (p: number) => { page = p; fetchData(); },
              onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
            }"
          />
        </NTabPane>

        <!-- Tab 2: 敏感词库 -->
        <NTabPane name="word" tab="敏感词库">
          <NSpace align="center" justify="space-between" class="mb-3">
            <NSpace align="center">
              <NInput v-model:value="wordSearch" placeholder="搜索词库名称" clearable style="width: 250px" />
              <NButton type="primary" :loading="wordLoading" size="small" @click="fetchWordList">搜索</NButton>
              <NButton size="small" @click="() => { wordSearch = ''; fetchWordList(); }">重置</NButton>
            </NSpace>
            <NButton type="primary" size="small" @click="openLibDialog('word')">新增词库</NButton>
          </NSpace>

          <NDataTable
            :columns="wordColumns"
            :data="safeWordList"
            :loading="wordLoading"
            :bordered="false"
            size="small"
            striped
            :pagination="{
              page: wordPage, pageSize: wordPageSize, itemCount: wordTotal,
              showSizePicker: true, pageSizes: [10, 15, 20, 50],
              onUpdatePage: (p: number) => { wordPage = p; fetchWordList(); },
              onUpdatePageSize: (s: number) => { wordPageSize = s; wordPage = 1; fetchWordList(); },
            }"
          />
        </NTabPane>

        <!-- Tab 3: 敏感文件库 -->
        <NTabPane name="file" tab="敏感文件库">
          <NSpace align="center" justify="space-between" class="mb-3">
            <NSpace align="center">
              <NInput v-model:value="fileSearch" placeholder="搜索文件库名称" clearable style="width: 250px" />
              <NButton type="primary" :loading="fileLoading" size="small" @click="fetchFileList">搜索</NButton>
              <NButton size="small" @click="() => { fileSearch = ''; fetchFileList(); }">重置</NButton>
            </NSpace>
            <NButton type="primary" size="small" @click="openLibDialog('file')">新增文件库</NButton>
          </NSpace>

          <NDataTable
            :columns="fileColumns"
            :data="safeFileList"
            :loading="fileLoading"
            :bordered="false"
            size="small"
            striped
            :pagination="{
              page: filePage, pageSize: filePageSize, itemCount: fileTotal,
              showSizePicker: true, pageSizes: [10, 15, 20, 50],
              onUpdatePage: (p: number) => { filePage = p; fetchFileList(); },
              onUpdatePageSize: (s: number) => { filePageSize = s; filePage = 1; fetchFileList(); },
            }"
          />
        </NTabPane>
      </NTabs>
    </NCard>

    <!-- 扫描字典新建弹窗 -->
    <NModal v-model:show="showCreateModal" preset="card" title="新建字典" style="width: 480px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称"><NInput v-model:value="createForm.name" placeholder="字典名称" /></NFormItem>
        <NFormItem label="类型"><NSelect v-model:value="createForm.type" :options="typeOptions" /></NFormItem>
        <NFormItem label="描述"><NInput v-model:value="createForm.description" type="textarea" placeholder="可选描述" :rows="3" /></NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="showCreateModal = false">取消</NButton>
          <NButton type="primary" :disabled="!createForm.name" @click="handleCreate">创建</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 扫描字典导入弹窗 -->
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
      <NDrawerContent :title="`${currentDict?.name ?? ''} - 条目管理`">
        <template #[headerExtraSlot]>
          <NSpace :size="8">
            <NButton size="tiny" @click="openImport(currentDict?.id ?? '')">批量导入</NButton>
            <NPopconfirm @positive-click="handleClear">
              <template #trigger>
                <NButton size="tiny" type="error">清空</NButton>
              </template>
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
          <div v-if="entries.length === 0 && !entryLoading">
            <NEmpty description="暂无条目" />
          </div>
          <div v-else style="max-height: calc(100vh - 260px); overflow-y: auto">
            <div
              v-for="entry in entries"
              :key="entry.id"
              style="display: flex; align-items: center; justify-content: space-between; padding: 6px 10px; border-bottom: 1px solid #f0f0f0; font-family: monospace; font-size: 13px"
            >
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

    <!-- 敏感词库/文件库 新增编辑弹窗 -->
    <NModal v-model:show="libDialogVisible" preset="card" :title="libDialogTitle" style="width: 500px">
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="名称" required>
          <NInput v-model:value="libForm.name" placeholder="请输入名称" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="libForm.description" type="textarea" :rows="3" placeholder="请输入描述" />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="libDialogVisible = false">取消</NButton>
          <NButton type="primary" :loading="libSubmitting" @click="handleLibSubmit">确定</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
