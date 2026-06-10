<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey } from 'naive-ui';

import type { FileEntry } from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

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
  NUpload,
  NUploadDragger,
  type UploadFileInfo,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchCreateFileEntries,
  deleteFileEntries,
  getFileEntryList,
  getFileLibraryDetail,
  importFileEntries,
} from '#/api/sitemonitor';

defineOptions({ name: 'FileLibraryDetail' });

const route = useRoute();
const router = useRouter();
const libraryId = route.params.id as string;

const libraryInfo = ref<any>({});
const loading = ref(false);

const entryList = ref<FileEntry[]>([]);
const safeEntryList = computed(() =>
  Array.isArray(entryList.value) ? entryList.value : [],
);
const entryPagination = reactive({
  page: 1,
  pageSize: 50,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [20, 50, 100, 200],
});
const entrySearch = ref('');

const entryDialogVisible = ref(false);
const entryInput = ref('');
const entryRisk = ref('high');

const riskTagType = (
  v: string,
): 'default' | 'error' | 'info' | 'primary' | 'warning' => {
  if (v === 'critical') return 'error';
  if (v === 'high') return 'warning';
  if (v === 'medium') return 'primary';
  return 'info';
};
const riskLabel = (v: string) =>
  ({ critical: '严重', high: '高', low: '低', medium: '中' })[
    v as 'critical' | 'high' | 'low' | 'medium'
  ] ?? v;

const riskOptions = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
];

const selectedEntryIds = ref<DataTableRowKey[]>([]);

async function fetchLibrary() {
  try {
    const res = await getFileLibraryDetail(libraryId);
    libraryInfo.value = (res as any)?.data ?? res;
  } catch {
    message.error('获取文件库详情失败');
  }
}

async function fetchEntries() {
  loading.value = true;
  try {
    const res = await getFileEntryList({
      page: entryPagination.page,
      library_id: libraryId,
      path: entrySearch.value,
      page_size: entryPagination.pageSize,
    });
    entryList.value = res.data || [];
    entryPagination.itemCount = (res as any).count || 0;
  } catch {
    entryList.value = [];
  } finally {
    loading.value = false;
  }
}

function handleAddEntries() {
  entryInput.value = '';
  entryRisk.value = 'high';
  entryDialogVisible.value = true;
}

async function handleSubmitEntries() {
  const lines = entryInput.value
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  if (lines.length === 0) {
    message.warning('请输入至少一条路径');
    return;
  }
  try {
    const entries = lines.map((line) => {
      const parts = line.split(/\s+/);
      return {
        library_id: libraryId,
        mark: parts.slice(1).join(' ') || '',
        path: parts[0]!,
        risk: entryRisk.value,
      };
    });
    await batchCreateFileEntries(entries);
    message.success(`成功添加 ${lines.length} 条路径`);
    entryDialogVisible.value = false;
    fetchEntries();
  } catch (e: any) {
    message.error(e?.msg || '添加失败');
  }
}

function handleDeleteEntries() {
  if (selectedEntryIds.value.length === 0) {
    message.warning('请选择要删除的记录');
    return;
  }
  dialog.warning({
    title: '提示',
    content: `确认删除选中的 ${selectedEntryIds.value.length} 条记录？`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteFileEntries(selectedEntryIds.value as number[]);
        message.success('删除成功');
        selectedEntryIds.value = [];
        fetchEntries();
      } catch (e: any) {
        message.error(e?.msg || '删除失败');
      }
    },
  });
}

const entryColumns = computed<DataTableColumns<FileEntry>>(() => [
  { type: 'selection' },
  { key: 'id', title: 'ID', width: 80 },
  { key: 'path', title: '路径', minWidth: 250, ellipsis: { tooltip: true } },
  {
    key: 'mark',
    title: '标记',
    minWidth: 150,
    ellipsis: { tooltip: true },
  },
  {
    key: 'risk',
    title: '风险',
    width: 100,
    render: (row) =>
      h(
        NTag,
        { type: riskTagType(row.risk), size: 'small', bordered: false },
        { default: () => riskLabel(row.risk) },
      ),
  },
  {
    key: 'created_at',
    title: '创建时间',
    width: 180,
    render: (row) =>
      row.created_at ? new Date(row.created_at).toLocaleString() : '-',
  },
]);

const importDialogVisible = ref(false);
const importRisk = ref('high');
const importFile = ref<File | null>(null);
const importing = ref(false);

function handleImport() {
  importRisk.value = 'high';
  importFile.value = null;
  importDialogVisible.value = true;
}

function handleImportFileChange({
  fileList,
}: {
  fileList: UploadFileInfo[];
}) {
  importFile.value = fileList[0]?.file ?? null;
}

async function handleSubmitImport() {
  if (!importFile.value) {
    message.warning('请选择文件');
    return;
  }
  importing.value = true;
  try {
    const fd = new FormData();
    fd.append('file', importFile.value);
    fd.append('library_id', libraryId);
    fd.append('risk', importRisk.value);
    const res = await importFileEntries(fd);
    const result = (res as any)?.data ?? res;
    message.success(
      `导入完成：成功 ${result?.imported ?? 0} 条，重复跳过 ${result?.duplicated ?? 0} 条`,
    );
    importDialogVisible.value = false;
    fetchEntries();
  } catch (e: any) {
    message.error(e?.msg || '导入失败');
  } finally {
    importing.value = false;
  }
}

onMounted(() => {
  fetchLibrary();
  fetchEntries();
});
</script>

<template>
  <Page :title="libraryInfo?.name || '文件库详情'" :description="libraryInfo?.description">
    <NSpace align="center" class="mb-3">
      <NButton @click="router.back()">返回</NButton>
    </NSpace>

    <NCard size="small">
      <NSpace justify="space-between" align="center" class="mb-3">
        <NSpace align="center">
          <NInput
            v-model:value="entrySearch"
            placeholder="搜索路径"
            clearable
            style="width: 220px"
            @keyup.enter="fetchEntries"
          />
          <NButton type="primary" @click="fetchEntries">搜索</NButton>
        </NSpace>
        <NSpace align="center">
          <NButton
            type="error"
            :disabled="selectedEntryIds.length === 0"
            @click="handleDeleteEntries"
          >
            批量删除 ({{ selectedEntryIds.length }})
          </NButton>
          <NButton @click="handleImport">导入路径</NButton>
          <NButton type="primary" @click="handleAddEntries">添加路径</NButton>
        </NSpace>
      </NSpace>

      <NDataTable
        :columns="entryColumns"
        :data="safeEntryList"
        :loading="loading"
        :pagination="entryPagination"
        :row-key="(r: FileEntry) => r.id"
        remote
        size="small"
        @update:checked-row-keys="(keys: DataTableRowKey[]) => (selectedEntryIds = keys)"
        @update:page="
          (p: number) => {
            entryPagination.page = p;
            fetchEntries();
          }
        "
        @update:page-size="
          (s: number) => {
            entryPagination.pageSize = s;
            entryPagination.page = 1;
            fetchEntries();
          }
        "
      />
    </NCard>

    <NModal
      v-model:show="entryDialogVisible"
      preset="card"
      title="批量添加路径"
      style="width: 500px"
    >
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="风险等级">
          <NSelect v-model:value="entryRisk" :options="riskOptions" />
        </NFormItem>
        <NFormItem label="路径列表">
          <NInput
            v-model:value="entryInput"
            type="textarea"
            :rows="10"
            placeholder="每行一条，格式: /path/to/file 备注(可选)"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="entryDialogVisible = false">取消</NButton>
          <NButton type="primary" @click="handleSubmitEntries">添加</NButton>
        </NSpace>
      </template>
    </NModal>

    <NModal
      v-model:show="importDialogVisible"
      preset="card"
      title="导入敏感文件路径"
      style="width: 520px"
    >
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="风险等级">
          <NSelect v-model:value="importRisk" :options="riskOptions" />
        </NFormItem>
        <NFormItem label="文件上传">
          <NUpload
            :max="1"
            accept=".txt,.csv"
            :default-upload="false"
            @change="handleImportFileChange"
          >
            <NUploadDragger>
              <p class="mb-2 text-sm">点击或拖拽 TXT/CSV 文件到此处</p>
              <p class="text-muted-foreground text-xs">
                每行一条路径，格式：路径,备注(可选),风险等级(可选)
              </p>
              <p class="text-muted-foreground text-xs">
                以 # 开头的行视为注释，自动去重
              </p>
            </NUploadDragger>
          </NUpload>
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="importDialogVisible = false">取消</NButton>
          <NButton
            type="primary"
            :loading="importing"
            :disabled="!importFile"
            @click="handleSubmitImport"
          >
            开始导入
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>
