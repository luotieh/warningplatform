<script lang="ts" setup>
import type { DataTableColumns, DataTableRowKey } from 'naive-ui';

import type { WordCategory, WordEntry } from '#/api/monitor';

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
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  batchCreateWordEntries,
  createWordCategory,
  deleteWordCategory,
  deleteWordEntries,
  getWordCategoryList,
  getWordEntryList,
  getWordLibraryDetail,
  importWordEntries,
  updateWordCategory,
} from '#/api/monitor';

defineOptions({ name: 'WordLibraryDetail' });

const route = useRoute();
const router = useRouter();
const libraryId = route.params.id as string;

const libraryInfo = ref<any>({});
const categories = ref<WordCategory[]>([]);
const activeCatId = ref('');
const loading = ref(false);

const entryList = ref<WordEntry[]>([]);
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

const catDialogVisible = ref(false);
const catDialogTitle = ref('新增分类');
const catForm = reactive({
  description: '',
  id: '',
  isEdit: false,
  name: '',
});

const entryDialogVisible = ref(false);
const entryInput = ref('');
const entrySeverity = ref('medium');

const severityTagType = (
  v: string,
): 'default' | 'error' | 'info' | 'primary' | 'warning' => {
  if (v === 'critical') return 'error';
  if (v === 'high') return 'warning';
  if (v === 'medium') return 'primary';
  return 'info';
};
const severityLabel = (v: string) =>
  ({ critical: '严重', high: '高', low: '低', medium: '中' })[
    v as 'critical' | 'high' | 'low' | 'medium'
  ] ?? v;

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高', value: 'high' },
  { label: '中', value: 'medium' },
  { label: '低', value: 'low' },
];

const selectedEntryIds = ref<DataTableRowKey[]>([]);

async function fetchLibrary() {
  try {
    const res = await getWordLibraryDetail(libraryId);
    libraryInfo.value = (res as any)?.data ?? res;
  } catch {
    message.error('获取词库详情失败');
  }
}

async function fetchCategories() {
  try {
    const res = await getWordCategoryList(libraryId);
    categories.value = Array.isArray(res) ? res : ((res as any)?.data || []);
    if (categories.value.length > 0 && !activeCatId.value) {
      activeCatId.value = categories.value[0]!.id;
    }
    if (activeCatId.value) fetchEntries();
  } catch {
    message.error('获取分类失败');
  }
}

async function fetchEntries() {
  if (!activeCatId.value) return;
  loading.value = true;
  try {
    const res = await getWordEntryList({
      category_id: activeCatId.value,
      index: entryPagination.page,
      size: entryPagination.pageSize,
      word: entrySearch.value,
    });
    entryList.value = res.data || [];
    entryPagination.itemCount = (res as any).count || 0;
  } catch {
    entryList.value = [];
  } finally {
    loading.value = false;
  }
}

function selectCategory(catId: string) {
  activeCatId.value = catId;
  entryPagination.page = 1;
  fetchEntries();
}

function handleAddCategory() {
  catDialogTitle.value = '新增分类';
  catForm.isEdit = false;
  catForm.id = '';
  catForm.name = '';
  catForm.description = '';
  catDialogVisible.value = true;
}

function handleEditCategory(cat: WordCategory) {
  catDialogTitle.value = '编辑分类';
  catForm.isEdit = true;
  catForm.id = cat.id;
  catForm.name = cat.name;
  catForm.description = cat.description;
  catDialogVisible.value = true;
}

async function handleSubmitCategory() {
  if (!catForm.name.trim()) {
    message.warning('请填写分类名称');
    return;
  }
  try {
    if (catForm.isEdit) {
      await updateWordCategory(catForm.id, {
        description: catForm.description,
        name: catForm.name,
      });
      message.success('更新成功');
    } else {
      await createWordCategory({
        description: catForm.description,
        library_id: libraryId,
        name: catForm.name,
      });
      message.success('创建成功');
    }
    catDialogVisible.value = false;
    fetchCategories();
  } catch (e: any) {
    message.error(e?.msg || '操作失败');
  }
}

function handleDeleteCategory(cat: WordCategory) {
  dialog.warning({
    title: '提示',
    content: `确认删除分类「${cat.name}」及其所有词条？`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteWordCategory(cat.id);
        message.success('删除成功');
        if (activeCatId.value === cat.id) activeCatId.value = '';
        fetchCategories();
      } catch (e: any) {
        message.error(e?.msg || '删除失败');
      }
    },
  });
}

function handleAddEntries() {
  entryInput.value = '';
  entrySeverity.value = 'medium';
  entryDialogVisible.value = true;
}

async function handleSubmitEntries() {
  const words = entryInput.value
    .split('\n')
    .map((w) => w.trim())
    .filter(Boolean);
  if (words.length === 0) {
    message.warning('请输入至少一个词条');
    return;
  }
  try {
    const entries = words.map((word) => ({
      category_id: activeCatId.value,
      severity: entrySeverity.value,
      word,
    }));
    await batchCreateWordEntries(entries);
    message.success(`成功添加 ${words.length} 个词条`);
    entryDialogVisible.value = false;
    fetchEntries();
  } catch (e: any) {
    message.error(e?.msg || '添加失败');
  }
}

function handleDeleteEntries() {
  if (selectedEntryIds.value.length === 0) {
    message.warning('请选择要删除的词条');
    return;
  }
  dialog.warning({
    title: '提示',
    content: `确认删除选中的 ${selectedEntryIds.value.length} 个词条？`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteWordEntries(selectedEntryIds.value as number[]);
        message.success('删除成功');
        selectedEntryIds.value = [];
        fetchEntries();
      } catch (e: any) {
        message.error(e?.msg || '删除失败');
      }
    },
  });
}

const importDialogVisible = ref(false);
const importSeverity = ref('medium');
const importFile = ref<File | null>(null);
const importing = ref(false);

function handleImport() {
  importFile.value = null;
  importSeverity.value = 'medium';
  importDialogVisible.value = true;
}

function handleImportFileChange(options: { file: { file: File | null } }) {
  importFile.value = options.file.file;
}

async function handleSubmitImport() {
  if (!importFile.value) {
    message.warning('请选择文件');
    return;
  }
  if (!activeCatId.value) {
    message.warning('请先选择一个分类');
    return;
  }
  importing.value = true;
  try {
    const res: any = await importWordEntries(
      importFile.value,
      activeCatId.value,
      importSeverity.value,
    );
    const data = res?.data ?? res;
    message.success(
      `导入完成：新增 ${data?.imported ?? 0} 个词条${data?.duplicated ? `，去重 ${data.duplicated} 个` : ''}`,
    );
    importDialogVisible.value = false;
    fetchEntries();
  } catch (e: any) {
    message.error(e?.msg || '导入失败');
  } finally {
    importing.value = false;
  }
}

const entryColumns = computed<DataTableColumns<WordEntry>>(() => [
  { type: 'selection' },
  { key: 'id', title: 'ID', width: 80 },
  { key: 'word', title: '敏感词', minWidth: 200 },
  {
    key: 'severity',
    title: '严重程度',
    width: 100,
    render: (row) =>
      h(
        NTag,
        { type: severityTagType(row.severity), size: 'small', bordered: false },
        { default: () => severityLabel(row.severity) },
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

onMounted(() => {
  fetchLibrary();
  fetchCategories();
});
</script>

<template>
  <Page :title="libraryInfo?.name || '词库详情'" :description="libraryInfo?.description">
    <NSpace align="center" class="mb-3">
      <NButton @click="router.back()">返回</NButton>
    </NSpace>

    <div class="flex gap-3" style="min-height: 500px">
      <!-- 左侧分类 -->
      <NCard size="small" style="width: 260px; flex-shrink: 0">
        <template #header>
          <span class="font-bold">分类列表</span>
        </template>
        <template #header-extra>
          <NButton size="tiny" type="primary" @click="handleAddCategory">
            新增
          </NButton>
        </template>
        <div
          v-if="categories.length === 0"
          class="text-muted-foreground py-8 text-center"
        >
          暂无分类
        </div>
        <div
          v-for="cat in categories"
          :key="cat.id"
          class="hover:bg-accent mb-1 flex cursor-pointer items-center justify-between rounded px-3 py-2 transition-colors"
          :class="{ 'bg-primary/10': activeCatId === cat.id }"
          @click="selectCategory(cat.id)"
        >
          <span class="flex-1 truncate">{{ cat.name }}</span>
          <NSpace size="small" @click.stop>
            <NButton text size="tiny" @click="handleEditCategory(cat)">
              编辑
            </NButton>
            <NButton
              text
              size="tiny"
              type="error"
              @click="handleDeleteCategory(cat)"
            >
              删除
            </NButton>
          </NSpace>
        </div>
      </NCard>

      <!-- 右侧词条列表 -->
      <NCard size="small" style="flex: 1; min-width: 0">
        <NSpace justify="space-between" align="center" class="mb-3">
          <NSpace align="center">
            <NInput
              v-model:value="entrySearch"
              placeholder="搜索词条"
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
            <NButton
              type="primary"
              :disabled="!activeCatId"
              @click="handleAddEntries"
            >
              添加词条
            </NButton>
            <NButton
              :disabled="!activeCatId"
              @click="handleImport"
            >
              导入词条
            </NButton>
          </NSpace>
        </NSpace>

        <NDataTable
          :columns="entryColumns"
          :data="safeEntryList"
          :loading="loading"
          :pagination="entryPagination"
          :row-key="(r: WordEntry) => r.id"
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
    </div>

    <!-- 分类弹窗 -->
    <NModal
      v-model:show="catDialogVisible"
      preset="card"
      :title="catDialogTitle"
      style="width: 420px"
    >
      <NForm label-placement="left" :label-width="60">
        <NFormItem label="名称" required>
          <NInput
            v-model:value="catForm.name"
            placeholder="如：涉黄、涉政"
          />
        </NFormItem>
        <NFormItem label="描述">
          <NInput
            v-model:value="catForm.description"
            type="textarea"
            :rows="2"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="catDialogVisible = false">取消</NButton>
          <NButton type="primary" @click="handleSubmitCategory">确定</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 词条批量添加弹窗 -->
    <NModal
      v-model:show="entryDialogVisible"
      preset="card"
      title="批量添加词条"
      style="width: 500px"
    >
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="敏感等级">
          <NSelect v-model:value="entrySeverity" :options="severityOptions" />
        </NFormItem>
        <NFormItem label="词条内容">
          <NInput
            v-model:value="entryInput"
            type="textarea"
            :rows="10"
            placeholder="每行一个敏感词"
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
    <!-- 导入词条弹窗 -->
    <NModal
      v-model:show="importDialogVisible"
      preset="card"
      title="导入敏感词"
      style="width: 520px"
    >
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="敏感等级">
          <NSelect v-model:value="importSeverity" :options="severityOptions" />
        </NFormItem>
        <NFormItem label="上传文件">
          <NUpload
            :max="1"
            accept=".txt,.csv,.text"
            :default-upload="false"
            @change="handleImportFileChange"
          >
            <NUploadDragger>
              <div class="py-4 text-center">
                <div class="text-base font-semibold">
                  点击或拖拽文件到此处
                </div>
                <div class="text-muted-foreground mt-1 text-xs">
                  支持 .txt .csv 格式，每行一个敏感词，#开头为注释行
                </div>
              </div>
            </NUploadDragger>
          </NUpload>
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="importDialogVisible = false">取消</NButton>
          <NButton type="primary" :loading="importing" @click="handleSubmitImport">
            开始导入
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>
