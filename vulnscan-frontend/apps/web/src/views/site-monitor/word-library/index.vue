<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import type { WordLibrary } from '#/api/sitemonitor';

import { computed, h, onMounted, reactive, ref } from 'vue';
import { useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NInput,
  NModal,
  NSpace,
} from 'naive-ui';

import { dialog, message } from '#/adapter/naive';
import {
  createWordCategory,
  createWordLibrary,
  deleteWordLibrary,
  getWordLibraryList,
  updateWordLibrary,
} from '#/api/sitemonitor';

defineOptions({ name: 'WordLibrary' });

const router = useRouter();
const loading = ref(false);
const dataList = ref<WordLibrary[]>([]);
const safeDataList = computed(() =>
  Array.isArray(dataList.value) ? dataList.value : [],
);
const pagination = reactive({
  page: 1,
  pageSize: 10,
  itemCount: 0,
  showSizePicker: true,
  pageSizes: [10, 15, 20, 50],
});

const searchForm = reactive({ name: '' });

const dialogVisible = ref(false);
const dialogTitle = ref('新增词库');
const formData = reactive({
  description: '',
  id: '',
  isEdit: false,
  name: '',
});
const submitting = ref(false);

async function onSearch() {
  loading.value = true;
  try {
    const res = await getWordLibraryList({
      index: pagination.page,
      name: searchForm.name,
      size: pagination.pageSize,
    });
    dataList.value = res.data || [];
    pagination.itemCount = (res as any).count || 0;
  } catch {
    dataList.value = [];
  } finally {
    loading.value = false;
  }
}

function handleAdd() {
  dialogTitle.value = '新增词库';
  formData.isEdit = false;
  formData.id = '';
  formData.name = '';
  formData.description = '';
  dialogVisible.value = true;
}

function handleEdit(row: WordLibrary) {
  dialogTitle.value = '编辑词库';
  formData.isEdit = true;
  formData.id = row.id;
  formData.name = row.name;
  formData.description = row.description;
  dialogVisible.value = true;
}

async function handleSubmit() {
  if (!formData.name.trim()) {
    message.warning('请填写词库名称');
    return;
  }
  submitting.value = true;
  try {
    if (formData.isEdit) {
      await updateWordLibrary(formData.id, {
        description: formData.description,
        name: formData.name,
      });
      message.success('更新成功');
    } else {
      const res = await createWordLibrary({
        description: formData.description,
        name: formData.name,
      });
      const newId = (res as any)?.id ?? (res as any)?.data?.id;
      if (newId) {
        try {
          await createWordCategory({
            library_id: newId,
            name: formData.name.trim(),
            description: '自动创建的默认分类',
          });
        } catch { /* 默认分类创建失败不阻塞主流程 */ }
      }
      message.success('创建成功');
    }
    dialogVisible.value = false;
    onSearch();
  } catch (e: any) {
    message.error(e?.msg || '操作失败');
  } finally {
    submitting.value = false;
  }
}

function handleDelete(row: WordLibrary) {
  dialog.warning({
    title: '提示',
    content: `确认删除词库「${row.name}」？删除后不可恢复`,
    positiveText: '确认删除',
    negativeText: '取消',
    onPositiveClick: async () => {
      try {
        await deleteWordLibrary(row.id);
        message.success('删除成功');
        onSearch();
      } catch (e: any) {
        message.error(e?.msg || '删除失败');
      }
    },
  });
}

function goDetail(row: WordLibrary) {
  router.push(`/monitor/rules/word-library/detail/${row.id}`);
}

const columns = computed<DataTableColumns<WordLibrary>>(() => [
  { key: 'name', title: '词库名称', minWidth: 160 },
  {
    key: 'description',
    title: '描述',
    minWidth: 200,
    ellipsis: { tooltip: true },
  },
  {
    key: 'created_at',
    title: '创建时间',
    minWidth: 160,
    render: (row) =>
      row.created_at
        ? dayjs(row.created_at).format('YYYY-MM-DD HH:mm:ss')
        : '-',
  },
  {
    key: 'op',
    title: '操作',
    width: 280,
    fixed: 'right',
    render: (row) =>
      h(NSpace, { size: 'small' }, () => [
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            onClick: () => goDetail(row),
          },
          { default: () => '详情' },
        ),
        h(
          NButton,
          {
            text: true,
            type: 'primary',
            size: 'small',
            onClick: () => handleEdit(row),
          },
          { default: () => '编辑' },
        ),
        h(
          NButton,
          {
            text: true,
            type: 'error',
            size: 'small',
            onClick: () => handleDelete(row),
          },
          { default: () => '删除' },
        ),
      ]),
  },
]);

onMounted(() => onSearch());
</script>

<template>
  <Page title="敏感词库" description="管理敏感词库与分类">
    <NCard size="small" class="mb-3">
      <NSpace align="center">
        <span>名称</span>
        <NInput
          v-model:value="searchForm.name"
          placeholder="请输入词库名称"
          clearable
          style="width: 250px"
        />
        <NButton type="primary" :loading="loading" @click="onSearch">
          搜索
        </NButton>
        <NButton
          @click="
            () => {
              searchForm.name = '';
              onSearch();
            }
          "
        >
          重置
        </NButton>
      </NSpace>
    </NCard>

    <NCard title="敏感词库管理">
      <template #header-extra>
        <NButton type="primary" @click="handleAdd">新增词库</NButton>
      </template>
      <NDataTable
        :columns="columns"
        :data="safeDataList"
        :loading="loading"
        :pagination="pagination"
        :row-key="(r: WordLibrary) => r.id"
        remote
        size="small"
        @update:page="
          (p: number) => {
            pagination.page = p;
            onSearch();
          }
        "
        @update:page-size="
          (s: number) => {
            pagination.pageSize = s;
            pagination.page = 1;
            onSearch();
          }
        "
      />
    </NCard>

    <NModal
      v-model:show="dialogVisible"
      preset="card"
      :title="dialogTitle"
      style="width: 500px"
    >
      <NForm label-placement="left" :label-width="80">
        <NFormItem label="名称" required>
          <NInput
            v-model:value="formData.name"
            placeholder="请输入词库名称"
          />
        </NFormItem>
        <NFormItem label="描述">
          <NInput
            v-model:value="formData.description"
            type="textarea"
            :rows="3"
            placeholder="请输入描述"
          />
        </NFormItem>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="dialogVisible = false">取消</NButton>
          <NButton type="primary" :loading="submitting" @click="handleSubmit">
            确定
          </NButton>
        </NSpace>
      </template>
    </NModal>
  </Page>
</template>
