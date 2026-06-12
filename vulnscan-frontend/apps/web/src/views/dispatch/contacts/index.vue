<script setup lang="ts">
import { ref, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NFormItem, NInput, NInputGroup, NPopconfirm, NDynamicTags,
  useMessage,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getContactList, createContact, updateContact, deleteContact,
  type DispatchContact,
} from '#/api/dispatch';
import { useNaiveTablePagination } from '#/composables/useNaiveTablePagination';

const message = useMessage();
const loading = ref(false);
const data = ref<DispatchContact[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');

async function fetchData() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: page.value, page_size: pageSize.value };
    if (keyword.value) params.keyword = keyword.value;
    const res = await getContactList(params);
    data.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

const { pagination } = useNaiveTablePagination({ page, pageSize, total, onFetch: fetchData });

onMounted(fetchData);

function fmtTime(t: string | null) {
  if (!t) return '-';
  return new Date(t).toLocaleString('zh-CN');
}

const columns: DataTableColumns<DispatchContact> = [
  { title: '姓名', key: 'name', width: 120 },
  { title: '公司/单位', key: 'company', width: 180, ellipsis: { tooltip: true },
    render: (row) => row.company || '-',
  },
  { title: '角色', key: 'role', width: 120, render: (row) => row.role || '-' },
  { title: '邮箱', key: 'email', width: 200, ellipsis: { tooltip: true },
    render: (row) => row.email || '-',
  },
  { title: '电话', key: 'phone', width: 140, render: (row) => row.phone || '-' },
  { title: '标签', key: 'tags', minWidth: 160,
    render: (row) => {
      const tags = row.tags || [];
      if (tags.length === 0) return '-';
      return h(NSpace, { size: 'small' }, () =>
        tags.map((t) => h(NTag, { size: 'small', bordered: false }, () => t)),
      );
    },
  },
  { title: '创建时间', key: 'created_at', width: 160, render: (row) => fmtTime(row.created_at) },
  {
    title: '操作', key: 'actions', width: 140, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, () => [
      h(NButton, { size: 'tiny', quaternary: true, type: 'info', onClick: () => openEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'tiny', quaternary: true, type: 'error' }, () => '删除'),
        default: () => '确认删除此联系人？',
      }),
    ]),
  },
];

async function handleDelete(id: string) {
  try {
    await deleteContact(id);
    message.success('已删除');
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

// ─── 新增/编辑弹窗 ───

const showModal = ref(false);
const isEdit = ref(false);
const editId = ref('');
const form = ref({
  name: '',
  company: '',
  role: '',
  email: '',
  phone: '',
  tags: [] as string[],
  note: '',
});

function openCreate() {
  isEdit.value = false;
  editId.value = '';
  form.value = { name: '', company: '', role: '', email: '', phone: '', tags: [], note: '' };
  showModal.value = true;
}

function openEdit(row: DispatchContact) {
  isEdit.value = true;
  editId.value = row.id;
  form.value = {
    name: row.name,
    company: row.company || '',
    role: row.role || '',
    email: row.email || '',
    phone: row.phone || '',
    tags: [...(row.tags || [])],
    note: row.note || '',
  };
  showModal.value = true;
}

const submitting = ref(false);

async function handleSubmit() {
  if (!form.value.name) {
    message.warning('请填写姓名');
    return;
  }
  submitting.value = true;
  try {
    if (isEdit.value) {
      await updateContact(editId.value, form.value);
      message.success('修改成功');
    } else {
      await createContact(form.value);
      message.success('创建成功');
    }
    showModal.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  } finally {
    submitting.value = false;
  }
}

function handleSearch() {
  page.value = 1;
  fetchData();
}
</script>

<template>
  <div class="p-4">
    <NCard title="外部人员管理" :bordered="false">
      <template #header-extra>
        <NSpace>
          <NInputGroup>
            <NInput v-model:value="keyword" placeholder="搜索姓名/公司/邮箱" clearable style="width: 220px"
              @keydown.enter="handleSearch" @clear="handleSearch" />
            <NButton type="primary" @click="handleSearch">搜索</NButton>
          </NInputGroup>
          <NButton type="primary" @click="openCreate">新增联系人</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination"
        :scroll-x="1200" :row-key="(r: DispatchContact) => r.id" size="small" striped />
    </NCard>

    <NModal v-model:show="showModal" preset="dialog"
      :title="isEdit ? '编辑联系人' : '新增联系人'" style="width: 560px"
      :positive-text="isEdit ? '保存' : '创建'" negative-text="取消"
      :loading="submitting" @positive-click="handleSubmit">
      <NForm :model="form" label-placement="left" label-width="auto" style="margin-top: 16px">
        <NFormItem label="姓名" required>
          <NInput v-model:value="form.name" placeholder="请输入姓名" />
        </NFormItem>
        <NFormItem label="公司/单位">
          <NInput v-model:value="form.company" placeholder="所属公司或单位" />
        </NFormItem>
        <NFormItem label="角色">
          <NInput v-model:value="form.role" placeholder="安全工程师/渗透测试员/运维人员" />
        </NFormItem>
        <NFormItem label="邮箱">
          <NInput v-model:value="form.email" placeholder="邮箱地址" />
        </NFormItem>
        <NFormItem label="电话">
          <NInput v-model:value="form.phone" placeholder="联系电话" />
        </NFormItem>
        <NFormItem label="标签">
          <NDynamicTags v-model:value="form.tags" />
        </NFormItem>
        <NFormItem label="备注">
          <NInput v-model:value="form.note" type="textarea" :rows="2" placeholder="备注信息" />
        </NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
