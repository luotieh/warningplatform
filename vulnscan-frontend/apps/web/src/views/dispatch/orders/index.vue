<script setup lang="ts">
import { ref, h, onMounted, computed } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NFormItem, NInput, NSelect, NInputNumber, NDatePicker,
  NPopconfirm, NInputGroup, NIcon, NTooltip, NBadge,
  useMessage,
} from 'naive-ui';
import type { DataTableColumns, SelectOption } from 'naive-ui';
import { useRouter } from 'vue-router';
import {
  getOrderList, createOrder, cancelOrder, assignOrder,
  type DispatchOrder,
  DispatchStatusLabels, DispatchStatusTypes,
  DispatchTypeLabels, PriorityLabels, PriorityColors,
  SourceTypeLabels,
  type DispatchStatus, type DispatchType,
  getContactList, type DispatchContact,
  getIAMUserList, type IAMUser,
} from '#/api/dispatch';
import { useNaiveTablePagination } from '#/composables/useNaiveTablePagination';

const message = useMessage();
const router = useRouter();
const loading = ref(false);
const data = ref<DispatchOrder[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const filterStatus = ref<string | null>(null);
const filterType = ref<string | null>(null);

async function fetchData() {
  loading.value = true;
  try {
    const params: Record<string, any> = {
      page: page.value,
      page_size: pageSize.value,
    };
    if (keyword.value) params.keyword = keyword.value;
    if (filterStatus.value) params.status = filterStatus.value;
    if (filterType.value) params.type = filterType.value;
    const res = await getOrderList(params);
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

function priorityTag(p: number) {
  return h(NTag, {
    size: 'small',
    bordered: false,
    style: { color: PriorityColors[p] || '#999', backgroundColor: `${PriorityColors[p] || '#999'}18` },
  }, () => PriorityLabels[p] || `P${p}`);
}

const statusOptions: SelectOption[] = Object.entries(DispatchStatusLabels).map(([v, l]) => ({ value: v, label: l }));
const typeOptions: SelectOption[] = Object.entries(DispatchTypeLabels).map(([v, l]) => ({ value: v, label: l }));

const columns: DataTableColumns<DispatchOrder> = [
  { title: '编号', key: 'code', width: 160, ellipsis: { tooltip: true } },
  { title: '标题', key: 'title', minWidth: 200, ellipsis: { tooltip: true },
    render: (row) => h('a', {
      style: 'color: var(--n-link-text-color, #2080f0); cursor: pointer; text-decoration: none;',
      onClick: () => router.push(`/dispatch/orders/${row.id}`),
    }, row.title),
  },
  { title: '类型', key: 'type', width: 100,
    render: (row) => h(NTag, { size: 'small', bordered: false }, () => DispatchTypeLabels[row.type] || row.type),
  },
  { title: '优先级', key: 'priority', width: 80, render: (row) => priorityTag(row.priority) },
  { title: '状态', key: 'status', width: 90,
    render: (row) => h(NTag, {
      size: 'small',
      type: DispatchStatusTypes[row.status] as any,
      bordered: false,
    }, () => DispatchStatusLabels[row.status] || row.status),
  },
  { title: '处理人', key: 'assignee_name', width: 100, ellipsis: { tooltip: true },
    render: (row) => row.assignee_name || '-',
  },
  { title: '来源', key: 'source_type', width: 90,
    render: (row) => h(NTag, { size: 'small', bordered: false, type: 'default' },
      () => SourceTypeLabels[row.source_type] || row.source_type || '-'),
  },
  { title: '截止时间', key: 'deadline', width: 160, render: (row) => fmtTime(row.deadline) },
  { title: '创建时间', key: 'created_at', width: 160, render: (row) => fmtTime(row.created_at) },
  {
    title: '操作', key: 'actions', width: 160, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, () => {
      const actions: any[] = [
        h(NButton, { size: 'tiny', quaternary: true, type: 'info',
          onClick: () => router.push(`/dispatch/orders/${row.id}`),
        }, () => '详情'),
      ];
      if (row.status === 'draft' || row.status === 'rejected') {
        actions.push(h(NButton, { size: 'tiny', quaternary: true, type: 'warning',
          onClick: () => openAssign(row),
        }, () => '指派'));
      }
      if (row.status !== 'completed' && row.status !== 'cancelled') {
        actions.push(h(NPopconfirm, { onPositiveClick: () => handleCancel(row.id) }, {
          trigger: () => h(NButton, { size: 'tiny', quaternary: true, type: 'error' }, () => '取消'),
          default: () => '确认取消此派发单？',
        }));
      }
      return actions;
    }),
  },
];

async function handleCancel(id: string) {
  try {
    await cancelOrder(id);
    message.success('已取消');
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

// ─── 创建派发单 ───

const showCreate = ref(false);
const createForm = ref({
  title: '',
  description: '',
  type: 'vuln_retest' as DispatchType,
  priority: 3,
  source_type: 'manual',
  assignee_type: 'internal',
  assignee_name: '',
  assignee_contact: '',
  assignee_id: '',
  deadline: null as number | null,
});

function openCreate() {
  createForm.value = {
    title: '',
    description: '',
    type: 'vuln_retest',
    priority: 3,
    source_type: 'manual',
    assignee_type: 'internal',
    assignee_name: '',
    assignee_contact: '',
    assignee_id: '',
    deadline: null,
  };
  loadIAMUsers();
  showCreate.value = true;
}

const creating = ref(false);

async function handleCreate() {
  if (!createForm.value.title) {
    message.warning('请填写标题');
    return;
  }
  creating.value = true;
  try {
    const payload: Record<string, any> = { ...createForm.value };
    if (createForm.value.deadline) {
      payload.deadline = new Date(createForm.value.deadline).toISOString().slice(0, 19).replace('T', ' ');
    } else {
      delete payload.deadline;
    }
    await createOrder(payload);
    message.success('创建成功');
    showCreate.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '创建失败');
  } finally {
    creating.value = false;
  }
}

// ─── 指派弹窗 ───

const showAssign = ref(false);
const assignTarget = ref<DispatchOrder | null>(null);
const assignForm = ref({
  assignee_type: 'internal',
  assignee_name: '',
  assignee_contact: '',
  assignee_id: '',
  deadline: null as number | null,
});
const contacts = ref<DispatchContact[]>([]);
const iamUsers = ref<IAMUser[]>([]);
const iamUsersLoading = ref(false);

async function loadContacts() {
  try {
    const res = await getContactList({ page: 1, page_size: 100 });
    contacts.value = res.items;
  } catch {}
}

async function loadIAMUsers() {
  iamUsersLoading.value = true;
  try {
    const res = await getIAMUserList({ page: 1, page_size: 200 });
    iamUsers.value = res.items;
  } catch {} finally { iamUsersLoading.value = false; }
}

const iamUserOptions = computed<SelectOption[]>(() =>
  iamUsers.value.map((u) => ({
    value: u.user_id,
    label: `${u.name || u.account} (${u.account})`,
  })),
);

function onIAMUserSelect(userId: string) {
  const u = iamUsers.value.find((x) => x.user_id === userId);
  if (u) {
    assignForm.value.assignee_id = u.user_id;
    assignForm.value.assignee_name = u.name || u.account;
    assignForm.value.assignee_contact = u.email || u.phone || '';
  }
}

function onIAMUserSelectForCreate(userId: string) {
  const u = iamUsers.value.find((x) => x.user_id === userId);
  if (u) {
    createForm.value.assignee_id = u.user_id;
    createForm.value.assignee_name = u.name || u.account;
    createForm.value.assignee_contact = u.email || u.phone || '';
  }
}

function openAssign(row: DispatchOrder) {
  assignTarget.value = row;
  assignForm.value = {
    assignee_type: row.assignee_type || 'internal',
    assignee_name: row.assignee_name || '',
    assignee_contact: row.assignee_contact || '',
    assignee_id: row.assignee_id || '',
    deadline: row.deadline ? new Date(row.deadline).getTime() : null,
  };
  loadContacts();
  loadIAMUsers();
  showAssign.value = true;
}

const contactOptions = computed<SelectOption[]>(() =>
  contacts.value.map((c) => ({
    value: c.id,
    label: `${c.name} - ${c.company || ''} (${c.email || c.phone || ''})`,
  })),
);

function onContactSelect(id: string) {
  const c = contacts.value.find((x) => x.id === id);
  if (c) {
    assignForm.value.assignee_name = c.name;
    assignForm.value.assignee_contact = c.email || c.phone;
    assignForm.value.assignee_id = c.id;
  }
}

const assigning = ref(false);

async function handleAssign() {
  if (!assignTarget.value || !assignForm.value.assignee_name) {
    message.warning('请选择或填写处理人');
    return;
  }
  assigning.value = true;
  try {
    const payload: Record<string, any> = { ...assignForm.value };
    if (assignForm.value.deadline) {
      payload.deadline = new Date(assignForm.value.deadline).toISOString().slice(0, 19).replace('T', ' ');
    } else {
      delete payload.deadline;
    }
    await assignOrder(assignTarget.value.id, payload);
    message.success('指派成功');
    showAssign.value = false;
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '指派失败');
  } finally {
    assigning.value = false;
  }
}

function handleSearch() {
  page.value = 1;
  fetchData();
}
</script>

<template>
  <div class="p-4">
    <NCard title="派发单列表" :bordered="false">
      <template #header-extra>
        <NSpace>
          <NInputGroup>
            <NInput v-model:value="keyword" placeholder="搜索编号/标题/处理人" clearable style="width: 240px"
              @keydown.enter="handleSearch" @clear="handleSearch" />
            <NButton type="primary" @click="handleSearch">搜索</NButton>
          </NInputGroup>
          <NSelect v-model:value="filterStatus" :options="statusOptions" placeholder="状态筛选"
            clearable style="width: 120px" @update:value="handleSearch" />
          <NSelect v-model:value="filterType" :options="typeOptions" placeholder="类型筛选"
            clearable style="width: 120px" @update:value="handleSearch" />
          <NButton type="primary" @click="openCreate">创建派发单</NButton>
        </NSpace>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :pagination="pagination"
        :scroll-x="1400" :row-key="(r: DispatchOrder) => r.id" size="small" striped />
    </NCard>

    <!-- 创建派发单弹窗 -->
    <NModal v-model:show="showCreate" preset="dialog" title="创建派发单" style="width: 640px"
      positive-text="创建" negative-text="取消" :loading="creating" @positive-click="handleCreate">
      <NForm :model="createForm" label-placement="left" label-width="auto" style="margin-top: 16px">
        <NFormItem label="标题" required>
          <NInput v-model:value="createForm.title" placeholder="请输入派发单标题" />
        </NFormItem>
        <NFormItem label="类型">
          <NSelect v-model:value="createForm.type" :options="typeOptions" />
        </NFormItem>
        <NFormItem label="优先级">
          <NSelect v-model:value="createForm.priority"
            :options="[{value:1,label:'最低'},{value:2,label:'低'},{value:3,label:'中'},{value:4,label:'高'},{value:5,label:'紧急'}]" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="createForm.description" type="textarea" :rows="3" placeholder="详细描述" />
        </NFormItem>
        <NFormItem label="选择处理人" required>
          <NSelect :options="iamUserOptions" :loading="iamUsersLoading"
            filterable clearable placeholder="从系统用户中选择"
            @update:value="onIAMUserSelectForCreate" />
        </NFormItem>
        <NFormItem label="处理人姓名">
          <NInput v-model:value="createForm.assignee_name" placeholder="自动填充" />
        </NFormItem>
        <NFormItem label="联系方式">
          <NInput v-model:value="createForm.assignee_contact" placeholder="邮箱或手机" />
        </NFormItem>
        <NFormItem label="截止时间">
          <NDatePicker v-model:value="createForm.deadline" type="datetime" clearable style="width: 100%" />
        </NFormItem>
      </NForm>
    </NModal>

    <!-- 指派弹窗 -->
    <NModal v-model:show="showAssign" preset="dialog" title="指派处理人" style="width: 560px"
      positive-text="确认指派" negative-text="取消" :loading="assigning" @positive-click="handleAssign">
      <NForm :model="assignForm" label-placement="left" label-width="auto" style="margin-top: 16px">
        <NFormItem label="选择处理人" required>
          <NSelect :options="iamUserOptions" :loading="iamUsersLoading"
            filterable clearable placeholder="从系统用户中选择"
            @update:value="onIAMUserSelect" />
        </NFormItem>
        <NFormItem label="处理人姓名">
          <NInput v-model:value="assignForm.assignee_name" placeholder="自动填充" />
        </NFormItem>
        <NFormItem label="联系方式">
          <NInput v-model:value="assignForm.assignee_contact" placeholder="邮箱或手机" />
        </NFormItem>
        <NFormItem label="截止时间">
          <NDatePicker v-model:value="assignForm.deadline" type="datetime" clearable style="width: 100%" />
        </NFormItem>
      </NForm>
    </NModal>
  </div>
</template>
