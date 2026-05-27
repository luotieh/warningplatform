<script lang="ts" setup>
import { h, onMounted, reactive, ref, watch } from 'vue';
import type { DataTableColumns, FormInst, PaginationProps } from 'naive-ui';
import {
  NButton,
  NCascader,
  NCard,
  NDataTable,
  NForm,
  NFormItem,
  NGrid,
  NGridItem,
  NInput,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSwitch,
  NTag,
  useMessage,
} from 'naive-ui';

import type { Organize } from '#/api/assetmgr';
import {
  createOrganize,
  deleteOrganize,
  getOrganizeList,
  syncIamOrganizes,
  updateOrganize,
} from '#/api/assetmgr';
import OrganizeTreeSelect from '#/components/organize/OrganizeTreeSelect.vue';
import { organizeProfileFormRules } from '#/utils/form-rules';
import { validateUnitProfile } from '#/utils/validators';
import { dictItemsToOptions, getSystemDictItems } from '#/api/system/dict';
import { regionOptions } from '#/utils/region';

defineOptions({ name: 'AssetOrganize' });

const message = useMessage();
const loading = ref(false);
const syncLoading = ref(false);
const data = ref<Organize[]>([]);
const showModal = ref(false);
const editingId = ref<null | string>(null);
const organizeFormRef = ref<FormInst | null>(null);

const searchForm = reactive({ keyword: '' });

const pagination = reactive<PaginationProps>({
  page: 1,
  pageSize: 15,
  itemCount: 0,
  pageSizes: [10, 15, 20, 50],
  showSizePicker: true,
  prefix: ({ itemCount }: { itemCount: number }) => `共 ${itemCount} 条`,
});

const formData = reactive({
  name: '',
  parent_id: '',
  unified_social_credit_code: '',
  industry_category: '',
  unit_type: '',
  is_notification_member: false,
  region_code: '',
  unit_detail_address: '',
  leader_name: '',
  leader_title: '',
  responsible_department_name: '',
  department_leader_name: '',
  department_leader_title: '',
  department_leader_phone: '',
  contact_name: '',
  contact_title: '',
  contact_phone: '',
});

const unitTypeOptions = ref<{ label: string; value: string }[]>([
  { label: '政府机关', value: '政府机关' },
  { label: '事业单位', value: '事业单位' },
  { label: '企业', value: '企业' },
  { label: '其他', value: '其他' },
]);
const industryCategoryOptions = ref<{ label: string; value: string }[]>([
  { label: '政务', value: '政务' },
  { label: '金融', value: '金融' },
  { label: '教育', value: '教育' },
  { label: '其他', value: '其他' },
]);

async function loadOrganizeDictOptions() {
  try {
    unitTypeOptions.value = dictItemsToOptions(await getSystemDictItems('organize_unit_type', true));
  } catch {
    /* keep fallback */
  }
  try {
    industryCategoryOptions.value = dictItemsToOptions(
      await getSystemDictItems('organize_industry_category', true),
    );
  } catch {
    /* keep fallback */
  }
}

const columns: DataTableColumns<Organize> = [
  {
    title: '单位名称',
    key: 'name',
    width: 280,
    ellipsis: { tooltip: true },
    render: (row: Organize) => h('div', {
      style: { display: 'flex', flexDirection: 'column', gap: '2px' },
    }, [
      h('span', row.name || '-'),
      row.parent_name
        ? h('span', {
            style: { color: 'var(--n-text-color-3)', fontSize: '12px' },
          }, `上级单位：${row.parent_name}`)
        : h('span', {
            style: { color: 'var(--n-text-color-3)', fontSize: '12px' },
          }, '顶级单位'),
    ]),
  },
  { title: '统一社会信用代码', key: 'unified_social_credit_code', width: 200, ellipsis: { tooltip: true } },
  { title: '单位类型', key: 'unit_type', width: 110 },
  { title: '行业分类', key: 'industry_category', width: 110 },
  {
    title: '通报成员',
    key: 'is_notification_member',
    width: 90,
    render: (row: Organize) => (row.is_notification_member ? '是' : '否'),
  },
  { title: '网络安全责任部门', key: 'responsible_department_name', width: 160, ellipsis: { tooltip: true } },
  { title: '联系人', key: 'contact_name', width: 100 },
  { title: '联系人职务', key: 'contact_title', width: 120, ellipsis: { tooltip: true } },
  { title: '联系电话', key: 'contact_phone', width: 130 },
  {
    title: '资产数',
    key: 'asset_count',
    width: 80,
    align: 'center',
    render: (row: Organize) =>
      row.asset_count > 0
        ? h(NTag, { size: 'small', type: 'info', round: true, bordered: false }, () => String(row.asset_count))
        : h('span', { style: 'color: var(--n-text-color-3)' }, '0'),
  },
  {
    title: '操作',
    key: 'actions',
    width: 140,
    fixed: 'right' as const,
    render: (row: Organize) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'small', onClick: () => onEdit(row) }, () => '编辑'),
      h(NPopconfirm, { onPositiveClick: () => onDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => '确认删除该单位？',
      }),
    ]),
  },
];

async function fetchList() {
  loading.value = true;
  try {
    const res = await getOrganizeList({
      page: pagination.page,
      page_size: pagination.pageSize,
      name: searchForm.keyword || undefined,
    });
    const raw = res?.data ?? res;
    const items = raw?.data;
    data.value = Array.isArray(items) ? items : [];
    pagination.itemCount = Number(raw?.count ?? data.value.length);
  } catch {
    message.error('加载单位列表失败');
  } finally {
    loading.value = false;
  }
}

function handlePageChange(page: number) {
  pagination.page = page;
  fetchList();
}

function handlePageSizeChange(pageSize: number) {
  pagination.pageSize = pageSize;
  pagination.page = 1;
  fetchList();
}

function handleSearch() {
  pagination.page = 1;
  fetchList();
}

function handleReset() {
  searchForm.keyword = '';
  pagination.page = 1;
  fetchList();
}

function resetForm() {
  Object.assign(formData, {
    name: '',
    parent_id: '',
    unified_social_credit_code: '',
    industry_category: '',
    unit_type: '',
    is_notification_member: false,
    region_code: '',
    unit_detail_address: '',
    leader_name: '',
    leader_title: '',
    responsible_department_name: '',
    department_leader_name: '',
    department_leader_title: '',
    department_leader_phone: '',
    contact_name: '',
    contact_title: '',
    contact_phone: '',
  });
}

function onAdd() {
  editingId.value = null;
  resetForm();
  showModal.value = true;
}

function onEdit(row: Organize) {
  editingId.value = row.id;
  Object.assign(formData, {
    name: row.name,
    parent_id: row.parent_id,
    unified_social_credit_code: row.unified_social_credit_code,
    industry_category: row.industry_category,
    unit_type: row.unit_type,
    is_notification_member: row.is_notification_member ?? false,
    region_code: row.region_code || '',
    unit_detail_address: row.unit_detail_address || row.address || '',
    leader_name: row.leader_name,
    leader_title: row.leader_title,
    responsible_department_name: row.responsible_department_name,
    department_leader_name: row.department_leader_name,
    department_leader_title: row.department_leader_title,
    department_leader_phone: row.department_leader_phone,
    contact_name: row.contact_name,
    contact_title: row.contact_title,
    contact_phone: row.contact_phone,
  });
  showModal.value = true;
}

async function onSave() {
  if (!formData.name) {
    message.warning('请填写单位名称');
    return;
  }
  try {
    await organizeFormRef.value?.validate();
  } catch {
    return;
  }
  const profileErr = validateUnitProfile(formData);
  if (profileErr) {
    message.warning(profileErr);
    return;
  }
  try {
    const payload = { ...formData };
    if (editingId.value) {
      await updateOrganize(editingId.value, payload);
      message.success('更新成功');
    } else {
      await createOrganize(payload);
      message.success('创建成功');
    }
    showModal.value = false;
    await fetchList();
  } catch {
    message.error('操作失败');
  }
}

async function onDelete(id: string) {
  try {
    await deleteOrganize(id);
    message.success('删除成功');
    fetchList();
  } catch {
    message.error('删除失败');
  }
}

async function onSyncIam() {
  syncLoading.value = true;
  try {
    const res: any = await syncIamOrganizes();
    const synced = Number(res?.synced ?? 0);
    const total = Number(res?.total ?? synced);
    message.success(`IAM 同步完成：新增 ${synced} 个单位，共 ${total} 个`);
    await fetchList();
  } catch {
    message.error('IAM 同步失败，请确认已登录且 IAM 服务可用');
  } finally {
    syncLoading.value = false;
  }
}

watch(showModal, (visible) => {
  if (!visible) organizeFormRef.value?.restoreValidation();
});

onMounted(() => {
  void loadOrganizeDictOptions();
  fetchList();
});
</script>

<template>
  <div style="padding: 16px">
    <NCard title="单位管理" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NButton size="small" :loading="syncLoading" @click="onSyncIam">同步IAM</NButton>
          <NButton type="primary" size="small" @click="onAdd">新建单位</NButton>
        </NSpace>
      </template>

      <div style="margin-bottom: 12px; color: var(--n-text-color-3)">
        IAM 同步后的组织数据以树形结构展示，本地维护的补充信息不会丢失。支持新建、编辑和删除操作。
      </div>

      <NForm inline label-placement="left" :show-feedback="false" style="margin-bottom: 16px">
        <NFormItem label="关键词">
          <NInput v-model:value="searchForm.keyword" placeholder="输入单位名称" clearable style="width: 220px" @keydown.enter="handleSearch" />
        </NFormItem>
        <NFormItem>
          <NSpace :size="8">
            <NButton type="primary" @click="handleSearch">搜索</NButton>
            <NButton @click="handleReset">重置</NButton>
          </NSpace>
        </NFormItem>
      </NForm>

      <NDataTable
        :columns="columns"
        :data="data"
        :loading="loading"
        :row-key="(row: Organize) => row.id"
        :bordered="false"
        :scroll-x="1500"
        :pagination="pagination"
        size="small"
        striped
        remote
        @update:page="handlePageChange"
        @update:page-size="handlePageSizeChange"
      />
    </NCard>

    <NModal v-model:show="showModal" preset="dialog" :title="editingId ? '编辑单位' : '新建单位'" style="width: 860px">
      <NForm
        ref="organizeFormRef"
        :model="formData"
        :rules="organizeProfileFormRules"
        label-placement="left"
        label-width="120"
        style="margin-top: 16px"
      >
        <NGrid :cols="2" :x-gap="16">
          <NGridItem>
            <NFormItem label="单位名称" required>
              <NInput v-model:value="formData.name" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="上级单位">
              <OrganizeTreeSelect
                v-model="formData.parent_id"
                :exclude-id="editingId"
                placeholder="请选择上级单位（可搜索）"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="统一社会信用代码" path="unified_social_credit_code">
              <NInput
                v-model:value="formData.unified_social_credit_code"
                placeholder="18 位，可选"
                maxlength="18"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="单位类型">
              <NSelect v-model:value="formData.unit_type" :options="unitTypeOptions" clearable />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="行业分类">
              <NSelect
                v-model:value="formData.industry_category"
                :options="industryCategoryOptions"
                clearable
                filterable
                placeholder="请选择"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="是否通报成员单位">
              <NSwitch v-model:value="formData.is_notification_member" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="省市区">
              <NCascader
                v-model:value="formData.region_code"
                clearable
                filterable
                check-strategy="child"
                :options="regionOptions"
                placeholder="请选择省 / 市 / 区县"
              />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="详细地址">
              <NInput v-model:value="formData.unit_detail_address" placeholder="街道、门牌号等" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="网络安全分管领导">
              <NInput v-model:value="formData.leader_name" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="负责人职务/职称">
              <NInput v-model:value="formData.leader_title" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="网络安全责任部门">
              <NInput v-model:value="formData.responsible_department_name" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="负责部门负责人">
              <NInput v-model:value="formData.department_leader_name" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="部门负责人职务/职称">
              <NInput v-model:value="formData.department_leader_title" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="部门负责人电话" path="department_leader_phone">
              <NInput v-model:value="formData.department_leader_phone" placeholder="11 位手机或固话" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="联系人">
              <NInput v-model:value="formData.contact_name" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="联系人职务/职称">
              <NInput v-model:value="formData.contact_title" />
            </NFormItem>
          </NGridItem>
          <NGridItem>
            <NFormItem label="联系电话" path="contact_phone">
              <NInput v-model:value="formData.contact_phone" placeholder="11 位手机或固话" />
            </NFormItem>
          </NGridItem>
        </NGrid>
      </NForm>
      <template #action>
        <NSpace>
          <NButton @click="showModal = false">取消</NButton>
          <NButton type="primary" @click="onSave">确认</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
