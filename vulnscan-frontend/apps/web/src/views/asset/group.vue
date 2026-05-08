<script lang="ts" setup>
import { h, onMounted, ref, reactive } from 'vue';
import {
  NButton, NCard, NDataTable, NSpace, NModal, NForm, NFormItem,
  NInput, NPopconfirm, NSelect, NSwitch, NTag, useMessage,
} from 'naive-ui';
import { requestClient } from '#/api/request';

defineOptions({ name: 'AssetGroup' });

const message = useMessage();
const loading = ref(false);
const data = ref<any[]>([]);
const showModal = ref(false);
const saving = ref(false);
const refreshingId = ref('');

const form = reactive({
  name: '', description: '', is_dynamic: false,
  rule_field: '', rule_op: '', rule_value: '',
});

const ruleFieldOptions = [
  { label: '类型', value: 'type' },
  { label: '系统类型', value: 'system_type' },
  { label: '保护等级', value: 'security_protection_level' },
  { label: '生命周期', value: 'lifecycle_state' },
  { label: '数据来源', value: 'data_source' },
  { label: '地址', value: 'address' },
  { label: '域名', value: 'domain' },
  { label: '服务', value: 'service' },
  { label: '操作系统', value: 'os' },
];

const ruleOpOptions = [
  { label: '等于', value: 'eq' },
  { label: '包含', value: 'contains' },
  { label: '前缀匹配', value: 'prefix' },
  { label: '不等于', value: 'neq' },
];

const columns = [
  { title: '分组名称', key: 'name', minWidth: 150,
    render: (row: any) => h(NSpace, { size: 4, align: 'center' }, () => [
      row.name,
      row.is_dynamic ? h(NTag, { size: 'tiny', type: 'info', bordered: false }, () => '动态') : null,
    ]),
  },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  { title: '资产数', key: 'asset_count', width: 90 },
  { title: '规则', key: 'rule', width: 200,
    render: (row: any) => row.is_dynamic
      ? h('span', { style: 'font-size:12px;color:#666' }, `${row.rule_field} ${row.rule_op} "${row.rule_value}"`)
      : '-',
  },
  { title: '创建时间', key: 'created_at', width: 170 },
  { title: '操作', key: 'actions', width: 180,
    render: (row: any) => h(NSpace, { size: 4 }, () => [
      row.is_dynamic ? h(NButton, {
        size: 'small', type: 'info', text: true,
        loading: refreshingId.value === row.id,
        onClick: () => onRefresh(row.id),
      }, () => '刷新') : null,
      h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error', text: true }, () => '删除'),
        default: () => '确定删除此分组？',
      }),
    ]),
  },
];

async function fetchData() {
  loading.value = true;
  try {
    const res: any = await requestClient.get('/asset/group/list');
    const items = res?.data ?? res;
    data.value = Array.isArray(items) ? items : (items?.items ?? []);
  } finally { loading.value = false; }
}

function resetForm() {
  Object.assign(form, { name: '', description: '', is_dynamic: false, rule_field: '', rule_op: '', rule_value: '' });
}

async function handleCreate() {
  if (!form.name) { message.warning('请输入分组名称'); return; }
  if (form.is_dynamic && (!form.rule_field || !form.rule_op || !form.rule_value)) {
    message.warning('动态分组必须填写完整规则');
    return;
  }
  saving.value = true;
  try {
    await requestClient.post('/asset/group', form);
    message.success('分组创建成功');
    showModal.value = false;
    resetForm();
    fetchData();
  } catch (e: any) {
    message.error(e?.message || '创建失败');
  } finally { saving.value = false; }
}

async function handleDelete(id: string) {
  try {
    await requestClient.delete(`/asset/group/${id}`);
    message.success('已删除');
    fetchData();
  } catch (e: any) {
    message.error(e?.msg || e?.message || '删除失败');
  }
}

async function onRefresh(id: string) {
  refreshingId.value = id;
  try {
    const res: any = await requestClient.post(`/asset/group/${id}/refresh`);
    const matched = res?.data?.matched ?? res?.matched ?? 0;
    message.success(`已匹配 ${matched} 个资产`);
    fetchData();
  } catch { message.error('刷新失败'); }
  finally { refreshingId.value = ''; }
}

onMounted(fetchData);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="资产分组" size="small">
      <template #header-extra>
        <NButton type="primary" size="small" @click="showModal = true">新建分组</NButton>
      </template>
      <NDataTable :columns="columns" :data="data" :loading="loading" :bordered="false" size="small" striped />
    </NCard>

    <NModal v-model:show="showModal" title="新建分组" preset="card" style="width: 520px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="名称"><NInput v-model:value="form.name" placeholder="分组名称" /></NFormItem>
        <NFormItem label="描述"><NInput v-model:value="form.description" type="textarea" :rows="2" placeholder="分组描述" /></NFormItem>
        <NFormItem label="动态分组"><NSwitch v-model:value="form.is_dynamic" /></NFormItem>
        <template v-if="form.is_dynamic">
          <NFormItem label="规则字段"><NSelect v-model:value="form.rule_field" :options="ruleFieldOptions" placeholder="选择字段" /></NFormItem>
          <NFormItem label="匹配方式"><NSelect v-model:value="form.rule_op" :options="ruleOpOptions" placeholder="选择方式" /></NFormItem>
          <NFormItem label="匹配值"><NInput v-model:value="form.rule_value" placeholder="输入匹配值" /></NFormItem>
        </template>
      </NForm>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showModal = false">取消</NButton>
          <NButton type="primary" :loading="saving" @click="handleCreate">确定</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
