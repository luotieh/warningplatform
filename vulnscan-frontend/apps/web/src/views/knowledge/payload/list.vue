<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h, onMounted, ref } from 'vue';

import {
  NButton,
  NCard,
  NDataTable,
  NDrawer,
  NDrawerContent,
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
  NSwitch,
  NInputGroup,
  useMessage,
} from 'naive-ui';

import { dialog } from '#/adapter/naive';

import {
  getPayloadList,
  getPatternList,
  getConfigList,
  getCategories,
  createPayload,
  updatePayload,
  deletePayload,
  createPattern,
  updatePattern,
  deletePattern,
  createConfig,
  updateConfig,
  deleteConfig,
  batchCreatePayloads,
  batchCreatePatterns,
  type VulnPayload,
  type VulnPayloadPattern,
  type VulnPayloadConfig,
} from '#/api/payload';

defineOptions({ name: 'PayloadManage' });

const message = useMessage();
const activeTab = ref('payloads');

const categoryOptions = ref<{ label: string; value: string }[]>([
  { label: 'SQL注入', value: 'sqli' },
  { label: 'XSS', value: 'xss' },
  { label: 'CRLF注入', value: 'crlf' },
  { label: '命令注入', value: 'cmdi' },
  { label: '路径遍历', value: 'lfi' },
  { label: 'SSRF', value: 'ssrf' },
  { label: 'SSTI', value: 'ssti' },
  { label: 'XXE', value: 'xxe' },
  { label: 'JWT安全', value: 'jwt' },
  { label: 'NoSQL注入', value: 'nosqli' },
]);

// ═══════════════════════════════════
// Payload Tab
// ═══════════════════════════════════
const payloadLoading = ref(false);
const payloadData = ref<VulnPayload[]>([]);
const payloadTotal = ref(0);
const payloadPage = ref(1);
const payloadPageSize = ref(20);
const payloadKeyword = ref('');
const payloadCategoryFilter = ref<string | null>(null);
const payloadTypeFilter = ref<string | null>(null);

const payloadColumns: DataTableColumns<VulnPayload> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '分类', key: 'category', width: 100, render: (row) => {
    const opt = categoryOptions.value.find(o => o.value === row.category);
    return h(NTag, { type: 'info', size: 'small' }, { default: () => opt?.label || row.category });
  }},
  { title: '名称', key: 'name', width: 150 },
  { title: 'Payload', key: 'value', ellipsis: { tooltip: true } },
  { title: '类型', key: 'type', width: 80 },
  { title: '数据库', key: 'databases', width: 100 },
  { title: '严重性', key: 'severity', width: 80, render: (row) => {
    const typeMap: Record<string, any> = { low: 'default', medium: 'warning', high: 'error', critical: 'error' };
    return h(NTag, { type: typeMap[row.severity] || 'default', size: 'small' }, { default: () => row.severity || '-' });
  }},
  { title: '启用', key: 'enabled', width: 60, render: (row) => {
    return h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, { default: () => row.enabled ? '是' : '否' });
  }},
  {
    title: '操作', key: 'actions', width: 150, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, {
      default: () => [
        h(NButton, { size: 'small', onClick: () => openPayloadEdit(row) }, { default: () => '编辑' }),
        h(NPopconfirm, { onPositiveClick: () => handleDeletePayload(row.id) }, {
          trigger: () => h(NButton, { size: 'small', type: 'error' }, { default: () => '删除' }),
          default: () => '确定删除此 Payload 吗？',
        }),
      ],
    }),
  },
];

const showPayloadModal = ref(false);
const payloadForm = ref<Partial<VulnPayload>>({});
const payloadFormMode = ref<'create' | 'edit'>('create');

async function loadPayloads() {
  payloadLoading.value = true;
  try {
    const params: Record<string, any> = {
      page: payloadPage.value,
      page_size: payloadPageSize.value,
    };
    if (payloadKeyword.value) params.keyword = payloadKeyword.value;
    if (payloadCategoryFilter.value) params.category = payloadCategoryFilter.value;
    if (payloadTypeFilter.value) params.type = payloadTypeFilter.value;
    const res = await getPayloadList(params);
    payloadData.value = res.items;
    payloadTotal.value = res.total;
  } catch (e: any) {
    message.error('加载 Payload 列表失败: ' + (e.message || e));
  } finally {
    payloadLoading.value = false;
  }
}

function openPayloadCreate() {
  payloadFormMode.value = 'create';
  payloadForm.value = { category: 'sqli', enabled: true, sort_order: 0 };
  showPayloadModal.value = true;
}

function openPayloadEdit(row: VulnPayload) {
  payloadFormMode.value = 'edit';
  payloadForm.value = { ...row };
  showPayloadModal.value = true;
}

async function handleSavePayload() {
  try {
    if (payloadFormMode.value === 'create') {
      await createPayload(payloadForm.value);
      message.success('创建成功');
    } else {
      await updatePayload(payloadForm.value.id!, payloadForm.value);
      message.success('更新成功');
    }
    showPayloadModal.value = false;
    loadPayloads();
  } catch (e: any) {
    message.error('保存失败: ' + (e.message || e));
  }
}

async function handleDeletePayload(id: number) {
  try {
    await deletePayload(id);
    message.success('删除成功');
    loadPayloads();
  } catch (e: any) {
    message.error('删除失败: ' + (e.message || e));
  }
}

const showBatchPayloadModal = ref(false);
const batchPayloadText = ref('');
const batchPayloadImporting = ref(false);

async function handleBatchImportPayloads() {
  batchPayloadImporting.value = true;
  try {
    const lines = batchPayloadText.value.trim().split('\n').filter(l => l.trim());
    const payloads = lines.map(line => {
      try {
        const obj = JSON.parse(line);
        return { ...obj, enabled: obj.enabled !== false };
      } catch {
        return { name: line.substring(0, 50), value: line, category: payloadCategoryFilter.value || 'sqli', enabled: true };
      }
    });
    await batchCreatePayloads(payloads);
    message.success(`成功导入 ${payloads.length} 条 Payload`);
    showBatchPayloadModal.value = false;
    batchPayloadText.value = '';
    loadPayloads();
  } catch (e: any) {
    message.error('批量导入失败: ' + (e.message || e));
  } finally {
    batchPayloadImporting.value = false;
  }
}

// ═══════════════════════════════════
// Pattern Tab
// ═══════════════════════════════════
const patternLoading = ref(false);
const patternData = ref<VulnPayloadPattern[]>([]);
const patternTotal = ref(0);
const patternPage = ref(1);
const patternPageSize = ref(20);
const patternKeyword = ref('');
const patternCategoryFilter = ref<string | null>(null);

const patternColumns: DataTableColumns<VulnPayloadPattern> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '分类', key: 'category', width: 100, render: (row) => {
    const opt = categoryOptions.value.find(o => o.value === row.category);
    return h(NTag, { type: 'info', size: 'small' }, { default: () => opt?.label || row.category });
  }},
  { title: '名称', key: 'name', width: 150 },
  { title: '正则模式', key: 'pattern', ellipsis: { tooltip: true } },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  { title: '严重性', key: 'severity', width: 80, render: (row) => {
    const typeMap: Record<string, any> = { low: 'default', medium: 'warning', high: 'error', critical: 'error' };
    return h(NTag, { type: typeMap[row.severity] || 'default', size: 'small' }, { default: () => row.severity || '-' });
  }},
  { title: '启用', key: 'enabled', width: 60, render: (row) => {
    return h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, { default: () => row.enabled ? '是' : '否' });
  }},
  {
    title: '操作', key: 'actions', width: 150, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, {
      default: () => [
        h(NButton, { size: 'small', onClick: () => openPatternEdit(row) }, { default: () => '编辑' }),
        h(NPopconfirm, { onPositiveClick: () => handleDeletePattern(row.id) }, {
          trigger: () => h(NButton, { size: 'small', type: 'error' }, { default: () => '删除' }),
          default: () => '确定删除此 Pattern 吗？',
        }),
      ],
    }),
  },
];

const showPatternModal = ref(false);
const patternForm = ref<Partial<VulnPayloadPattern>>({});
const patternFormMode = ref<'create' | 'edit'>('create');

async function loadPatterns() {
  patternLoading.value = true;
  try {
    const params: Record<string, any> = {
      page: patternPage.value,
      page_size: patternPageSize.value,
    };
    if (patternKeyword.value) params.keyword = patternKeyword.value;
    if (patternCategoryFilter.value) params.category = patternCategoryFilter.value;
    const res = await getPatternList(params);
    patternData.value = res.items;
    patternTotal.value = res.total;
  } catch (e: any) {
    message.error('加载 Pattern 列表失败: ' + (e.message || e));
  } finally {
    patternLoading.value = false;
  }
}

function openPatternCreate() {
  patternFormMode.value = 'create';
  patternForm.value = { category: 'sqli_error', enabled: true };
  showPatternModal.value = true;
}

function openPatternEdit(row: VulnPayloadPattern) {
  patternFormMode.value = 'edit';
  patternForm.value = { ...row };
  showPatternModal.value = true;
}

async function handleSavePattern() {
  try {
    if (patternFormMode.value === 'create') {
      await createPattern(patternForm.value);
      message.success('创建成功');
    } else {
      await updatePattern(patternForm.value.id!, patternForm.value);
      message.success('更新成功');
    }
    showPatternModal.value = false;
    loadPatterns();
  } catch (e: any) {
    message.error('保存失败: ' + (e.message || e));
  }
}

async function handleDeletePattern(id: number) {
  try {
    await deletePattern(id);
    message.success('删除成功');
    loadPatterns();
  } catch (e: any) {
    message.error('删除失败: ' + (e.message || e));
  }
}

const showBatchPatternModal = ref(false);
const batchPatternText = ref('');
const batchPatternImporting = ref(false);

async function handleBatchImportPatterns() {
  batchPatternImporting.value = true;
  try {
    const lines = batchPatternText.value.trim().split('\n').filter(l => l.trim());
    const patterns = lines.map(line => {
      try {
        const obj = JSON.parse(line);
        return { ...obj, enabled: obj.enabled !== false };
      } catch {
        return { name: 'custom_pattern', pattern: line, category: patternCategoryFilter.value || 'sqli_error', enabled: true, description: '批量导入' };
      }
    });
    await batchCreatePatterns(patterns);
    message.success(`成功导入 ${patterns.length} 条 Pattern`);
    showBatchPatternModal.value = false;
    batchPatternText.value = '';
    loadPatterns();
  } catch (e: any) {
    message.error('批量导入失败: ' + (e.message || e));
  } finally {
    batchPatternImporting.value = false;
  }
}

// ═══════════════════════════════════
// Config Tab
// ═══════════════════════════════════
const configLoading = ref(false);
const configData = ref<VulnPayloadConfig[]>([]);
const configCategoryFilter = ref<string | null>(null);

const configColumns: DataTableColumns<VulnPayloadConfig> = [
  { title: 'ID', key: 'id', width: 60 },
  { title: '分类', key: 'category', width: 100, render: (row) => {
    const opt = categoryOptions.value.find(o => o.value === row.category);
    return h(NTag, { type: 'info', size: 'small' }, { default: () => opt?.label || row.category });
  }},
  { title: '配置键', key: 'config_key', width: 150 },
  { title: '配置值', key: 'config_val', ellipsis: { tooltip: true } },
  { title: '启用', key: 'enabled', width: 60, render: (row) => {
    return h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, { default: () => row.enabled ? '是' : '否' });
  }},
  {
    title: '操作', key: 'actions', width: 150, fixed: 'right',
    render: (row) => h(NSpace, { size: 'small' }, {
      default: () => [
        h(NButton, { size: 'small', onClick: () => openConfigEdit(row) }, { default: () => '编辑' }),
        h(NPopconfirm, { onPositiveClick: () => handleDeleteConfig(row.id) }, {
          trigger: () => h(NButton, { size: 'small', type: 'error' }, { default: () => '删除' }),
          default: () => '确定删除此 Config 吗？',
        }),
      ],
    }),
  },
];

const showConfigModal = ref(false);
const configForm = ref<Partial<VulnPayloadConfig>>({});
const configFormMode = ref<'create' | 'edit'>('create');

async function loadConfigs() {
  configLoading.value = true;
  try {
    const params: Record<string, any> = {};
    if (configCategoryFilter.value) params.category = configCategoryFilter.value;
    configData.value = await getConfigList(params);
  } catch (e: any) {
    message.error('加载 Config 列表失败: ' + (e.message || e));
  } finally {
    configLoading.value = false;
  }
}

function openConfigCreate() {
  configFormMode.value = 'create';
  configForm.value = { category: 'sqli_boolean', enabled: true };
  showConfigModal.value = true;
}

function openConfigEdit(row: VulnPayloadConfig) {
  configFormMode.value = 'edit';
  configForm.value = { ...row };
  showConfigModal.value = true;
}

async function handleSaveConfig() {
  try {
    if (configFormMode.value === 'create') {
      await createConfig(configForm.value);
      message.success('创建成功');
    } else {
      await updateConfig(configForm.value.id!, configForm.value);
      message.success('更新成功');
    }
    showConfigModal.value = false;
    loadConfigs();
  } catch (e: any) {
    message.error('保存失败: ' + (e.message || e));
  }
}

async function handleDeleteConfig(id: number) {
  try {
    await deleteConfig(id);
    message.success('删除成功');
    loadConfigs();
  } catch (e: any) {
    message.error('删除失败: ' + (e.message || e));
  }
}

onMounted(() => {
  loadPayloads();
  loadPatterns();
  loadConfigs();
});
</script>

<template>
  <div class="p-4">
    <NTabs v-model:value="activeTab" type="line" animated>
      <NTabPane name="payloads" tab="Payload 管理">
        <NCard :bordered="false">
          <template #header>
            <NSpace justify="space-between" align="center">
              <span>漏洞扫描 Payload 管理</span>
              <NSpace>
                <NButton size="small" @click="showBatchPayloadModal = true">批量导入</NButton>
                <NButton type="primary" size="small" @click="openPayloadCreate">新建 Payload</NButton>
              </NSpace>
            </NSpace>
          </template>

          <NSpace class="mb-4">
            <NInput v-model:value="payloadKeyword" placeholder="搜索名称/值/描述" clearable style="width: 200px" @update:value="loadPayloads" />
            <NSelect v-model:value="payloadCategoryFilter" :options="categoryOptions" placeholder="全部分类" clearable style="width: 150px" @update:value="loadPayloads" />
            <NSelect v-model:value="payloadTypeFilter" :options="[
              { label: 'error', value: 'error' },
              { label: 'boolean', value: 'boolean' },
              { label: 'time', value: 'time' },
              { label: 'union', value: 'union' },
            ]" placeholder="全部类型" clearable style="width: 120px" @update:value="loadPayloads" />
          </NSpace>

          <NDataTable
            :columns="payloadColumns"
            :data="payloadData"
            :loading="payloadLoading"
            :pagination="{
              page: payloadPage,
              pageSize: payloadPageSize,
              itemCount: payloadTotal,
              showSizePicker: true,
              pageSizes: [10, 20, 50, 100],
              onUpdatePage: (p) => { payloadPage = p; loadPayloads(); },
              onUpdatePageSize: (s) => { payloadPageSize = s; payloadPage = 1; loadPayloads(); },
            }"
            :bordered="false"
            size="small"
          />
        </NCard>
      </NTabPane>

      <NTabPane name="patterns" tab="检测模式管理">
        <NCard :bordered="false">
          <template #header>
            <NSpace justify="space-between" align="center">
              <span>漏洞检测 Pattern 管理</span>
              <NSpace>
                <NButton size="small" @click="showBatchPatternModal = true">批量导入</NButton>
                <NButton type="primary" size="small" @click="openPatternCreate">新建 Pattern</NButton>
              </NSpace>
            </NSpace>
          </template>

          <NSpace class="mb-4">
            <NInput v-model:value="patternKeyword" placeholder="搜索名称/模式/描述" clearable style="width: 200px" @update:value="loadPatterns" />
            <NSelect v-model:value="patternCategoryFilter" :options="categoryOptions" placeholder="全部分类" clearable style="width: 150px" @update:value="loadPatterns" />
          </NSpace>

          <NDataTable
            :columns="patternColumns"
            :data="patternData"
            :loading="patternLoading"
            :pagination="{
              page: patternPage,
              pageSize: patternPageSize,
              itemCount: patternTotal,
              showSizePicker: true,
              pageSizes: [10, 20, 50, 100],
              onUpdatePage: (p) => { patternPage = p; loadPatterns(); },
              onUpdatePageSize: (s) => { patternPageSize = s; patternPage = 1; loadPatterns(); },
            }"
            :bordered="false"
            size="small"
          />
        </NCard>
      </NTabPane>

      <NTabPane name="configs" tab="扫描配置管理">
        <NCard :bordered="false">
          <template #header>
            <NSpace justify="space-between" align="center">
              <span>漏洞扫描配置管理</span>
              <NButton type="primary" size="small" @click="openConfigCreate">新建配置</NButton>
            </NSpace>
          </template>

          <NSpace class="mb-4">
            <NSelect v-model:value="configCategoryFilter" :options="categoryOptions" placeholder="全部分类" clearable style="width: 150px" @update:value="loadConfigs" />
          </NSpace>

          <NDataTable
            :columns="configColumns"
            :data="configData"
            :loading="configLoading"
            :bordered="false"
            size="small"
          />
        </NCard>
      </NTabPane>
    </NTabs>

    <!-- Payload Edit Modal -->
    <NModal v-model:show="showPayloadModal" preset="dialog" :title="payloadFormMode === 'create' ? '新建 Payload' : '编辑 Payload'" style="max-width: 600px">
      <NForm :model="payloadForm" label-placement="left" label-width="80">
        <NFormItem label="分类">
          <NSelect v-model:value="payloadForm.category" :options="categoryOptions" />
        </NFormItem>
        <NFormItem label="名称">
          <NInput v-model:value="payloadForm.name" />
        </NFormItem>
        <NFormItem label="Payload值">
          <NInput v-model:value="payloadForm.value" type="textarea" :autosize="{ minRows: 2, maxRows: 4 }" />
        </NFormItem>
        <NFormItem label="类型">
          <NInput v-model:value="payloadForm.type" placeholder="error/boolean/time/union" />
        </NFormItem>
        <NFormItem label="数据库">
          <NInput v-model:value="payloadForm.databases" placeholder="all,mysql,oracle,mssql,postgresql" />
        </NFormItem>
        <NFormItem label="期望响应">
          <NInput v-model:value="payloadForm.expect" type="textarea" />
        </NFormItem>
        <NFormItem label="上下文">
          <NInput v-model:value="payloadForm.context" placeholder="param,header,cookie,body" />
        </NFormItem>
        <NFormItem label="标签">
          <NInput v-model:value="payloadForm.tags" placeholder="逗号分隔" />
        </NFormItem>
        <NFormItem label="严重性">
          <NSelect v-model:value="payloadForm.severity" :options="[
            { label: 'low', value: 'low' },
            { label: 'medium', value: 'medium' },
            { label: 'high', value: 'high' },
            { label: 'critical', value: 'critical' },
          ]" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="payloadForm.description" type="textarea" />
        </NFormItem>
        <NFormItem label="排序">
          <NInput v-model:value="payloadForm.sort_order" type="number" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="payloadForm.enabled" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showPayloadModal = false">取消</NButton>
          <NButton type="primary" @click="handleSavePayload">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Pattern Edit Modal -->
    <NModal v-model:show="showPatternModal" preset="dialog" :title="patternFormMode === 'create' ? '新建 Pattern' : '编辑 Pattern'" style="max-width: 600px">
      <NForm :model="patternForm" label-placement="left" label-width="80">
        <NFormItem label="分类">
          <NSelect v-model:value="patternForm.category" :options="categoryOptions" />
        </NFormItem>
        <NFormItem label="名称">
          <NInput v-model:value="patternForm.name" />
        </NFormItem>
        <NFormItem label="正则模式">
          <NInput v-model:value="patternForm.pattern" type="textarea" :autosize="{ minRows: 3, maxRows: 6 }" />
        </NFormItem>
        <NFormItem label="描述">
          <NInput v-model:value="patternForm.description" type="textarea" />
        </NFormItem>
        <NFormItem label="严重性">
          <NSelect v-model:value="patternForm.severity" :options="[
            { label: 'low', value: 'low' },
            { label: 'medium', value: 'medium' },
            { label: 'high', value: 'high' },
            { label: 'critical', value: 'critical' },
          ]" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="patternForm.enabled" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showPatternModal = false">取消</NButton>
          <NButton type="primary" @click="handleSavePattern">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Config Edit Modal -->
    <NModal v-model:show="showConfigModal" preset="dialog" :title="configFormMode === 'create' ? '新建配置' : '编辑配置'" style="max-width: 500px">
      <NForm :model="configForm" label-placement="left" label-width="80">
        <NFormItem label="分类">
          <NSelect v-model:value="configForm.category" :options="categoryOptions" />
        </NFormItem>
        <NFormItem label="配置键">
          <NInput v-model:value="configForm.config_key" />
        </NFormItem>
        <NFormItem label="配置值">
          <NInput v-model:value="configForm.config_val" type="textarea" />
        </NFormItem>
        <NFormItem label="启用">
          <NSwitch v-model:value="configForm.enabled" />
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showConfigModal = false">取消</NButton>
          <NButton type="primary" @click="handleSaveConfig">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Batch Import Payload Modal -->
    <NModal v-model:show="showBatchPayloadModal" preset="dialog" title="批量导入 Payload" style="max-width: 700px">
      <div>
        <NText depth="3" class="mb-2 block">每行一个 Payload，支持 JSON 格式或纯文本（纯文本将自动创建为简单 Payload）</NText>
        <NInput v-model:value="batchPayloadText" type="textarea" :autosize="{ minRows: 10, maxRows: 20 }" placeholder='{"name":"test","value":"1 OR 1=1","category":"sqli","type":"boolean"}' />
      </div>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showBatchPayloadModal = false">取消</NButton>
          <NButton type="primary" :loading="batchPayloadImporting" @click="handleBatchImportPayloads">导入</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Batch Import Pattern Modal -->
    <NModal v-model:show="showBatchPatternModal" preset="dialog" title="批量导入 Pattern" style="max-width: 700px">
      <div>
        <NText depth="3" class="mb-2 block">每行一个 Pattern，支持 JSON 格式或纯正则表达式</NText>
        <NInput v-model:value="batchPatternText" type="textarea" :autosize="{ minRows: 10, maxRows: 20 }" placeholder='{"name":"mysql_error","pattern":"(?i)MySQL.*error","category":"sqli_error","severity":"high"}' />
      </div>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showBatchPatternModal = false">取消</NButton>
          <NButton type="primary" :loading="batchPatternImporting" @click="handleBatchImportPatterns">导入</NButton>
        </NSpace>
      </template>
    </NModal>
  </div>
</template>
