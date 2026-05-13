<script setup lang="ts">
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NModal, NForm,
  NInput, NSelect, NSwitch, NPopconfirm, NGrid,
  NFormItemGi, useMessage, NDynamicTags, NDrawer, NDrawerContent,
  NDescriptions, NDescriptionsItem, NEmpty,
  NDivider, NTimeline, NTimelineItem,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getTemplateList, createTemplate, updateTemplate,
  deleteTemplate, toggleTemplate,
  type ScanTemplate, type TemplateStage, type TemplateParam,
} from '#/api/template';

const message = useMessage();
const loading = ref(false);
const data = ref<ScanTemplate[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const keyword = ref('');
const category = ref('');

const categoryOptions = [
  { label: '全部', value: '' },
  { label: '内置', value: 'builtin' },
  { label: '自定义', value: 'custom' },
  { label: 'Web', value: 'web' },
  { label: '主机', value: 'host' },
  { label: '应急', value: 'emergency' },
];

async function fetchData() {
  loading.value = true;
  try {
    const params: Record<string, any> = { page: page.value, page_size: pageSize.value };
    if (keyword.value) params.keyword = keyword.value;
    if (category.value) params.category = category.value;
    const res = await getTemplateList(params);
    data.value = res.items;
    total.value = res.total;
  } finally {
    loading.value = false;
  }
}

onMounted(fetchData);

const moduleLabels: Record<string, string> = {
  port_scan: '端口扫描', service_probe: '服务识别', web_fingerprint: 'Web指纹',
  dir_scan: '目录扫描', info_leak: '信息泄露', sqli: 'SQL注入',
  xss: 'XSS检测', cert_check: '证书检测', weak_pass: '弱口令',
  subdomain: '子域名', dns_all: 'DNS枚举', webcrawl: '爬虫',
  bruteforce: '密码爆破', nuclei: 'Nuclei POC',
};

const columns = computed<DataTableColumns<ScanTemplate>>(() => [
  {
    title: '名称', key: 'name', width: 200,
    render: (row) => h('a', {
      style: 'cursor:pointer;color:var(--primary-color)',
      onClick: () => openDetail(row),
    }, row.name),
  },
  {
    title: '分类', key: 'category', width: 100,
    render: (row) => h(NTag, { size: 'small', bordered: false }, () => row.category || '-'),
  },
  {
    title: '标签', key: 'tags', width: 200,
    render: (row) => h(NSpace, { size: 4 }, () =>
      (row.tags ?? []).map((t: string) => h(NTag, { size: 'tiny', type: 'info', bordered: false }, () => t)),
    ),
  },
  {
    title: '阶段', key: 'stages', width: 80,
    render: (row) => (row.stages?.length ?? 0).toString(),
  },
  {
    title: '内置', key: 'builtin', width: 70,
    render: (row) => h(NTag, { type: row.builtin ? 'primary' : 'default', size: 'small' }, () => row.builtin ? '是' : '否'),
  },
  {
    title: '状态', key: 'enabled', width: 80,
    render: (row) => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '启用' : '停用'),
  },
  { title: '版本', key: 'version', width: 80 },
  { title: '使用次数', key: 'usage_count', width: 80 },
  {
    title: '操作', key: 'actions', width: 220, fixed: 'right',
    render: (row) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'tiny', quaternary: true, onClick: () => openEditor(row) }, () => '编辑'),
      h(NButton, {
        size: 'tiny', quaternary: true,
        type: row.enabled ? 'warning' : 'success',
        onClick: () => handleToggle(row),
      }, () => row.enabled ? '停用' : '启用'),
      h(NButton, { size: 'tiny', quaternary: true, type: 'primary', onClick: () => handleClone(row) }, () => '克隆'),
      row.builtin
        ? null
        : h(NPopconfirm, { onPositiveClick: () => handleDelete(row.id) }, {
            trigger: () => h(NButton, { size: 'tiny', quaternary: true, type: 'error' }, () => '删除'),
            default: () => '确定删除该模板？',
          }),
    ]),
  },
]);

async function handleToggle(row: ScanTemplate) {
  await toggleTemplate(row.id, !row.enabled);
  message.success(row.enabled ? '已停用' : '已启用');
  fetchData();
}

async function handleDelete(id: string) {
  await deleteTemplate(id);
  message.success('已删除');
  fetchData();
}

function handleClone(row: ScanTemplate) {
  openEditor(undefined, row);
}

// ---- Editor Modal ----
const editorVisible = ref(false);
const editingId = ref('');
const form = ref<Record<string, any>>({
  name: '', code: '', category: 'custom', description: '', icon: '',
  tags: [] as string[], params: [] as TemplateParam[], stages: [] as TemplateStage[],
});

function openEditor(row?: ScanTemplate, cloneFrom?: ScanTemplate) {
  const src = row ?? cloneFrom;
  if (src) {
    editingId.value = row ? row.id : '';
    form.value = {
      name: cloneFrom ? `${src.name} (副本)` : src.name,
      code: cloneFrom ? '' : src.code,
      category: src.category,
      description: src.description,
      icon: src.icon,
      tags: [...(src.tags ?? [])],
      params: JSON.parse(JSON.stringify(src.params ?? [])),
      stages: JSON.parse(JSON.stringify(src.stages ?? [])),
    };
  } else {
    editingId.value = '';
    form.value = {
      name: '', code: '', category: 'custom', description: '', icon: '',
      tags: [], params: [], stages: [],
    };
  }
  editorVisible.value = true;
}

function addStage() {
  form.value.stages.push({ name: '', module: '', parallel: false, config: {} });
}

function removeStage(idx: number) {
  form.value.stages.splice(idx, 1);
}

function addParam() {
  form.value.params.push({ name: '', type: 'string', default: '', required: false, description: '' });
}

function removeParam(idx: number) {
  form.value.params.splice(idx, 1);
}

async function handleSave() {
  if (!form.value.name) { message.warning('请输入名称'); return; }

  const payload = { ...form.value };
  if (editingId.value) {
    await updateTemplate(editingId.value, payload);
    message.success('已更新');
  } else {
    await createTemplate(payload);
    message.success('已创建');
  }
  editorVisible.value = false;
  fetchData();
}

// ---- Detail Drawer ----
const detailVisible = ref(false);
const detailItem = ref<ScanTemplate | null>(null);

function openDetail(row: ScanTemplate) {
  detailItem.value = row;
  detailVisible.value = true;
}
</script>

<template>
  <div class="p-4">
    <NCard title="扫描模板" size="small">
      <template #header-extra>
        <NSpace :size="8">
          <NSelect v-model:value="category" size="small" :options="categoryOptions" style="width:120px" @update:value="fetchData" />
          <NInput v-model:value="keyword" size="small" placeholder="搜索模板" clearable style="width:180px" @keyup.enter="fetchData" />
          <NButton size="small" @click="fetchData">搜索</NButton>
          <NButton size="small" type="primary" @click="openEditor()">新建模板</NButton>
        </NSpace>
      </template>
      <NDataTable
        :columns="columns" :data="data" :loading="loading" size="small"
        :scroll-x="1200" :pagination="{
          page, pageSize, itemCount: total, showSizePicker: true,
          pageSizes: [10, 20, 50],
          onUpdatePage: (p: number) => { page = p; fetchData(); },
          onUpdatePageSize: (s: number) => { pageSize = s; page = 1; fetchData(); },
        }"
      />
    </NCard>

    <!-- Editor Modal -->
    <NModal v-model:show="editorVisible" preset="card" :title="editingId ? '编辑模板' : '新建模板'" style="width:780px;max-height:85vh;overflow:auto">
      <NForm :model="form" label-placement="left" label-width="80">
        <NGrid :cols="2" :x-gap="16">
          <NFormItemGi label="名称" span="2">
            <NInput v-model:value="form.name" placeholder="模板名称" />
          </NFormItemGi>
          <NFormItemGi label="编码">
            <NInput v-model:value="form.code" placeholder="唯一编码 (如 web-full)" />
          </NFormItemGi>
          <NFormItemGi label="分类">
            <NSelect v-model:value="form.category" :options="categoryOptions.filter(o => o.value)" />
          </NFormItemGi>
          <NFormItemGi label="描述" span="2">
            <NInput v-model:value="form.description" type="textarea" :rows="2" />
          </NFormItemGi>
          <NFormItemGi label="标签" span="2">
            <NDynamicTags v-model:value="form.tags" />
          </NFormItemGi>
        </NGrid>

        <NDivider>扫描参数 ({{ form.params.length }})</NDivider>
        <div v-for="(p, idx) in form.params" :key="idx" class="mb-3 p-3" style="border:1px solid var(--border-color);border-radius:6px">
          <NGrid :cols="3" :x-gap="12">
            <NFormItemGi label="名称" :show-feedback="false">
              <NInput v-model:value="p.name" size="small" placeholder="参数名" />
            </NFormItemGi>
            <NFormItemGi label="类型" :show-feedback="false">
              <NSelect v-model:value="p.type" size="small" :options="[{ label: 'string', value: 'string' }, { label: 'int', value: 'int' }, { label: 'bool', value: 'bool' }]" />
            </NFormItemGi>
            <NFormItemGi label="默认值" :show-feedback="false">
              <NInput v-model:value="p.default" size="small" placeholder="默认值" />
            </NFormItemGi>
          </NGrid>
          <NGrid :cols="2" :x-gap="12" class="mt-2">
            <NFormItemGi label="描述" :show-feedback="false">
              <NInput v-model:value="p.description" size="small" />
            </NFormItemGi>
            <NFormItemGi :show-feedback="false">
              <NSpace>
                <NSwitch v-model:value="p.required" size="small" /> <span style="font-size:12px">必填</span>
                <NButton size="tiny" type="error" quaternary @click="removeParam(idx as number)">移除</NButton>
              </NSpace>
            </NFormItemGi>
          </NGrid>
        </div>
        <NButton size="small" dashed block @click="addParam">+ 添加参数</NButton>

        <NDivider>扫描阶段 ({{ form.stages.length }})</NDivider>
        <div v-for="(s, idx) in form.stages" :key="idx" class="mb-3 p-3" style="border:1px solid var(--border-color);border-radius:6px">
          <NGrid :cols="3" :x-gap="12">
            <NFormItemGi label="名称" :show-feedback="false">
              <NInput v-model:value="s.name" size="small" placeholder="阶段名" />
            </NFormItemGi>
            <NFormItemGi label="模块" :show-feedback="false">
              <NInput v-model:value="s.module" size="small" placeholder="模块ID (如 port_scan)" />
            </NFormItemGi>
            <NFormItemGi :show-feedback="false">
              <NSpace>
                <NSwitch v-model:value="s.parallel" size="small" /> <span style="font-size:12px">并行</span>
                <NButton size="tiny" type="error" quaternary @click="removeStage(idx as number)">移除</NButton>
              </NSpace>
            </NFormItemGi>
          </NGrid>
        </div>
        <NButton size="small" dashed block @click="addStage">+ 添加阶段</NButton>
      </NForm>
      <template #footer>
        <NSpace justify="end">
          <NButton @click="editorVisible = false">取消</NButton>
          <NButton type="primary" @click="handleSave">保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- Detail Drawer -->
    <NDrawer v-model:show="detailVisible" width="560">
      <NDrawerContent v-if="detailItem" :title="detailItem.name">
        <NDescriptions label-placement="left" :column="1" bordered size="small">
          <NDescriptionsItem label="编码">{{ detailItem.code || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="分类">{{ detailItem.category || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="描述">{{ detailItem.description || '-' }}</NDescriptionsItem>
          <NDescriptionsItem label="版本">{{ detailItem.version }}</NDescriptionsItem>
          <NDescriptionsItem label="内置">{{ detailItem.builtin ? '是' : '否' }}</NDescriptionsItem>
          <NDescriptionsItem label="使用次数">{{ detailItem.usage_count }}</NDescriptionsItem>
          <NDescriptionsItem label="标签">
            <NSpace :size="4">
              <NTag v-for="t in detailItem.tags" :key="t" size="small" type="info">{{ t }}</NTag>
            </NSpace>
          </NDescriptionsItem>
        </NDescriptions>

        <NDivider>参数定义 ({{ detailItem.params?.length ?? 0 }})</NDivider>
        <div v-if="detailItem.params?.length">
          <div v-for="p in detailItem.params" :key="p.name" class="mb-2 p-2" style="background:var(--card-color);border-radius:4px">
            <div style="font-weight:600">{{ p.name }} <NTag size="tiny" :bordered="false">{{ p.type }}</NTag></div>
            <div style="font-size:12px;color:var(--text-color-3)">{{ p.description }} | 默认: {{ p.default ?? '-' }} {{ p.required ? '(必填)' : '' }}</div>
          </div>
        </div>
        <NEmpty v-else description="无参数" />

        <NDivider>扫描阶段 ({{ detailItem.stages?.length ?? 0 }})</NDivider>
        <NTimeline v-if="detailItem.stages?.length">
          <NTimelineItem
            v-for="(s, idx) in detailItem.stages"
            :key="idx"
            :title="`${idx + 1}. ${s.name}`"
            :type="s.parallel ? 'info' : 'success'"
          >
            <div style="font-size:12px">
              模块: <NTag size="tiny" :bordered="false">{{ moduleLabels[s.module] || s.module }}</NTag>
              <span v-if="s.parallel" style="margin-left:8px;color:var(--info-color)">并行</span>
            </div>
          </NTimelineItem>
        </NTimeline>
        <NEmpty v-else description="无阶段定义" />
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
