<script setup lang="ts">
import { ref, computed, h, onMounted } from 'vue';
import {
  NCard, NDataTable, NButton, NSpace, NTag, NPopconfirm,
  NInput, NSelect, NSwitch, NDrawer, NDrawerContent,
  NForm, NGrid, NFormItemGi, NDynamicTags, NDivider,
  NCollapse, NCollapseItem, NTooltip, NEmpty,
  NDescriptions, NDescriptionsItem, NTimeline, NTimelineItem,
  useMessage,
} from 'naive-ui';
import type { DataTableColumns } from 'naive-ui';
import {
  getTemplateList, createTemplate, updateTemplate,
  deleteTemplate, toggleTemplate,
  type ScanTemplate, type TemplateStage, type TemplateParam,
} from '#/api/template';
import { getPipelineModules, type ModuleInfo } from '#/api/pipeline';

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

const allModules = ref<ModuleInfo[]>([]);

const categoryLabels: Record<string, string> = {
  discover: '发现', host: '主机', probe: '探测', recon: '侦察', vuln: '漏洞',
};

const modulesByCategory = computed(() => {
  const map = new Map<string, ModuleInfo[]>();
  for (const m of allModules.value) {
    const cat = m.category || 'other';
    if (!map.has(cat)) map.set(cat, []);
    map.get(cat)!.push(m);
  }
  return map;
});

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

async function loadModules() {
  try {
    allModules.value = await getPipelineModules();
  } catch {}
}

onMounted(() => { fetchData(); loadModules(); });

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

// ---- Visual Editor ----
const editorVisible = ref(false);
const editingId = ref('');
const activeStageIdx = ref(0);
const form = ref<{
  name: string; code: string; category: string; description: string;
  tags: string[]; params: TemplateParam[]; stages: TemplateStage[];
}>({
  name: '', code: '', category: 'custom', description: '',
  tags: [], params: [], stages: [],
});

function getStageModules(stage: TemplateStage): string[] {
  if (stage.modules && stage.modules.length > 0) return stage.modules;
  if (stage.module) return [stage.module];
  return [];
}

function setStageModules(stage: TemplateStage, ids: string[]) {
  stage.modules = ids;
  stage.module = undefined;
}

function openEditor(row?: ScanTemplate, cloneFrom?: ScanTemplate) {
  const src = row ?? cloneFrom;
  if (src) {
    editingId.value = row ? row.id : '';
    form.value = {
      name: cloneFrom ? `${src.name} (副本)` : src.name,
      code: cloneFrom ? '' : (src.code || ''),
      category: src.category || 'custom',
      description: src.description || '',
      tags: [...(src.tags ?? [])],
      params: JSON.parse(JSON.stringify(src.params ?? [])),
      stages: JSON.parse(JSON.stringify(src.stages ?? [])),
    };
  } else {
    editingId.value = '';
    form.value = {
      name: '', code: '', category: 'custom', description: '',
      tags: [], params: [], stages: [],
    };
  }
  editorVisible.value = true;
}

function addStage() {
  form.value.stages.push({ name: `stage-${form.value.stages.length + 1}`, modules: [], parallel: false });
}

function removeStage(idx: number) {
  form.value.stages.splice(idx, 1);
}

function moveStage(idx: number, dir: 'up' | 'down') {
  const newIdx = dir === 'up' ? idx - 1 : idx + 1;
  if (newIdx < 0 || newIdx >= form.value.stages.length) return;
  const temp = form.value.stages[idx]!;
  form.value.stages[idx] = form.value.stages[newIdx]!;
  form.value.stages[newIdx] = temp;
}

function addModuleToStage(stageIdx: number, mod: ModuleInfo) {
  const stage = form.value.stages[stageIdx];
  if (!stage) return;
  const ids = getStageModules(stage);
  if (ids.includes(mod.id)) {
    message.warning(`模块 "${mod.name}" 已在此阶段中`);
    return;
  }
  setStageModules(stage, [...ids, mod.id]);
}

function removeModuleFromStage(stageIdx: number, modId: string) {
  const stage = form.value.stages[stageIdx];
  if (!stage) return;
  setStageModules(stage, getStageModules(stage).filter(id => id !== modId));
}

function addModuleToActiveStage(mod: ModuleInfo) {
  if (form.value.stages.length === 0) {
    addStage();
    activeStageIdx.value = 0;
  }
  addModuleToStage(activeStageIdx.value, mod);
}

function addParam() {
  form.value.params.push({ name: '', type: 'string', default: '', required: false, description: '' });
}

function removeParam(idx: number) {
  form.value.params.splice(idx, 1);
}

async function handleSave() {
  if (!form.value.name) { message.warning('请输入名称'); return; }
  if (form.value.stages.length === 0) { message.warning('请至少添加一个阶段'); return; }

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

function getModuleName(id: string): string {
  const m = allModules.value.find(mod => mod.id === id);
  return m ? m.name : id;
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

    <!-- Visual Editor Drawer -->
    <NDrawer v-model:show="editorVisible" :width="960" placement="right">
      <NDrawerContent :title="editingId ? '编辑模板' : '新建模板'" :native-scrollbar="false">
        <NForm :model="form" label-placement="left" label-width="70">
          <NGrid :cols="2" :x-gap="16">
            <NFormItemGi label="名称" span="1">
              <NInput v-model:value="form.name" placeholder="模板名称" />
            </NFormItemGi>
            <NFormItemGi label="编码" span="1">
              <NInput v-model:value="form.code" placeholder="唯一编码 (如 web-full)" />
            </NFormItemGi>
            <NFormItemGi label="分类" span="1">
              <NSelect v-model:value="form.category" :options="categoryOptions.filter(o => o.value)" />
            </NFormItemGi>
            <NFormItemGi label="标签" span="1">
              <NDynamicTags v-model:value="form.tags" />
            </NFormItemGi>
            <NFormItemGi label="描述" span="2">
              <NInput v-model:value="form.description" type="textarea" :rows="2" />
            </NFormItemGi>
          </NGrid>
        </NForm>

        <NDivider>扫描阶段 ({{ form.stages.length }})</NDivider>

        <div style="display:flex;gap:16px;min-height:300px">
          <!-- Module Panel -->
          <div style="width:220px;flex-shrink:0;border:1px solid var(--border-color);border-radius:8px;padding:8px;overflow-y:auto;max-height:500px">
            <div style="font-size:12px;color:var(--text-color-3);margin-bottom:8px">可用模块（点击添加到选中阶段）</div>
            <NCollapse :default-expanded-names="['discover','vuln']">
              <NCollapseItem
                v-for="[cat, mods] in modulesByCategory"
                :key="cat"
                :title="`${categoryLabels[cat] || cat} (${mods.length})`"
                :name="cat"
              >
                <div style="display:flex;flex-direction:column;gap:3px">
                  <NTooltip v-for="mod in mods" :key="mod.id" trigger="hover" placement="right">
                    <template #trigger>
                      <div
                        :style="{
                          padding:'4px 8px', borderRadius:'4px', fontSize:'12px', cursor:'pointer',
                          border: '1px solid var(--border-color)',
                          background: '#fafafa',
                        }"
                        @click="addModuleToActiveStage(mod)"
                      >
                        {{ mod.name }}
                      </div>
                    </template>
                    {{ mod.id }}
                  </NTooltip>
                </div>
              </NCollapseItem>
            </NCollapse>
          </div>

          <!-- Stage Editor -->
          <div style="flex:1;display:flex;flex-direction:column;gap:0">
            <div v-if="form.stages.length === 0" style="text-align:center;padding:40px 0">
              <NEmpty description="暂无阶段，点击下方按钮添加" />
            </div>

            <template v-for="(stage, si) in form.stages" :key="si">
              <div v-if="si > 0" style="display:flex;justify-content:center;padding:2px 0">
                <div style="width:2px;height:20px;background:linear-gradient(#1890ff,#722ed1);border-radius:1px" />
              </div>

              <NCard
                size="small"
                :class="{ 'stage-active': activeStageIdx === si }"
                @click="activeStageIdx = si"
              >
                <template #header>
                  <NSpace align="center" :size="8">
                    <NInput v-model:value="stage.name" size="tiny" style="width:130px;font-weight:600" placeholder="阶段名" />
                    <NSwitch v-model:value="stage.parallel" size="small" />
                    <span style="font-size:11px;color:var(--text-color-3)">并行</span>
                    <NTag size="tiny" :bordered="false">{{ getStageModules(stage).length }} 模块</NTag>
                  </NSpace>
                </template>
                <template #header-extra>
                  <NSpace :size="4">
                    <NButton size="tiny" text :disabled="si === 0" @click.stop="moveStage(si, 'up')">↑</NButton>
                    <NButton size="tiny" text :disabled="si === form.stages.length - 1" @click.stop="moveStage(si, 'down')">↓</NButton>
                    <NButton size="tiny" text type="error" @click.stop="removeStage(si)">×</NButton>
                  </NSpace>
                </template>

                <div v-if="getStageModules(stage).length === 0" style="color:#999;font-size:12px;padding:4px 0">
                  点击左侧模块添加，或使用下方选择器
                </div>
                <div style="display:flex;flex-wrap:wrap;gap:5px">
                  <NTag
                    v-for="mid in getStageModules(stage)"
                    :key="mid"
                    closable size="small"
                    @close="removeModuleFromStage(si, mid)"
                  >
                    {{ getModuleName(mid) }}
                  </NTag>
                </div>

                <NSelect
                  filterable placeholder="添加模块..." size="tiny" style="margin-top:6px;max-width:240px"
                  :options="allModules.filter(m => !getStageModules(stage).includes(m.id)).map(m => ({ label: m.name, value: m.id }))"
                  :value="null"
                  @update:value="(id: string) => { const mod = allModules.find(m => m.id === id); if (mod) addModuleToStage(si, mod); }"
                />
              </NCard>
            </template>

            <NButton dashed block size="small" style="margin-top:8px" @click="addStage">+ 添加阶段</NButton>
          </div>
        </div>

        <NDivider>参数定义 ({{ form.params.length }})</NDivider>
        <div v-for="(p, idx) in form.params" :key="idx" class="mb-2 p-2" style="border:1px solid var(--border-color);border-radius:6px">
          <NGrid :cols="4" :x-gap="8">
            <NFormItemGi label="名称" :show-feedback="false">
              <NInput v-model:value="p.name" size="small" placeholder="参数名" />
            </NFormItemGi>
            <NFormItemGi label="类型" :show-feedback="false">
              <NSelect v-model:value="p.type" size="small" :options="[{label:'string',value:'string'},{label:'int',value:'int'},{label:'bool',value:'bool'}]" />
            </NFormItemGi>
            <NFormItemGi label="默认值" :show-feedback="false">
              <NInput v-model:value="p.default" size="small" />
            </NFormItemGi>
            <NFormItemGi :show-feedback="false">
              <NSpace>
                <NSwitch v-model:value="p.required" size="small" /><span style="font-size:11px">必填</span>
                <NButton size="tiny" type="error" quaternary @click="removeParam(idx)">移除</NButton>
              </NSpace>
            </NFormItemGi>
          </NGrid>
        </div>
        <NButton size="small" dashed block @click="addParam">+ 添加参数</NButton>

        <template #footer>
          <NSpace justify="end">
            <NButton @click="editorVisible = false">取消</NButton>
            <NButton type="primary" @click="handleSave">保存</NButton>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>

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

        <NDivider>扫描阶段 ({{ detailItem.stages?.length ?? 0 }})</NDivider>
        <NTimeline v-if="detailItem.stages?.length">
          <NTimelineItem
            v-for="(s, idx) in detailItem.stages"
            :key="idx"
            :title="`${idx + 1}. ${s.name}`"
            :type="s.parallel ? 'info' : 'success'"
          >
            <NSpace :size="4" style="margin-top:4px">
              <NTag v-for="mid in getStageModules(s)" :key="mid" size="tiny" :bordered="false">{{ getModuleName(mid) }}</NTag>
            </NSpace>
          </NTimelineItem>
        </NTimeline>
        <NEmpty v-else description="无阶段定义" />
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
