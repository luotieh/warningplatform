<script lang="ts" setup>
import { h, onMounted, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NDrawer, NDrawerContent, NEmpty, NForm,
  NFormItem, NGrid, NGridItem, NInput, NModal, NPopconfirm, NSelect,
  NSpace, NStatistic, NTabPane, NTabs, NTag, NPagination,
} from 'naive-ui';
import type { ASMChange, ASMDiscoveredAsset, ASMProject, ASMSeed } from '#/api/asm';
import {
  addSeed, createProject, deleteProject, deleteSeed,
  getChanges, getDiscoveredAssets, getExposureReport, getProject, getProjects, exportAssets, runDiscovery,
} from '#/api/asm';
import { message } from '#/adapter/naive';
import { useErrorHandler } from '#/composables/useErrorHandler';

defineOptions({ name: 'ASMIndex' });

const { handleError } = useErrorHandler();
const loading = ref(false);
const projects = ref<ASMProject[]>([]);
const showCreate = ref(false);
const createForm = ref({ name: '', description: '', schedule: '0 0 * * *', seeds: [{ type: 'domain', value: '' }] });

const drawerVisible = ref(false);
const activeProject = ref<ASMProject | null>(null);
const projectSeeds = ref<ASMSeed[]>([]);
const discoveredAssets = ref<ASMDiscoveredAsset[]>([]);
const changes = ref<ASMChange[]>([]);
const discovering = ref(false);
const activeTab = ref('assets');

const assetFilter = ref({ keyword: '', type: '', status: '', min_risk: 0 });
const assetPage = ref(1);
const assetPageSize = ref(20);
const assetTotal = ref(0);

const assetTypeOptions = [
  { label: '全部', value: '' },
  { label: '域名', value: 'domain' },
  { label: '子域名', value: 'subdomain' },
  { label: 'IP', value: 'ip' },
  { label: 'URL', value: 'url' },
  { label: '端口', value: 'port' },
  { label: '服务', value: 'service' },
];

const assetStatusOptions = [
  { label: '全部', value: '' },
  { label: '活跃', value: 'active' },
  { label: '不活跃', value: 'inactive' },
];

const riskOptions = [
  { label: '全部', value: 0 },
  { label: '高风险 (≥70)', value: 70 },
  { label: '中风险 (≥40)', value: 40 },
];

const seedTypeOptions = [
  { label: '域名', value: 'domain' },
  { label: 'IP/CIDR', value: 'ip' },
  { label: 'ASN', value: 'asn' },
  { label: 'URL', value: 'url' },
  { label: '关键词', value: 'keyword' },
];

const columns = [
  { title: '项目名', key: 'name', minWidth: 160 },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  { title: '调度', key: 'schedule', width: 130 },
  {
    title: '状态', key: 'enabled', width: 80,
    render: (row: ASMProject) => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '启用' : '停用'),
  },
  { title: '创建时间', key: 'created_at', width: 170 },
  {
    title: '操作', key: 'actions', width: 200, fixed: 'right' as const,
    render: (row: ASMProject) => h(NSpace, { size: 4 }, () => [
      h(NButton, { size: 'small', type: 'info', onClick: () => openProject(row) }, () => '查看'),
      h(NButton, { size: 'small', type: 'warning', loading: discovering.value, onClick: () => onRunDiscovery(row.id) }, () => '执行发现'),
      h(NPopconfirm, { onPositiveClick: () => onDelete(row.id) }, {
        trigger: () => h(NButton, { size: 'small', type: 'error' }, () => '删除'),
        default: () => '确定删除此项目？所有数据将被清除',
      }),
    ]),
  },
];

const assetColumns = [
  { title: '类型', key: 'type', width: 80, render: (row: ASMDiscoveredAsset) => h(NTag, { size: 'small' }, () => row.type) },
  { title: '值', key: 'value', minWidth: 200, ellipsis: { tooltip: true } },
  { title: '来源', key: 'source', width: 120 },
  { title: '风险分', key: 'risk_score', width: 70, sorter: 'default' as const },
  { title: '状态', key: 'status', width: 80 },
  { title: '最后发现', key: 'last_seen', width: 170 },
];

const changeColumns = [
  {
    title: '级别', key: 'severity', width: 80,
    render: (row: ASMChange) => {
      const typeMap: Record<string, any> = { high: 'error', medium: 'warning', low: 'info', info: 'default' };
      return h(NTag, { size: 'small', type: typeMap[row.severity] ?? 'default' }, () => row.severity);
    },
  },
  { title: '字段', key: 'field', width: 120 },
  { title: '旧值', key: 'old_value', width: 160, ellipsis: { tooltip: true } },
  { title: '新值', key: 'new_value', width: 160, ellipsis: { tooltip: true } },
  { title: '时间', key: 'change_at', width: 170 },
];

async function fetchProjects() {
  loading.value = true;
  try {
    const res: any = await getProjects();
    const body = res?.data ?? res;
    projects.value = body?.data ?? [];
  } catch (e) { handleError(e, '获取项目列表失败'); }
  finally { loading.value = false; }
}

async function onCreate() {
  if (!createForm.value.name) { message.warning('请输入项目名'); return; }
  const validSeeds = createForm.value.seeds.filter(s => s.value);
  try {
    await createProject({ ...createForm.value, seeds: validSeeds });
    message.success('项目创建成功');
    showCreate.value = false;
    createForm.value = { name: '', description: '', schedule: '0 0 * * *', seeds: [{ type: 'domain', value: '' }] };
    fetchProjects();
  } catch (e) { handleError(e, '创建失败'); }
}

async function onDelete(id: string) {
  try { await deleteProject(id); message.success('已删除'); fetchProjects(); }
  catch (e) { handleError(e, '删除失败'); }
}

async function openProject(project: ASMProject) {
  activeProject.value = project;
  drawerVisible.value = true;
  discoveredAssets.value = [];
  changes.value = [];
  projectSeeds.value = [];
  report.value = null;
  try {
    const res: any = await getProject(project.id);
    const body = res?.data ?? res;
    projectSeeds.value = body?.seeds ?? [];
  } catch {}
  await Promise.allSettled([loadProjectData(project.id), loadReport(project.id)]);
}

async function loadProjectData(id: string) {
  try {
    const params: Record<string, any> = {
      index: assetPage.value,
      size: assetPageSize.value,
    };
    if (assetFilter.value.keyword) params.keyword = assetFilter.value.keyword;
    if (assetFilter.value.type) params.type = assetFilter.value.type;
    if (assetFilter.value.status) params.status = assetFilter.value.status;
    if (assetFilter.value.min_risk > 0) params.min_risk = assetFilter.value.min_risk;

    const [assetsRes, changesRes] = await Promise.allSettled([
      getDiscoveredAssets(id, params),
      getChanges(id),
    ]);
    if (assetsRes.status === 'fulfilled') {
      const body = (assetsRes.value as any)?.data ?? assetsRes.value;
      discoveredAssets.value = body?.data ?? [];
      assetTotal.value = body?.count ?? 0;
    }
    if (changesRes.status === 'fulfilled') {
      const body = (changesRes.value as any)?.data ?? changesRes.value;
      changes.value = body?.data ?? [];
    }
  } catch {}
}

function onAssetFilterChange() {
  assetPage.value = 1;
  if (activeProject.value) loadProjectData(activeProject.value.id);
}

function onAssetPageChange(p: number) {
  assetPage.value = p;
  if (activeProject.value) loadProjectData(activeProject.value.id);
}

function onAssetPageSizeChange(s: number) {
  assetPageSize.value = s;
  assetPage.value = 1;
  if (activeProject.value) loadProjectData(activeProject.value.id);
}

function onExportAssets() {
  if (!activeProject.value) return;
  window.open(exportAssets(activeProject.value.id), '_blank');
}

async function onRunDiscovery(id: string) {
  discovering.value = true;
  try {
    await runDiscovery(id);
    message.success('发现任务已启动，请稍后刷新查看结果');
    if (activeProject.value?.id === id) {
      setTimeout(() => loadProjectData(id), 3000);
    }
  } catch (e) { handleError(e, '发现执行失败'); }
  finally { discovering.value = false; }
}

const report = ref<any>(null);

async function loadReport(id: string) {
  try {
    const res: any = await getExposureReport(id);
    report.value = res?.data ?? res;
  } catch { report.value = null; }
}

const newSeedType = ref('domain');
const newSeedValue = ref('');

async function onAddSeed() {
  if (!newSeedValue.value || !activeProject.value) return;
  try {
    await addSeed(activeProject.value.id, { type: newSeedType.value, value: newSeedValue.value });
    message.success('种子添加成功');
    newSeedValue.value = '';
    const res: any = await getProject(activeProject.value.id);
    projectSeeds.value = (res?.data ?? res)?.seeds ?? [];
  } catch (e) { handleError(e, '添加失败'); }
}

async function onDeleteSeed(seedId: string) {
  if (!activeProject.value) return;
  try {
    await deleteSeed(activeProject.value.id, seedId);
    projectSeeds.value = projectSeeds.value.filter(s => s.id !== seedId);
    message.success('已删除');
  } catch (e) { handleError(e, '删除失败'); }
}

onMounted(fetchProjects);
</script>

<template>
  <div style="padding: 16px">
    <NCard title="攻击面管理 (ASM)" size="small">
      <template #header-extra>
        <NButton type="primary" size="small" @click="showCreate = true">新建项目</NButton>
      </template>
      <NDataTable :columns="columns" :data="projects" :loading="loading" :bordered="false" size="small" striped />
    </NCard>

    <!-- 创建弹窗 -->
    <NModal v-model:show="showCreate" preset="card" title="新建ASM项目" style="width: 560px">
      <NForm label-placement="left" label-width="80">
        <NFormItem label="项目名" required><NInput v-model:value="createForm.name" /></NFormItem>
        <NFormItem label="描述"><NInput v-model:value="createForm.description" type="textarea" :rows="2" /></NFormItem>
        <NFormItem label="调度"><NInput v-model:value="createForm.schedule" placeholder="cron表达式, 如 0 0 * * *" /></NFormItem>
        <NFormItem label="种子">
          <div style="width: 100%">
            <div v-for="(seed, idx) in createForm.seeds" :key="idx" style="display:flex;gap:8px;margin-bottom:8px">
              <NSelect v-model:value="seed.type" :options="seedTypeOptions" style="width:120px" />
              <NInput v-model:value="seed.value" placeholder="输入值" style="flex:1" />
              <NButton v-if="createForm.seeds.length > 1" text type="error" @click="createForm.seeds.splice(idx, 1)">×</NButton>
            </div>
            <NButton text type="info" @click="createForm.seeds.push({ type: 'domain', value: '' })">+ 添加种子</NButton>
          </div>
        </NFormItem>
      </NForm>
      <template #action>
        <NSpace justify="end">
          <NButton @click="showCreate = false">取消</NButton>
          <NButton type="primary" @click="onCreate">创建并保存</NButton>
        </NSpace>
      </template>
    </NModal>

    <!-- 项目详情抽屉 -->
    <NDrawer v-model:show="drawerVisible" :width="700">
      <NDrawerContent :title="activeProject?.name ?? 'ASM项目'">
        <NGrid :cols="3" :x-gap="12" style="margin-bottom:16px">
          <NGridItem><NCard size="small"><NStatistic label="发现资产" :value="discoveredAssets.length" /></NCard></NGridItem>
          <NGridItem><NCard size="small"><NStatistic label="变更记录" :value="changes.length" /></NCard></NGridItem>
          <NGridItem><NCard size="small"><NStatistic label="种子数" :value="projectSeeds.length" /></NCard></NGridItem>
        </NGrid>

        <NTabs v-model:value="activeTab" type="line" size="small">
          <NTabPane name="assets" tab="发现资产">
            <NSpace style="margin-bottom:12px" :wrap="true" :size="8">
              <NInput v-model:value="assetFilter.keyword" placeholder="搜索资产值" size="small" style="width:180px" clearable @clear="onAssetFilterChange" @keyup.enter="onAssetFilterChange" />
              <NSelect v-model:value="assetFilter.type" :options="assetTypeOptions" size="small" style="width:110px" @update:value="onAssetFilterChange" />
              <NSelect v-model:value="assetFilter.status" :options="assetStatusOptions" size="small" style="width:110px" @update:value="onAssetFilterChange" />
              <NSelect v-model:value="assetFilter.min_risk" :options="riskOptions" size="small" style="width:130px" @update:value="onAssetFilterChange" />
              <NButton size="small" @click="onAssetFilterChange">搜索</NButton>
              <NButton size="small" type="info" @click="onExportAssets">导出CSV</NButton>
            </NSpace>
            <NEmpty v-if="discoveredAssets.length === 0" description="暂无发现资产，点击「执行发现」启动扫描" />
            <template v-else>
              <NDataTable :data="discoveredAssets" :columns="assetColumns" :bordered="false" size="small" :max-height="350" />
              <div style="display:flex;justify-content:flex-end;margin-top:12px">
                <NPagination
                  :page="assetPage"
                  :page-size="assetPageSize"
                  :item-count="assetTotal"
                  :page-sizes="[10, 20, 50]"
                  show-size-picker
                  @update:page="onAssetPageChange"
                  @update:page-size="onAssetPageSizeChange"
                />
              </div>
            </template>
          </NTabPane>
          <NTabPane name="changes" tab="变更记录">
            <NEmpty v-if="changes.length === 0" description="暂无变更记录" />
            <NDataTable v-else :data="changes" :columns="changeColumns" :bordered="false" size="small" :max-height="400" />
          </NTabPane>
          <NTabPane name="report" tab="暴露面报告">
            <div v-if="!report" style="text-align:center;padding:32px;color:#999">暂无数据，请先执行发现</div>
            <template v-else>
              <NGrid :cols="4" :x-gap="12" style="margin-bottom:16px">
                <NGridItem><NCard size="small"><NStatistic label="资产总数" :value="report.total_assets ?? 0" /></NCard></NGridItem>
                <NGridItem><NCard size="small"><NStatistic label="变更记录" :value="report.recent_changes ?? 0" /></NCard></NGridItem>
                <NGridItem><NCard size="small"><NStatistic label="待处理告警" :value="report.open_alerts ?? 0" /></NCard></NGridItem>
                <NGridItem><NCard size="small"><NStatistic label="高风险资产" :value="report.risk_distribution?.[0]?.count ?? 0" /></NCard></NGridItem>
              </NGrid>
              <NGrid :cols="2" :x-gap="12" style="margin-bottom:12px">
                <NGridItem>
                  <NCard title="类型分布" size="small">
                    <div v-for="item in (report.type_distribution ?? [])" :key="item.type" style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f0f0f0">
                      <NTag size="small">{{ item.type }}</NTag>
                      <span style="font-weight:500">{{ item.count }}</span>
                    </div>
                  </NCard>
                </NGridItem>
                <NGridItem>
                  <NCard title="来源分布" size="small">
                    <div v-for="item in (report.source_stats ?? [])" :key="item.source" style="display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #f0f0f0">
                      <span style="font-size:12px">{{ item.source }}</span>
                      <span style="font-weight:500">{{ item.count }}</span>
                    </div>
                  </NCard>
                </NGridItem>
              </NGrid>
              <NCard title="高风险资产 Top 10" size="small">
                <NDataTable
                  v-if="(report.top_risk_assets ?? []).length > 0"
                  :data="report.top_risk_assets"
                  :columns="[
                    { title: '类型', key: 'type', width: 80 },
                    { title: '值', key: 'value', ellipsis: { tooltip: true } },
                    { title: '来源', key: 'source', width: 140 },
                    { title: '风险分', key: 'risk_score', width: 70, sorter: 'default' },
                  ]"
                  :bordered="false"
                  size="small"
                />
                <NEmpty v-else description="暂无高风险资产" />
              </NCard>
            </template>
          </NTabPane>
          <NTabPane name="seeds" tab="种子管理">
            <NSpace style="margin-bottom:12px">
              <NSelect v-model:value="newSeedType" :options="seedTypeOptions" style="width:120px" size="small" />
              <NInput v-model:value="newSeedValue" placeholder="输入种子值" size="small" style="width:200px" />
              <NButton type="primary" size="small" @click="onAddSeed">添加</NButton>
            </NSpace>
            <div v-for="seed in projectSeeds" :key="seed.id" style="display:flex;align-items:center;gap:8px;margin-bottom:6px;padding:6px 10px;background:#f9f9f9;border-radius:4px">
              <NTag size="small" type="info">{{ seed.type }}</NTag>
              <span style="flex:1;font-size:13px">{{ seed.value }}</span>
              <span v-if="seed.last_run_at" style="font-size:11px;color:#999">{{ seed.last_run_at }}</span>
              <NButton text type="error" size="small" @click="onDeleteSeed(seed.id)">删除</NButton>
            </div>
          </NTabPane>
        </NTabs>
      </NDrawerContent>
    </NDrawer>
  </div>
</template>
