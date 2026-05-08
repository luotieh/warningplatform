<script lang="ts" setup>
import { h, onMounted, ref } from 'vue';
import {
  NButton, NCard, NDataTable, NDrawer, NDrawerContent, NEmpty,
  NGrid, NGridItem, NInput, NModal, NPagination, NSelect, NSpace, NStatistic, NSwitch,
  NTabPane, NTabs, NTag, NDynamicTags, NCheckbox, NCheckboxGroup,
  useMessage,
} from 'naive-ui';
import type { CVEEntry, IntelSource, IntelSubscription } from '#/api/intel';
import {
  getIntelStats, matchFingerprint, searchCVE, syncNow,
  listSubscriptions, createSubscription, updateSubscription, deleteSubscription, testSubscription,
  addSource, updateSource, deleteSource, getTrend,
  listIOC, createIOC, deleteIOC, toggleIOC, scanAssetsIOC,
  listCPEMappings, addCPEMapping, deleteCPEMapping,
  fetchExploit,
} from '#/api/intel';
import type { IOCIndicator, CPEMapping } from '#/api/intel';

defineOptions({ name: 'IntelIndex' });

const message = useMessage();
const loading = ref(false);
const stats = ref<any>(null);
const searchResults = ref<CVEEntry[]>([]);
const searchTotal = ref(0);
const keyword = ref('');
const severityFilter = ref<string | null>(null);
const exploitFilter = ref(false);
const kevFilter = ref(false);
const sources = ref<IntelSource[]>([]);
const syncing = ref(false);

const fpProduct = ref('');
const fpVersion = ref('');
const fpResults = ref<any[]>([]);
const fpLoading = ref(false);

const detailVisible = ref(false);
const detailCVE = ref<CVEEntry | null>(null);

const severityOptions = [
  { label: '全部', value: '' },
  { label: 'Critical', value: 'critical' },
  { label: 'High', value: 'high' },
  { label: 'Medium', value: 'medium' },
  { label: 'Low', value: 'low' },
];

const columns = [
  {
    title: 'CVE ID', key: 'id', width: 160,
    render: (row: CVEEntry) => h(NButton, { text: true, type: 'info', size: 'small', onClick: () => openDetail(row) }, () => row.id),
  },
  {
    title: '严重度', key: 'severity', width: 90,
    render: (row: CVEEntry) => {
      const typeMap: Record<string, any> = { critical: 'error', high: 'warning', medium: 'info', low: 'default' };
      return h(NTag, { size: 'small', type: typeMap[row.severity] ?? 'default' }, () => row.severity);
    },
  },
  { title: 'CVSS', key: 'cvss_score', width: 70 },
  {
    title: 'EPSS', key: 'epss_score', width: 70,
    render: (row: CVEEntry) => row.epss_score > 0 ? `${(row.epss_score * 100).toFixed(1)}%` : '-',
    sorter: (a: CVEEntry, b: CVEEntry) => (a.epss_score ?? 0) - (b.epss_score ?? 0),
  },
  { title: '描述', key: 'description', ellipsis: { tooltip: true } },
  {
    title: '标记', key: 'flags', width: 120,
    render: (row: CVEEntry) => {
      const tags: any[] = [];
      if (row.has_exploit) tags.push(h(NTag, { size: 'tiny', type: 'error', bordered: false }, () => 'EXP'));
      if (row.in_kev) tags.push(h(NTag, { size: 'tiny', type: 'warning', bordered: false }, () => 'KEV'));
      return h(NSpace, { size: 2 }, () => tags);
    },
  },
  { title: '发布时间', key: 'published', width: 110, render: (row: CVEEntry) => row.published?.slice(0, 10) ?? '-' },
];

async function fetchStats() {
  try {
    const res: any = await getIntelStats();
    const body = res?.data ?? res;
    stats.value = body;
    sources.value = body?.sources ?? [];
  } catch {}
}

const currentPage = ref(1);
const pageSize = ref(100);

async function onSearch(page = 1) {
  loading.value = true;
  currentPage.value = page;
  try {
    const params: any = { page, page_size: pageSize.value };
    if (keyword.value) params.q = keyword.value;
    if (severityFilter.value) params.severity = severityFilter.value;
    if (exploitFilter.value) params.has_exploit = 'true';
    if (kevFilter.value) params.in_kev = 'true';
    const res: any = await searchCVE(params);
    const body = res?.data ?? res;
    searchResults.value = body?.results ?? [];
    searchTotal.value = body?.total ?? 0;
  } catch { message.error('搜索失败'); }
  finally { loading.value = false; }
}

async function onSync() {
  syncing.value = true;
  try {
    await syncNow();
    message.success('同步任务已触发');
    setTimeout(fetchStats, 3000);
  } catch { message.error('同步触发失败'); }
  finally { syncing.value = false; }
}

// --- 情报源管理 ---
const srcModalVisible = ref(false);
const srcForm = ref<{ name: string; type: string; url: string; sync_interval: string; api_key: string }>({
  name: '', type: 'custom', url: '', sync_interval: '24h', api_key: '',
});

function openSrcModal() {
  srcForm.value = { name: '', type: 'custom', url: '', sync_interval: '24h', api_key: '' };
  srcModalVisible.value = true;
}

async function onSaveSrc() {
  if (!srcForm.value.name || !srcForm.value.url) { message.warning('请填写名称和URL'); return; }
  try {
    await addSource({ ...srcForm.value, enabled: true });
    message.success('添加成功');
    srcModalVisible.value = false;
    fetchStats();
  } catch { message.error('添加失败'); }
}

async function onToggleSource(src: IntelSource) {
  try {
    await updateSource(src.name, { enabled: !src.enabled });
    message.success('已更新');
    fetchStats();
  } catch { message.error('操作失败'); }
}

async function onDeleteSource(src: IntelSource) {
  try {
    await deleteSource(src.name);
    message.success('已删除');
    fetchStats();
  } catch { message.error('删除失败（内置源不可删除）'); }
}

async function onMatchFP() {
  if (!fpProduct.value) { message.warning('请输入产品名'); return; }
  fpLoading.value = true;
  try {
    const res: any = await matchFingerprint(fpProduct.value, fpVersion.value);
    const body = res?.data ?? res;
    fpResults.value = body?.matches ?? [];
    if (fpResults.value.length === 0) {
      message.info('未找到匹配的CVE');
    }
  } catch { message.error('匹配失败'); }
  finally { fpLoading.value = false; }
}

function openDetail(cve: CVEEntry) {
  detailCVE.value = cve;
  detailVisible.value = true;
}

// --- Exploit 查看 ---
const exploitModalVisible = ref(false);
const exploitContent = ref('');
const exploitMeta = ref<any>(null);
const exploitLoading = ref(false);

async function viewExploit(url: string) {
  exploitLoading.value = true;
  exploitContent.value = '';
  exploitMeta.value = null;
  exploitModalVisible.value = true;
  try {
    const res: any = await fetchExploit(url);
    const body = res?.data ?? res;
    exploitContent.value = body?.content ?? '无法获取内容';
    exploitMeta.value = body?.metadata ?? null;
    if (body?.error) {
      exploitContent.value = `获取失败: ${body.error}`;
    }
  } catch { exploitContent.value = '请求失败'; }
  finally { exploitLoading.value = false; }
}

// --- 订阅管理 ---
const subscriptions = ref<IntelSubscription[]>([]);
const subLoading = ref(false);
const subModalVisible = ref(false);
const subForm = ref<{
  id?: string;
  name: string;
  products: string[];
  keywords: string[];
  severities: string[];
  only_exploit: boolean;
  only_kev: boolean;
}>({ name: '', products: [], keywords: [], severities: [], only_exploit: false, only_kev: false });

const testResult = ref<any>(null);
const testModalVisible = ref(false);

async function fetchSubscriptions() {
  subLoading.value = true;
  try {
    const res: any = await listSubscriptions();
    subscriptions.value = res?.data ?? res ?? [];
  } catch {}
  finally { subLoading.value = false; }
}

function openSubModal(sub?: IntelSubscription) {
  if (sub) {
    subForm.value = {
      id: sub.id,
      name: sub.name,
      products: sub.products ?? [],
      keywords: sub.keywords ?? [],
      severities: sub.severities ?? [],
      only_exploit: sub.only_exploit,
      only_kev: sub.only_kev,
    };
  } else {
    subForm.value = { name: '', products: [], keywords: [], severities: [], only_exploit: false, only_kev: false };
  }
  subModalVisible.value = true;
}

async function onSaveSub() {
  if (!subForm.value.name) { message.warning('请输入订阅名称'); return; }
  try {
    if (subForm.value.id) {
      await updateSubscription(subForm.value.id, subForm.value);
    } else {
      await createSubscription(subForm.value);
    }
    message.success('保存成功');
    subModalVisible.value = false;
    fetchSubscriptions();
  } catch { message.error('保存失败'); }
}

async function onDeleteSub(id: string) {
  try {
    await deleteSubscription(id);
    message.success('已删除');
    fetchSubscriptions();
  } catch { message.error('删除失败'); }
}

async function onToggleSub(sub: IntelSubscription) {
  try {
    await updateSubscription(sub.id, { enabled: !sub.enabled });
    fetchSubscriptions();
  } catch { message.error('操作失败'); }
}

async function onTestSub(id: string) {
  try {
    const res: any = await testSubscription(id);
    testResult.value = res?.data ?? res;
    testModalVisible.value = true;
  } catch { message.error('测试失败'); }
}

// --- IOC 威胁指标 ---
const iocList = ref<IOCIndicator[]>([]);
const iocLoading = ref(false);
const iocModalVisible = ref(false);
const iocForm = ref<{ type: string; value: string; threat_type: string; severity: string; source: string; description: string }>({
  type: 'ip', value: '', threat_type: '', severity: 'high', source: '', description: '',
});
const iocScanResult = ref<any>(null);
const iocScanModalVisible = ref(false);

async function fetchIOC() {
  iocLoading.value = true;
  try {
    const res: any = await listIOC();
    iocList.value = res?.items ?? res?.data ?? res ?? [];
  } catch {}
  finally { iocLoading.value = false; }
}

async function onCreateIOC() {
  if (!iocForm.value.value) { message.warning('请输入指标值'); return; }
  try {
    await createIOC(iocForm.value);
    message.success('添加成功');
    iocModalVisible.value = false;
    fetchIOC();
  } catch { message.error('添加失败'); }
}

async function onDeleteIOC(id: string) {
  try { await deleteIOC(id); message.success('已删除'); fetchIOC(); }
  catch { message.error('删除失败'); }
}

async function onToggleIOC(id: string) {
  try { await toggleIOC(id); fetchIOC(); }
  catch { message.error('操作失败'); }
}

async function onScanAssets() {
  try {
    const res: any = await scanAssetsIOC();
    iocScanResult.value = res?.data ?? res;
    iocScanModalVisible.value = true;
    if ((iocScanResult.value?.hits ?? 0) > 0) {
      message.warning(`发现 ${iocScanResult.value.hits} 个IOC命中！`);
    } else {
      message.success('未发现命中');
    }
  } catch { message.error('扫描失败'); }
}

const iocColumns = [
  { title: '类型', key: 'type', width: 80, render: (row: IOCIndicator) => h(NTag, { size: 'small' }, () => row.type.toUpperCase()) },
  { title: '指标值', key: 'value', width: 200, ellipsis: { tooltip: true } },
  { title: '威胁类型', key: 'threat_type', width: 100 },
  {
    title: '严重度', key: 'severity', width: 80,
    render: (row: IOCIndicator) => h(NTag, { size: 'small', type: row.severity === 'critical' ? 'error' : row.severity === 'high' ? 'warning' : 'info' }, () => row.severity),
  },
  { title: '来源', key: 'source', width: 120, ellipsis: { tooltip: true } },
  { title: '命中数', key: 'hit_count', width: 60 },
  { title: '状态', key: 'enabled', width: 60, render: (row: IOCIndicator) => h(NTag, { size: 'tiny', type: row.enabled ? 'success' : 'default' }, () => row.enabled ? '启' : '停') },
  {
    title: '操作', key: 'actions', width: 130,
    render: (row: IOCIndicator) => h(NSpace, { size: 4 }, () => [
      h(NButton, { text: true, size: 'small', type: row.enabled ? 'default' : 'success', onClick: () => onToggleIOC(row.id) }, () => row.enabled ? '停用' : '启用'),
      h(NButton, { text: true, size: 'small', type: 'error', onClick: () => onDeleteIOC(row.id) }, () => '删除'),
    ]),
  },
];

// --- 趋势分析 ---
const trendDimension = ref<'time' | 'severity' | 'product' | 'exploit'>('time');
const trendData = ref<any[]>([]);
const trendLoading = ref(false);

async function fetchTrend() {
  trendLoading.value = true;
  try {
    const res: any = await getTrend(trendDimension.value);
    const body = res?.data ?? res;
    trendData.value = body?.data ?? [];
  } catch {}
  finally { trendLoading.value = false; }
}

function trendBarWidth(count: number) {
  const max = Math.max(...trendData.value.map((d: any) => d.count || 0), 1);
  return `${Math.round((count / max) * 100)}%`;
}

// --- CPE 映射管理 ---
const cpeMappings = ref<CPEMapping[]>([]);
const cpeLoading = ref(false);
const cpeModalVisible = ref(false);
const cpeForm = ref<{ product: string; version: string; cpe_matches: string[] }>({ product: '', version: '*', cpe_matches: [] });
const cpeSearch = ref('');

async function fetchCPEMappings() {
  cpeLoading.value = true;
  try {
    const res: any = await listCPEMappings(cpeSearch.value || undefined);
    const body = res?.data ?? res;
    cpeMappings.value = body?.mappings ?? [];
  } catch {}
  finally { cpeLoading.value = false; }
}

async function onAddCPE() {
  if (!cpeForm.value.product || cpeForm.value.cpe_matches.length === 0) {
    message.warning('请填写产品名和CPE匹配规则');
    return;
  }
  try {
    await addCPEMapping(cpeForm.value);
    message.success('添加成功');
    cpeModalVisible.value = false;
    fetchCPEMappings();
  } catch { message.error('添加失败'); }
}

async function onDeleteCPE(product: string) {
  try { await deleteCPEMapping(product); message.success('已删除'); fetchCPEMappings(); }
  catch { message.error('删除失败'); }
}

const cpeColumns = [
  { title: '产品', key: 'product', width: 150 },
  { title: '版本', key: 'version', width: 80 },
  { title: 'CPE匹配规则', key: 'cpe_matches', render: (row: CPEMapping) => (row.cpe_matches ?? []).join(', '), ellipsis: { tooltip: true } },
  {
    title: '操作', key: 'actions', width: 80,
    render: (row: CPEMapping) => h(NButton, { text: true, size: 'small', type: 'error', onClick: () => onDeleteCPE(row.product) }, () => '删除'),
  },
];

const subColumns = [
  { title: '名称', key: 'name', width: 150 },
  {
    title: '产品', key: 'products', width: 160,
    render: (row: IntelSubscription) => (row.products ?? []).join(', ') || '-',
  },
  {
    title: '关键词', key: 'keywords', width: 160,
    render: (row: IntelSubscription) => (row.keywords ?? []).join(', ') || '-',
  },
  {
    title: '条件', key: 'filters', width: 130,
    render: (row: IntelSubscription) => {
      const tags: any[] = [];
      if (row.severities?.length) tags.push(h(NTag, { size: 'tiny', bordered: false }, () => row.severities.join(',')));
      if (row.only_exploit) tags.push(h(NTag, { size: 'tiny', type: 'error', bordered: false }, () => 'EXP'));
      if (row.only_kev) tags.push(h(NTag, { size: 'tiny', type: 'warning', bordered: false }, () => 'KEV'));
      return h(NSpace, { size: 2 }, () => tags.length ? tags : ['-']);
    },
  },
  {
    title: '状态', key: 'enabled', width: 70,
    render: (row: IntelSubscription) => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '启用' : '停用'),
  },
  { title: '匹配数', key: 'match_count', width: 70 },
  {
    title: '最后匹配', key: 'last_match_at', width: 150,
    render: (row: IntelSubscription) => row.last_match_at?.slice(0, 19).replace('T', ' ') ?? '-',
  },
  {
    title: '操作', key: 'actions', width: 200,
    render: (row: IntelSubscription) => h(NSpace, { size: 4 }, () => [
      h(NButton, { text: true, type: 'primary', size: 'small', onClick: () => openSubModal(row) }, () => '编辑'),
      h(NButton, { text: true, type: 'info', size: 'small', onClick: () => onTestSub(row.id) }, () => '测试'),
      h(NButton, { text: true, type: row.enabled ? 'default' : 'success', size: 'small', onClick: () => onToggleSub(row) }, () => row.enabled ? '停用' : '启用'),
      h(NButton, { text: true, type: 'error', size: 'small', onClick: () => onDeleteSub(row.id) }, () => '删除'),
    ]),
  },
];

onMounted(() => { fetchStats(); onSearch(); fetchSubscriptions(); fetchTrend(); fetchIOC(); fetchCPEMappings(); });
</script>

<template>
  <div style="padding: 16px">
    <!-- 统计概览 -->
    <NGrid :cols="6" :x-gap="12" style="margin-bottom:16px">
      <NGridItem><NCard size="small"><NStatistic label="CVE总量" :value="stats?.total ?? 0" /></NCard></NGridItem>
      <NGridItem><NCard size="small"><NStatistic label="Critical" :value="stats?.critical ?? 0" /></NCard></NGridItem>
      <NGridItem><NCard size="small"><NStatistic label="High" :value="stats?.high ?? 0" /></NCard></NGridItem>
      <NGridItem><NCard size="small"><NStatistic label="有EXP" :value="stats?.with_exploit ?? 0" /></NCard></NGridItem>
      <NGridItem><NCard size="small"><NStatistic label="在KEV" :value="stats?.in_kev ?? 0" /></NCard></NGridItem>
      <NGridItem>
        <NCard size="small">
          <NStatistic label="情报源" :value="sources.length" />
          <NButton size="tiny" type="primary" :loading="syncing" @click="onSync" style="margin-top:4px">立即同步</NButton>
        </NCard>
      </NGridItem>
    </NGrid>

    <NTabs type="line" size="small">
      <NTabPane name="search" tab="CVE搜索">
        <NSpace style="margin-bottom:12px" align="center">
          <NInput v-model:value="keyword" placeholder="CVE ID或关键词" style="width:240px" size="small" @keyup.enter="onSearch(1)" />
          <NSelect v-model:value="severityFilter" :options="severityOptions" style="width:120px" size="small" clearable placeholder="严重度" />
          <NSpace align="center" :size="4">
            <span style="font-size:12px">有EXP</span>
            <NSwitch v-model:value="exploitFilter" size="small" />
          </NSpace>
          <NSpace align="center" :size="4">
            <span style="font-size:12px">在KEV</span>
            <NSwitch v-model:value="kevFilter" size="small" />
          </NSpace>
          <NButton type="primary" size="small" @click="onSearch(1)" :loading="loading">搜索</NButton>
        </NSpace>
        <NDataTable :columns="columns" :data="searchResults" :loading="loading" :bordered="false" size="small" striped :max-height="600" virtual-scroll />
        <div v-if="searchTotal > 0" style="margin-top:10px;display:flex;justify-content:space-between;align-items:center">
          <span style="font-size:12px;color:#666">共 {{ searchTotal }} 条结果（按时间倒序）</span>
          <NPagination
            :page="currentPage"
            :page-size="pageSize"
            :item-count="searchTotal"
            size="small"
            show-size-picker
            :page-sizes="[50, 100, 200]"
            @update:page="onSearch"
            @update:page-size="(s: number) => { pageSize = s; onSearch(1); }"
          />
        </div>
      </NTabPane>

      <NTabPane name="match" tab="指纹匹配">
        <NSpace style="margin-bottom:12px">
          <NInput v-model:value="fpProduct" placeholder="产品名(如 Nginx, Redis)" style="width:200px" size="small" />
          <NInput v-model:value="fpVersion" placeholder="版本(可选)" style="width:140px" size="small" />
          <NButton type="primary" size="small" :loading="fpLoading" @click="onMatchFP">匹配CVE</NButton>
        </NSpace>
        <NEmpty v-if="fpResults.length === 0" description="输入产品名和版本进行CVE匹配" />
        <NDataTable
          v-else
          :data="fpResults"
          :columns="[
            { title: 'CVE ID', key: 'cve.id', width: 160, render: (row: any) => row.cve?.id ?? '-' },
            { title: '严重度', key: 'cve.severity', width: 90, render: (row: any) => h(NTag, { size: 'small', type: row.cve?.severity === 'critical' ? 'error' : row.cve?.severity === 'high' ? 'warning' : 'info' }, () => row.cve?.severity ?? '-') },
            { title: 'CVSS', key: 'cve.cvss_score', width: 70, render: (row: any) => row.cve?.cvss_score ?? '-' },
            { title: '匹配CPE', key: 'matched_cpe', ellipsis: { tooltip: true } },
            { title: '置信度', key: 'confidence', width: 70 },
          ]"
          :bordered="false"
          size="small"
        />
      </NTabPane>

      <NTabPane name="sources" tab="情报源">
        <NSpace style="margin-bottom:12px">
          <NButton type="primary" size="small" @click="openSrcModal">添加自定义源</NButton>
          <NButton size="small" :loading="syncing" @click="onSync">立即同步全部</NButton>
        </NSpace>
        <NDataTable
          :data="sources"
          :columns="[
            { title: '名称', key: 'name', width: 140 },
            { title: '类型', key: 'type', width: 100 },
            { title: 'URL', key: 'url', ellipsis: { tooltip: true } },
            { title: '同步间隔', key: 'sync_interval', width: 90 },
            { title: '记录数', key: 'entry_count', width: 70 },
            { title: '最后同步', key: 'last_sync', width: 160 },
            { title: '状态', key: 'enabled', width: 70, render: (row: IntelSource) => h(NTag, { type: row.enabled ? 'success' : 'default', size: 'small' }, () => row.enabled ? '启用' : '停用') },
            { title: '操作', key: 'actions', width: 130, render: (row: IntelSource) => h(NSpace, { size: 4 }, () => [
              h(NButton, { text: true, size: 'small', type: row.enabled ? 'default' : 'success', onClick: () => onToggleSource(row) }, () => row.enabled ? '停用' : '启用'),
              row.custom ? h(NButton, { text: true, size: 'small', type: 'error', onClick: () => onDeleteSource(row) }, () => '删除') : null,
            ]) },
          ]"
          :bordered="false"
          size="small"
        />
      </NTabPane>

      <NTabPane name="ioc" tab="IOC指标">
        <NSpace style="margin-bottom:12px">
          <NButton type="primary" size="small" @click="iocModalVisible = true">添加指标</NButton>
          <NButton size="small" type="warning" @click="onScanAssets">扫描资产匹配</NButton>
        </NSpace>
        <NDataTable :columns="iocColumns" :data="iocList" :loading="iocLoading" :bordered="false" size="small" :max-height="500" />
      </NTabPane>

      <NTabPane name="trend" tab="趋势分析">
        <NSpace style="margin-bottom:12px" align="center">
          <NSelect v-model:value="trendDimension" :options="[{label:'时间趋势',value:'time'},{label:'严重度分布',value:'severity'},{label:'Top产品',value:'product'},{label:'Exploit分布',value:'exploit'}]" style="width:160px" size="small" @update:value="fetchTrend" />
        </NSpace>
        <div v-if="trendLoading" style="text-align:center;padding:40px;color:#999">加载中...</div>
        <div v-else-if="trendData.length === 0" style="text-align:center;padding:40px;color:#999">暂无数据</div>
        <div v-else style="max-height:500px;overflow-y:auto">
          <div v-for="item in trendData" :key="item.month || item.severity || item.product" style="display:flex;align-items:center;margin-bottom:6px">
            <span style="width:100px;font-size:12px;text-align:right;margin-right:8px;color:#555;flex-shrink:0">{{ item.month || item.severity || item.product }}</span>
            <div style="flex:1;background:#f0f0f0;border-radius:3px;height:20px;position:relative">
              <div :style="{ width: trendBarWidth(item.count), height: '100%', borderRadius: '3px', background: item.severity === 'critical' ? '#ff4d4f' : item.severity === 'high' ? '#ff7a45' : item.severity === 'medium' ? '#ffc53d' : '#52c41a' }" />
            </div>
            <span style="width:50px;font-size:12px;text-align:right;margin-left:8px;color:#333">{{ item.count }}</span>
          </div>
        </div>
      </NTabPane>

      <NTabPane name="cpe" tab="CPE映射库">
        <NSpace style="margin-bottom:12px">
          <NInput v-model:value="cpeSearch" placeholder="搜索产品名" size="small" style="width:200px" @keyup.enter="fetchCPEMappings" />
          <NButton size="small" @click="fetchCPEMappings">搜索</NButton>
          <NButton type="primary" size="small" @click="cpeModalVisible = true">添加映射</NButton>
        </NSpace>
        <NDataTable :columns="cpeColumns" :data="cpeMappings" :loading="cpeLoading" :bordered="false" size="small" :max-height="500" />
      </NTabPane>

      <NTabPane name="subscriptions" tab="漏洞订阅">
        <NSpace style="margin-bottom:12px">
          <NButton type="primary" size="small" @click="openSubModal()">新建订阅规则</NButton>
        </NSpace>
        <NDataTable :columns="subColumns" :data="subscriptions" :loading="subLoading" :bordered="false" size="small" />
      </NTabPane>
    </NTabs>

    <!-- CVE详情抽屉 -->
    <NDrawer v-model:show="detailVisible" :width="560">
      <NDrawerContent :title="detailCVE?.id ?? 'CVE详情'">
        <template v-if="detailCVE">
          <NSpace vertical :size="12">
            <NSpace>
              <NTag :type="detailCVE.severity === 'critical' ? 'error' : detailCVE.severity === 'high' ? 'warning' : 'info'" size="small">{{ detailCVE.severity }}</NTag>
              <span style="font-weight:500">CVSS {{ detailCVE.cvss_score }}</span>
              <NTag v-if="detailCVE.has_exploit" type="error" size="small" :bordered="false">有EXP</NTag>
              <NTag v-if="detailCVE.in_kev" type="warning" size="small" :bordered="false">KEV</NTag>
            </NSpace>
            <div style="font-size:13px;line-height:1.6">{{ detailCVE.description }}</div>
            <div v-if="detailCVE.cvss_vector" style="font-size:12px;color:#666;font-family:monospace">{{ detailCVE.cvss_vector }}</div>
            <div v-if="detailCVE.cwe?.length">
              <span style="font-weight:500;font-size:12px">CWE: </span>
              <NTag v-for="cwe in detailCVE.cwe" :key="cwe" size="small" style="margin-right:4px">{{ cwe }}</NTag>
            </div>
            <div v-if="detailCVE.has_exploit" style="background:#fff2f0;padding:8px 12px;border-radius:4px;border:1px solid #ffccc7">
              <div style="font-weight:600;font-size:13px;color:#cf1322;margin-bottom:6px">Exploit 情报</div>
              <NGrid :cols="3" :x-gap="8">
                <NGridItem>
                  <span style="font-size:11px;color:#666">类型: </span>
                  <NTag size="tiny" :type="detailCVE.exploit_type === 'weaponized' ? 'error' : detailCVE.exploit_type === 'poc' ? 'warning' : 'info'">
                    {{ { weaponized: '武器化', poc: 'PoC', public: '公开EXP' }[detailCVE.exploit_type] || detailCVE.exploit_type || '-' }}
                  </NTag>
                </NGridItem>
                <NGridItem>
                  <span style="font-size:11px;color:#666">利用难度: </span>
                  <NTag size="tiny" :type="detailCVE.difficulty === 'low' ? 'error' : detailCVE.difficulty === 'medium' ? 'warning' : 'default'">
                    {{ { low: '低', medium: '中', high: '高', unknown: '未知' }[detailCVE.difficulty] || '-' }}
                  </NTag>
                </NGridItem>
                <NGridItem>
                  <span style="font-size:11px;color:#666">影响: </span>
                  <NTag size="tiny" :type="detailCVE.impact === 'rce' ? 'error' : 'info'">
                    {{ { rce: 'RCE', privilege_escalation: '提权', dos: 'DoS', info_disclosure: '信息泄露', other: '其他' }[detailCVE.impact] || '-' }}
                  </NTag>
                </NGridItem>
              </NGrid>
              <div v-if="detailCVE.exploit_urls?.length" style="margin-top:6px">
                <span style="font-size:11px;color:#666">EXP链接:</span>
                <div v-for="url in detailCVE.exploit_urls.slice(0, 5)" :key="url" style="font-size:11px;margin-top:2px;display:flex;align-items:center;gap:6px">
                  <a :href="url" target="_blank" rel="noopener" style="color:#cf1322;word-break:break-all;flex:1">{{ url }}</a>
                  <NButton text type="primary" size="tiny" @click="viewExploit(url)">查看代码</NButton>
                </div>
              </div>
            </div>
            <div v-if="detailCVE.epss_score > 0" style="background:#e6f7ff;padding:6px 12px;border-radius:4px;border:1px solid #91d5ff">
              <span style="font-size:12px;font-weight:500">EPSS评分: {{ (detailCVE.epss_score * 100).toFixed(2) }}%</span>
              <span style="font-size:11px;color:#666;margin-left:12px">排名前 {{ ((1 - detailCVE.epss_percentile) * 100).toFixed(1) }}%</span>
            </div>
            <div v-if="detailCVE.references?.length">
              <span style="font-weight:500;font-size:12px">参考链接:</span>
              <div v-for="ref in detailCVE.references.slice(0, 5)" :key="ref" style="font-size:12px;margin-top:2px">
                <a :href="ref" target="_blank" rel="noopener" style="color:#2080f0;word-break:break-all">{{ ref }}</a>
              </div>
            </div>
            <NGrid :cols="2" :x-gap="8">
              <NGridItem><span style="font-size:12px;color:#666">发布: {{ detailCVE.published?.slice(0, 10) }}</span></NGridItem>
              <NGridItem><span style="font-size:12px;color:#666">更新: {{ detailCVE.modified?.slice(0, 10) }}</span></NGridItem>
            </NGrid>
          </NSpace>
        </template>
      </NDrawerContent>
    </NDrawer>

    <!-- 订阅编辑 Modal -->
    <NModal v-model:show="subModalVisible" preset="card" :title="subForm.id ? '编辑订阅' : '新建订阅'" style="width:520px">
      <NSpace vertical :size="16">
        <div>
          <div style="font-size:13px;margin-bottom:4px">订阅名称 *</div>
          <NInput v-model:value="subForm.name" placeholder="如：关注 Nginx 高危漏洞" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">关注产品（按回车添加）</div>
          <NDynamicTags v-model:value="subForm.products" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">关键词（按回车添加）</div>
          <NDynamicTags v-model:value="subForm.keywords" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">严重度过滤</div>
          <NCheckboxGroup v-model:value="subForm.severities">
            <NSpace>
              <NCheckbox value="critical" label="Critical" />
              <NCheckbox value="high" label="High" />
              <NCheckbox value="medium" label="Medium" />
              <NCheckbox value="low" label="Low" />
            </NSpace>
          </NCheckboxGroup>
        </div>
        <NSpace>
          <NCheckbox v-model:checked="subForm.only_exploit">仅有EXP</NCheckbox>
          <NCheckbox v-model:checked="subForm.only_kev">仅在KEV</NCheckbox>
        </NSpace>
        <NSpace justify="end">
          <NButton size="small" @click="subModalVisible = false">取消</NButton>
          <NButton type="primary" size="small" @click="onSaveSub">保存</NButton>
        </NSpace>
      </NSpace>
    </NModal>

    <!-- IOC添加 Modal -->
    <NModal v-model:show="iocModalVisible" preset="card" title="添加威胁指标" style="width:480px">
      <NSpace vertical :size="12">
        <div>
          <div style="font-size:13px;margin-bottom:4px">类型</div>
          <NSelect v-model:value="iocForm.type" :options="[{label:'IP',value:'ip'},{label:'域名',value:'domain'},{label:'哈希',value:'hash'},{label:'URL',value:'url'}]" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">指标值 *</div>
          <NInput v-model:value="iocForm.value" placeholder="如: 1.2.3.4 / evil.com / sha256hash" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">威胁类型</div>
          <NInput v-model:value="iocForm.threat_type" placeholder="如: C2, Malware, Phishing" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">严重度</div>
          <NSelect v-model:value="iocForm.severity" :options="[{label:'Critical',value:'critical'},{label:'High',value:'high'},{label:'Medium',value:'medium'},{label:'Low',value:'low'}]" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">来源</div>
          <NInput v-model:value="iocForm.source" placeholder="如: 内部情报 / AlienVault" size="small" />
        </div>
        <NSpace justify="end">
          <NButton size="small" @click="iocModalVisible = false">取消</NButton>
          <NButton type="primary" size="small" @click="onCreateIOC">添加</NButton>
        </NSpace>
      </NSpace>
    </NModal>

    <!-- IOC扫描结果 Modal -->
    <NModal v-model:show="iocScanModalVisible" preset="card" title="IOC资产扫描结果" style="width:640px">
      <template v-if="iocScanResult">
        <div style="margin-bottom:8px;font-size:13px">
          扫描 {{ iocScanResult.scanned_assets }} 个资产，IOC规则 {{ iocScanResult.ioc_count }} 条，命中 <b style="color:#cf1322">{{ iocScanResult.hits }}</b> 个
        </div>
        <NDataTable
          v-if="iocScanResult.results?.length"
          :data="iocScanResult.results"
          :columns="[
            { title: '资产', key: 'asset_name', width: 150 },
            { title: 'IOC类型', key: 'ioc_type', width: 80 },
            { title: '匹配值', key: 'ioc_value', width: 200 },
            { title: '严重度', key: 'severity', width: 80 },
          ]"
          :bordered="false"
          size="small"
          :max-height="400"
        />
        <NEmpty v-else description="未发现命中" />
      </template>
    </NModal>

    <!-- CPE映射添加 Modal -->
    <NModal v-model:show="cpeModalVisible" preset="card" title="添加CPE映射" style="width:520px">
      <NSpace vertical :size="12">
        <div>
          <div style="font-size:13px;margin-bottom:4px">产品名 *</div>
          <NInput v-model:value="cpeForm.product" placeholder="如: Nginx, MySQL, Spring Boot" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">版本（* 表示所有版本）</div>
          <NInput v-model:value="cpeForm.version" placeholder="*" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">CPE匹配规则（按回车添加）</div>
          <NDynamicTags v-model:value="cpeForm.cpe_matches" />
          <div style="font-size:11px;color:#999;margin-top:4px">格式: cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*</div>
        </div>
        <NSpace justify="end">
          <NButton size="small" @click="cpeModalVisible = false">取消</NButton>
          <NButton type="primary" size="small" @click="onAddCPE">添加</NButton>
        </NSpace>
      </NSpace>
    </NModal>

    <!-- 添加情报源 Modal -->
    <NModal v-model:show="srcModalVisible" preset="card" title="添加自定义情报源" style="width:480px">
      <NSpace vertical :size="12">
        <div>
          <div style="font-size:13px;margin-bottom:4px">名称 *</div>
          <NInput v-model:value="srcForm.name" placeholder="如: 私有CVE源" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">类型</div>
          <NSelect v-model:value="srcForm.type" :options="[{label:'CVE数据库',value:'cve_database'},{label:'Advisory',value:'advisory'},{label:'Exploit',value:'exploit'},{label:'自定义',value:'custom'}]" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">URL *</div>
          <NInput v-model:value="srcForm.url" placeholder="https://..." size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">同步间隔</div>
          <NSelect v-model:value="srcForm.sync_interval" :options="[{label:'1小时',value:'1h'},{label:'6小时',value:'6h'},{label:'12小时',value:'12h'},{label:'24小时',value:'24h'},{label:'7天',value:'168h'}]" size="small" />
        </div>
        <div>
          <div style="font-size:13px;margin-bottom:4px">API Key（可选）</div>
          <NInput v-model:value="srcForm.api_key" placeholder="可选" size="small" type="password" show-password-on="click" />
        </div>
        <NSpace justify="end">
          <NButton size="small" @click="srcModalVisible = false">取消</NButton>
          <NButton type="primary" size="small" @click="onSaveSrc">添加</NButton>
        </NSpace>
      </NSpace>
    </NModal>

    <!-- 测试订阅结果 Modal -->
    <NModal v-model:show="testModalVisible" preset="card" title="订阅测试结果" style="width:640px">
      <template v-if="testResult">
        <div style="margin-bottom:8px;font-size:13px">
          规则「{{ testResult.subscription?.name }}」在当前情报库中匹配到 <b>{{ testResult.matched }}</b> 条CVE（展示前20条）
        </div>
        <NDataTable
          :data="testResult.preview ?? []"
          :columns="[
            { title: 'CVE ID', key: 'id', width: 150 },
            { title: '严重度', key: 'severity', width: 90 },
            { title: 'CVSS', key: 'cvss_score', width: 60 },
            { title: '描述', key: 'description', ellipsis: { tooltip: true } },
          ]"
          :bordered="false"
          size="small"
          :max-height="400"
        />
      </template>
    </NModal>

    <!-- Exploit代码查看 Modal -->
    <NModal v-model:show="exploitModalVisible" preset="card" title="Exploit 代码" style="width:800px">
      <div v-if="exploitLoading" style="text-align:center;padding:40px;color:#999">加载中...</div>
      <template v-else>
        <div v-if="exploitMeta" style="margin-bottom:8px;font-size:12px;color:#666">
          来源: {{ exploitMeta.source }} &nbsp;|&nbsp;
          <a v-if="exploitMeta.raw_url" :href="exploitMeta.raw_url" target="_blank" rel="noopener" style="color:#2080f0">原始链接</a>
        </div>
        <pre style="max-height:600px;overflow:auto;background:#1e1e1e;color:#d4d4d4;padding:12px;border-radius:6px;font-size:12px;font-family:'Fira Code',Consolas,monospace;white-space:pre-wrap;word-break:break-all">{{ exploitContent }}</pre>
      </template>
    </NModal>
  </div>
</template>
