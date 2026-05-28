<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h, onBeforeUnmount, onMounted, ref, watch } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { useTabs } from '@vben/hooks';

import type { Asset, AssetEnrichDetail, RiskTrendItem } from '#/api/asset';
import {
  deleteAsset,
  enrichAsset,
  getAssetDetail,
  getAssetEnrich,
  getAssetRiskTrend,
  getAssetScreenshot,
  recalcAssetRisk,
} from '#/api/asset';
import {
  getAssetChangeLogs,
  getConstructionList,
  getOrganizeDetail,
} from '#/api/assetmgr';
import {
  createTask,
  getScanEnginePresets,
  type ScanEnginePreset,
} from '#/api/task';
import { fetchAuthImageObjectUrl } from '#/composables/useAuthImageObjectUrl';

import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDivider,
  NEmpty,
  NGrid,
  NGridItem,
  NModal,
  NPopconfirm,
  NSelect,
  NSpace,
  NSpin,
  NStatistic,
  NTabPane,
  NTabs,
  NTag,
  NTooltip,
  useMessage,
} from 'naive-ui';

defineOptions({ name: 'AssetDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const { setTabTitle, resetTabTitle } = useTabs();

const assetId = computed(() => route.params.id as string);

const loading = ref(false);
const enrichLoading = ref(false);
const scanSubmitting = ref(false);
const asset = ref<Asset | null>(null);
const enrich = ref<AssetEnrichDetail | null>(null);
const riskTrend = ref<RiskTrendItem[]>([]);
const activeTab = ref('basic');

const changeLogs = ref<any[]>([]);
const changeLogsLoading = ref(false);
const screenshotRefreshing = ref(false);
const showScreenshotPreview = ref(false);

const screenshotUrl = ref('');
const screenshotObjectUrl = ref('');

const screenshotSrc = computed(() => {
  if (screenshotObjectUrl.value) return screenshotObjectUrl.value;
  const b64 = asset.value?.screenshot || enrich.value?.screenshot;
  if (!b64 || b64.length < 100) return '';
  return `data:image/jpeg;base64,${b64}`;
});
/** 所属单位名称（接口仅返回 organize_id，名称需单独查组织） */
const organizeName = ref('');
const operationOrgName = ref('');

const enginePresets = ref<ScanEnginePreset[]>([]);
const scanEnginePreset = ref('');

const enginePresetDetailOptions = computed(() => [
  { label: '不使用预设', value: '' },
  ...enginePresets.value.map((p) => ({
    label: `${p.name} — ${p.description}`,
    value: p.name,
  })),
]);

const changeTypeMap: Record<
  string,
  { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }
> = {
  create: { label: '创建', type: 'success' },
  delete: { label: '删除', type: 'error' },
  state_change: { label: '状态变更', type: 'warning' },
  update: { label: '更新', type: 'info' },
};

const sourceLabelMap: Record<string, string> = {
  asset_import: '资产导入',
  system: '系统',
  user: '人工',
};

const fieldLabelMap: Record<string, string> = {
  address: '地址',
  asset_family: '资产分类',
  data_source: '数据来源',
  domain: '域名',
  name: '系统名称',
  organize_id: '所属单位',
  port: '端口',
  protocol: '协议',
  remark: '备注',
  responsible_user_name: '责任人',
  security_protection_level: '等保等级',
  service: '服务',
  version: '版本',
  'lifecycle state': '生命周期状态',
  lifecycle_state: '生命周期状态',
  is_online: '在线状态',
  is_key: '关键资产',
  ipv4: 'IPv4',
  ipv6: 'IPv6',
  data_number: '数据编号',
};

/** 资产分类 value → 展示名（与台账字典一致，缺省时回退原文） */
const assetFamilyLabelMap: Record<string, string> = {
  ip: 'IP资产',
  domain_site: '域名网站',
  business_system: '业务系统',
  hardware: '硬件设备',
  software: '软件资产',
  app: 'APP',
  mini_program: '小程序',
  official_account: '公众号',
  public_mailbox: '公共邮箱',
  other: '其他',
};

function formatOperatorDisplay(raw?: string) {
  if (!raw || raw === '-') return '-';
  const s = String(raw);
  if (s.length <= 14) return s;
  return `${s.slice(0, 8)}…${s.slice(-6)}`;
}

const changeLogColumns: DataTableColumns<any> = [
  {
    title: '变更类型',
    key: 'change_type',
    width: 100,
    render: (row: any) => {
      const meta = changeTypeMap[row.change_type];
      return meta
        ? h(NTag, { size: 'small', type: meta.type }, () => meta.label)
        : row.change_type;
    },
  },
  {
    title: '字段',
    key: 'field',
    minWidth: 120,
    width: 140,
    ellipsis: { tooltip: true },
    render: (row: any) => fieldLabelMap[row.field] || row.field,
  },
  {
    title: '旧值',
    key: 'old_value',
    minWidth: 100,
    width: 140,
    ellipsis: { tooltip: true },
  },
  {
    title: '新值',
    key: 'new_value',
    minWidth: 100,
    width: 140,
    ellipsis: { tooltip: true },
  },
  {
    title: '来源',
    key: 'source',
    width: 88,
    render: (row: any) => sourceLabelMap[row.source] || row.source || '-',
  },
  {
    title: '操作人',
    key: 'operator',
    minWidth: 120,
    width: 160,
    render: (row: any) => {
      const full = row.operator ?? '-';
      const short = formatOperatorDisplay(full === '-' ? undefined : full);
      return h(
        'span',
        {
          class: 'asset-detail__mono',
          title: full === short ? undefined : full,
        },
        short,
      );
    },
  },
  {
    title: '时间',
    key: 'created_at',
    width: 172,
    render: (row: any) => formatDateTime(row.created_at),
  },
];

/** 端口探测表：优先 ports；仅有 services 时映射为同列结构（避免 data 为 undefined 导致表格报错） */
const portProbeRows = computed(() => {
  const e = enrich.value;
  if (!e) return [];
  const ports = e.ports;
  if (Array.isArray(ports) && ports.length > 0) {
    return ports.map((row) => ({
      port: row.port,
      protocol: row.protocol ?? '-',
      service: row.service ?? '-',
      version: row.version ?? '-',
    }));
  }
  const services = e.services;
  if (Array.isArray(services) && services.length > 0) {
    return services.map((row) => ({
      port: row.port ?? '-',
      protocol: row.protocol?.trim() || '-',
      service: row.service_name ?? '-',
      version: row.version ?? '-',
    }));
  }
  return [];
});

const assetFamilyLabel = computed(() => {
  const v = asset.value?.asset_family;
  if (!v) return '-';
  return assetFamilyLabelMap[v] ?? v;
});

const assetTargetLine = computed(() => {
  if (!asset.value) return '';
  return getAssetTarget(asset.value) || '-';
});

const severityMap: Record<
  string,
  { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }
> = {
  critical: { label: '严重', type: 'error' },
  high: { label: '高危', type: 'error' },
  medium: { label: '中危', type: 'warning' },
  low: { label: '低危', type: 'info' },
  info: { label: '信息', type: 'default' },
};

const vulnColumns: DataTableColumns<any> = [
  { title: '漏洞名称', key: 'title', ellipsis: { tooltip: true }, width: 300 },
  {
    title: '严重程度',
    key: 'severity',
    width: 100,
    render: (row) => {
      const meta = severityMap[row.severity] || {
        label: row.severity,
        type: 'default' as const,
      };
      return h(NTag, { size: 'small', type: meta.type }, () => meta.label);
    },
  },
  { title: '状态', key: 'status', width: 80 },
  { title: '目标', key: 'target', width: 150, ellipsis: { tooltip: true } },
  {
    title: '发现时间',
    key: 'created_at',
    width: 170,
    render: (row: any) => formatDateTime(row.created_at),
  },
];

function formatDateTime(value?: string) {
  if (!value) return '-';
  return value.replace('T', ' ').replace(/\.\d+.*$/, '');
}

function formatDate(value?: string) {
  if (!value) return '-';
  return value.slice(0, 10);
}

function getRiskColor(score: number) {
  if (score >= 70) return '#d03050';
  if (score >= 40) return '#f0a020';
  return '#18a058';
}

function getAssetTarget(row: Asset) {
  if (row.address) return row.address;
  if (row.domain) return row.port ? `${row.domain}:${row.port}` : row.domain;
  if (row.ipv4) return row.port ? `${row.ipv4}:${row.port}` : row.ipv4;
  return row.port ? `${row.address}:${row.port}` : row.address;
}

function resolveScanTemplateId(row: Asset) {
  if (
    [
      'domain_site',
      'business_system',
      'app',
      'mini_program',
      'official_account',
      'public_mailbox',
    ].includes(row.asset_family || '')
  ) {
    return 'web-full';
  }
  return 'full';
}

async function fetchOrganizeName(orgId?: string) {
  organizeName.value = '';
  if (!orgId) return;
  try {
    const org: any = await getOrganizeDetail(orgId);
    organizeName.value = org?.name?.trim() || '';
  } catch {
    organizeName.value = '';
  }
}

async function fetchOperationOrgName(orgId?: string) {
  operationOrgName.value = '';
  if (!orgId) return;
  try {
    const res: any = await getConstructionList({ page: 1, page_size: 500 });
    const body = res?.data ?? res;
    const list = (body?.data ?? body ?? []) as Array<{
      id: string;
      name?: string;
    }>;
    operationOrgName.value =
      list.find((item) => item.id === orgId)?.name?.trim() ?? '';
  } catch {
    operationOrgName.value = '';
  }
}

async function syncTabTitleWithAsset() {
  const name = asset.value?.name?.trim();
  if (name) await setTabTitle(`资产 · ${name}`);
  else await setTabTitle('资产详情');
}

async function fetchDetail() {
  loading.value = true;
  try {
    asset.value = await getAssetDetail(assetId.value);
    await Promise.all([
      fetchOrganizeName(asset.value?.organize_id),
      fetchOperationOrgName(asset.value?.operation_org_id),
      syncTabTitleWithAsset(),
      fetchScreenshotStatus(),
    ]);
  } catch {
    message.error('获取资产详情失败');
    asset.value = null;
    organizeName.value = '';
    operationOrgName.value = '';
    await syncTabTitleWithAsset();
  } finally {
    loading.value = false;
  }
}

async function fetchScreenshotStatus() {
  try {
    const res = await getAssetScreenshot(assetId.value);
    if (res?.screenshot_url) {
      screenshotUrl.value = res.screenshot_url;
      await loadScreenshotFromStorage();
    } else {
      screenshotUrl.value = '';
    }
  } catch {
    screenshotUrl.value = '';
  }
}

async function loadScreenshotFromStorage() {
  if (!screenshotUrl.value) return;
  try {
    if (screenshotObjectUrl.value)
      URL.revokeObjectURL(screenshotObjectUrl.value);
    screenshotObjectUrl.value = await fetchAuthImageObjectUrl(
      screenshotUrl.value,
    );
  } catch {
    screenshotObjectUrl.value = '';
  }
}

async function fetchEnrich() {
  enrichLoading.value = true;
  try {
    enrich.value = (await getAssetEnrich(assetId.value)) ?? null;
  } catch {
    enrich.value = null;
  } finally {
    enrichLoading.value = false;
  }
}

async function fetchRiskTrend() {
  try {
    const res: any = await getAssetRiskTrend(assetId.value);
    riskTrend.value = (res?.data ?? res) || [];
  } catch {
    riskTrend.value = [];
  }
}

async function onEnrich() {
  enrichLoading.value = true;
  try {
    const data = await enrichAsset(assetId.value);
    const tid = data?.task_id;
    message.success(
      tid
        ? `已提交「${data.template || '资产信息富化'}」扫描（任务 ID：${tid}）。完成后结果会回写到本资产；富化任务记录将自动清理，请刷新本页查看。再次富化可点「信息富化」。`
        : '已提交富化扫描，完成后请刷新本页查看结果。',
    );
    await Promise.all([fetchDetail(), fetchEnrich()]);
  } catch {
    message.error('富化失败');
  } finally {
    enrichLoading.value = false;
  }
}

async function onRefreshScreenshot() {
  screenshotRefreshing.value = true;
  try {
    const res = await getAssetScreenshot(assetId.value, true);
    if (res?.screenshot_url) {
      screenshotUrl.value = res.screenshot_url;
      if (asset.value) asset.value.screenshot = '';
      await loadScreenshotFromStorage();
      message.success('截图已刷新');
    } else if (res?.screenshot && asset.value) {
      screenshotUrl.value = '';
      asset.value.screenshot = res.screenshot;
      message.success('截图已刷新');
    } else {
      message.warning(
        '未能采集到截图（可能目标地址不可达或服务器未安装浏览器）',
      );
    }
  } catch {
    message.error('截图刷新失败');
  } finally {
    screenshotRefreshing.value = false;
  }
}

async function onRecalcRisk() {
  try {
    await recalcAssetRisk(assetId.value);
    message.success('风险重算完成');
    await fetchDetail();
  } catch {
    message.error('风险重算失败');
  }
}

async function onScan() {
  if (!asset.value) return;
  const target = getAssetTarget(asset.value);
  if (!target) {
    message.warning('当前资产缺少可扫描地址');
    return;
  }
  scanSubmitting.value = true;
  try {
    const parameters: Record<string, any> = {};
    if (scanEnginePreset.value)
      parameters.engine_preset = scanEnginePreset.value;
    await createTask({
      name: `扫描-${asset.value.name || asset.value.address}`,
      targets: [target],
      template_id: resolveScanTemplateId(asset.value),
      parameters: Object.keys(parameters).length > 0 ? parameters : undefined,
    });
    message.success('扫描任务已创建');
  } catch (e: any) {
    message.error(e?.message || '创建扫描任务失败');
  } finally {
    scanSubmitting.value = false;
  }
}

async function onDelete() {
  try {
    await deleteAsset(assetId.value);
    message.success('删除成功');
    router.replace('/asset/ledger');
  } catch {
    message.error('删除失败');
  }
}

function onTabChange(tab: string) {
  activeTab.value = tab;
  if (tab === 'riskTrend') fetchRiskTrend();
  if (tab === 'changelog') fetchChangeLogs();
}

async function fetchChangeLogs() {
  if (changeLogs.value.length) return;
  changeLogsLoading.value = true;
  try {
    const raw: any = await getAssetChangeLogs(assetId.value);
    const list = Array.isArray(raw) ? raw : (raw?.items ?? raw?.data ?? []);
    changeLogs.value = Array.isArray(list) ? list : [];
  } catch {
    changeLogs.value = [];
  } finally {
    changeLogsLoading.value = false;
  }
}

async function loadEnginePresetsForDetail() {
  try {
    enginePresets.value = await getScanEnginePresets();
  } catch {
    enginePresets.value = [];
  }
}

watch(
  assetId,
  () => {
    organizeName.value = '';
    changeLogs.value = [];
    riskTrend.value = [];
    scanEnginePreset.value = '';
    void resetTabTitle();
    void fetchDetail();
    void fetchEnrich();
  },
  { immediate: true },
);

onMounted(() => {
  void loadEnginePresetsForDetail();
});

onBeforeUnmount(() => {
  void resetTabTitle();
  if (screenshotObjectUrl.value) URL.revokeObjectURL(screenshotObjectUrl.value);
});
</script>

<template>
  <div style="padding: 16px">
    <NSpace vertical :size="16">
      <!-- 头部 -->
      <NCard size="small" class="asset-detail__head-card">
        <div class="asset-detail__head-row">
          <div class="asset-detail__head-main">
            <NButton text class="asset-detail__back" @click="router.back()"
              >← 返回</NButton
            >
            <div class="asset-detail__head-text">
              <div class="asset-detail__title-line">
                <h2 class="asset-detail__title">
                  {{ asset?.name || '资产详情' }}
                </h2>
                <NTag v-if="asset?.is_key" type="warning" size="small"
                  >关键资产</NTag
                >
                <NTag
                  v-if="asset?.reachable_checked_at"
                  :type="asset?.reachable ? 'success' : 'default'"
                  size="small"
                >
                  {{ asset?.reachable ? '在线' : '离线' }}
                </NTag>
              </div>
              <div v-if="asset" class="asset-detail__meta-line">
                <span class="asset-detail__meta-item">
                  <span class="asset-detail__meta-k">访问目标</span
                  >{{ assetTargetLine }}
                </span>
                <span class="asset-detail__meta-sep">·</span>
                <span class="asset-detail__meta-item">
                  <span class="asset-detail__meta-k">分类</span
                  >{{ assetFamilyLabel }}
                </span>
                <template v-if="asset.data_number">
                  <span class="asset-detail__meta-sep">·</span>
                  <span class="asset-detail__meta-item">
                    <span class="asset-detail__meta-k">数据编号</span
                    >{{ asset.data_number }}
                  </span>
                </template>
                <template v-if="asset.organize_id || organizeName">
                  <span class="asset-detail__meta-sep">·</span>
                  <span class="asset-detail__meta-item">
                    <span class="asset-detail__meta-k">所属单位</span>
                    <template v-if="organizeName">{{ organizeName }}</template>
                    <template v-else>
                      <span
                        class="asset-detail__mono"
                        :title="asset.organize_id"
                        >{{ asset.organize_id }}</span
                      >
                    </template>
                  </span>
                </template>
              </div>
            </div>
          </div>
          <NSpace
            :size="8"
            class="asset-detail__head-actions"
            align="center"
            wrap
          >
            <NSelect
              v-model:value="scanEnginePreset"
              class="asset-detail__scan-preset"
              size="small"
              :options="enginePresetDetailOptions"
              placeholder="引擎预设（可选）"
              filterable
              clearable
              :consistent-menu-width="false"
            />
            <NButton
              size="small"
              type="warning"
              :loading="scanSubmitting"
              @click="onScan"
              >发起扫描</NButton
            >
            <NTooltip placement="bottom" :content-style="{ maxWidth: '380px' }">
              <template #trigger>
                <NButton
                  size="small"
                  type="info"
                  :loading="enrichLoading"
                  @click="onEnrich"
                  >信息富化</NButton
                >
              </template>
              根据访问地址 / IPv4 / 域名尝试解析并补全信息（如解析出
              IP、反向域名、SSL
              证书到期时间等），并写回当前资产记录；下方「网络信息」与统计会随之更新。
            </NTooltip>
            <NButton size="small" @click="onRecalcRisk">风险重算</NButton>
            <NButton
              size="small"
              @click="router.push(`/asset/ledger?edit=${assetId}`)"
              >编辑</NButton
            >
            <NPopconfirm @positive-click="onDelete">
              <template #trigger>
                <NButton size="small" type="error">删除</NButton>
              </template>
              确认删除该资产？
            </NPopconfirm>
          </NSpace>
        </div>
      </NCard>

      <!-- 统计卡片 -->
      <NGrid :cols="5" :x-gap="16">
        <NGridItem>
          <NCard size="small">
            <NStatistic label="风险评分" :value="asset?.risk_score ?? 0">
              <template #suffix>
                <span
                  :style="{
                    color: getRiskColor(asset?.risk_score ?? 0),
                    fontSize: '14px',
                  }"
                  >分</span
                >
              </template>
            </NStatistic>
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small">
            <NStatistic label="漏洞数" :value="asset?.vuln_count ?? 0" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small">
            <NStatistic label="告警数" :value="asset?.events_count ?? 0" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small">
            <NStatistic label="通报数" :value="asset?.circular_count ?? 0" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small">
            <NStatistic label="开放端口" :value="portProbeRows.length" />
          </NCard>
        </NGridItem>
      </NGrid>

      <!-- 首页截图 -->
      <NCard size="small" title="首页截图">
        <template #header-extra>
          <NButton
            size="small"
            :loading="screenshotRefreshing"
            @click="onRefreshScreenshot"
          >
            {{ screenshotSrc ? '刷新截图' : '采集截图' }}
          </NButton>
        </template>
        <div
          v-if="screenshotSrc"
          class="asset-detail__screenshot"
          @click="showScreenshotPreview = true"
        >
          <img :src="screenshotSrc" alt="首页截图" />
          <div class="asset-detail__screenshot-hint">点击查看大图</div>
        </div>
        <NEmpty v-else description="暂无截图，点击「采集截图」获取" />
      </NCard>

      <NModal
        v-model:show="showScreenshotPreview"
        preset="card"
        title="首页截图"
        style="width: 90vw; max-width: 1200px"
      >
        <div style="text-align: center">
          <img
            :src="screenshotSrc"
            alt="首页截图"
            style="max-width: 100%; height: auto; border-radius: 4px"
          />
        </div>
      </NModal>

      <!-- 详情标签页 -->
      <NCard size="small" :bordered="false">
        <NTabs
          v-model:value="activeTab"
          type="line"
          @update:value="onTabChange"
        >
          <!-- 基本信息 -->
          <NTabPane name="basic" tab="基本信息">
            <NDescriptions
              :column="2"
              label-placement="left"
              bordered
              size="small"
            >
              <NDescriptionsItem label="系统名称">{{
                asset?.name || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="所属单位">
                <template v-if="organizeName">{{ organizeName }}</template>
                <span
                  v-else-if="asset?.organize_id"
                  class="asset-detail__mono"
                  >{{ asset.organize_id }}</span
                >
                <template v-else>-</template>
              </NDescriptionsItem>
              <NDescriptionsItem label="资产分类">{{
                assetFamilyLabel
              }}</NDescriptionsItem>
              <NDescriptionsItem label="数据编号">{{
                asset?.data_number || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="运维单位">
                <template v-if="operationOrgName">{{
                  operationOrgName
                }}</template>
                <span
                  v-else-if="asset?.operation_org_id"
                  class="asset-detail__mono"
                  >{{ asset.operation_org_id }}</span
                >
                <template v-else>-</template>
              </NDescriptionsItem>
              <NDescriptionsItem label="是否联网">
                <NTag
                  :type="asset?.is_online ? 'success' : 'default'"
                  size="small"
                >
                  {{ asset?.is_online ? '是' : '否' }}
                </NTag>
              </NDescriptionsItem>
              <NDescriptionsItem label="在线状态（探测）">
                <template v-if="asset?.reachable_checked_at">
                  <NTag
                    :type="asset?.reachable ? 'success' : 'default'"
                    size="small"
                  >
                    {{ asset?.reachable ? '在线' : '离线' }}
                  </NTag>
                  <span class="asset-detail__meta-k" style="margin-left: 8px">
                    {{ formatDateTime(asset.reachable_checked_at) }}
                  </span>
                </template>
                <template v-else>未检测</template>
              </NDescriptionsItem>
              <NDescriptionsItem label="是否关键资产">
                <NTag
                  :type="asset?.is_key ? 'warning' : 'default'"
                  size="small"
                >
                  {{ asset?.is_key ? '是' : '否' }}
                </NTag>
              </NDescriptionsItem>
              <NDescriptionsItem label="安全保护等级">{{
                asset?.security_protection_level || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="等保备案证明编号">{{
                asset?.filing_cert_number || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="ICP备案号">{{
                asset?.icp_filing_number || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="数据来源">{{
                asset?.data_source || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="责任人">{{
                asset?.responsible_user_name || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="备注">{{
                asset?.remark || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="创建时间">{{
                formatDateTime(asset?.created_at)
              }}</NDescriptionsItem>
              <NDescriptionsItem label="更新时间">{{
                formatDateTime(asset?.updated_at)
              }}</NDescriptionsItem>
            </NDescriptions>
          </NTabPane>

          <!-- 网络信息 -->
          <NTabPane name="network" tab="网络信息">
            <NDescriptions
              :column="2"
              label-placement="left"
              bordered
              size="small"
            >
              <NDescriptionsItem label="访问地址">{{
                asset?.address || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="域名">{{
                asset?.domain || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="IPv4">{{
                asset?.ipv4 || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="IPv6">{{
                asset?.ipv6 || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="端口">{{
                asset?.port ?? '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="协议">{{
                asset?.protocol || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="服务">{{
                asset?.service || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="版本">{{
                asset?.version || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="操作系统">{{
                asset?.os || '-'
              }}</NDescriptionsItem>
              <NDescriptionsItem label="SSL证书到期">{{
                formatDate(asset?.ssl_expires_at)
              }}</NDescriptionsItem>
              <NDescriptionsItem label="域名到期">{{
                formatDate(asset?.domain_expires_at)
              }}</NDescriptionsItem>
            </NDescriptions>

            <NDivider>端口与服务</NDivider>
            <NDataTable
              v-if="portProbeRows.length"
              :columns="[
                { title: '端口', key: 'port', width: 100 },
                { title: '协议', key: 'protocol', width: 90 },
                {
                  title: '服务',
                  key: 'service',
                  minWidth: 120,
                  ellipsis: { tooltip: true },
                },
                {
                  title: '版本',
                  key: 'version',
                  minWidth: 100,
                  ellipsis: { tooltip: true },
                },
              ]"
              :data="portProbeRows"
              :bordered="false"
              size="small"
              :max-height="400"
              :scroll-x="640"
            />
            <NEmpty v-else description="暂无端口与服务数据" />
          </NTabPane>

          <!-- 漏洞列表 -->
          <NTabPane name="vulns" tab="漏洞列表">
            <NDataTable
              v-if="enrich?.asset_vulns?.length || enrich?.vulns?.length"
              :columns="vulnColumns"
              :data="
                enrich?.asset_vulns?.length
                  ? enrich.asset_vulns
                  : enrich?.vulns || []
              "
              :bordered="false"
              size="small"
              :max-height="500"
              striped
            />
            <NEmpty v-else description="暂无漏洞数据" />
          </NTabPane>

          <!-- 风险趋势 -->
          <NTabPane name="riskTrend" tab="风险趋势">
            <NDataTable
              v-if="riskTrend.length"
              :columns="[
                {
                  title: '记录时间',
                  key: 'recorded_at',
                  width: 180,
                  render: (row: any) => formatDateTime(row.recorded_at),
                },
                { title: '综合评分', key: 'score', width: 100 },
                { title: '漏洞评分', key: 'vuln_score', width: 100 },
                { title: '暴露评分', key: 'exposure_score', width: 100 },
                { title: '告警评分', key: 'alert_score', width: 100 },
                { title: 'SSL评分', key: 'ssl_score', width: 100 },
              ]"
              :data="riskTrend"
              :bordered="false"
              size="small"
              :max-height="400"
            />
            <NEmpty v-else description="暂无风险趋势数据" />
          </NTabPane>

          <!-- 扫描历史 -->
          <NTabPane name="scanHistory" tab="扫描历史">
            <NDataTable
              v-if="enrich?.scan_history?.length"
              :columns="[
                {
                  title: '任务名称',
                  key: 'name',
                  width: 200,
                  ellipsis: { tooltip: true },
                },
                { title: '状态', key: 'status', width: 100 },
                {
                  title: '创建时间',
                  key: 'created_at',
                  width: 170,
                  render: (row: any) => formatDateTime(row.created_at),
                },
                {
                  title: '完成时间',
                  key: 'finished_at',
                  width: 170,
                  render: (row: any) => formatDateTime(row.finished_at),
                },
              ]"
              :data="enrich.scan_history"
              :bordered="false"
              size="small"
              :max-height="400"
            />
            <NEmpty v-else description="暂无扫描历史" />
          </NTabPane>

          <!-- 变更日志 -->
          <NTabPane name="changelog" tab="变更日志">
            <NSpin :show="changeLogsLoading">
              <NDataTable
                v-if="changeLogs.length"
                :columns="changeLogColumns"
                :data="changeLogs"
                :bordered="false"
                size="small"
                :max-height="500"
                striped
                :scroll-x="980"
              />
              <NEmpty
                v-else-if="!changeLogsLoading"
                description="暂无变更记录"
              />
            </NSpin>
          </NTabPane>
        </NTabs>
      </NCard>
    </NSpace>
  </div>
</template>

<style scoped>
.asset-detail__head-card :deep(.n-card__content) {
  padding-top: 12px;
  padding-bottom: 12px;
}

.asset-detail__head-row {
  align-items: flex-start;
  display: flex;
  flex-wrap: wrap;
  gap: 12px 16px;
  justify-content: space-between;
}

.asset-detail__head-main {
  display: flex;
  gap: 10px;
  min-width: 0;
}

.asset-detail__back {
  flex-shrink: 0;
  font-size: 15px;
  margin-top: 2px;
}

.asset-detail__head-text {
  min-width: 0;
}

.asset-detail__title-line {
  align-items: center;
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.asset-detail__title {
  font-size: 20px;
  font-weight: 600;
  line-height: 1.35;
  margin: 0;
}

.asset-detail__meta-line {
  color: var(--n-text-color-2);
  font-size: 13px;
  line-height: 1.6;
  margin-top: 6px;
  word-break: break-all;
}

.asset-detail__meta-k {
  color: var(--n-text-color-3);
  margin-right: 4px;
}

.asset-detail__meta-sep {
  color: var(--n-text-color-3);
  margin: 0 6px;
}

.asset-detail__meta-item {
  white-space: normal;
}

.asset-detail__head-actions {
  flex-shrink: 0;
}

.asset-detail__scan-preset {
  width: min(240px, 42vw);
}

.asset-detail__mono {
  font-family:
    ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, 'Liberation Mono',
    'Courier New', monospace;
  font-size: 12px;
}

.asset-detail__screenshot {
  position: relative;
  border: 1px solid var(--n-border-color);
  border-radius: 8px;
  max-width: 720px;
  margin: 0 auto;
  overflow: hidden;
  cursor: pointer;
  box-shadow: 0 2px 8px rgb(0 0 0 / 6%);
  transition:
    box-shadow 0.2s,
    transform 0.2s;
}

.asset-detail__screenshot:hover {
  box-shadow: 0 4px 16px rgb(0 0 0 / 12%);
  transform: translateY(-1px);
}

.asset-detail__screenshot img {
  display: block;
  height: auto;
  width: 100%;
}

.asset-detail__screenshot-hint {
  position: absolute;
  right: 0;
  bottom: 0;
  left: 0;
  padding: 4px 0;
  font-size: 12px;
  color: #fff;
  text-align: center;
  background: linear-gradient(transparent, rgb(0 0 0 / 40%));
  opacity: 0;
  transition: opacity 0.2s;
}

.asset-detail__screenshot:hover .asset-detail__screenshot-hint {
  opacity: 1;
}
</style>
