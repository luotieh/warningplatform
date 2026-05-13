<script lang="ts" setup>
import type { DataTableColumns } from 'naive-ui';

import { computed, h, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import type { Asset, AssetEnrichDetail, RiskTrendItem } from '#/api/asset';
import {
  deleteAsset,
  enrichAsset,
  getAssetDetail,
  getAssetEnrich,
  getAssetRiskTrend,
  recalcAssetRisk,
} from '#/api/asset';
import { getAssetChangeLogs } from '#/api/assetmgr';
import { createTask } from '#/api/task';

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
  NPopconfirm,
  NSpace,
  NStatistic,
  NTabPane,
  NTabs,
  NTag,
  useMessage,
} from 'naive-ui';

defineOptions({ name: 'AssetDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();

const assetId = computed(() => route.params.id as string);

const loading = ref(false);
const enrichLoading = ref(false);
const asset = ref<Asset | null>(null);
const enrich = ref<AssetEnrichDetail | null>(null);
const riskTrend = ref<RiskTrendItem[]>([]);
const activeTab = ref('basic');

const changeLogs = ref<any[]>([]);
const changeLogsLoading = ref(false);

const changeTypeMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
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
  asset_subtype: '资产子类',
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
  system_type: '系统类型',
  type: '资产类型',
  version: '版本',
};

const changeLogColumns: DataTableColumns<any> = [
  {
    title: '变更类型', key: 'change_type', width: 100,
    render: (row: any) => {
      const meta = changeTypeMap[row.change_type];
      return meta ? h(NTag, { size: 'small', type: meta.type }, () => meta.label) : row.change_type;
    },
  },
  { title: '字段', key: 'field', width: 130, render: (row: any) => fieldLabelMap[row.field] || row.field },
  { title: '旧值', key: 'old_value', width: 160, ellipsis: { tooltip: true } },
  { title: '新值', key: 'new_value', width: 160, ellipsis: { tooltip: true } },
  { title: '来源', key: 'source', width: 90, render: (row: any) => sourceLabelMap[row.source] || row.source },
  { title: '操作人', key: 'operator', width: 110, ellipsis: { tooltip: true } },
  { title: '时间', key: 'created_at', width: 160, render: (row: any) => formatDateTime(row.created_at) },
];

const severityMap: Record<string, { label: string; type: 'default' | 'error' | 'info' | 'success' | 'warning' }> = {
  critical: { label: '严重', type: 'error' },
  high: { label: '高危', type: 'error' },
  medium: { label: '中危', type: 'warning' },
  low: { label: '低危', type: 'info' },
  info: { label: '信息', type: 'default' },
};

const vulnColumns: DataTableColumns<any> = [
  { title: '漏洞名称', key: 'title', ellipsis: { tooltip: true }, width: 300 },
  {
    title: '严重程度', key: 'severity', width: 100,
    render: (row) => {
      const meta = severityMap[row.severity] || { label: row.severity, type: 'default' as const };
      return h(NTag, { size: 'small', type: meta.type }, () => meta.label);
    },
  },
  { title: '状态', key: 'status', width: 80 },
  { title: '目标', key: 'target', width: 150, ellipsis: { tooltip: true } },
  { title: '发现时间', key: 'created_at', width: 170, render: (row: any) => formatDateTime(row.created_at) },
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
  if (row.url) return row.url;
  if (row.domain) return row.port ? `${row.domain}:${row.port}` : row.domain;
  if (row.ipv4) return row.port ? `${row.ipv4}:${row.port}` : row.ipv4;
  return row.port ? `${row.address}:${row.port}` : row.address;
}

async function fetchDetail() {
  loading.value = true;
  try {
    asset.value = await getAssetDetail(assetId.value);
  } catch {
    message.error('获取资产详情失败');
  } finally {
    loading.value = false;
  }
}

async function fetchEnrich() {
  enrichLoading.value = true;
  try {
    enrich.value = await getAssetEnrich(assetId.value) ?? null;
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
    await enrichAsset(assetId.value);
    message.success('富化完成');
    await fetchEnrich();
  } catch {
    message.error('富化失败');
  } finally {
    enrichLoading.value = false;
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
  try {
    await createTask({ name: `扫描-${asset.value.name || asset.value.address}`, targets: [target] });
    message.success('扫描任务已创建');
  } catch {
    message.error('创建扫描任务失败');
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
    const items: any = await getAssetChangeLogs(assetId.value);
    changeLogs.value = Array.isArray(items) ? items : [];
  } catch {
    changeLogs.value = [];
  } finally {
    changeLogsLoading.value = false;
  }
}

onMounted(() => {
  fetchDetail();
  fetchEnrich();
});
</script>

<template>
  <div style="padding: 16px">
    <NSpace vertical :size="16">
      <!-- 头部 -->
      <NCard size="small">
        <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px">
          <div style="display: flex; align-items: center; gap: 12px">
            <NButton text @click="router.back()" style="font-size: 18px">
              ←
            </NButton>
            <h2 style="margin: 0; font-size: 20px">
              {{ asset?.name || '资产详情' }}
            </h2>
            <NTag v-if="asset?.is_key" type="warning" size="small">关键资产</NTag>
          </div>
          <NSpace :size="8">
            <NButton size="small" type="warning" @click="onScan">发起扫描</NButton>
            <NButton size="small" type="info" :loading="enrichLoading" @click="onEnrich">信息富化</NButton>
            <NButton size="small" @click="onRecalcRisk">风险重算</NButton>
            <NButton size="small" @click="router.push(`/asset/ledger?edit=${assetId}`)">编辑</NButton>
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
                <span :style="{ color: getRiskColor(asset?.risk_score ?? 0), fontSize: '14px' }">分</span>
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
            <NStatistic label="开放端口" :value="enrich?.ports?.length ?? 0" />
          </NCard>
        </NGridItem>
      </NGrid>

      <!-- 详情标签页 -->
      <NCard size="small" :bordered="false">
        <NTabs v-model:value="activeTab" type="line" @update:value="onTabChange">
          <!-- 基本信息 -->
          <NTabPane name="basic" tab="基本信息">
            <NDescriptions :column="2" label-placement="left" bordered size="small">
              <NDescriptionsItem label="系统名称">{{ asset?.name || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="资产类型">{{ asset?.type || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="资产分类">{{ asset?.asset_family || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="资产子类">{{ asset?.asset_subtype || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="系统类型">{{ asset?.system_type || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="数据编号">{{ asset?.data_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="地域">{{ asset?.region_name || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="是否联网">
                <NTag :type="asset?.is_online ? 'success' : 'default'" size="small">
                  {{ asset?.is_online ? '是' : '否' }}
                </NTag>
              </NDescriptionsItem>
              <NDescriptionsItem label="是否关键资产">
                <NTag :type="asset?.is_key ? 'warning' : 'default'" size="small">
                  {{ asset?.is_key ? '是' : '否' }}
                </NTag>
              </NDescriptionsItem>
              <NDescriptionsItem label="安全保护等级">{{ asset?.security_protection_level || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="备案证明编号">{{ asset?.filing_cert_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="ICP备案号">{{ asset?.icp_filing_number || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="数据来源">{{ asset?.data_source || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="责任人">{{ asset?.responsible_user_name || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="备注">{{ asset?.remark || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="创建时间">{{ formatDateTime(asset?.created_at) }}</NDescriptionsItem>
              <NDescriptionsItem label="更新时间">{{ formatDateTime(asset?.updated_at) }}</NDescriptionsItem>
            </NDescriptions>
          </NTabPane>

          <!-- 网络信息 -->
          <NTabPane name="network" tab="网络信息">
            <NDescriptions :column="2" label-placement="left" bordered size="small">
              <NDescriptionsItem label="地址">{{ asset?.address || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="域名">{{ asset?.domain || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="IPv4">{{ asset?.ipv4 || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="IPv6">{{ asset?.ipv6 || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="URL">{{ asset?.url || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="端口">{{ asset?.port || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="协议">{{ asset?.protocol || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="服务">{{ asset?.service || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="版本">{{ asset?.version || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="操作系统">{{ asset?.os || '-' }}</NDescriptionsItem>
              <NDescriptionsItem label="SSL证书到期">{{ formatDate(asset?.ssl_expires_at) }}</NDescriptionsItem>
              <NDescriptionsItem label="域名到期">{{ formatDate(asset?.domain_expires_at) }}</NDescriptionsItem>
            </NDescriptions>

            <NDivider>端口与服务</NDivider>
            <NDataTable
              v-if="enrich?.ports?.length || enrich?.services?.length"
              :columns="[
                { title: '端口', key: 'port', width: 80 },
                { title: '协议', key: 'protocol', width: 80 },
                { title: '服务', key: 'service', width: 150 },
                { title: '版本', key: 'version', width: 150 },
              ]"
              :data="enrich.ports"
              :bordered="false"
              size="small"
              :max-height="400"
            />
            <NEmpty v-else description="暂无端口与服务数据" />
          </NTabPane>

          <!-- 漏洞列表 -->
          <NTabPane name="vulns" tab="漏洞列表">
            <NDataTable
              v-if="enrich?.asset_vulns?.length || enrich?.vulns?.length"
              :columns="vulnColumns"
              :data="enrich?.asset_vulns?.length ? enrich.asset_vulns : (enrich?.vulns || [])"
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
                { title: '记录时间', key: 'recorded_at', width: 180, render: (row: any) => formatDateTime(row.recorded_at) },
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
                { title: '任务名称', key: 'name', width: 200, ellipsis: { tooltip: true } },
                { title: '状态', key: 'status', width: 100 },
                { title: '创建时间', key: 'created_at', width: 170, render: (row: any) => formatDateTime(row.created_at) },
                { title: '完成时间', key: 'finished_at', width: 170, render: (row: any) => formatDateTime(row.finished_at) },
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
            <NDataTable
              v-if="changeLogs.length"
              :columns="changeLogColumns"
              :data="changeLogs"
              :bordered="false"
              size="small"
              :max-height="500"
              striped
              :loading="changeLogsLoading"
            />
            <NEmpty v-else description="暂无变更记录" />
          </NTabPane>
        </NTabs>
      </NCard>
    </NSpace>
  </div>
</template>