<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import {
  NButton,
  NEmpty,
  NPopconfirm,
  NSpin,
  NTag,
  NTimeline,
  NTimelineItem,
  NTooltip,
  useMessage,
} from 'naive-ui';

import {
  getVulnDetail,
  markFixed,
  markIgnored,
  reopenVuln,
  deleteVuln,
  getVulnStatusHistory,
  retestVuln,
  type Vulnerability,
  type VulnStatusHistory,
} from '#/api/vuln';
import { getProductDetail, type Product } from '#/api/product/index';
import {
  getTargetList,
  getTargetStats,
  type MonitorTarget,
  type TargetSummary,
} from '#/api/sitemonitor';

defineOptions({ name: 'VulnDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(true);
const retestLoading = ref(false);
const vuln = ref<Vulnerability | null>(null);
const history = ref<VulnStatusHistory[]>([]);
const productInfo = ref<Product | null>(null);

const sevConfig: Record<string, { label: string; fg: string; bg: string; border: string }> = {
  critical: { label: '严重', fg: '#cf1322', bg: '#fff1f0', border: '#ffa39e' },
  high: { label: '高危', fg: '#d46b08', bg: '#fff7e6', border: '#ffd591' },
  medium: { label: '中危', fg: '#d4b106', bg: '#fffbe6', border: '#ffe58f' },
  low: { label: '低危', fg: '#389e0d', bg: '#f6ffed', border: '#b7eb8f' },
  info: { label: '信息', fg: '#1890ff', bg: '#f0f5ff', border: '#91d5ff' },
};
const statusLabels: Record<string, string> = {
  open: '待修复', fixed: '已修复', ignored: '已忽略', reopened: '已重开', verified: '已验证',
};
const statusTypes: Record<string, string> = {
  open: 'error', fixed: 'success', ignored: 'default', reopened: 'warning', verified: 'error',
};

const sev = computed(() => sevConfig[vuln.value?.severity ?? ''] ?? sevConfig.info!);
const isActionable = computed(() => vuln.value?.status === 'open' || vuln.value?.status === 'reopened');
const isRestorable = computed(() => vuln.value?.status === 'fixed' || vuln.value?.status === 'ignored');

function formatTime(t?: string) {
  if (!t) return '-';
  return t.replace('T', ' ').slice(0, 19);
}

function cveUrl(id: string) {
  return `https://nvd.nist.gov/vuln/detail/${id}`;
}

function cweUrl(id: string) {
  const num = id.replace(/^CWE-/i, '');
  return `https://cwe.mitre.org/data/definitions/${num}.html`;
}

async function fetchData() {
  try {
    const id = route.params.id as string;
    vuln.value = await getVulnDetail(id);
    try {
      history.value = (await getVulnStatusHistory(id)) as unknown as VulnStatusHistory[] ?? [];
    } catch { history.value = []; }
    if (vuln.value?.product_id) {
      try {
        productInfo.value = await getProductDetail(vuln.value.product_id);
      } catch { productInfo.value = null; }
    }
  } finally {
    loading.value = false;
  }
}

function historyTimelineType(newStatus: string): 'error' | 'success' | 'warning' | 'info' | 'default' {
  const m: Record<string, any> = { open: 'error', fixed: 'success', ignored: 'default', reopened: 'warning' };
  return m[newStatus] ?? 'info';
}

async function handleAction(action: 'fix' | 'ignore' | 'reopen') {
  if (!vuln.value) return;
  try {
    if (action === 'fix') await markFixed(vuln.value.id);
    else if (action === 'ignore') await markIgnored(vuln.value.id);
    else await reopenVuln(vuln.value.id);
    message.success('操作成功');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '操作失败');
  }
}

async function handleRetest() {
  if (!vuln.value) return;
  retestLoading.value = true;
  try {
    const res = await retestVuln(vuln.value.id);
    message.success(res?.task_id ? `回测任务已提交（${res.task_id}）` : '回测任务已提交');
    if (res?.task_id) {
      router.push(`/scan/task/${res.task_id}`);
    }
  } catch (e: any) {
    message.error(e?.message || '回测失败');
  } finally {
    retestLoading.value = false;
  }
}

async function handleDelete() {
  if (!vuln.value) return;
  try {
    await deleteVuln(vuln.value.id);
    message.success('已删除');
    router.push('/vuln');
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

const evidenceCopied = ref(false);
function copyEvidence() {
  if (!vuln.value?.evidence) return;
  navigator.clipboard.writeText(vuln.value.evidence).then(() => {
    evidenceCopied.value = true;
    setTimeout(() => { evidenceCopied.value = false; }, 2000);
  }).catch(() => {});
}

const monitorTargets = ref<MonitorTarget[]>([]);
const monitorStatsMap = ref<Record<string, TargetSummary>>({});
const monitorLoading = ref(false);

const dimensionLabels: Record<string, string> = {
  availability: '可用性',
  tamper: '篡改',
  blacklink: '暗链',
  sensitive_word: '敏感词',
  domain_hijack: 'DNS劫持',
  sensitive_file: '敏感文件',
};

async function fetchMonitorForAsset() {
  const aid = vuln.value?.asset_id;
  if (!aid) return;
  monitorLoading.value = true;
  try {
    const [res, stats] = await Promise.all([
      getTargetList({ asset_id: aid, page: 1, page_size: 10 }),
      getTargetStats(),
    ]);
    monitorTargets.value = res?.data ?? [];
    monitorStatsMap.value = stats ?? {};
  } catch {
    monitorTargets.value = [];
    monitorStatsMap.value = {};
  } finally {
    monitorLoading.value = false;
  }
}

onMounted(async () => {
  await fetchData();
  fetchMonitorForAsset();
});
</script>

<template>
  <div class="vd-page">
    <NSpin :show="loading">
      <template v-if="vuln">
        <!-- Breadcrumb back -->
        <div class="vd-back" @click="router.push('/vuln')">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6" /></svg>
          返回漏洞列表
        </div>

        <!-- Header Card -->
        <div class="vd-header" :style="{ borderLeftColor: sev.fg }">
          <div class="vd-header__main">
            <div class="vd-header__top">
              <span class="vd-sev-badge" :style="{ background: sev.bg, color: sev.fg, borderColor: sev.border }">
                {{ sev.label }}
              </span>
              <NTag :type="(statusTypes[vuln.status] || 'default') as any" size="small" round :bordered="false">
                {{ statusLabels[vuln.status] ?? vuln.status }}
              </NTag>
              <span v-if="vuln.confidence != null" class="vd-confidence">
                置信度 {{ vuln.confidence }}%
              </span>
            </div>
            <h1 class="vd-title">{{ vuln.title }}</h1>
            <div class="vd-meta-row">
              <span class="vd-meta-item">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
                首次发现 {{ formatTime(vuln.first_seen_at) }}
              </span>
              <span class="vd-meta-item">
                最近发现 {{ formatTime(vuln.last_seen_at) }}
              </span>
              <span v-if="vuln.module_id" class="vd-meta-item">
                模块 {{ vuln.module_id }}
              </span>
            </div>
          </div>
          <div class="vd-header__actions">
            <NButton size="small" type="warning" :loading="retestLoading" @click="handleRetest">
              <template #icon>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>
              </template>
              回测
            </NButton>
            <NButton v-if="isActionable" size="small" type="success" @click="handleAction('fix')">标记修复</NButton>
            <NButton v-if="isActionable" size="small" secondary @click="handleAction('ignore')">忽略</NButton>
            <NButton v-if="isRestorable" size="small" type="warning" secondary @click="handleAction('reopen')">重新打开</NButton>
            <NPopconfirm @positive-click="handleDelete">
              <template #trigger>
                <NButton size="small" type="error" quaternary>删除</NButton>
              </template>
              确定删除此漏洞？
            </NPopconfirm>
          </div>
        </div>

        <!-- Two Column Layout -->
        <div class="vd-body">
          <!-- Left: Main Content -->
          <div class="vd-main">
            <!-- Target & References Info -->
            <div class="vd-info-card">
              <div class="vd-info-card__title">目标信息</div>
              <div class="vd-kv-grid">
                <div class="vd-kv">
                  <span class="vd-kv__label">目标</span>
                  <code class="vd-kv__value vd-kv__mono">{{ vuln.target }}{{ vuln.port ? `:${vuln.port}` : '' }}</code>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">URL</span>
                  <span class="vd-kv__value">{{ vuln.url || '-' }}</span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">CVE</span>
                  <span class="vd-kv__value">
                    <template v-if="vuln.cve_ids?.length">
                      <a
                        v-for="c in vuln.cve_ids" :key="c"
                        :href="cveUrl(c)"
                        target="_blank"
                        rel="noopener"
                        class="vd-cve-link"
                      >{{ c }}</a>
                    </template>
                    <span v-else class="vd-muted">-</span>
                  </span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">CWE</span>
                  <span class="vd-kv__value">
                    <template v-if="vuln.cwe_ids?.length">
                      <a
                        v-for="c in vuln.cwe_ids" :key="c"
                        :href="cweUrl(c)"
                        target="_blank"
                        rel="noopener"
                        class="vd-cve-link"
                        style="background: #f5f5f5; color: #555"
                      >{{ c }}</a>
                    </template>
                    <span v-else class="vd-muted">-</span>
                  </span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">关联任务</span>
                  <span class="vd-kv__value">
                    <NButton v-if="vuln.task_id" text type="info" size="small" @click="router.push(`/scan/task/${vuln.task_id}`)">{{ vuln.task_id }}</NButton>
                    <span v-else class="vd-muted">-</span>
                  </span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">关联资产</span>
                  <span class="vd-kv__value">
                    <NButton v-if="vuln.asset_id" text type="info" size="small" @click="router.push(`/asset/ledger?id=${vuln.asset_id}`)">{{ vuln.asset_id }}</NButton>
                    <span v-else class="vd-muted">未关联</span>
                  </span>
                </div>
              </div>
            </div>

            <!-- 站点监测关联 -->
            <div v-if="vuln.asset_id && monitorTargets.length" class="vd-info-card">
              <div class="vd-info-card__title">站点监测</div>
              <div
                v-for="mt in monitorTargets"
                :key="mt.id"
                class="vd-monitor-row"
              >
                <NButton
                  text
                  type="info"
                  size="small"
                  @click="router.push({ name: 'MonitorTargetDetail', params: { id: mt.id } })"
                >
                  {{ mt.name || mt.target_value }}
                </NButton>
                <NTag
                  :type="mt.enabled ? 'success' : 'default'"
                  size="small"
                >
                  {{ mt.enabled ? '启用' : '停用' }}
                </NTag>
                <template v-if="monitorStatsMap[mt.id]">
                  <NTag
                    v-for="(dim, key) in monitorStatsMap[mt.id]?.dimensions"
                    :key="key"
                    :type="dim.last_has_issue ? 'error' : 'success'"
                    size="small"
                    round
                  >
                    {{ dimensionLabels[key as string] || key }}
                    <template v-if="dim.issue_count > 0">
                      · {{ dim.issue_count }}
                    </template>
                  </NTag>
                </template>
              </div>
            </div>

            <!-- Affected Product -->
            <div v-if="productInfo" class="vd-info-card">
              <div class="vd-info-card__title">受影响产品</div>
              <div class="vd-kv-grid">
                <div class="vd-kv">
                  <span class="vd-kv__label">产品</span>
                  <span class="vd-kv__value" style="font-weight: 500">{{ productInfo.name }}</span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">厂商</span>
                  <span class="vd-kv__value">{{ productInfo.vendor || '-' }}</span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">分类</span>
                  <span class="vd-kv__value">{{ productInfo.category || '-' }}</span>
                </div>
                <div class="vd-kv">
                  <span class="vd-kv__label">主页</span>
                  <span class="vd-kv__value">
                    <a v-if="productInfo.homepage" :href="productInfo.homepage" target="_blank" rel="noopener" class="vd-cve-link">{{ productInfo.homepage }}</a>
                    <span v-else class="vd-muted">-</span>
                  </span>
                </div>
              </div>
              <div v-if="productInfo.description" class="vd-description" style="margin-top: 8px">{{ productInfo.description }}</div>
            </div>

            <!-- Description -->
            <div v-if="vuln.description" class="vd-info-card">
              <div class="vd-info-card__title">漏洞描述</div>
              <div class="vd-description">{{ vuln.description }}</div>
            </div>

            <!-- Evidence -->
            <div v-if="vuln.evidence" class="vd-info-card">
              <div class="vd-info-card__title">
                验证证据
                <NTooltip>
                  <template #trigger>
                    <button class="vd-copy-btn" @click="copyEvidence">
                      <svg v-if="!evidenceCopied" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                      <svg v-else viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#52c41a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                    </button>
                  </template>
                  {{ evidenceCopied ? '已复制' : '复制证据' }}
                </NTooltip>
              </div>
              <pre class="vd-code-block">{{ vuln.evidence }}</pre>
            </div>

            <!-- Solution -->
            <div v-if="vuln.solution" class="vd-info-card vd-solution-card">
              <div class="vd-solution-icon">
                <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="#16a34a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </div>
              <div>
                <div class="vd-info-card__title" style="color: #166534">修复建议</div>
                <div class="vd-solution-text">{{ vuln.solution }}</div>
              </div>
            </div>
          </div>

          <!-- Right: Sidebar -->
          <div class="vd-sidebar">
            <!-- Severity Card -->
            <div class="vd-sidebar-card vd-sev-card" :style="{ background: sev.bg, borderColor: sev.border }">
              <div class="vd-sev-card__label">严重程度</div>
              <div class="vd-sev-card__value" :style="{ color: sev.fg }">{{ sev.label }}</div>
              <div v-if="vuln.confidence != null" class="vd-sev-card__conf">
                <div class="vd-sev-card__conf-bar">
                  <div class="vd-sev-card__conf-fill" :style="{ width: `${vuln.confidence}%`, background: sev.fg }" />
                </div>
                <span class="vd-sev-card__conf-text">{{ vuln.confidence }}% 置信度</span>
              </div>
            </div>

            <!-- Status History -->
            <div class="vd-sidebar-card">
              <div class="vd-sidebar-card__title">状态变更历史</div>
              <NTimeline v-if="history.length" style="margin-top: 4px">
                <NTimelineItem
                  v-for="h in history" :key="h.id"
                  :type="historyTimelineType(h.new_status)"
                  :title="`${statusLabels[h.old_status] ?? h.old_status} → ${statusLabels[h.new_status] ?? h.new_status}`"
                  :time="h.created_at ? new Date(h.created_at).toLocaleString('zh-CN') : ''"
                >
                  <div v-if="h.comment" class="vd-history-comment">{{ h.comment }}</div>
                  <div v-if="h.operator" class="vd-history-operator">{{ h.operator }}</div>
                </NTimelineItem>
              </NTimeline>
              <NEmpty v-else description="暂无变更记录" :show-icon="false" style="padding: 20px 0" />
            </div>
          </div>
        </div>
      </template>
    </NSpin>
  </div>
</template>

<style scoped>
.vd-page {
  padding: 20px 24px;
  max-width: 1200px;
  margin: 0 auto;
}

/* Back link */
.vd-back {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 13px;
  color: var(--text-color-3, #666);
  cursor: pointer;
  margin-bottom: 16px;
  transition: color 0.15s;
}
.vd-back:hover {
  color: var(--primary-color, #1890ff);
}

/* Header */
.vd-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 24px;
  padding: 20px 24px;
  background: var(--card-color, #fff);
  border-radius: 12px;
  border: 1px solid var(--border-color, #eef2f6);
  border-left: 4px solid;
  margin-bottom: 20px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04), 0 1px 2px rgba(0, 0, 0, 0.02);
  transition: box-shadow 0.2s;
}
.vd-header:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
}
.vd-header__main {
  flex: 1;
  min-width: 0;
}
.vd-header__top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.vd-sev-badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 12px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid;
  letter-spacing: 0.5px;
}
.vd-confidence {
  font-size: 12px;
  color: var(--text-color-3, #8c8c8c);
  margin-left: 4px;
}
.vd-title {
  font-size: 20px;
  font-weight: 700;
  color: var(--text-color-1, #1a1a1a);
  line-height: 1.4;
  margin: 0 0 10px;
  word-break: break-word;
}
.vd-meta-row {
  display: flex;
  align-items: center;
  gap: 16px;
  flex-wrap: wrap;
}
.vd-meta-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 12px;
  color: var(--text-color-3, #8c8c8c);
}
.vd-header__actions {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-shrink: 0;
  flex-wrap: wrap;
}

/* Body layout */
.vd-body {
  display: grid;
  grid-template-columns: 1fr 300px;
  gap: 20px;
  align-items: start;
}
@media (max-width: 860px) {
  .vd-body {
    grid-template-columns: 1fr;
  }
}

/* Info Card */
.vd-info-card {
  background: var(--card-color, #fff);
  border: 1px solid var(--border-color, #eef2f6);
  border-radius: 12px;
  padding: 20px;
  margin-bottom: 16px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
  transition: box-shadow 0.2s;
}
.vd-info-card:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
}
.vd-info-card__title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text-color-1, #1a1a1a);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding-left: 10px;
  border-left: 3px solid var(--primary-color, #1890ff);
}

/* KV Grid */
.vd-kv-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0;
  border: 1px solid var(--border-color, #f0f0f0);
  border-radius: 8px;
  overflow: hidden;
}
.vd-kv {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--border-color-light, #f5f5f5);
  font-size: 13px;
  transition: background 0.15s;
}
.vd-kv:hover {
  background: var(--hover-color, rgba(0, 0, 0, 0.02));
}
.vd-kv:nth-child(odd) {
  border-right: 1px solid var(--border-color-light, #f5f5f5);
}
.vd-kv:nth-last-child(-n+2) {
  border-bottom: none;
}
.vd-kv__label {
  font-size: 11px;
  color: var(--text-color-3, #8c8c8c);
  font-weight: 500;
  text-transform: uppercase;
  letter-spacing: 0.3px;
}
.vd-kv__value {
  color: var(--text-color-1, #333);
  word-break: break-all;
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.vd-kv__mono {
  font-family: 'SF Mono', Consolas, Monaco, monospace;
  font-size: 12px;
}
.vd-muted {
  color: var(--text-color-4, #ccc);
}

/* CVE link */
.vd-cve-link {
  display: inline-flex;
  align-items: center;
  padding: 1px 8px;
  background: var(--primary-color-suppl, #f0f5ff);
  color: var(--primary-color, #1890ff);
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  text-decoration: none;
  transition: background 0.15s, transform 0.1s;
  font-family: 'SF Mono', Consolas, Monaco, monospace;
}
.vd-cve-link:hover {
  background: var(--primary-color-hover, #d6e4ff);
  transform: translateY(-1px);
}

/* Description */
.vd-description {
  font-size: 13px;
  line-height: 1.8;
  color: var(--text-color-2, #444);
  white-space: pre-wrap;
  word-break: break-word;
}

/* Code block */
.vd-code-block {
  margin: 0;
  padding: 16px;
  background: #1a1b2e;
  color: #c9d1d9;
  border-radius: 8px;
  font-size: 12px;
  font-family: 'SF Mono', Consolas, Monaco, monospace;
  line-height: 1.65;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 420px;
  border: 1px solid #2d2d3d;
  position: relative;
}
.vd-code-block::before {
  content: 'EVIDENCE';
  position: absolute;
  top: 8px;
  right: 12px;
  font-size: 9px;
  font-weight: 700;
  letter-spacing: 1px;
  color: #4a5568;
  opacity: 0.5;
}

/* Copy button */
.vd-copy-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 26px;
  height: 26px;
  border: 1px solid var(--border-color, #e8e8e8);
  border-radius: 6px;
  background: var(--card-color, #fafafa);
  cursor: pointer;
  transition: all 0.15s;
  padding: 0;
}
.vd-copy-btn:hover {
  border-color: var(--primary-color, #1890ff);
  background: var(--primary-color-suppl, #f0f5ff);
}

/* Solution card */
.vd-solution-card {
  display: flex;
  gap: 14px;
  background: #f0fdf4;
  border-color: #bbf7d0;
  position: relative;
  overflow: hidden;
}
.vd-solution-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: linear-gradient(90deg, #16a34a, #22c55e);
}
.vd-solution-card .vd-info-card__title {
  border-left-color: #16a34a;
}
.vd-solution-icon {
  flex-shrink: 0;
  margin-top: 2px;
}
.vd-solution-text {
  font-size: 13px;
  line-height: 1.8;
  color: #166534;
  white-space: pre-wrap;
  word-break: break-word;
}

/* Sidebar */
.vd-sidebar-card {
  background: var(--card-color, #fff);
  border: 1px solid var(--border-color, #eef2f6);
  border-radius: 12px;
  padding: 16px;
  margin-bottom: 16px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
  transition: box-shadow 0.2s;
}
.vd-sidebar-card:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
}
.vd-sidebar-card__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-color-1, #1a1a1a);
  margin-bottom: 12px;
  padding-left: 10px;
  border-left: 3px solid var(--primary-color, #1890ff);
}

/* Severity sidebar card */
.vd-sev-card {
  text-align: center;
  padding: 20px;
  position: relative;
  overflow: hidden;
}
.vd-sev-card::after {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 3px;
  background: currentColor;
  opacity: 0.4;
}
.vd-sev-card__label {
  font-size: 11px;
  color: var(--text-color-3, #8c8c8c);
  text-transform: uppercase;
  letter-spacing: 0.5px;
  margin-bottom: 6px;
}
.vd-sev-card__value {
  font-size: 28px;
  font-weight: 800;
  line-height: 1.2;
  margin-bottom: 12px;
}
.vd-sev-card__conf {
  margin-top: 4px;
}
.vd-sev-card__conf-bar {
  height: 6px;
  background: rgba(0, 0, 0, 0.06);
  border-radius: 3px;
  overflow: hidden;
  margin-bottom: 6px;
}
.vd-sev-card__conf-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.6s ease;
}
.vd-sev-card__conf-text {
  font-size: 11px;
  color: var(--text-color-3, #8c8c8c);
}

/* History */
.vd-history-comment {
  font-size: 12px;
  color: var(--text-color-3, #999);
}
.vd-history-operator {
  font-size: 11px;
  color: var(--text-color-3, #999);
  margin-top: 2px;
}

/* Dark mode overrides */
:global(html.dark) .vd-code-block {
  background: #0d1117;
  border-color: #30363d;
  color: #e6edf3;
}
:global(html.dark) .vd-solution-card {
  background: #0a1f14;
  border-color: #1a4731;
}
:global(html.dark) .vd-solution-text {
  color: #6ee7b7;
}
:global(html.dark) .vd-solution-card .vd-info-card__title {
  color: #34d399;
}

.vd-monitor-row {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
  padding: 6px 0;
}

.vd-monitor-row + .vd-monitor-row {
  border-top: 1px solid var(--n-border-color, #eee);
}
</style>
