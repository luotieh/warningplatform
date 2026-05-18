<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDescriptions,
  NDescriptionsItem,
  NSpace,
  NSpin,
  NTag,
  NPopconfirm,
  NTimeline,
  NTimelineItem,
  NEmpty,
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

defineOptions({ name: 'VulnDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(true);
const retestLoading = ref(false);
const vuln = ref<Vulnerability | null>(null);
const history = ref<VulnStatusHistory[]>([]);

const sevLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};
const sevColors: Record<string, { bg: string; fg: string }> = {
  critical: { bg: '#fff1f0', fg: '#cf1322' },
  high: { bg: '#fff7e6', fg: '#d46b08' },
  medium: { bg: '#fffbe6', fg: '#d4b106' },
  low: { bg: '#f6ffed', fg: '#389e0d' },
  info: { bg: '#f0f5ff', fg: '#1890ff' },
};
const statusLabels: Record<string, string> = {
  open: '待修复', fixed: '已修复', ignored: '已忽略', reopened: '已重开', verified: '已验证',
};
const statusTypes: Record<string, string> = {
  open: 'error', fixed: 'success', ignored: 'default', reopened: 'warning', verified: 'error',
};

async function fetchData() {
  try {
    const id = route.params.id as string;
    vuln.value = await getVulnDetail(id);
    try {
      history.value = (await getVulnStatusHistory(id)) as unknown as VulnStatusHistory[] ?? [];
    } catch { history.value = []; }
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

onMounted(fetchData);
</script>

<template>
  <div style="padding: 16px; max-width: 960px; margin: 0 auto">
    <NSpin :show="loading">
      <template v-if="vuln">
        <NCard size="small" style="margin-bottom: 16px">
          <template #header>
            <NSpace align="center" :size="12">
              <span style="font-size: 16px; font-weight: 600">{{ vuln.title }}</span>
              <span
                style="padding: 3px 12px; border-radius: 4px; font-size: 12px; font-weight: 600"
                :style="{ background: (sevColors[vuln.severity] ?? { bg: '#f5f5f5' }).bg, color: (sevColors[vuln.severity] ?? { fg: '#999' }).fg }"
              >{{ sevLabels[vuln.severity] ?? vuln.severity }}</span>
              <NTag :type="(statusTypes[vuln.status] || 'default') as any" size="small" :bordered="false">
                {{ statusLabels[vuln.status] ?? vuln.status }}
              </NTag>
            </NSpace>
          </template>
          <template #header-extra>
            <NSpace :size="8">
              <NButton size="small" type="warning" :loading="retestLoading" @click="handleRetest">漏洞回测</NButton>
              <NButton v-if="vuln.status === 'open' || vuln.status === 'reopened'" size="small" type="success" @click="handleAction('fix')">标记修复</NButton>
              <NButton v-if="vuln.status === 'open' || vuln.status === 'reopened'" size="small" @click="handleAction('ignore')">标记忽略</NButton>
              <NButton v-if="vuln.status === 'fixed' || vuln.status === 'ignored'" size="small" type="warning" @click="handleAction('reopen')">重新打开</NButton>
              <NPopconfirm @positive-click="handleDelete">
                <template #trigger>
                  <NButton size="small" type="error">删除</NButton>
                </template>
                确定删除此漏洞？
              </NPopconfirm>
            </NSpace>
          </template>

          <NDescriptions label-placement="left" bordered :column="2" size="small">
            <NDescriptionsItem label="目标">
              <code style="font-size: 12px">{{ vuln.target }}{{ vuln.port ? `:${vuln.port}` : '' }}</code>
            </NDescriptionsItem>
            <NDescriptionsItem label="URL">{{ vuln.url || '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="CVE">
              <NSpace v-if="vuln.cve_ids?.length" :size="4">
                <NTag v-for="c in vuln.cve_ids" :key="c" size="tiny" type="info" :bordered="false">{{ c }}</NTag>
              </NSpace>
              <span v-else style="color: #ccc">-</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="CWE">
              <NSpace v-if="vuln.cwe_ids?.length" :size="4">
                <NTag v-for="c in vuln.cwe_ids" :key="c" size="tiny" :bordered="false">{{ c }}</NTag>
              </NSpace>
              <span v-else style="color: #ccc">-</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="置信度">{{ vuln.confidence ?? '-' }}%</NDescriptionsItem>
            <NDescriptionsItem label="扫描模块">{{ vuln.module_id }}</NDescriptionsItem>
            <NDescriptionsItem label="关联任务">{{ vuln.task_id }}</NDescriptionsItem>
            <NDescriptionsItem label="关联资产">
              <NButton v-if="vuln.asset_id" text type="info" size="small" @click="router.push(`/asset/ledger?id=${vuln.asset_id}`)">
                {{ vuln.asset_id }}
              </NButton>
              <span v-else style="color: #ccc">未关联</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="首次发现">{{ vuln.first_seen_at ?? '-' }}</NDescriptionsItem>
            <NDescriptionsItem label="最近发现">{{ vuln.last_seen_at ?? '-' }}</NDescriptionsItem>
          </NDescriptions>
        </NCard>

        <NCard v-if="vuln.description" title="漏洞描述" size="small" style="margin-bottom: 16px">
          <div style="line-height: 1.8; font-size: 13px; color: #333">{{ vuln.description }}</div>
        </NCard>

        <NCard v-if="vuln.evidence" title="证据" size="small" style="margin-bottom: 16px">
          <pre style="padding: 14px; background: #1e1e2e; color: #cdd6f4; border-radius: 8px; font-size: 12px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; max-height: 400px; line-height: 1.6; margin: 0; font-family: 'SF Mono', Consolas, monospace">{{ vuln.evidence }}</pre>
        </NCard>

        <NCard v-if="vuln.solution" title="修复建议" size="small" style="margin-bottom: 16px">
          <div style="padding: 12px; background: #f0fdf4; border-radius: 6px; line-height: 1.8; font-size: 13px; color: #166534; border: 1px solid #bbf7d0">{{ vuln.solution }}</div>
        </NCard>

        <NCard title="状态变更历史" size="small">
          <NTimeline v-if="history.length">
            <NTimelineItem
              v-for="h in history" :key="h.id"
              :type="historyTimelineType(h.new_status)"
              :title="`${statusLabels[h.old_status] ?? h.old_status} → ${statusLabels[h.new_status] ?? h.new_status}`"
              :time="h.created_at ? new Date(h.created_at).toLocaleString('zh-CN') : ''"
            >
              <div v-if="h.comment" style="font-size:12px;color:var(--text-color-3)">{{ h.comment }}</div>
              <div v-if="h.operator" style="font-size:11px;color:var(--text-color-3)">操作人: {{ h.operator }}</div>
            </NTimelineItem>
          </NTimeline>
          <NEmpty v-else description="暂无状态变更记录" />
        </NCard>
      </template>
    </NSpin>
  </div>
</template>
