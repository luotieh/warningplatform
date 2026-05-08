<script lang="ts" setup>
import { onMounted, ref } from 'vue';
import {
  NCard, NGrid, NGridItem, NStatistic, NSpin, NTag, NSpace,
  NProgress, NTimeline, NTimelineItem, NDataTable, NEmpty,
} from 'naive-ui';
import { EchartsUI, useEcharts } from '@vben/plugins/echarts';
import type { EchartsUIType } from '@vben/plugins/echarts';
import {
  getDashboardOverview, getVulnTrend, getTaskTrend,
  getTopVulnAssets, getTaskStatusDist, getRecentActivity,
  getRecentTasks, type SecurityPosture,
} from '#/api/dashboard';
import { getDashboardStats as getIncidentStats, type DashboardStats as IncidentDashboardStats } from '#/api/incident';

defineOptions({ name: 'DashboardOverview' });

const loading = ref(true);
const posture = ref<SecurityPosture | null>(null);
const taskStatusDist = ref<Record<string, number>>({});
const recentActivities = ref<any[]>([]);
const recentTasks = ref<any[]>([]);
const incidentStats = ref<IncidentDashboardStats | null>(null);

const vulnTrendRef = ref<EchartsUIType>();
const taskTrendRef = ref<EchartsUIType>();
const severityPieRef = ref<EchartsUIType>();
const topAssetsRef = ref<EchartsUIType>();

const { renderEcharts: renderVulnTrend } = useEcharts(vulnTrendRef);
const { renderEcharts: renderTaskTrend } = useEcharts(taskTrendRef);
const { renderEcharts: renderSeverityPie } = useEcharts(severityPieRef);
const { renderEcharts: renderTopAssets } = useEcharts(topAssetsRef);

const sevColors: Record<string, string> = {
  critical: '#e53e3e', high: '#dd6b20', medium: '#d69e2e', low: '#38a169', info: '#4299e1',
};
const sevLabels: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
};
const taskColumns = [
  { title: '任务名称', key: 'name', ellipsis: { tooltip: true } },
  { title: '状态', key: 'status', width: 90 },
  { title: '进度', key: 'progress', width: 80, render: (row: any) => `${row.progress ?? 0}%` },
  { title: '目标数', key: 'total_targets', width: 70 },
  { title: '创建时间', key: 'created_at', width: 160 },
];

onMounted(async () => {
  try {
    const [overviewRes, vulnTrendRes, taskTrendRes, topAssetsRes, taskDistRes, activityRes, tasksRes, incidentRes] =
      await Promise.allSettled([
        getDashboardOverview(),
        getVulnTrend(),
        getTaskTrend(),
        getTopVulnAssets(),
        getTaskStatusDist(),
        getRecentActivity(),
        getRecentTasks({ page: 1, page_size: 8 }),
        getIncidentStats(),
      ]);

    if (overviewRes.status === 'fulfilled') posture.value = overviewRes.value as SecurityPosture;
    if (taskDistRes.status === 'fulfilled') taskStatusDist.value = (taskDistRes.value as Record<string, number>) ?? {};
    if (activityRes.status === 'fulfilled') recentActivities.value = (activityRes.value as any[]) ?? [];
    if (incidentRes.status === 'fulfilled') incidentStats.value = incidentRes.value as IncidentDashboardStats;
    if (tasksRes.status === 'fulfilled') {
      const r = tasksRes.value as any;
      recentTasks.value = r?.items ?? [];
    }

    if (vulnTrendRes.status === 'fulfilled') {
      const trend = (vulnTrendRes.value as any[]) ?? [];
      renderVulnTrend({
        tooltip: { trigger: 'axis' },
        grid: { left: 40, right: 16, top: 24, bottom: 28 },
        xAxis: {
          type: 'category',
          data: trend.map((p: any) => new Date(p.timestamp).toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' })),
          axisLabel: { fontSize: 10 },
        },
        yAxis: { type: 'value', minInterval: 1 },
        series: [{
          type: 'line', data: trend.map((p: any) => p.value),
          smooth: true, areaStyle: { opacity: 0.15 },
          itemStyle: { color: '#e53e3e' },
        }],
      });
    }

    if (taskTrendRes.status === 'fulfilled') {
      const trend = (taskTrendRes.value as any[]) ?? [];
      renderTaskTrend({
        tooltip: { trigger: 'axis' },
        grid: { left: 40, right: 16, top: 24, bottom: 28 },
        xAxis: {
          type: 'category',
          data: trend.map((p: any) => new Date(p.timestamp).toLocaleDateString('zh-CN', { month: 'short', day: 'numeric' })),
          axisLabel: { fontSize: 10 },
        },
        yAxis: { type: 'value', minInterval: 1 },
        series: [{
          type: 'bar', data: trend.map((p: any) => p.value),
          itemStyle: { color: '#4299e1', borderRadius: [4, 4, 0, 0] },
        }],
      });
    }

    if (overviewRes.status === 'fulfilled' && posture.value?.severity_distribution) {
      const dist = posture.value.severity_distribution;
      renderSeverityPie({
        tooltip: { trigger: 'item' },
        legend: { bottom: 0, textStyle: { fontSize: 11 } },
        series: [{
          type: 'pie', radius: ['40%', '65%'], center: ['50%', '44%'],
          label: { show: true, formatter: '{b}\n{c}', fontSize: 11 },
          data: Object.entries(dist).map(([sev, count]) => ({
            name: sevLabels[sev] || sev, value: count,
            itemStyle: { color: sevColors[sev] || '#999' },
          })),
        }],
      });
    }

    if (topAssetsRes.status === 'fulfilled') {
      const assets = ((topAssetsRes.value as any[]) ?? []).slice(0, 8);
      renderTopAssets({
        tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
        grid: { left: 120, right: 30, top: 12, bottom: 20 },
        xAxis: { type: 'value', minInterval: 1 },
        yAxis: {
          type: 'category',
          data: assets.map((a: any) => a.host).reverse(),
          axisLabel: { fontSize: 10, width: 100, overflow: 'truncate' },
        },
        series: [{
          type: 'bar',
          data: assets.map((a: any) => a.vuln_count).reverse(),
          itemStyle: {
            borderRadius: [0, 4, 4, 0],
            color: { type: 'linear', x: 0, y: 0, x2: 1, y2: 0, colorStops: [
              { offset: 0, color: '#dd6b20' }, { offset: 1, color: '#e53e3e' },
            ] },
          },
        }],
      });
    }
  } finally {
    loading.value = false;
  }
});

function riskColor(score: number) {
  if (score >= 80) return '#38a169';
  if (score >= 60) return '#d69e2e';
  if (score >= 40) return '#dd6b20';
  return '#e53e3e';
}
</script>

<template>
  <div class="dashboard-page">
    <NSpin :show="loading">
      <!-- Section: 安全态势 -->
      <div class="section-title">安全态势总览</div>
      <NGrid :cols="5" :x-gap="16" :y-gap="16" responsive="screen" :item-responsive="true">
        <NGridItem :span="1">
          <div class="kpi-card kpi-assets">
            <div class="kpi-icon">
              <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg>
            </div>
            <div class="kpi-body">
              <div class="kpi-value">{{ posture?.total_assets ?? 0 }}</div>
              <div class="kpi-label">资产总数</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem :span="1">
          <div class="kpi-card kpi-vulns">
            <div class="kpi-icon">
              <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/></svg>
            </div>
            <div class="kpi-body">
              <div class="kpi-value">{{ posture?.total_vulns ?? 0 }}</div>
              <div class="kpi-label">漏洞总数</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem :span="1">
          <div class="kpi-card kpi-scans">
            <div class="kpi-icon">
              <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
            </div>
            <div class="kpi-body">
              <div class="kpi-value">{{ posture?.active_scans ?? 0 }}</div>
              <div class="kpi-label">运行中扫描</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem :span="1">
          <div class="kpi-card kpi-score">
            <div class="kpi-score-ring">
              <NProgress
                type="circle" :percentage="Math.round(posture?.risk_score ?? 0)"
                :color="riskColor(posture?.risk_score ?? 0)"
                :stroke-width="7" style="width:56px"
              />
            </div>
            <div class="kpi-body">
              <div class="kpi-label" style="margin-top: 2px">安全评分</div>
            </div>
          </div>
        </NGridItem>
        <NGridItem :span="1">
          <div class="kpi-card kpi-dist">
            <div class="kpi-label" style="margin-bottom: 10px">漏洞分布</div>
            <NSpace :size="6" :wrap="true">
              <NTag v-for="(count, sev) in posture?.severity_distribution" :key="sev" size="small" round
                :style="{ background: sevColors[sev as string] + '18', color: sevColors[sev as string], border: `1px solid ${sevColors[sev as string]}30`, fontWeight: '600', fontSize: '12px' }">
                {{ sevLabels[sev as string] || sev }} {{ count }}
              </NTag>
            </NSpace>
          </div>
        </NGridItem>
      </NGrid>

      <!-- Section: 监控统计 -->
      <div class="section-title" style="margin-top: 24px">监控与告警</div>
      <NGrid :cols="4" :x-gap="16" responsive="screen">
        <NGridItem>
          <NCard size="small" class="stat-card">
            <NStatistic label="监控任务" :value="posture?.monitor_stats?.total_tasks ?? 0" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small" class="stat-card">
            <NStatistic label="启用中" :value="posture?.monitor_stats?.enabled_tasks ?? 0">
              <template #prefix><span class="stat-dot" style="background:#52c41a" /></template>
            </NStatistic>
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small" class="stat-card">
            <NStatistic label="告警总数" :value="posture?.monitor_stats?.total_alerts ?? 0" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard size="small" class="stat-card">
            <NStatistic label="待处理告警" :value="posture?.monitor_stats?.open_alerts ?? 0">
              <template #suffix>
                <NTag v-if="(posture?.monitor_stats?.open_alerts ?? 0) > 0" type="error" size="small" round>需关注</NTag>
              </template>
            </NStatistic>
          </NCard>
        </NGridItem>
      </NGrid>

      <!-- Section: 事件/通报统计 -->
      <template v-if="incidentStats">
        <div class="section-title" style="margin-top: 24px">安全事件</div>
        <NGrid :cols="5" :x-gap="16" responsive="screen">
          <NGridItem>
            <NCard size="small" class="stat-card stat-card-hoverable" @click="$router.push('/incident/list')">
              <NStatistic label="事件总数" :value="incidentStats.total" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard size="small" class="stat-card stat-card-hoverable" @click="$router.push('/incident/list')">
              <NStatistic label="待审核" :value="incidentStats.pending_audit">
                <template #suffix>
                  <NTag v-if="(incidentStats.pending_audit ?? 0) > 0" type="warning" size="small" round>待处理</NTag>
                </template>
              </NStatistic>
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard size="small" class="stat-card stat-card-hoverable" @click="$router.push('/incident/list')">
              <NStatistic label="整改中" :value="incidentStats.in_remediation" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard size="small" class="stat-card">
              <NStatistic label="已关闭" :value="incidentStats.closed" />
            </NCard>
          </NGridItem>
          <NGridItem>
            <NCard size="small" class="stat-card stat-card-hoverable" @click="$router.push('/incident/list')">
              <NStatistic label="超期事件" :value="incidentStats.overdue">
                <template #suffix>
                  <NTag v-if="(incidentStats.overdue ?? 0) > 0" type="error" size="small" round>超期</NTag>
                </template>
              </NStatistic>
            </NCard>
          </NGridItem>
        </NGrid>
      </template>

      <!-- Charts Row 1 -->
      <NGrid :cols="2" :x-gap="16" style="margin-top:24px" responsive="screen">
        <NGridItem>
          <NCard title="漏洞趋势（近30天）" size="small">
            <EchartsUI ref="vulnTrendRef" height="260px" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="任务趋势（近30天）" size="small">
            <EchartsUI ref="taskTrendRef" height="260px" />
          </NCard>
        </NGridItem>
      </NGrid>

      <!-- Charts Row 2 -->
      <NGrid :cols="2" :x-gap="16" style="margin-top:16px" responsive="screen">
        <NGridItem>
          <NCard title="漏洞严重级别分布" size="small">
            <EchartsUI ref="severityPieRef" height="280px" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="高危资产 TOP 8" size="small">
            <EchartsUI ref="topAssetsRef" height="280px" />
          </NCard>
        </NGridItem>
      </NGrid>

      <!-- 高风险资产 Top10 -->
      <NCard title="高风险资产 Top 10（漏洞+告警联合）" size="small" style="margin-top:16px">
        <NDataTable
          :data="posture?.top_risk_assets ?? []"
          :bordered="false" size="small" :pagination="false" :max-height="320"
          :columns="[
            { title: '资产名', key: 'name', ellipsis: { tooltip: true } },
            { title: '地址', key: 'address', width: 160, ellipsis: { tooltip: true } },
            { title: '风险分', key: 'risk_score', width: 80, sorter: 'default' },
            { title: '漏洞数', key: 'vuln_count', width: 80, sorter: 'default' },
            { title: '未处理告警', key: 'alert_count', width: 100, sorter: 'default' },
          ]"
        />
      </NCard>

      <!-- Bottom: Recent Tasks + Activity -->
      <NGrid :cols="3" :x-gap="16" style="margin-top:16px" responsive="screen">
        <NGridItem :span="2">
          <NCard title="最近扫描任务" size="small">
            <NDataTable :columns="taskColumns" :data="recentTasks" :bordered="false" size="small" :pagination="false" max-height="360" />
          </NCard>
        </NGridItem>
        <NGridItem>
          <NCard title="最近动态" size="small">
            <NTimeline v-if="recentActivities.length">
              <NTimelineItem
                v-for="(a, idx) in recentActivities.slice(0, 10)" :key="idx"
                :type="a.type === 'vuln' ? 'error' : 'info'"
                :title="a.title"
                :time="a.created_at ? new Date(a.created_at).toLocaleString('zh-CN') : ''"
              >
                <NTag size="tiny" :type="a.type === 'vuln' ? 'error' : 'info'" :bordered="false" round>
                  {{ a.type === 'vuln' ? '漏洞' : '任务' }}
                </NTag>
                {{ a.detail }}
              </NTimelineItem>
            </NTimeline>
            <NEmpty v-else description="暂无动态" />
          </NCard>
        </NGridItem>
      </NGrid>
    </NSpin>
  </div>
</template>

<style scoped>
.dashboard-page {
  padding: 20px 24px;
  max-width: 1600px;
}

.section-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text-color-1, #1a1a1a);
  margin-bottom: 14px;
  padding-left: 2px;
  letter-spacing: 0.3px;
}

.kpi-card {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 18px 20px;
  border-radius: 12px;
  background: #fff;
  border: 1px solid #f0f0f0;
  transition: box-shadow 0.2s, transform 0.15s;
  min-height: 88px;
}
.kpi-card:hover {
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);
  transform: translateY(-1px);
}

.kpi-icon {
  width: 44px;
  height: 44px;
  border-radius: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.kpi-assets .kpi-icon { background: #e6f7ff; color: #1890ff; }
.kpi-vulns .kpi-icon { background: #fff2e8; color: #fa541c; }
.kpi-scans .kpi-icon { background: #e6fffb; color: #13c2c2; }

.kpi-body {
  flex: 1;
  min-width: 0;
}

.kpi-value {
  font-size: 26px;
  font-weight: 700;
  line-height: 1.2;
  color: var(--text-color-1, #1a1a1a);
  font-variant-numeric: tabular-nums;
}

.kpi-label {
  font-size: 12px;
  color: var(--text-color-3, #999);
  margin-top: 2px;
  font-weight: 500;
}

.kpi-score {
  justify-content: center;
  gap: 12px;
}

.kpi-score-ring {
  flex-shrink: 0;
}

.kpi-dist {
  flex-direction: column;
  align-items: flex-start;
  padding: 14px 16px;
}

.stat-card {
  transition: box-shadow 0.2s, transform 0.15s;
}
.stat-card:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.05);
}

.stat-card-hoverable {
  cursor: pointer;
}
.stat-card-hoverable:hover {
  transform: translateY(-1px);
  border-color: #d6e4ff;
}

.stat-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  margin-right: 4px;
}

:deep(.n-card) {
  border-radius: 10px;
}
</style>
