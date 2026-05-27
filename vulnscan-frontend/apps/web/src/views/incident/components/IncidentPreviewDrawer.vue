<script lang="ts" setup>
import { ref, watch, computed } from 'vue';
import {
  NDrawer, NDrawerContent, NButton, NSpace, NTag, NProgress,
  NDescriptions, NDescriptionsItem, NSpin, NEmpty, NDivider,
} from 'naive-ui';
import { useRouter } from 'vue-router';
import {
  getIncidentDetail,
  type SecurityIncident,
} from '#/api/incident';
import {
  buildIncidentOverviewStats,
  type OverviewStatItem,
} from './incident-overview-stats';

const props = defineProps<{
  show: boolean;
  incidentId: string | null;
}>();

const emit = defineEmits<{
  (e: 'update:show', value: boolean): void;
}>();

const router = useRouter();
const loading = ref(false);
const incident = ref<SecurityIncident | null>(null);

const levelLabels: Record<number, string> = { 1: '低危', 2: '中危', 3: '高危', 4: '紧急' };
const levelColors: Record<number, string> = { 1: '#18a058', 2: '#2080f0', 3: '#f0a020', 4: '#d03050' };
const statusLabels: Record<number, string> = {
  1: '待人工复核', 2: '复核通过', 3: '复核失败',
  4: '待整改', 5: '整改中', 6: '待验证', 7: '已关闭',
};
const statusTypes: Record<number, string> = {
  1: 'default', 2: 'success', 3: 'error', 4: 'warning', 5: 'info', 6: 'warning', 7: 'default',
};
const sourceLabels: Record<number, string> = {
  1: '站点监测', 2: '漏洞扫描', 3: '流量分析', 4: '风险探测',
};

function formatTime(t?: string) {
  if (!t) return '-';
  try { return new Date(t).toLocaleString('zh-CN'); }
  catch { return t; }
}

const overview = computed(() => {
  if (!incident.value) return null;
  return buildIncidentOverviewStats(incident.value, { formatTime });
});

const eventTags = computed(() => {
  const tags = incident.value?.ai_tags;
  if (!tags) return [];
  if (Array.isArray(tags)) return tags;
  return tags.split(',').map(t => t.trim()).filter(Boolean);
});

const description = computed(() => {
  return incident.value?.event_metadata?.incident_description || '';
});

const truncatedDesc = computed(() => {
  const d = description.value;
  if (d.length <= 500) return d;
  return `${d.slice(0, 500)}...`;
});

watch(
  () => [props.show, props.incidentId] as const,
  async ([show, id]) => {
    if (!show || !id) {
      incident.value = null;
      return;
    }
    loading.value = true;
    try {
      incident.value = await getIncidentDetail(id) as any;
    } catch {
      incident.value = null;
    } finally {
      loading.value = false;
    }
  },
);

function goDetail() {
  if (!props.incidentId) return;
  emit('update:show', false);
  router.push(`/incident/list/${props.incidentId}`);
}

function cellClass(item: OverviewStatItem) {
  return ['preview-cell', item.highlight ? `preview-cell--${item.highlight}` : ''];
}

function valueClass(item: OverviewStatItem) {
  return [
    'preview-cell__value',
    item.mono ? 'preview-cell__value--mono' : '',
    item.highlight ? `preview-cell__value--${item.highlight}` : '',
  ];
}
</script>

<template>
  <NDrawer
    :show="show"
    :width="520"
    placement="right"
    @update:show="(v: boolean) => emit('update:show', v)"
  >
    <NDrawerContent closable>
      <template #header>
        <NSpace align="center" :size="8" v-if="incident">
          <span style="font-weight:600;font-size:15px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:inline-block">
            {{ incident.name }}
          </span>
          <span
            :style="{
              padding: '2px 7px', borderRadius: '4px', fontSize: '11px',
              fontWeight: '600', color: '#fff',
              background: levelColors[incident.level] ?? '#999',
            }"
          >{{ levelLabels[incident.level] ?? '-' }}</span>
          <NTag
            :type="(statusTypes[incident.status] || 'default') as any"
            size="small"
            :bordered="false"
          >{{ statusLabels[incident.status] ?? '-' }}</NTag>
        </NSpace>
        <span v-else>事件预览</span>
      </template>

      <template #footer>
        <NSpace justify="end">
          <NButton @click="emit('update:show', false)">关闭</NButton>
          <NButton type="primary" @click="goDetail">查看详情</NButton>
        </NSpace>
      </template>

      <NSpin :show="loading">
        <template v-if="incident && overview">
          <!-- 基础信息 -->
          <NDescriptions :column="2" size="small" label-placement="left" bordered>
            <NDescriptionsItem label="事件编号">
              <code style="font-size:12px">{{ incident.incident_no }}</code>
            </NDescriptionsItem>
            <NDescriptionsItem label="来源">
              {{ sourceLabels[incident.source] ?? '-' }}
            </NDescriptionsItem>
            <NDescriptionsItem label="创建时间" :span="2">
              {{ formatTime(incident.created_at) }}
            </NDescriptionsItem>
          </NDescriptions>

          <!-- AI 分析摘要 -->
          <template v-if="incident.ai_pre_status === 1">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">AI 分析</span>
            </NDivider>
            <div class="preview-ai-row">
              <div class="preview-ai-item">
                <div class="preview-ai-label">置信度</div>
                <NProgress
                  type="circle"
                  :percentage="Math.round((incident.ai_confidence ?? 0) * 100)"
                  :stroke-width="5"
                  style="width:56px"
                />
              </div>
              <div class="preview-ai-item">
                <div class="preview-ai-label">风险评分</div>
                <NProgress
                  type="line"
                  :percentage="incident.risk_score ?? 0"
                  indicator-placement="inside"
                  style="width:140px"
                />
              </div>
              <div class="preview-ai-item" v-if="incident.ai_category">
                <div class="preview-ai-label">分类</div>
                <NTag size="small" type="info">{{ incident.ai_category }}</NTag>
              </div>
            </div>
            <div v-if="eventTags.length" style="margin-top:8px">
              <NSpace :size="4" :wrap="true">
                <NTag v-for="t in eventTags" :key="t" size="tiny" :bordered="false">{{ t }}</NTag>
              </NSpace>
            </div>
            <div v-if="incident.ai_vuln_desc" style="margin-top:10px">
              <div style="font-size:11px;color:var(--n-text-color-3);margin-bottom:4px;font-weight:600;color:#d03050">漏洞描述</div>
              <div class="preview-ai-opinion">{{ incident.ai_vuln_desc }}</div>
            </div>
            <div v-if="incident.ai_vuln_harm" style="margin-top:8px">
              <div style="font-size:11px;color:var(--n-text-color-3);margin-bottom:4px;font-weight:600;color:#f0a020">漏洞危害</div>
              <div class="preview-ai-opinion">{{ incident.ai_vuln_harm }}</div>
            </div>
            <div v-if="incident.ai_fix_advice" style="margin-top:8px">
              <div style="font-size:11px;color:var(--n-text-color-3);margin-bottom:4px;font-weight:600;color:#18a058">修复建议</div>
              <div class="preview-ai-opinion">{{ incident.ai_fix_advice }}</div>
            </div>
            <div
              v-if="incident.ai_opinion"
              class="preview-ai-opinion"
              style="margin-top:10px"
            >{{ incident.ai_opinion }}</div>
          </template>

          <!-- 事件摘要 -->
          <template v-if="overview.primary.length">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">事件摘要</span>
            </NDivider>
            <div class="preview-grid">
              <div
                v-for="(item, idx) in overview.primary"
                :key="`p-${idx}`"
                :class="cellClass(item)"
              >
                <span class="preview-cell__label">{{ item.label }}</span>
                <span :class="valueClass(item)">{{ item.value }}</span>
              </div>
            </div>
          </template>

          <!-- 漏洞信息 -->
          <template v-if="overview.vuln.length">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">漏洞信息</span>
            </NDivider>
            <div class="preview-grid">
              <div
                v-for="(item, idx) in overview.vuln"
                :key="`v-${idx}`"
                :class="cellClass(item)"
              >
                <span class="preview-cell__label">{{ item.label }}</span>
                <span :class="valueClass(item)">{{ item.value }}</span>
              </div>
            </div>
          </template>

          <!-- 资产信息 -->
          <template v-if="overview.asset.length">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">涉事资产</span>
            </NDivider>
            <div class="preview-grid">
              <div
                v-for="(item, idx) in overview.asset"
                :key="`a-${idx}`"
                class="preview-cell"
              >
                <span class="preview-cell__label">{{ item.label }}</span>
                <span :class="valueClass(item)">{{ item.value }}</span>
              </div>
            </div>
          </template>

          <!-- 事件描述 -->
          <template v-if="description">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">事件描述</span>
            </NDivider>
            <div class="preview-desc">{{ truncatedDesc }}</div>
          </template>

          <!-- SLA -->
          <template v-if="incident.sla_deadline">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">SLA</span>
            </NDivider>
            <NDescriptions :column="2" size="small" label-placement="left" bordered>
              <NDescriptionsItem label="SLA期限">
                <span
                  :style="new Date(incident.sla_deadline) < new Date() ? 'color:#d03050;font-weight:600' : ''"
                >{{ formatTime(incident.sla_deadline) }}</span>
                <NTag
                  v-if="new Date(incident.sla_deadline) < new Date()"
                  size="tiny"
                  type="error"
                  :bordered="false"
                  style="margin-left:6px"
                >已超期</NTag>
              </NDescriptionsItem>
              <NDescriptionsItem label="催办次数">
                {{ incident.sla_reminder_count ?? 0 }}
              </NDescriptionsItem>
            </NDescriptions>
          </template>

          <!-- 整改 -->
          <template v-if="incident.remediation_plan || incident.remediation_result">
            <NDivider style="margin:16px 0 12px">
              <span style="font-size:12px;color:var(--n-text-color-3)">整改记录</span>
            </NDivider>
            <NDescriptions :column="1" size="small" label-placement="left" bordered>
              <NDescriptionsItem v-if="incident.remediation_plan" label="整改方案">
                {{ incident.remediation_plan }}
              </NDescriptionsItem>
              <NDescriptionsItem v-if="incident.remediation_result" label="整改结果">
                {{ incident.remediation_result }}
              </NDescriptionsItem>
              <NDescriptionsItem v-if="incident.remediation_assignee" label="责任人">
                {{ incident.remediation_assignee }}
              </NDescriptionsItem>
            </NDescriptions>
          </template>
        </template>

        <NEmpty v-else-if="!loading" description="暂无数据" style="padding:48px 0" />
      </NSpin>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.preview-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 8px;
}

.preview-cell {
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--n-border-color);
  background: var(--n-action-color);
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.preview-cell__label {
  font-size: 11px;
  color: var(--n-text-color-3);
}

.preview-cell__value {
  font-size: 13px;
  font-weight: 500;
  color: var(--n-text-color);
  word-break: break-word;
}

.preview-cell__value--mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
  font-weight: 400;
}

.preview-cell__value--error { color: var(--n-error-color); font-weight: 600; }
.preview-cell__value--success { color: var(--n-success-color); font-weight: 600; }
.preview-cell__value--warning { color: var(--n-warning-color); font-weight: 600; }
.preview-cell__value--info { color: var(--n-info-color); font-weight: 600; }

.preview-cell--error {
  border-color: color-mix(in srgb, var(--n-error-color) 28%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-error-color) 6%, var(--n-action-color));
}
.preview-cell--success {
  border-color: color-mix(in srgb, var(--n-success-color) 28%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-success-color) 6%, var(--n-action-color));
}
.preview-cell--warning {
  border-color: color-mix(in srgb, var(--n-warning-color) 28%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-warning-color) 6%, var(--n-action-color));
}
.preview-cell--info {
  border-color: color-mix(in srgb, var(--n-info-color) 22%, var(--n-border-color));
  background: color-mix(in srgb, var(--n-info-color) 5%, var(--n-action-color));
}

.preview-ai-row {
  display: flex;
  align-items: center;
  gap: 20px;
  flex-wrap: wrap;
}

.preview-ai-item {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.preview-ai-label {
  font-size: 11px;
  color: var(--n-text-color-3);
}

.preview-ai-opinion {
  margin-top: 10px;
  padding: 10px 12px;
  background: var(--n-action-color);
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
  font-size: 12px;
  line-height: 1.75;
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 200px;
  overflow: auto;
}

.preview-desc {
  font-size: 13px;
  line-height: 1.75;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--n-text-color-2);
  padding: 10px 12px;
  background: var(--n-action-color);
  border: 1px solid var(--n-border-color);
  border-radius: 6px;
  max-height: 200px;
  overflow: auto;
}
</style>
