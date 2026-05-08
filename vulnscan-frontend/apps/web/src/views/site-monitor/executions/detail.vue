<script lang="ts" setup>
import { computed, onMounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import { Page } from '@vben/common-ui';

import dayjs from 'dayjs';
import {
  NButton,
  NCard,
  NCollapse,
  NCollapseItem,
  NDescriptions,
  NDescriptionsItem,
  NEmpty,
  NInput,
  NSpace,
  NSpin,
  NTag,
} from 'naive-ui';

import { message } from '#/adapter/naive';
import { getExecutionDetail } from '#/api/monitor';
import { createIncident, type CreateIncidentReq } from '#/api/incident';

import AvailabilityDetail from './components/AvailabilityDetail.vue';
import BlacklinkDetail from './components/BlacklinkDetail.vue';
import DomainHijackDetail from './components/DomainHijackDetail.vue';
import SensitiveFileDetail from './components/SensitiveFileDetail.vue';
import SensitiveWordDetail from './components/SensitiveWordDetail.vue';
import TamperDetail from './components/TamperDetail.vue';

defineOptions({ name: 'ExecutionDetail' });

const route = useRoute();
const router = useRouter();
const execId = route.params.id as string;
const loading = ref(false);
const detail = ref<any>(null);

const dimensionOptions: Record<string, string> = {
  availability: '可用性监测',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持监测',
  sensitive_file: '敏感文件监测',
  sensitive_word: '敏感词监测',
  tamper: '篡改监测',
};

const statusTagType = (
  s: string,
): 'default' | 'error' | 'info' | 'success' | 'warning' => {
  if (s === 'success') return 'success';
  if (s === 'failed') return 'error';
  if (s === 'running') return 'warning';
  return 'info';
};

const statusLabel = (s: string) => {
  const map: Record<string, string> = {
    failed: '失败',
    pending: '等待中',
    running: '运行中',
    success: '成功',
  };
  return map[s] || s;
};

const parsedResult = computed(() => {
  if (!detail.value?.result_json) return null;
  try {
    return JSON.parse(detail.value.result_json);
  } catch {
    return null;
  }
});

async function fetchDetail() {
  loading.value = true;
  try {
    const res: any = await getExecutionDetail(execId);
    detail.value = res?.data ?? res;
  } catch (e: any) {
    message.error(e?.msg || '获取执行详情失败');
  } finally {
    loading.value = false;
  }
}

const formatTime = (t: string) =>
  t ? dayjs(t).format('YYYY-MM-DD HH:mm:ss') : '-';

const durationSec = computed(() => {
  if (!detail.value?.started_at || !detail.value?.finished_at) return null;
  const ms = dayjs(detail.value.finished_at).diff(
    dayjs(detail.value.started_at),
  );
  return ms >= 0 ? (ms / 1000).toFixed(1) : null;
});

const convertingToIncident = ref(false);

const dimensionToIncidentType: Record<string, string> = {
  tamper: 'web_attack',
  blacklink: 'web_attack',
  sensitive_word: 'data_leak',
  sensitive_file: 'data_leak',
  domain_hijack: 'intrusion',
  availability: 'dos',
};

const dimensionToLevel: Record<string, number> = {
  tamper: 4,
  blacklink: 3,
  sensitive_word: 3,
  sensitive_file: 3,
  domain_hijack: 4,
  availability: 3,
};

function buildMonitorDescription(d: any, result: any): string {
  const parts: string[] = [];
  const dim = d.dimension;
  const dimLabel = dimensionOptions[dim] || dim;

  parts.push(`监测维度: ${dimLabel}`);
  parts.push(`目标URL: ${d.url}`);
  if (d.agent_id) parts.push(`Agent: ${d.agent_id}`);
  if (d.started_at) parts.push(`检测时间: ${formatTime(d.started_at)}`);
  if (durationSec.value) parts.push(`耗时: ${durationSec.value}秒`);

  if (!result) return parts.join('\n');

  if (dim === 'tamper' && result.diffs?.length) {
    parts.push(`\n篡改详情 (${result.diffs.length}处变更):`);
    for (const diff of result.diffs.slice(0, 5)) {
      parts.push(`  - [${diff.severity || '未知'}] ${diff.type || '内容变更'}${diff.selector ? ' (' + diff.selector + ')' : ''}`);
    }
    if (result.diffs.length > 5) parts.push(`  ... 共${result.diffs.length}处`);
  } else if (dim === 'blacklink') {
    const links = result.blacklink_matches || [];
    const backdoors = result.backdoor_findings || [];
    if (links.length) {
      parts.push(`\n暗链 (${links.length}个):`);
      for (const l of links.slice(0, 5)) {
        parts.push(`  - ${l.url || l.domain || '未知链接'}${l.hidden ? ' [隐藏]' : ''}`);
      }
    }
    if (backdoors.length) {
      parts.push(`\n后门 (${backdoors.length}个):`);
      for (const b of backdoors.slice(0, 3)) {
        parts.push(`  - ${b.path || b.url || '未知路径'}`);
      }
    }
  } else if (dim === 'sensitive_word') {
    const matches = result.matches || [];
    if (matches.length) {
      parts.push(`\n敏感词命中 (${matches.length}处):`);
      for (const m of matches.slice(0, 5)) {
        parts.push(`  - [${m.severity || ''}] "${m.keyword || m.word || ''}" ${m.context ? '上下文: ' + String(m.context).slice(0, 80) : ''}`);
      }
    }
  } else if (dim === 'sensitive_file') {
    const files = result.files || result.matches || [];
    if (files.length) {
      parts.push(`\n敏感文件 (${files.length}个):`);
      for (const f of files.slice(0, 5)) {
        parts.push(`  - ${f.path || f.url || f.filename || '未知文件'}`);
      }
    }
  } else if (dim === 'domain_hijack') {
    if (result.hijacked) parts.push('\n状态: 检测到域名劫持');
    if (result.resolved_ip) parts.push(`解析IP: ${result.resolved_ip}`);
    if (result.expected_ip) parts.push(`预期IP: ${result.expected_ip}`);
    if (result.dns_provider) parts.push(`DNS: ${result.dns_provider}`);
  } else if (dim === 'availability') {
    if (result.available === false) parts.push('\n状态: 站点不可用');
    if (result.status_code) parts.push(`HTTP状态码: ${result.status_code}`);
    if (result.response_time_ms) parts.push(`响应时间: ${result.response_time_ms}ms`);
    if (result.error) parts.push(`错误: ${result.error}`);
  }

  return parts.join('\n');
}

async function convertToIncident() {
  if (!detail.value) return;
  const d = detail.value;
  const result = parsedResult.value;
  const dimLabel = dimensionOptions[d.dimension] || d.dimension;

  const req: CreateIncidentReq = {
    name: `[${dimLabel}] ${d.url}`,
    level: dimensionToLevel[d.dimension] ?? 3,
    source: 1,
    report_time: d.started_at || d.created_at || undefined,
    asset: {
      domain_ip: d.url,
      asset_name: d.url,
    },
    metadata: {
      incident_type: dimensionToIncidentType[d.dimension] ?? 'other',
      incident_description: buildMonitorDescription(d, result),
      incident_url: d.url,
      discovery_time: d.started_at || d.created_at || undefined,
    },
  };

  convertingToIncident.value = true;
  try {
    await createIncident(req);
    message.success('已转为安全事件');
  } catch (e: any) {
    message.error(e?.msg || '转为事件失败');
  } finally {
    convertingToIncident.value = false;
  }
}

onMounted(() => fetchDetail());
</script>

<template>
  <Page title="执行详情">
    <template #extra>
      <NSpace>
        <NButton
          v-if="detail?.has_issue"
          type="warning"
          :loading="convertingToIncident"
          @click="convertToIncident"
        >
          转为安全事件
        </NButton>
        <NButton @click="router.back()">返回</NButton>
      </NSpace>
    </template>

    <NSpin :show="loading">
      <template v-if="detail">
        <!-- 头部状态条 -->
        <NCard class="mb-3" size="small">
          <NSpace align="center">
            <NTag
              :type="statusTagType(detail.status)"
              size="medium"
              :bordered="false"
            >
              {{ statusLabel(detail.status) }}
            </NTag>
            <NTag
              v-if="detail.dimension"
              type="primary"
              size="medium"
              :bordered="false"
            >
              {{ dimensionOptions[detail.dimension] || detail.dimension }}
            </NTag>
            <NTag
              v-if="detail.has_issue"
              type="error"
              size="medium"
              :bordered="false"
            >
              ⚠ 发现安全问题
            </NTag>
          </NSpace>
        </NCard>

        <!-- 基本信息 -->
        <NCard title="基本信息" class="mb-3" size="small">
          <NDescriptions :column="3" bordered size="small">
            <NDescriptionsItem label="执行ID">
              <span class="font-mono text-xs">{{ detail.id }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="任务ID">
              <span class="font-mono text-xs">{{ detail.task_id }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="Agent ID">
              <span class="font-mono text-xs">{{ detail.agent_id || '-' }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="目标URL" :span="3">
              <span class="font-mono text-xs break-all">{{ detail.url }}</span>
            </NDescriptionsItem>
            <NDescriptionsItem label="监测维度">
              <NTag type="primary" size="small" :bordered="false">
                {{ dimensionOptions[detail.dimension] || detail.dimension }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="执行状态">
              <NTag
                :type="statusTagType(detail.status)"
                size="small"
                :bordered="false"
              >
                {{ statusLabel(detail.status) }}
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem label="耗时">
              <span class="font-mono">
                {{ durationSec == null ? '-' : `${durationSec} 秒` }}
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem label="开始时间">
              {{ formatTime(detail.started_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="结束时间">
              {{ formatTime(detail.finished_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem label="创建时间">
              {{ formatTime(detail.created_at) }}
            </NDescriptionsItem>
            <NDescriptionsItem v-if="detail.error" label="执行错误" :span="3">
              <span class="text-error font-mono text-sm">{{ detail.error }}</span>
            </NDescriptionsItem>
          </NDescriptions>
        </NCard>

        <!-- 维度详情 -->
        <template v-if="parsedResult">
          <AvailabilityDetail
            v-if="detail.dimension === 'availability'"
            :result="parsedResult"
            class="mb-3"
          />
          <TamperDetail
            v-else-if="detail.dimension === 'tamper'"
            :result="parsedResult"
            :execution-id="execId"
            class="mb-3"
          />
          <BlacklinkDetail
            v-else-if="detail.dimension === 'blacklink'"
            :result="parsedResult"
            class="mb-3"
          />
          <SensitiveWordDetail
            v-else-if="detail.dimension === 'sensitive_word'"
            :result="parsedResult"
            class="mb-3"
          />
          <SensitiveFileDetail
            v-else-if="detail.dimension === 'sensitive_file'"
            :result="parsedResult"
            class="mb-3"
          />
          <DomainHijackDetail
            v-else-if="detail.dimension === 'domain_hijack'"
            :result="parsedResult"
            class="mb-3"
          />
        </template>

        <NCard
          v-else-if="detail.status === 'failed'"
          class="mb-3"
          size="small"
        >
          <NEmpty description="执行失败，无结果数据">
            <template #extra>
              <div class="text-error mt-2 text-sm">
                {{ detail.error || '执行异常，未返回结果' }}
              </div>
            </template>
          </NEmpty>
        </NCard>

        <!-- 原始 JSON -->
        <NCard
          v-if="detail.result_json"
          class="mb-3"
          size="small"
        >
          <NCollapse>
            <NCollapseItem title="原始 result_json（调试用）" name="raw">
              <NInput
                type="textarea"
                :value="JSON.stringify(parsedResult, null, 2)"
                readonly
                :rows="16"
                class="font-mono"
              />
            </NCollapseItem>
          </NCollapse>
        </NCard>
      </template>
    </NSpin>
  </Page>
</template>
