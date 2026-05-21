<script lang="ts" setup>
import { computed } from 'vue';

import {
  NButton,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NSpace,
  NTag,
} from 'naive-ui';

import type { ScanFinding } from '#/api/task';

import { formatFindingDataValue } from './finding-display';

const props = defineProps<{
  show: boolean;
  finding: ScanFinding | null;
  moduleLabel?: string;
  convertingToIncident?: boolean;
  markingFP?: boolean;
  retesting?: boolean;
}>();

const emit = defineEmits<{
  'update:show': [value: boolean];
  retest: [];
  'to-incident': [];
  'mark-fp': [];
}>();

const dataKeyLabels: Record<string, string> = {
  url: 'URL',
  ip: 'IP',
  port: '端口',
  protocol: '协议',
  host: '主机',
  domain: '域名',
  service: '服务',
  version: '版本',
  banner: 'Banner',
  server: '服务器',
  title: '页面标题',
  name: '名称',
  category: '分类',
  method: '方法',
  record_type: '记录类型',
  value: '值',
  payload: 'Payload',
  path: '路径',
  action: '表单 Action',
  inputs: '输入字段',
  status_code: '状态码',
  content_type: '内容类型',
  screenshot: '页面截图',
  source: '来源',
  evidence: '证据',
  proof: '验证摘录',
  check: '检测方式',
  verification_detail: '验证说明',
  waf: 'WAF',
  cdn: 'CDN',
};

const sourceLabels: Record<string, string> = {
  brute_pipeline: '字典爆破',
  passive_crtsh: 'CRT.sh',
  crawler: '爬虫',
  tls_cert: 'TLS证书',
};

const typeLabels: Record<string, string> = {
  port_open: 'TCP端口',
  host_alive: '主机存活',
  service: '服务识别',
  sqli: 'SQL注入',
  xss: 'XSS',
  weak_pass: '弱口令',
};

const severityConfig: Record<string, { color: string; label: string }> = {
  critical: { color: '#d03050', label: '严重' },
  high: { color: '#f0a020', label: '高危' },
  medium: { color: '#2080f0', label: '中危' },
  low: { color: '#18a058', label: '低危' },
  info: { color: '#999', label: '信息' },
};

const drawerWidth = computed(() => {
  if (typeof window === 'undefined') return 780;
  return Math.min(Math.floor(window.innerWidth * 0.92), 880);
});

const dataPriority = ['proof', 'check', 'service', 'version', 'username', 'password', 'port', 'banner'];

const dataEntries = computed(() => {
  const data = props.finding?.data;
  if (!data) return [];
  const entries = Object.entries(data).filter(([key]) => key !== 'screenshot' && key !== 'body_preview');
  entries.sort((a, b) => {
    const ai = dataPriority.indexOf(a[0]);
    const bi = dataPriority.indexOf(b[0]);
    const ap = ai === -1 ? 999 : ai;
    const bp = bi === -1 ? 999 : bi;
    if (ap !== bp) return ap - bp;
    return a[0].localeCompare(b[0]);
  });
  return entries;
});

function cleanTarget(raw: string): string {
  let t = raw ?? '';
  if (t.startsWith('http://')) t = t.slice(7);
  else if (t.startsWith('https://')) t = t.slice(8);
  t = t.replace(/\/+$/, '');
  const portMatch = t.match(/:(\d+)$/);
  if (portMatch) t = t.slice(0, -portMatch[0].length);
  return t;
}

function formatTime(t?: string) {
  if (!t) return '-';
  return t.replace('T', ' ').slice(0, 19);
}

function getConfColor(conf: number): string {
  if (conf >= 90) return '#52c41a';
  if (conf >= 70) return '#faad14';
  if (conf >= 50) return '#fa8c16';
  return '#f5222d';
}

function displayDataValue(key: string, val: unknown): string {
  if (key === 'source' && typeof val === 'string') {
    return sourceLabels[val] ?? val;
  }
  if (key === 'cdn' && val === 'possible_cdn') return '疑似 CDN';
  return formatFindingDataValue(val);
}

function openScreenshot(b64: string) {
  const win = window.open();
  if (win) {
    win.document.write(`<img src="data:image/jpeg;base64,${b64}" style="max-width:100%">`);
    win.document.title = '页面截图';
  }
}
</script>

<template>
  <NDrawer :show="show" :width="drawerWidth" placement="right" @update:show="emit('update:show', $event)">
    <NDrawerContent closable>
      <template #header>
        <div class="finding-drawer-header">
          <div class="finding-drawer-header__title">{{ finding?.title || '发现详情' }}</div>
          <div v-if="finding" class="finding-drawer-header__meta">
            <NTag size="small" :bordered="false" type="info">
              {{ typeLabels[finding.type] ?? finding.type }}
            </NTag>
            <NTag
              size="small"
              :bordered="false"
              :style="`background:${(severityConfig[finding.severity] ?? { color: '#999' }).color}18;color:${(severityConfig[finding.severity] ?? { color: '#999' }).color}`"
            >
              {{ (severityConfig[finding.severity] ?? { label: finding.severity }).label }}
            </NTag>
          </div>
        </div>
      </template>

      <template v-if="finding">
        <section class="finding-drawer-section">
          <div class="finding-drawer-section__title">基本信息</div>
          <NDescriptions label-placement="left" bordered :column="1" size="small">
            <NDescriptionsItem label="目标">
              <span class="finding-drawer-mono">
                {{ cleanTarget(finding.target) }}{{ finding.port > 0 ? `:${finding.port}` : '' }}
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem label="模块">{{ moduleLabel || finding.module_id }}</NDescriptionsItem>
            <NDescriptionsItem label="置信度">
              <NTag
                size="small"
                :bordered="false"
                :style="`background: ${getConfColor(finding.confidence)}15; color: ${getConfColor(finding.confidence)}; font-weight: 600`"
              >
                {{ finding.confidence }}%
              </NTag>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="finding.protocol" label="协议">{{ finding.protocol }}</NDescriptionsItem>
            <NDescriptionsItem label="时间">{{ formatTime(finding.created_at) }}</NDescriptionsItem>
            <NDescriptionsItem v-if="(finding as any).verification_level" label="验证级别">
              <NTag
                size="small"
                :bordered="false"
                :type="(finding as any).verification_level === 'exploit' ? 'error' : 'warning'"
              >
                {{ (finding as any).verification_level === 'exploit' ? '实际利用' : '原理验证' }}
              </NTag>
            </NDescriptionsItem>
          </NDescriptions>
        </section>

        <section v-if="finding.confidence_reason" class="finding-drawer-section">
          <div class="finding-drawer-section__title">置信度依据</div>
          <pre class="finding-drawer-block">{{ finding.confidence_reason }}</pre>
        </section>

        <section v-if="finding.description" class="finding-drawer-section">
          <div class="finding-drawer-section__title">描述</div>
          <pre class="finding-drawer-block finding-drawer-block--text">{{ finding.description }}</pre>
        </section>

        <section v-if="finding.evidence || finding.data?.proof" class="finding-drawer-section">
          <div class="finding-drawer-section__title">验证证据</div>
          <pre v-if="finding.evidence" class="finding-drawer-block finding-drawer-block--code">{{ finding.evidence }}</pre>
          <pre
            v-if="finding.data?.proof && finding.data.proof !== finding.evidence"
            class="finding-drawer-block finding-drawer-block--code"
            style="margin-top: 8px"
          >{{ finding.data.proof }}</pre>
        </section>

        <section v-if="(finding as any).verification_detail" class="finding-drawer-section">
          <div class="finding-drawer-section__title">验证过程</div>
          <pre class="finding-drawer-block finding-drawer-block--text">{{ (finding as any).verification_detail }}</pre>
        </section>

        <section v-if="finding.data?.screenshot" class="finding-drawer-section">
          <div class="finding-drawer-section__title">页面截图</div>
          <div class="finding-drawer-screenshot">
            <img
              :src="`data:image/jpeg;base64,${finding.data.screenshot}`"
              alt="页面截图"
              @click="openScreenshot(finding.data.screenshot)"
            />
          </div>
        </section>

        <section v-if="dataEntries.length" class="finding-drawer-section">
          <div class="finding-drawer-section__title">扩展字段</div>
          <div class="finding-drawer-kv">
            <template v-for="[key, val] in dataEntries" :key="key">
              <div v-if="key === 'banner'" class="finding-drawer-kv-banner">
                <div class="finding-drawer-kv__label">{{ dataKeyLabels[key] ?? key }}</div>
                <pre class="finding-drawer-block finding-drawer-block--code">{{ formatFindingDataValue(val) }}</pre>
              </div>
              <div v-else class="finding-drawer-kv__row">
                <div class="finding-drawer-kv__label">{{ dataKeyLabels[key] ?? key }}</div>
                <pre class="finding-drawer-kv__value">{{ displayDataValue(key, val) }}</pre>
              </div>
            </template>
          </div>
        </section>

        <section class="finding-drawer-section finding-drawer-actions">
          <NSpace vertical :size="8">
            <NButton
              v-if="finding.severity && finding.severity !== 'info'"
              type="warning"
              :loading="convertingToIncident"
              block
              @click="emit('to-incident')"
            >
              转为安全事件
            </NButton>
            <NButton
              type="info"
              secondary
              :loading="retesting"
              block
              @click="emit('retest')"
            >
              漏洞回测
            </NButton>
            <NButton type="error" secondary :loading="markingFP" block @click="emit('mark-fp')">
              标记误报
            </NButton>
          </NSpace>
        </section>
      </template>
    </NDrawerContent>
  </NDrawer>
</template>

<style scoped>
.finding-drawer-header__title {
  font-size: 16px;
  font-weight: 600;
  line-height: 1.45;
  word-break: break-word;
}
.finding-drawer-header__meta {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}
.finding-drawer-section {
  margin-bottom: 20px;
}
.finding-drawer-section__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--n-text-color);
  margin-bottom: 10px;
  padding-left: 8px;
  border-left: 3px solid #1890ff;
}
.finding-drawer-block {
  margin: 0;
  padding: 12px 14px;
  font-size: 12px;
  line-height: 1.65;
  white-space: pre-wrap;
  word-break: break-word;
  border-radius: 8px;
  border: 1px solid #e8e8e8;
  background: #fafafa;
  color: #444;
  max-height: min(50vh, 420px);
  overflow: auto;
}
.finding-drawer-block--code {
  font-family: 'SF Mono', Consolas, Monaco, monospace;
  font-size: 11px;
  background: #1e1e2e;
  color: #cdd6f4;
  border-color: #2d2d3d;
}
.finding-drawer-block--text {
  background: #fff;
}
.finding-drawer-mono {
  font-family: 'SF Mono', Consolas, monospace;
  word-break: break-all;
}
.finding-drawer-screenshot {
  border: 1px solid #e8e8e8;
  border-radius: 8px;
  overflow: hidden;
  cursor: zoom-in;
}
.finding-drawer-screenshot img {
  width: 100%;
  display: block;
}
.finding-drawer-kv {
  border: 1px solid #e8e8e8;
  border-radius: 8px;
  overflow: hidden;
}
.finding-drawer-kv__row {
  display: grid;
  grid-template-columns: 130px 1fr;
  border-bottom: 1px solid #f0f0f0;
  font-size: 12px;
}
.finding-drawer-kv__row:last-child {
  border-bottom: none;
}
.finding-drawer-kv__label {
  padding: 10px 12px;
  background: #fafafa;
  color: #666;
  font-weight: 500;
  word-break: break-word;
}
.finding-drawer-kv__value {
  margin: 0;
  padding: 10px 12px;
  white-space: pre-wrap;
  word-break: break-word;
  color: #333;
  font-family: inherit;
  max-height: 280px;
  overflow: auto;
}
.finding-drawer-kv-banner {
  border-bottom: 1px solid #f0f0f0;
}
.finding-drawer-kv-banner .finding-drawer-kv__label {
  padding: 8px 12px;
}
.finding-drawer-actions {
  padding-top: 8px;
  border-top: 1px solid #eee;
}
</style>
