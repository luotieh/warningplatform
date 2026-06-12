<script lang="ts" setup>
import { computed, ref } from 'vue';

import {
  NButton,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NSpace,
  NSpin,
  NTag,
  NTooltip,
  useMessage,
} from 'naive-ui';

import {
  aiEnrichFinding,
  getEvidenceReport,
  type AIEnrichResult,
  type EvidenceReport,
  type ScanFinding,
} from '#/api/task';

import { formatFindingDataValue } from './finding-display';
import CreateDispatchDrawer from '#/views/dispatch/CreateDispatchDrawer.vue';

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
  cve_id: 'CVE 编号',
  cve: 'CVE 编号',
  cvss_score: 'CVSS 评分',
  owasp_category: 'OWASP 分类',
  owasp: 'OWASP 分类',
  remediation: '修复建议',
  solution: '修复建议',
  fix: '修复建议',
  reference: '参考链接',
  references: '参考链接',
  affect_scope: '影响范围',
  matched_at: '匹配位置',
  request: '请求报文',
  response: '响应报文',
  curl_command: 'cURL 命令',
  username: '用户名',
  password: '密码',
  param: '参数',
  technologies: '技术栈',
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

const severityConfig: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: '#d03050', bg: '#fff1f0', label: '严重' },
  high: { color: '#f0a020', bg: '#fff7e6', label: '高危' },
  medium: { color: '#2080f0', bg: '#f0f5ff', label: '中危' },
  low: { color: '#18a058', bg: '#f6ffed', label: '低危' },
  info: { color: '#999', bg: '#f5f5f5', label: '信息' },
};

const drawerWidth = computed(() => {
  if (typeof window === 'undefined') return 780;
  return Math.min(Math.floor(window.innerWidth * 0.92), 880);
});

const dataPriority = ['proof', 'check', 'service', 'version', 'username', 'password', 'port', 'banner'];

const prominentKeys = new Set([
  'screenshot', 'body_preview', 'cve_id', 'cve', 'cvss_score',
  'remediation', 'solution', 'fix', 'reference', 'references',
  'affect_scope', 'owasp_category', 'owasp', 'matched_at',
  'request', 'response', 'curl_command', 'verified', 'verify_detail', 'verify_variants',
]);

const cveId = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.cve_id || data.cve || '';
});

const cvssScore = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  const v = data.cvss_score ?? data.cvss;
  if (v === undefined || v === null) return '';
  return String(v);
});

const owaspCategory = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.owasp_category || data.owasp || '';
});

const remediation = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.remediation || data.solution || data.fix || '';
});

const vulnCause = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.vuln_cause || '';
});

const referenceLinks = computed(() => {
  const data = props.finding?.data;
  if (!data) return [];
  const raw = data.references || data.reference;
  if (!raw) return [];
  if (Array.isArray(raw)) return raw.filter(Boolean);
  if (typeof raw === 'string') {
    return raw.split(/[\n,;]/).map((s: string) => s.trim()).filter(Boolean);
  }
  return [];
});

const affectScope = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.affect_scope || '';
});

const matchedAt = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.matched_at || '';
});

const requestData = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.request || '';
});

const responseData = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.response || '';
});

const curlCommand = computed(() => {
  const data = props.finding?.data;
  if (!data) return '';
  return data.curl_command || '';
});

const dataEntries = computed(() => {
  const data = props.finding?.data;
  if (!data) return [];
  const entries = Object.entries(data).filter(([key]) => !prominentKeys.has(key));
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

const message = useMessage();
const aiEnriching = ref(false);
const aiEnrichResult = ref<AIEnrichResult | null>(null);

async function handleAIEnrich() {
  if (!props.finding) return;
  aiEnriching.value = true;
  aiEnrichResult.value = null;
  try {
    const result = await aiEnrichFinding(props.finding.task_id, props.finding.id);
    aiEnrichResult.value = result;
    message.success('AI 补充完成');
  } catch (e: any) {
    message.error(e?.message || 'AI 补充失败');
  } finally {
    aiEnriching.value = false;
  }
}

const evidenceCopied = ref(false);
function copyEvidence() {
  const text = props.finding?.evidence || props.finding?.data?.proof;
  if (!text) return;
  navigator.clipboard.writeText(String(text)).then(() => {
    evidenceCopied.value = true;
    setTimeout(() => { evidenceCopied.value = false; }, 2000);
  }).catch(() => {});
}

const aiVerifyData = computed(() => {
  const d = props.finding?.data;
  if (!d || d.ai_verified !== 'true') return null;
  return {
    isVulnerable: d.ai_verify_is_vulnerable as boolean,
    confidence: d.ai_verify_confidence as number,
    reasoning: d.ai_verify_reasoning as string,
    falseReason: d.ai_verify_false_reason as string | undefined,
    suggestion: d.ai_verify_suggestion as string | undefined,
  };
});

const verificationTimeline = computed(() => {
  const steps: Array<{
    icon: string;
    color: string;
    title: string;
    description: string;
    time?: string;
  }> = [];

  const f = props.finding;
  if (!f) return steps;

  steps.push({
    icon: 'scan',
    color: '#1890ff',
    title: '扫描发现',
    description: `模块 ${f.module_id} 检测到 ${typeLabels[f.type] ?? f.type} 类型漏洞`,
    time: formatTime(f.created_at),
  });

  if (f.evidence || f.data?.proof) {
    steps.push({
      icon: 'evidence',
      color: '#52c41a',
      title: '证据采集',
      description: f.evidence
        ? `已采集验证证据 (${f.evidence.length} 字符)`
        : '验证摘录已记录',
    });
  }

  if (f.data?.request || f.data?.response) {
    steps.push({
      icon: 'network',
      color: '#722ed1',
      title: '请求/响应记录',
      description: [
        f.data.request ? '已记录攻击请求' : '',
        f.data.response ? '已记录服务端响应' : '',
        f.data.curl_command ? '已生成 cURL 命令' : '',
      ].filter(Boolean).join('；'),
    });
  }

  if (f.data?.screenshot) {
    steps.push({
      icon: 'screenshot',
      color: '#13c2c2',
      title: '页面截图',
      description: '已自动采集目标页面截图',
    });
  }

  if (f.verification_level) {
    const levelLabel = f.verification_level === 'exploit' ? '实际利用验证' : '原理验证';
    steps.push({
      icon: 'verify',
      color: f.verification_level === 'exploit' ? '#f5222d' : '#faad14',
      title: `验证级别: ${levelLabel}`,
      description: f.verification_detail || '已完成漏洞可利用性验证',
    });
  }

  const av = aiVerifyData.value;
  if (av) {
    steps.push({
      icon: 'ai',
      color: av.isVulnerable ? '#52c41a' : '#ff4d4f',
      title: av.isVulnerable ? 'AI 确认漏洞存在' : 'AI 判定可能误报',
      description: `AI 置信度 ${av.confidence}%` +
        (av.falseReason ? `，误报原因: ${av.falseReason}` : ''),
    });
  }

  if (f.confidence > 0) {
    steps.push({
      icon: 'confidence',
      color: getConfColor(f.confidence),
      title: `综合置信度 ${f.confidence}%`,
      description: f.confidence_reason || '基于多维度分析的置信度评估',
    });
  }

  return steps;
});

const showDispatchDrawer = ref(false);

const exportingReport = ref(false);
async function handleExportReport() {
  const f = props.finding;
  if (!f) return;
  exportingReport.value = true;
  try {
    const report = await getEvidenceReport(f.task_id, f.id);
    downloadEvidenceReportHTML(report);
    message.success('证据报告已导出');
  } catch (e: any) {
    message.error(e?.message || '导出失败');
  } finally {
    exportingReport.value = false;
  }
}

function downloadEvidenceReportHTML(r: EvidenceReport) {
  const sevLabels: Record<string, string> = {
    critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
  };
  const sevColors: Record<string, string> = {
    critical: '#cf1322', high: '#fa8c16', medium: '#faad14', low: '#52c41a', info: '#999',
  };

  let screenshotHTML = '';
  if (r.screenshot) {
    screenshotHTML = `<div class="section"><h3>📸 页面截图</h3><img src="data:image/jpeg;base64,${r.screenshot}" style="max-width:100%;border:1px solid #ddd;border-radius:8px"/></div>`;
  }

  let aiHTML = '';
  if (r.ai_verified) {
    aiHTML = `<div class="section"><h3>🤖 AI 验证分析</h3>
      <div class="ai-box">
        <div class="ai-reasoning">${escapeHTML(r.ai_reasoning || '')}</div>
        ${r.ai_false_reason ? `<div class="ai-false"><strong>误报原因：</strong>${escapeHTML(r.ai_false_reason)}</div>` : ''}
        ${r.ai_suggestion ? `<div class="ai-suggestion"><strong>进一步建议：</strong>${escapeHTML(r.ai_suggestion)}</div>` : ''}
      </div>
    </div>`;
  }

  const html = `<!DOCTYPE html><html lang="zh-CN"><head>
<meta charset="UTF-8"><title>漏洞证据报告 - ${escapeHTML(r.title)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,system-ui,sans-serif;background:#f5f7fa;color:#333;padding:40px 20px}
.container{max-width:900px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.08);overflow:hidden}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);color:#fff;padding:32px 40px}
.header h1{font-size:20px;margin-bottom:8px}
.header .meta{display:flex;gap:12px;flex-wrap:wrap;font-size:13px;opacity:.85}
.sev-badge{display:inline-block;padding:2px 12px;border-radius:4px;font-weight:700;font-size:12px;color:#fff;background:${sevColors[r.severity] || '#999'}}
.body{padding:32px 40px}
.section{margin-bottom:28px}
.section h3{font-size:14px;font-weight:600;margin-bottom:12px;padding-left:10px;border-left:3px solid #1890ff;color:#1a1a2e}
.info-grid{display:grid;grid-template-columns:140px 1fr;gap:1px;background:#eee;border:1px solid #eee;border-radius:8px;overflow:hidden}
.info-grid .label{background:#f8f9fa;padding:10px 14px;font-size:12px;color:#666;font-weight:500}
.info-grid .value{background:#fff;padding:10px 14px;font-size:12px;word-break:break-all}
.code-block{background:#0d1117;color:#e6edf3;padding:14px 16px;border-radius:8px;font-family:'SF Mono',Consolas,monospace;font-size:11px;line-height:1.6;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow:auto}
.ai-box{background:#f0f7ff;border:1px solid #d6e4ff;border-radius:8px;padding:16px}
.ai-reasoning{font-size:12px;line-height:1.7;white-space:pre-wrap;margin-bottom:8px}
.ai-false,.ai-suggestion{font-size:12px;margin-top:8px;padding:8px 12px;background:#fff;border-radius:6px;border:1px solid #eee}
.footer{padding:20px 40px;border-top:1px solid #f0f0f0;font-size:11px;color:#999;text-align:center}
</style></head><body>
<div class="container">
<div class="header">
  <h1>${escapeHTML(r.title)}</h1>
  <div class="meta">
    <span class="sev-badge">${sevLabels[r.severity] || r.severity}</span>
    <span>目标: ${escapeHTML(r.target)}${r.port > 0 ? ':' + r.port : ''}</span>
    <span>置信度: ${r.confidence}%</span>
    ${r.cve_id ? `<span>CVE: ${escapeHTML(r.cve_id)}</span>` : ''}
    <span>发现时间: ${escapeHTML(r.created_at)}</span>
  </div>
</div>
<div class="body">
  <div class="section"><h3>📋 基本信息</h3>
    <div class="info-grid">
      <div class="label">漏洞类型</div><div class="value">${escapeHTML(r.vuln_type)}</div>
      <div class="label">验证级别</div><div class="value">${r.verification_level === 'exploit' ? '实际利用' : '原理验证'}</div>
      ${r.cvss_score ? `<div class="label">CVSS 评分</div><div class="value">${escapeHTML(r.cvss_score)}</div>` : ''}
      ${r.matched_at ? `<div class="label">匹配位置</div><div class="value">${escapeHTML(r.matched_at)}</div>` : ''}
    </div>
  </div>
  ${r.description ? `<div class="section"><h3>📝 描述</h3><div style="font-size:12px;line-height:1.7">${escapeHTML(r.description)}</div></div>` : ''}
  ${r.evidence ? `<div class="section"><h3>🔍 验证证据</h3><div class="code-block">${escapeHTML(r.evidence)}</div></div>` : ''}
  ${r.verification_detail ? `<div class="section"><h3>✅ 验证详情</h3><div style="font-size:12px;line-height:1.7;white-space:pre-wrap">${escapeHTML(r.verification_detail)}</div></div>` : ''}
  ${r.payload ? `<div class="section"><h3>💉 Payload</h3><div class="code-block">${escapeHTML(r.payload)}</div></div>` : ''}
  ${r.request ? `<div class="section"><h3>📤 请求报文</h3><div class="code-block">${escapeHTML(r.request)}</div></div>` : ''}
  ${r.response ? `<div class="section"><h3>📥 响应报文</h3><div class="code-block">${escapeHTML(r.response)}</div></div>` : ''}
  ${r.curl_command ? `<div class="section"><h3>🖥️ cURL 命令</h3><div class="code-block">${escapeHTML(r.curl_command)}</div></div>` : ''}
  ${screenshotHTML}
  ${aiHTML}
  ${r.remediation ? `<div class="section"><h3>🔧 修复建议</h3><div style="font-size:12px;line-height:1.7;background:#f6ffed;padding:14px 16px;border-radius:8px;border:1px solid #b7eb8f;white-space:pre-wrap">${escapeHTML(r.remediation)}</div></div>` : ''}
</div>
<div class="footer">漏洞证据报告 · 由安全扫描平台自动生成 · ${new Date().toLocaleString('zh-CN')}</div>
</div></body></html>`;

  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `证据报告_${r.title.replace(/[/\\?%*:|"<>]/g, '_').slice(0, 40)}_${r.finding_id.slice(0, 8)}.html`;
  a.click();
  URL.revokeObjectURL(url);
}

function escapeHTML(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/\n/g, '<br>');
}
</script>

<template>
  <NDrawer :show="show" :width="drawerWidth" placement="right" @update:show="emit('update:show', $event)">
    <NDrawerContent closable>
      <template #header>
        <div class="fd-header">
          <div class="fd-header__title">{{ finding?.title || '发现详情' }}</div>
          <div v-if="finding" class="fd-header__meta">
            <NTag size="small" :bordered="false" type="info">
              {{ typeLabels[finding.type] ?? finding.type }}
            </NTag>
            <span
              class="fd-sev-badge"
              :style="{
                background: (severityConfig[finding.severity] ?? severityConfig.info!).bg,
                color: (severityConfig[finding.severity] ?? severityConfig.info!).color,
                borderColor: (severityConfig[finding.severity] ?? severityConfig.info!).color + '40',
              }"
            >
              {{ (severityConfig[finding.severity] ?? { label: finding.severity }).label }}
            </span>
            <span v-if="finding.confidence" class="fd-conf-text">
              置信度 {{ finding.confidence }}%
            </span>
            <NTag v-for="tag in (finding.tags || [])" :key="tag" size="small" :bordered="false" style="background: #f0f0f0; color: #666">{{ tag }}</NTag>
          </div>
        </div>
      </template>

      <template v-if="finding">
        <section class="fd-section">
          <div class="fd-section__title">基本信息</div>
          <NDescriptions label-placement="left" bordered :column="1" size="small">
            <NDescriptionsItem label="目标">
              <span class="fd-mono">
                {{ cleanTarget(finding.target) }}{{ finding.port > 0 ? `:${finding.port}` : '' }}
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem label="模块">{{ moduleLabel || finding.module_id }}</NDescriptionsItem>
            <NDescriptionsItem label="置信度">
              <div class="fd-conf-inline">
                <div class="fd-conf-bar-track">
                  <div class="fd-conf-bar-fill" :style="{ width: `${finding.confidence}%`, background: getConfColor(finding.confidence) }" />
                </div>
                <NTag
                  size="small"
                  :bordered="false"
                  :style="`background: ${getConfColor(finding.confidence)}15; color: ${getConfColor(finding.confidence)}; font-weight: 600`"
                >
                  {{ finding.confidence }}%
                </NTag>
              </div>
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
            <NDescriptionsItem v-if="finding.data?.verified" label="验证结果">
              <span v-if="finding.data.verified === 'true'" style="color: #389e0d; font-weight: 600">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="#389e0d" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 2px"><polyline points="20 6 9 17 4 12" /></svg>
                已确认存在
              </span>
              <span v-else style="color: #8c8c8c">未确认</span>
              <span v-if="finding.data.verify_variants" style="margin-left: 8px; font-size: 11px; color: #666">
                (变体: {{ finding.data.verify_variants }})
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="cveId" label="CVE 编号">
              <a :href="`https://nvd.nist.gov/vuln/detail/${cveId}`" target="_blank" rel="noopener" style="color: #1890ff; text-decoration: none; font-weight: 600; font-family: 'SF Mono', Consolas, monospace">
                {{ cveId }}
              </a>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="cvssScore" label="CVSS 评分">
              <span :style="{ fontWeight: '700', color: parseFloat(cvssScore) >= 9 ? '#cf1322' : parseFloat(cvssScore) >= 7 ? '#fa8c16' : parseFloat(cvssScore) >= 4 ? '#faad14' : '#52c41a' }">
                {{ cvssScore }}
              </span>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="owaspCategory" label="OWASP">
              <NTag size="small" :bordered="false" type="info">{{ owaspCategory }}</NTag>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="affectScope" label="影响范围">{{ affectScope }}</NDescriptionsItem>
            <NDescriptionsItem v-if="matchedAt" label="匹配位置">
              <span class="fd-mono" style="font-size: 11px; word-break: break-all">{{ matchedAt }}</span>
            </NDescriptionsItem>
          </NDescriptions>
        </section>

        <section v-if="finding.confidence_reason" class="fd-section">
          <div class="fd-section__title">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#1890ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px"><circle cx="12" cy="12" r="10" /><line x1="12" y1="16" x2="12" y2="12" /><line x1="12" y1="8" x2="12.01" y2="8" /></svg>
            置信度依据
          </div>
          <div class="fd-conf-reason-card">
            <div class="fd-conf-reason-header">
              <span class="fd-conf-reason-score" :style="{ color: getConfColor(finding.confidence) }">{{ finding.confidence }}%</span>
              <span class="fd-conf-reason-level">{{ finding.confidence >= 90 ? '高置信度' : finding.confidence >= 70 ? '中高置信度' : finding.confidence >= 50 ? '中置信度' : '低置信度' }}</span>
            </div>
            <pre class="fd-block" style="margin: 0">{{ finding.confidence_reason }}</pre>
          </div>
        </section>

        <section v-if="finding.data?.verify_detail" class="fd-section">
          <div class="fd-section__title">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#52c41a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></svg>
            验证详情
          </div>
          <pre class="fd-block">{{ finding.data.verify_detail }}</pre>
        </section>

        <div class="fd-divider" />

        <section v-if="finding.description || aiEnrichResult?.description" class="fd-section">
          <div class="fd-section__title">描述</div>
          <pre class="fd-block fd-block--text">{{ aiEnrichResult?.description || finding.description }}</pre>
        </section>

        <section v-if="aiEnrichResult?.cause || vulnCause" class="fd-section">
          <div class="fd-section__title">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#fa8c16" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px"><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></svg>
            漏洞成因
            <NTag size="small" :bordered="false" type="warning" style="margin-left: 4px">AI</NTag>
          </div>
          <pre class="fd-block fd-block--text" style="background: #fff7e6; border-color: #ffd591">{{ aiEnrichResult?.cause || vulnCause }}</pre>
        </section>

        <section v-if="finding.evidence || finding.data?.proof" class="fd-section">
          <div class="fd-section__title">
            验证证据
            <NTooltip>
              <template #trigger>
                <button class="fd-copy-btn" @click="copyEvidence">
                  <svg v-if="!evidenceCopied" viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></svg>
                  <svg v-else viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#52c41a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                </button>
              </template>
              {{ evidenceCopied ? '已复制' : '复制' }}
            </NTooltip>
          </div>
          <pre v-if="finding.evidence" class="fd-block fd-block--code">{{ finding.evidence }}</pre>
          <pre
            v-if="finding.data?.proof && finding.data.proof !== finding.evidence"
            class="fd-block fd-block--code"
            style="margin-top: 8px"
          >{{ finding.data.proof }}</pre>
        </section>

        <section v-if="(finding as any).verification_detail" class="fd-section">
          <div class="fd-section__title">验证过程</div>
          <pre class="fd-block fd-block--text">{{ (finding as any).verification_detail }}</pre>
        </section>

        <!-- AI 验证分析 -->
        <section v-if="aiVerifyData" class="fd-section">
          <div class="fd-section__title">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#722ed1" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px"><path d="M12 2L2 7l10 5 10-5-10-5z" /><path d="M2 17l10 5 10-5" /><path d="M2 12l10 5 10-5" /></svg>
            AI 验证分析
            <NTag size="small" :bordered="false" :type="aiVerifyData.isVulnerable ? 'error' : 'success'" style="margin-left: 4px">
              {{ aiVerifyData.isVulnerable ? '确认漏洞' : '可能误报' }}
            </NTag>
          </div>
          <div class="fd-ai-verify-card">
            <div class="fd-ai-verify-header">
              <span class="fd-ai-verify-score" :style="{ color: aiVerifyData.isVulnerable ? '#f5222d' : '#52c41a' }">
                {{ aiVerifyData.confidence }}%
              </span>
              <span class="fd-ai-verify-label">AI 置信度</span>
            </div>
            <pre v-if="aiVerifyData.reasoning" class="fd-block fd-block--text" style="margin: 8px 0 0">{{ aiVerifyData.reasoning }}</pre>
            <div v-if="aiVerifyData.falseReason" class="fd-ai-false-reason">
              <strong>误报原因：</strong>{{ aiVerifyData.falseReason }}
            </div>
            <div v-if="aiVerifyData.suggestion" class="fd-ai-suggestion">
              <strong>进一步建议：</strong>{{ aiVerifyData.suggestion }}
            </div>
          </div>
        </section>

        <!-- 验证时间线 -->
        <section v-if="verificationTimeline.length > 1" class="fd-section">
          <div class="fd-section__title">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#1890ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px"><circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" /></svg>
            验证过程时间线
          </div>
          <div class="fd-timeline">
            <div
              v-for="(step, idx) in verificationTimeline"
              :key="idx"
              class="fd-timeline__item"
            >
              <div class="fd-timeline__line" :style="{ background: step.color }" />
              <div class="fd-timeline__dot" :style="{ background: step.color }" />
              <div class="fd-timeline__content">
                <div class="fd-timeline__title">{{ step.title }}</div>
                <div class="fd-timeline__desc">{{ step.description }}</div>
                <div v-if="step.time" class="fd-timeline__time">{{ step.time }}</div>
              </div>
            </div>
          </div>
        </section>

        <div class="fd-divider" />

        <section v-if="finding.data?.screenshot" class="fd-section">
          <div class="fd-section__title">页面截图</div>
          <div class="fd-screenshot">
            <img
              :src="`data:image/jpeg;base64,${finding.data.screenshot}`"
              alt="页面截图"
              @click="openScreenshot(finding.data.screenshot)"
            />
          </div>
        </section>

        <section v-if="remediation || aiEnrichResult?.remediation" class="fd-section">
          <div class="fd-section__title">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="#52c41a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 4px"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
            修复建议
            <NTag v-if="!remediation && aiEnrichResult?.remediation" size="small" :bordered="false" type="warning" style="margin-left: 4px">AI</NTag>
          </div>
          <pre class="fd-block fd-block--text" style="background: #f6ffed; border-color: #b7eb8f">{{ aiEnrichResult?.remediation || remediation }}</pre>
        </section>

        <section v-if="referenceLinks.length" class="fd-section">
          <div class="fd-section__title">参考链接</div>
          <div class="fd-ref-links">
            <a v-for="(link, idx) in referenceLinks" :key="idx" :href="link" target="_blank" rel="noopener" class="fd-ref-link">
              {{ link }}
            </a>
          </div>
        </section>

        <section v-if="requestData || responseData || curlCommand" class="fd-section">
          <div class="fd-section__title">请求/响应</div>
          <div v-if="curlCommand" style="margin-bottom: 8px">
            <div style="font-size: 11px; color: #999; margin-bottom: 4px; font-weight: 500">cURL 命令</div>
            <pre class="fd-block fd-block--code" style="font-size: 11px">{{ curlCommand }}</pre>
          </div>
          <div v-if="requestData" style="margin-bottom: 8px">
            <div style="font-size: 11px; color: #999; margin-bottom: 4px; font-weight: 500">请求</div>
            <pre class="fd-block fd-block--code" style="font-size: 11px; max-height: 200px">{{ requestData }}</pre>
          </div>
          <div v-if="responseData">
            <div style="font-size: 11px; color: #999; margin-bottom: 4px; font-weight: 500">响应</div>
            <pre class="fd-block fd-block--code" style="font-size: 11px; max-height: 200px">{{ responseData }}</pre>
          </div>
        </section>

        <section v-if="dataEntries.length" class="fd-section">
          <div class="fd-section__title">扩展字段</div>
          <div class="fd-kv">
            <template v-for="[key, val] in dataEntries" :key="key">
              <div v-if="key === 'banner'" class="fd-kv-banner">
                <div class="fd-kv__label">{{ dataKeyLabels[key] ?? key }}</div>
                <pre class="fd-block fd-block--code">{{ formatFindingDataValue(val) }}</pre>
              </div>
              <div v-else class="fd-kv__row">
                <div class="fd-kv__label">{{ dataKeyLabels[key] ?? key }}</div>
                <pre class="fd-kv__value">{{ displayDataValue(key, val) }}</pre>
              </div>
            </template>
          </div>
        </section>

        <div class="fd-divider" />

        <section class="fd-section fd-actions">
          <NSpace :size="10">
            <NButton
              v-if="finding.severity && finding.severity !== 'info'"
              type="warning"
              size="small"
              :loading="convertingToIncident"
              @click="emit('to-incident')"
            >
              <template #icon>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
              </template>
              转为安全事件
            </NButton>
            <NButton
              type="info"
              size="small"
              secondary
              :loading="retesting"
              @click="emit('retest')"
            >
              <template #icon>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>
              </template>
              漏洞回测
            </NButton>
            <NButton type="error" size="small" secondary :loading="markingFP" @click="emit('mark-fp')">
              <template #icon>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10" /><line x1="4.93" y1="4.93" x2="19.07" y2="19.07" /></svg>
              </template>
              标记误报
            </NButton>
            <NButton size="small" secondary type="primary" @click="showDispatchDrawer = true">
              <template #icon>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="22" y1="2" x2="11" y2="13" /><polygon points="22 2 15 22 11 13 2 9 22 2" /></svg>
              </template>
              派发处理
            </NButton>
            <NButton
              size="small"
              secondary
              :loading="aiEnriching"
              :disabled="!!aiEnrichResult"
              @click="handleAIEnrich"
            >
              <template #icon>
                <NSpin v-if="aiEnriching" :size="14" />
                <svg v-else viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z" /><path d="M2 17l10 5 10-5" /><path d="M2 12l10 5 10-5" /></svg>
              </template>
              {{ aiEnrichResult ? 'AI 已补充' : 'AI 补充' }}
            </NButton>
            <NButton
              size="small"
              secondary
              type="primary"
              :loading="exportingReport"
              @click="handleExportReport"
            >
              <template #icon>
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /><polyline points="10 9 9 9 8 9" /></svg>
              </template>
              导出证据报告
            </NButton>
          </NSpace>
        </section>
      </template>
    </NDrawerContent>
  </NDrawer>

  <CreateDispatchDrawer
    v-model:show="showDispatchDrawer"
    source-type="finding"
    :source-id="finding?.id"
    :source-title="finding?.title || finding?.module"
    default-type="vuln_retest"
    :source-detail="finding ? { severity: finding.severity, target: finding.target, status: finding.status } : undefined"
  />
</template>

<style scoped>
/* Header */
.fd-header__title {
  font-size: 17px;
  font-weight: 700;
  line-height: 1.4;
  word-break: break-word;
  color: var(--n-text-color);
}
.fd-header__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-top: 10px;
}
.fd-sev-badge {
  display: inline-flex;
  align-items: center;
  padding: 1px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 700;
  border: 1px solid;
  letter-spacing: 0.3px;
}
.fd-conf-text {
  font-size: 12px;
  color: var(--text-color-3, #8c8c8c);
}

.fd-conf-inline {
  display: flex;
  align-items: center;
  gap: 8px;
}

.fd-conf-bar-track {
  width: 60px;
  height: 5px;
  background: var(--border-color-light, #f0f0f0);
  border-radius: 3px;
  overflow: hidden;
}

.fd-conf-bar-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.4s ease;
}

.fd-conf-reason-card {
  background: var(--primary-color-suppl, #f0f7ff);
  border: 1px solid var(--primary-color-hover, #d6e4ff);
  border-radius: 8px;
  padding: 12px 14px;
}

.fd-conf-reason-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.fd-conf-reason-score {
  font-size: 18px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}

.fd-conf-reason-level {
  font-size: 12px;
  color: var(--text-color-2, #4a5568);
  font-weight: 500;
}

/* Section */
.fd-section {
  margin-bottom: 24px;
}
.fd-section__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--n-text-color);
  margin-bottom: 12px;
  padding-left: 10px;
  border-left: 3px solid var(--primary-color, #1890ff);
  display: flex;
  align-items: center;
  gap: 8px;
}

/* Divider */
.fd-divider {
  height: 1px;
  background: linear-gradient(to right, var(--border-color, #e8e8e8), transparent);
  margin: 8px 0 20px;
}

/* Blocks */
.fd-block {
  margin: 0;
  padding: 14px 16px;
  font-size: 12px;
  line-height: 1.7;
  white-space: pre-wrap;
  word-break: break-word;
  border-radius: 8px;
  border: 1px solid var(--border-color, #e8e8e8);
  background: var(--body-color, #fafafa);
  color: var(--text-color-2, #444);
  max-height: min(50vh, 420px);
  overflow: auto;
}
.fd-block--code {
  font-family: 'SF Mono', Consolas, Monaco, monospace;
  font-size: 11.5px;
  background: #0d1117;
  color: #e6edf3;
  border-color: #30363d;
  line-height: 1.65;
  box-shadow: inset 0 1px 3px rgba(0, 0, 0, 0.2);
}
.fd-block--text {
  background: var(--card-color, #fff);
  border-color: var(--border-color, #eef2f6);
}
.fd-mono {
  font-family: 'SF Mono', Consolas, monospace;
  word-break: break-all;
}

/* Copy button */
.fd-copy-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border: 1px solid var(--border-color, #e0e0e0);
  border-radius: 5px;
  background: var(--card-color, #fafafa);
  cursor: pointer;
  transition: all 0.15s;
  padding: 0;
}
.fd-copy-btn:hover {
  border-color: var(--primary-color, #1890ff);
  background: var(--primary-color-suppl, #f0f5ff);
}

/* Screenshot */
.fd-screenshot {
  border: 1px solid var(--border-color, #e8e8e8);
  border-radius: 8px;
  overflow: hidden;
  cursor: zoom-in;
  transition: box-shadow 0.2s;
}
.fd-screenshot:hover {
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
}
.fd-screenshot img {
  width: 100%;
  display: block;
}

/* KV table */
.fd-kv {
  border: 1px solid var(--border-color, #eef2f6);
  border-radius: 8px;
  overflow: hidden;
}
.fd-kv__row {
  display: grid;
  grid-template-columns: 130px 1fr;
  border-bottom: 1px solid var(--border-color-light, #f5f5f5);
  font-size: 12px;
  transition: background 0.1s;
}
.fd-kv__row:last-child {
  border-bottom: none;
}
.fd-kv__row:hover {
  background: var(--hover-color, #fafbfc);
}
.fd-kv__label {
  padding: 10px 14px;
  background: var(--body-color, #f8f9fa);
  color: var(--text-color-3, #666);
  font-weight: 500;
  word-break: break-word;
  border-right: 1px solid var(--border-color-light, #f0f0f0);
}
.fd-kv__value {
  margin: 0;
  padding: 10px 14px;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-color-1, #333);
  font-family: inherit;
  max-height: 280px;
  overflow: auto;
}
.fd-kv-banner {
  border-bottom: 1px solid var(--border-color-light, #f0f0f0);
}
.fd-kv-banner .fd-kv__label {
  padding: 8px 14px;
}

/* Actions */
.fd-actions {
  padding-top: 14px;
  border-top: 1px solid var(--border-color, #eef2f6);
  margin-top: 8px;
}

/* Reference Links */
.fd-ref-links {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.fd-ref-link {
  display: block;
  font-size: 12px;
  color: #1890ff;
  text-decoration: none;
  word-break: break-all;
  padding: 6px 10px;
  border-radius: 4px;
  background: #f0f5ff;
  border: 1px solid #d6e4ff;
  transition: background 0.15s;
}
.fd-ref-link:hover {
  background: #e6f7ff;
  border-color: #91d5ff;
}

/* AI Verify */
.fd-ai-verify-card {
  background: linear-gradient(135deg, #f9f0ff, #f0f5ff);
  border: 1px solid #d3adf7;
  border-radius: 8px;
  padding: 14px 16px;
}
.fd-ai-verify-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}
.fd-ai-verify-score {
  font-size: 20px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
}
.fd-ai-verify-label {
  font-size: 12px;
  color: var(--text-color-2, #666);
  font-weight: 500;
}
.fd-ai-false-reason {
  margin-top: 10px;
  padding: 8px 12px;
  background: #fff1f0;
  border: 1px solid #ffa39e;
  border-radius: 6px;
  font-size: 12px;
  line-height: 1.6;
}
.fd-ai-suggestion {
  margin-top: 8px;
  padding: 8px 12px;
  background: #e6fffb;
  border: 1px solid #87e8de;
  border-radius: 6px;
  font-size: 12px;
  line-height: 1.6;
}

/* Timeline */
.fd-timeline {
  position: relative;
  padding-left: 24px;
}
.fd-timeline__item {
  position: relative;
  padding-bottom: 20px;
}
.fd-timeline__item:last-child {
  padding-bottom: 0;
}
.fd-timeline__item:last-child .fd-timeline__line {
  display: none;
}
.fd-timeline__line {
  position: absolute;
  left: -18px;
  top: 14px;
  bottom: -6px;
  width: 2px;
  opacity: 0.3;
}
.fd-timeline__dot {
  position: absolute;
  left: -22px;
  top: 4px;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  box-shadow: 0 0 0 3px rgba(255, 255, 255, 0.9);
}
.fd-timeline__content {
  padding-left: 4px;
}
.fd-timeline__title {
  font-size: 13px;
  font-weight: 600;
  color: var(--n-text-color);
  line-height: 1.4;
}
.fd-timeline__desc {
  font-size: 12px;
  color: var(--text-color-2, #666);
  margin-top: 2px;
  line-height: 1.5;
}
.fd-timeline__time {
  font-size: 11px;
  color: var(--text-color-3, #999);
  margin-top: 2px;
}
</style>
