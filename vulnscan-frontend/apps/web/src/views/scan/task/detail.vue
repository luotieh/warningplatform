<script lang="ts" setup>
import { onMounted, onUnmounted, ref, computed, h, nextTick } from 'vue';
import { useRoute, useRouter } from 'vue-router';

import {
  NButton,
  NCard,
  NDataTable,
  NDescriptions,
  NDescriptionsItem,
  NDrawer,
  NDrawerContent,
  NInput,
  NModal,
  NPagination,
  NProgress,
  NSelect,
  NSpin,
  NTag,
  NSpace,
  NEmpty,
  NPopconfirm,
  NTooltip,
  useMessage,
} from 'naive-ui';

import {
  getTaskDetail,
  getTaskFindings,
  getTaskFindingSummary,
  getTaskAssets,
  cancelTask,
  deleteTask,
  rerunTask,
  pauseTask,
  resumeTask,
  exportTaskReport,
  subscribeScanEvents,
  type ScanTask,
  type ScanFinding,
  type FindingSummary,
  type AssetSummary,
  type LogPayload,
  getTaskLogs,
  type ScanLogEntry,
} from '#/api/task';

import { createIncident, type CreateIncidentReq } from '#/api/incident';
import { retestFindingFromScan } from '#/api/vuln';

import {
  buildScanIncidentDescription,
  classifyScanIncidentType,
} from '../scan-incident-description';
import { taskStatusLabels, taskStatusTypes } from '#/constants/status';
import TopologyGraph from '../components/topology-graph.vue';
import ScanFindingDetailDrawer from '../components/ScanFindingDetailDrawer.vue';
import {
  estimateTableScrollX,
  findingCellStack,
  findingCellSubtext,
  primaryDataHint,
} from '../components/finding-display';
import { downloadTaskReport } from '#/api/report';

defineOptions({ name: 'ScanTaskDetail' });

const route = useRoute();
const router = useRouter();
const message = useMessage();
const loading = ref(true);
const task = ref<ScanTask | null>(null);
let refreshTimer: ReturnType<typeof setInterval> | null = null;
let logPollTimer: ReturnType<typeof setInterval> | null = null;

const findings = ref<ScanFinding[]>([]);
const findingsTotal = ref(0);
const findingsPage = ref(1);
const findingsPageSize = ref(20);
const findingsLoading = ref(false);
const activeSubTab = ref('overview');
const filterSeverity = ref<string | null>(null);
const filterModule = ref<string | null>(null);
const filterKeyword = ref('');
const filterType = ref<string | null>(null);
const selectedHost = ref<AssetSummary | null>(null);
const endpointSearch = ref('');
const tabBarRef = ref<HTMLElement | null>(null);
const summary = ref<FindingSummary | null>(null);

const allTabView = ref<'grouped' | 'table'>('grouped');
const portTabView = ref<'card' | 'table'>('card');

interface TypeGroup {
  type: string;
  label: string;
  count: number;
  color: string;
  sevBreakdown: Record<string, number>;
}

const showDetail = ref(false);
const detailItem = ref<ScanFinding | null>(null);
const showAllModules = ref(false);

const assets = ref<AssetSummary[]>([]);
const assetsLoading = ref(false);

const selectedTreeNode = ref<string>('');

interface EndpointNode {
  key: string;
  host: string;
  port: number;
  label: string;
  count: number;
}

const selectedEndpoint = ref('');

const hostOnlyTabs = new Set(['subdomain', 'dns_record', 'cert_info', 'port_open', 'infra', 'nettopo', 'info_collect', 'all']);

const cachedEndpointList = ref<EndpointNode[]>([]);

const endpointList = computed<EndpointNode[]>(() => {
  if (selectedEndpoint.value && cachedEndpointList.value.length > 0) {
    return cachedEndpointList.value;
  }
  const groupByHostOnly = hostOnlyTabs.has(activeSubTab.value);
  const map = new Map<string, EndpointNode>();
  for (const f of mergedFindings.value) {
    const host = findingHost(f);
    const port = groupByHostOnly ? 0 : (f.port || 0);
    const key = groupByHostOnly ? host : (port > 0 ? `${host}:${port}` : host);
    const existing = map.get(key);
    if (existing) {
      existing.count++;
    } else {
      map.set(key, {
        key,
        host,
        port,
        label: groupByHostOnly ? host : key,
        count: 1,
      });
    }
  }
  const list = Array.from(map.values()).sort((a, b) => {
    if (a.host !== b.host) return a.host.localeCompare(b.host);
    return a.port - b.port;
  });
  if (list.length > 0) cachedEndpointList.value = list;
  return list.length > 0 ? list : cachedEndpointList.value;
});

interface LogEntry {
  id?: number;
  time: string;
  level: string;
  message: string;
  stage?: string;
  module?: string;
}
const liveLogs = ref<LogEntry[]>([]);
const liveModuleProgress = ref({ done: 0, total: 0 });

const stageLabels: Record<string, string> = {
  discover: '资产发现',
  recon: '信息收集',
  vuln: '漏洞检测',
  exploit: '漏洞利用',
  report: '报告生成',
};

function formatLogTime(iso?: string): string {
  const d = iso ? new Date(iso) : new Date();
  if (Number.isNaN(d.getTime())) return '--:--:--';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function scanLogToEntry(log: ScanLogEntry): LogEntry {
  return {
    id: log.id,
    time: formatLogTime(log.created_at),
    level: log.level,
    message: log.message,
    stage: log.stage,
    module: log.module,
  };
}

function appendLog(entry: LogEntry) {
  liveLogs.value = [entry, ...liveLogs.value].slice(0, 200);
}

function mergeApiLogs(entries: ScanLogEntry[]) {
  if (!entries.length) return;
  const maxId = liveLogs.value.reduce((m, l) => Math.max(m, l.id ?? 0), 0);
  const fresh = entries.filter((log) => log.id > maxId);
  if (!fresh.length) return;
  liveLogs.value = [...fresh.map(scanLogToEntry), ...liveLogs.value].slice(0, 200);
}

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
  powered_by: '技术栈',
  status_code: '状态码',
  title: '页面标题',
  name: '名称',
  category: '分类',
  method: '方法',
  record_type: '记录类型',
  value: '值',
  hash: 'Hash',
  username: '用户名',
  password: '密码',
  param: '参数',
  payload: 'Payload',
  type: '攻击类型',
  context: '上下文',
  cipher_suite: '密码套件',
  algorithm: '算法',
  key_size: '密钥大小',
  common_name: 'CN',
  issuer: '签发者',
  expired_at: '过期时间',
  expires_at: '到期时间',
  tls_version: 'TLS版本',
  waf: 'WAF',
  api_type: 'API类型',
  status: '状态',
  path: '路径',
  action: '表单Action',
  inputs: '输入字段',
  parameters: '参数',
  enctype: '编码类型',
  email: '邮箱',
  source: '来源',
  confidence_basis: '置信度依据',
  matched_seed: '命中种子域',
  matched_seed_root: '命中根域',
  matched_company: '命中公司名',
  query_company: '查询企业名称',
  matched_host: '搜索结果主机',
  tag: '标签',
  attribute: '属性',
  technologies: '技术栈',
  content_length: '内容长度',
  cdn_name: 'CDN',
  is_cdn: 'CDN检测',
  subdomain: '子域名',
  internal_ips: '内网IP',
  record_count: '记录数',
  scheme: '协议',
  response_time: '响应时间',
  redirect_url: '跳转地址',
  favicon_hash: 'Favicon Hash',
  jarm_hash: 'JARM Hash',
  content_type: '内容类型',
  header_server: '服务器',
  screenshot: '页面截图',
};

const retestingFindingId = ref<string | null>(null);

async function handleRetestFinding(row: ScanFinding) {
  retestingFindingId.value = row.id;
  try {
    const res = await retestFindingFromScan(row.id);
    message.success(res?.task_id ? `回测任务已提交（${res.task_id}）` : '回测任务已提交');
    if (res?.task_id) {
      router.push(`/scan/task/${res.task_id}`);
    }
  } catch (e: any) {
    message.error(e?.message || '回测失败');
  } finally {
    retestingFindingId.value = null;
  }
}

function openDetail(row: ScanFinding) {
  detailItem.value = row;
  showDetail.value = true;
}

const findingTableScrollX = computed(() =>
  estimateTableScrollX(findingColumns.value as Array<{ width?: number; minWidth?: number }>),
);

function findingRowProps(row: ScanFinding) {
  const sevColor = (severityConfig[row.severity] ?? { color: 'transparent' }).color;
  return {
    style: `cursor: pointer; --row-sev-color: ${sevColor}`,
    class: row.severity === 'critical' || row.severity === 'high' ? 'finding-row-high' : '',
    onClick: (e: MouseEvent) => {
      const el = e.target as HTMLElement;
      if (el.closest('button, a, .n-button')) return;
      openDetail(row);
    },
  };
}

function dataHint(row: ScanFinding): string {
  return primaryDataHint(row, (key) => d(row, key));
}

function openScreenshot(b64: string) {
  const win = window.open();
  if (win) {
    win.document.write(`<img src="data:image/jpeg;base64,${b64}" style="max-width:100%">`);
    win.document.title = '页面截图';
  }
}

const convertingToIncident = ref(false);
const markingFP = ref(false);

async function handleMarkFP(finding: ScanFinding) {
  const reason = window.prompt('请输入标记误报的原因（可选）：');
  if (reason === null) return;

  markingFP.value = true;
  try {
    const { markAsFP } = await import('#/api/fp-rule');
    await markAsFP({ finding_id: finding.id, match_type: 'fingerprint', reason: reason || '' });
    message.success('已标记为误报，后续扫描将自动过滤');
  } catch (e: any) {
    message.error(e?.message || '标记失败');
  } finally {
    markingFP.value = false;
  }
}

async function convertFindingToIncident(finding: ScanFinding) {
  const severityToLevel: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 1 };

  const d = finding.data || {};
  const target = cleanTarget(finding.target);
  const ip = d.ip || d.site_ip || '';
  const url = d.url || d.matched_at || (finding.port > 0 ? `${target}:${finding.port}` : target);

  let cvssScore: number | undefined;
  if (d.cvss_score != null) {
    const n = Number(d.cvss_score);
    if (!isNaN(n)) cvssScore = n;
  }

  let exploitDiff = '未知';
  if (finding.verification_level === 'exploit') exploitDiff = '低';
  else if (finding.verification_level === 'principle') exploitDiff = '中';

  const req: CreateIncidentReq = {
    name: finding.title || `${classifyScanIncidentType(finding)} - ${target}`,
    level: severityToLevel[finding.severity] ?? 2,
    source: 2,
    report_time: finding.created_at || undefined,
    asset: {
      domain_ip: target,
      site_ip: ip,
      asset_name: target,
      system_name: d.hostname || d.server || target,
    },
    metadata: {
      incident_type: classifyScanIncidentType(finding),
      incident_description: buildScanIncidentDescription(finding),
      incident_url: url,
      discovery_time: finding.created_at || undefined,
      cve_id: d.cve_id || d.cve || '',
      cvss_score: cvssScore,
      owasp_category: d.owasp_category || d.owasp || '',
      exploit_difficulty: exploitDiff,
      affect_scope: d.affect_scope || (finding.port > 0 ? `${target}:${finding.port}` : target),
    },
  };

  convertingToIncident.value = true;
  try {
    await createIncident(req);
    message.success('已转为安全事件');
  } catch (e: any) {
    message.error(e?.message || '转为事件失败');
  } finally {
    convertingToIncident.value = false;
  }
}

const profileLabels: Record<string, string> = {
  full: '全面扫描',
  quick: '快速扫描',
  recon: '信息收集',
  vuln: '漏洞扫描',
  'vuln-full': '深度漏洞',
};

const typeLabels: Record<string, string> = {
  // 资产发现
  host_alive: '主机存活',
  port_open: 'TCP端口',
  udp_port: 'UDP端口',
  service: '服务识别',
  // 网页/URL
  web_page: '网页',
  web_info: '网页',
  url: 'URL发现',
  form: '表单',
  script: '脚本',
  crawler: '爬虫发现',
  xhr: 'XHR请求',
  // DNS/子域名
  dns_record: 'DNS记录',
  subdomain: '子域名',
  dns_cname: 'DNS CNAME',
  dns_multi_ip: 'DNS多IP',
  dns_nameservers: 'DNS服务器',
  reverse_dns: '反向DNS',
  zone_transfer: '域传送',
  // 证书/TLS
  cert_info: '证书信息',
  cert_expired: '证书过期',
  cert_expiring_soon: '证书即将过期',
  self_signed_cert: '自签名证书',
  weak_tls: 'TLS弱配置',
  tls_fingerprint: 'TLS指纹',
  tls_cert_expired: 'TLS证书过期',
  tls_weak_version: 'TLS弱版本',
  weak_cipher: '弱加密套件',
  weak_signature: '弱签名算法',
  weak_key: '弱密钥',
  // 指纹/技术
  tech: '技术栈',
  tech_stack: '技术栈',
  fingerprint: '指纹',
  favicon: 'Favicon',
  favicon_hash: 'Favicon Hash',
  header_fingerprint: 'HTTP头指纹',
  js_fingerprint: 'JS指纹',
  screenshot: '页面截图',
  waf: 'WAF检测',
  waf_detected: 'WAF检测',
  // 网络拓扑/基础设施
  cdn_detected: 'CDN检测',
  load_balancer_detected: '负载均衡',
  traceroute: '路由追踪',
  network_gateway: '网络网关',
  ip_attribution: 'IP归属',
  real_ip: '真实IP',
  asn: 'ASN信息',
  organization: '组织信息',
  domain: '域名信息',
  ip_range: 'IP段',
  internal_ip_leak: '内网IP泄露',
  // 信息收集
  email: '邮箱',
  api_endpoint: 'API端点',
  directory: '目录',
  missing_security_headers: '缺失安全头',
  code_leak: '代码泄露',
  cyber_asset: '网络资产',
  nuclei: 'Nuclei检测',
  // 信息泄露
  info_leak: '信息泄露',
  body_regex: '正则匹配',
  body_contains: '内容匹配',
  header: 'HTTP头',
  git_leak: 'Git泄露',
  dir_found: '目录发现',
  // SQL注入
  sqli: 'SQL注入',
  sqli_error: 'SQLi(错误)',
  sqli_boolean: 'SQLi(布尔)',
  sqli_time: 'SQLi(时间)',
  sqli_union: 'SQLi(联合)',
  // XSS
  xss: 'XSS',
  xss_reflected: 'XSS(反射)',
  xss_dom: 'XSS(DOM)',
  // SSRF
  ssrf: 'SSRF',
  ssrf_potential: 'SSRF(疑似)',
  // 命令注入
  cmdi_time: '命令注入(时间)',
  cmdi_output: '命令注入(回显)',
  // 文件包含
  lfi: '文件包含',
  // SSTI
  ssti: 'SSTI',
  ssti_error: 'SSTI(错误)',
  ssti_exploit: 'SSTI(利用)',
  // XXE
  xxe_error: 'XXE(错误)',
  xxe_entity: 'XXE(实体)',
  xxe_file_read: 'XXE(文件读取)',
  xxe_ssrf: 'XXE(SSRF)',
  // NoSQL注入
  nosqli_error: 'NoSQLi(错误)',
  nosqli_boolean: 'NoSQLi(布尔)',
  nosqli_operator: 'NoSQLi(运算符)',
  nosqli_auth_bypass: 'NoSQLi(认证绕过)',
  // JWT
  jwt_alg_none: 'JWT(alg:none)',
  jwt_no_expiry: 'JWT(无过期)',
  jwt_long_expiry: 'JWT(长过期)',
  jwt_weak_secret: 'JWT(弱密钥)',
  jwt_alg_none_bypass: 'JWT(none绕过)',
  jwt_empty_sig: 'JWT(空签名)',
  // 弱口令/暴力破解
  weak_pass: '弱口令',
  weak_password: '弱口令',
  // API安全
  api_endpoint_exposed: 'API暴露',
  api_unauth_access: 'API未授权',
  api_no_rate_limit: 'API无限流',
  api_info_leak_header: 'API头泄露',
  api_cors_wildcard: 'CORS通配',
  api_verbose_error: 'API详细错误',
  api_idor: 'IDOR',
  api_graphql_introspection: 'GraphQL自省',
  api_graphql_types: 'GraphQL类型',
};

const typeColors: Record<string, string> = {
  // 资产发现
  host_alive: '#38a169',
  port_open: '#3182ce', udp_port: '#2b6cb0',
  service: '#805ad5',
  // 网页/URL
  web_page: '#dd6b20', web_info: '#dd6b20', url: '#718096', form: '#d69e2e', script: '#805ad5', xhr: '#805ad5', crawler: '#718096',
  // DNS/子域名
  dns_record: '#d69e2e', subdomain: '#319795',
  dns_cname: '#d69e2e', dns_multi_ip: '#d69e2e', dns_nameservers: '#d69e2e', reverse_dns: '#d69e2e', zone_transfer: '#e53e3e',
  // 证书/TLS
  cert_info: '#e53e3e', cert_expired: '#e53e3e', cert_expiring_soon: '#ed8936', self_signed_cert: '#e53e3e',
  weak_tls: '#c53030', tls_fingerprint: '#805ad5', tls_cert_expired: '#e53e3e', tls_weak_version: '#c53030',
  weak_cipher: '#c53030', weak_signature: '#c53030', weak_key: '#c53030',
  // 指纹/技术
  tech: '#9f7aea', tech_stack: '#9f7aea', fingerprint: '#9f7aea', favicon: '#805ad5', favicon_hash: '#805ad5',
  header_fingerprint: '#9f7aea', js_fingerprint: '#667eea', screenshot: '#a0aec0',
  waf: '#fc8181', waf_detected: '#fc8181',
  // 网络拓扑/基础设施
  cdn_detected: '#38b2ac', load_balancer_detected: '#38b2ac',
  traceroute: '#2b6cb0', network_gateway: '#805ad5',
  ip_attribution: '#4a5568', real_ip: '#2d3748', asn: '#4a5568', organization: '#4a5568', domain: '#4a5568', ip_range: '#4a5568',
  internal_ip_leak: '#ed8936',
  // 信息收集
  email: '#667eea', api_endpoint: '#3182ce', directory: '#718096',
  missing_security_headers: '#ed8936', code_leak: '#c53030', cyber_asset: '#4a5568', nuclei: '#e53e3e',
  // 信息泄露
  info_leak: '#ecc94b', body_regex: '#ecc94b', body_contains: '#ecc94b', header: '#718096',
  git_leak: '#c53030', dir_found: '#718096',
  // 漏洞
  sqli: '#e53e3e', sqli_error: '#e53e3e', sqli_boolean: '#e53e3e', sqli_time: '#e53e3e', sqli_union: '#e53e3e',
  xss: '#ed8936', xss_reflected: '#ed8936', xss_dom: '#ed8936',
  ssrf: '#e53e3e', ssrf_potential: '#fc8181',
  cmdi_time: '#c53030', cmdi_output: '#c53030',
  lfi: '#e53e3e',
  ssti: '#d53f8c', ssti_error: '#d53f8c', ssti_exploit: '#c53030',
  xxe_error: '#9b2c2c', xxe_entity: '#9b2c2c', xxe_file_read: '#9b2c2c', xxe_ssrf: '#9b2c2c',
  nosqli_error: '#b83280', nosqli_boolean: '#b83280', nosqli_operator: '#b83280', nosqli_auth_bypass: '#c53030',
  jwt_alg_none: '#805ad5', jwt_no_expiry: '#805ad5', jwt_long_expiry: '#805ad5', jwt_weak_secret: '#c53030', jwt_alg_none_bypass: '#c53030', jwt_empty_sig: '#c53030',
  weak_pass: '#ed8936', weak_password: '#ed8936',
  // API安全
  api_endpoint_exposed: '#e53e3e', api_unauth_access: '#c53030', api_no_rate_limit: '#ed8936',
  api_info_leak_header: '#ecc94b', api_cors_wildcard: '#e53e3e', api_verbose_error: '#ed8936',
  api_idor: '#c53030', api_graphql_introspection: '#805ad5', api_graphql_types: '#805ad5',
  // Tab 聚合类型
  vuln: '#e53e3e', infra: '#4a5568', api_disc: '#3182ce', info_collect: '#667eea',
};

const moduleLabels: Record<string, string> = {
  host_discover: '主机发现',
  web_recon: 'Web 信息收集',
  asset_enrich: '资产富化',
  web_vuln_scan: 'Web 漏洞检测',
  credential_audit: '凭据安全',
  infra_extra: '网络拓扑',
  icmp_ping: 'ICMP存活探测',
  port_scan: '端口扫描',
  syn_scan: 'SYN扫描',
  udp_scan: 'UDP扫描',
  service_probe: '服务识别',
  web_crawl: '网站爬虫',
  subdomain_brute: '子域名枚举',
  dns_all: 'DNS全量查询',
  tech_detect: '技术栈识别',
  waf_detect: 'WAF检测',
  web_fingerprint: '指纹识别',
  cert_check: '证书安全检查',
  favicon: '图标哈希识别',
  js_analyze: 'JS敏感信息分析',
  api_disc: 'API接口发现',
  dir_scan: '目录扫描',
  real_ip: '真实IP探测',
  ip_attr: 'IP属性查询',
  email_collect: '邮箱收集',
  company_recon: '企业资产发现',
  fpenhance: '增强指纹探测',
  nettopo: '网络拓扑探测',
  cyberspace: '网络空间测绘',
  sqli: 'SQL注入检测',
  xss: 'XSS检测',
  ssrf: 'SSRF检测',
  cmdi: '命令注入检测',
  lfi: '文件包含检测',
  ssti: '模板注入检测',
  xxe: 'XXE注入检测',
  nosqli: 'NoSQL注入检测',
  jwt_sec: 'JWT安全检测',
  weak_pass: '弱口令检测',
  brute_force: '密码爆破',
  info_leak: '信息泄露检测',
  git_leak: 'Git仓库泄露',
  apisec: 'API安全检测',
  screenshot: '页面截图',
  nuclei: 'Nuclei PoC',
  'nuclei-poc': 'Nuclei PoC',
  advanced_vuln: '高级漏洞检测',
  unauth: '未授权访问检测',
};

const runStatusText = computed(() => {
  if (!isActive.value || !task.value) return '';
  const parts: string[] = [];
  const stage = task.value.current_stage;
  if (stage) parts.push(stageLabels[stage] ?? stage);
  const mod = task.value.current_module;
  if (mod) {
    const labels = mod.split(' · ').map((m) => moduleLabels[m.trim()] ?? m.trim());
    parts.push(labels.join('、'));
  }
  const { done, total } = liveModuleProgress.value;
  if (total > 0) parts.push(`模块 ${done}/${total}`);
  parts.push(`${Math.round(task.value.progress ?? 0)}%`);
  return parts.join(' · ');
});

const severityConfig: Record<string, { color: string; label: string }> = {
  critical: { color: '#e53e3e', label: '严重' },
  high: { color: '#ed8936', label: '高危' },
  medium: { color: '#ecc94b', label: '中危' },
  low: { color: '#48bb78', label: '低危' },
  info: { color: '#4299e1', label: '信息' },
};

/** 「全部」Tab 不展示的发现类型（在「开放端口/服务」等专用 Tab 查看） */
const TYPES_IN_PORT_SERVICE_TAB = ['port_open', 'udp_port', 'service'] as const;
const EXCLUDE_FROM_ALL_TAB = ['host_alive', ...TYPES_IN_PORT_SERVICE_TAB].join(',');

const subTabDefs = [
  { key: 'overview', label: '任务概览', isOverview: true, group: 'summary' },
  { key: 'all', label: '全部', group: 'summary' },
  {
    key: 'port_open',
    label: '开放端口/服务',
    mergeTypes: [...TYPES_IN_PORT_SERVICE_TAB],
    group: 'summary',
  },
  { key: 'vuln', label: '漏洞', group: 'summary' },
  { key: 'host_alive', label: '存活主机', group: 'findings' },
  { key: 'subdomain', label: '子域名', group: 'findings' },
  { key: 'dns_record', label: 'DNS', mergeTypes: ['dns_record', 'dns_cname', 'dns_multi_ip', 'dns_nameservers', 'reverse_dns', 'zone_transfer'], group: 'findings' },
  { key: 'web_page', label: '网站/URL', mergeTypes: ['web_page', 'web_info', 'url', 'script', 'screenshot'], group: 'findings' },
  { key: 'crawler', label: '爬虫', mergeTypes: ['crawler', 'xhr'], group: 'findings' },
  { key: 'tech', label: '指纹', mergeTypes: ['tech', 'tech_stack', 'fingerprint', 'favicon', 'favicon_hash', 'header_fingerprint', 'js_fingerprint'], group: 'findings' },
  { key: 'cert_info', label: '证书/TLS', mergeTypes: ['cert_info', 'cert_expired', 'cert_expiring_soon', 'self_signed_cert', 'weak_tls', 'tls_fingerprint', 'tls_cert_expired', 'tls_weak_version', 'weak_cipher', 'weak_signature', 'weak_key'], group: 'findings' },
  { key: 'waf', label: 'WAF', mergeTypes: ['waf', 'waf_detected'], group: 'findings' },
  { key: 'infra', label: '基础设施', mergeTypes: ['ip_attribution', 'real_ip', 'asn', 'organization', 'domain', 'ip_range', 'internal_ip_leak'], group: 'findings' },
  { key: 'nettopo', label: '网络拓扑', mergeTypes: ['traceroute', 'network_gateway', 'dns_multi_ip', 'dns_cname', 'dns_nameservers', 'reverse_dns', 'cdn_detected', 'load_balancer_detected'], group: 'findings' },
  { key: 'form', label: '表单', group: 'findings' },
  { key: 'api_disc', label: 'API', mergeTypes: ['api_endpoint', 'api_endpoint_exposed', 'api_unauth_access', 'api_no_rate_limit', 'api_info_leak_header', 'api_cors_wildcard', 'api_verbose_error', 'api_idor', 'api_graphql_introspection', 'api_graphql_types'], group: 'findings' },
  { key: 'info_collect', label: '信息收集', mergeTypes: ['email', 'directory', 'dir_found', 'code_leak', 'cyber_asset', 'missing_security_headers', 'info_leak', 'body_regex', 'body_contains', 'header', 'git_leak', 'nuclei'], group: 'findings' },
];

const typeGroupedData = computed<TypeGroup[]>(() => {
  if (!summary.value?.by_type) return [];
  return Object.entries(summary.value.by_type)
    .sort((a, b) => b[1] - a[1])
    .map(([t, count]) => ({
      type: t,
      label: typeLabels[t] ?? t,
      count,
      color: typeColors[t] ?? '#718096',
      sevBreakdown: {},
    }));
});

function onTypeCardClick(tabKey: string) {
  if (tabKey === '__other') {
    allTabView.value = 'table';
    filterModule.value = null;
    filterSeverity.value = null;
    filterKeyword.value = '';
    findingsPage.value = 1;
    fetchFindings();
    return;
  }
  activeSubTab.value = tabKey;
  selectedEndpoint.value = '';
  cachedEndpointList.value = [];
  findingsPage.value = 1;
  fetchFindings();
}

function formatTime(raw?: string) {
  if (!raw) return '-';
  const d = new Date(raw);
  if (isNaN(d.getTime())) return raw;
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

const duration = computed(() => {
  if (!task.value?.started_at) return '-';
  const s = new Date(task.value.started_at).getTime();
  const e = task.value.finished_at
    ? new Date(task.value.finished_at).getTime()
    : Date.now();
  if (isNaN(s)) return '-';
  const diff = Math.max(0, Math.floor((e - s) / 1000));
  if (diff < 60) return `${diff}秒`;
  if (diff < 3600) return `${Math.floor(diff / 60)}分${diff % 60}秒`;
  return `${Math.floor(diff / 3600)}时${Math.floor((diff % 3600) / 60)}分`;
});

const isActive = computed(
  () => task.value?.status === 'running' || task.value?.status === 'queued',
);
const vulnTotal = computed(() =>
  (task.value?.vuln_critical ?? 0) + (task.value?.vuln_high ?? 0) +
  (task.value?.vuln_medium ?? 0) + (task.value?.vuln_low ?? 0),
);

/** 资产探测任务：结果以 host_alive 为主，需在专用 Tab 展示 */
const isAssetDiscoveryTask = computed(
  () => task.value?.type === 'asset_discovery',
);

const canRerun = computed(() => {
  const s = task.value?.status;
  return (
    !!s &&
    !isActive.value &&
    s !== 'splitting' &&
    s !== 'pending'
  );
});

const subTabsWithCount = computed(() => {
  if (!summary.value?.by_type) return subTabDefs.map((t) => ({ ...t, count: 0 }));

  const withCount = subTabDefs.map((t) => {
    if ('isOverview' in t && t.isOverview) return { ...t, count: -1 };
    let count = 0;
    if (t.key === 'all') {
      count = summary.value!.total_findings;
    } else if (t.key === 'host_alive') {
      count = summary.value!.by_type.host_alive ?? 0;
      if (count === 0 && (task.value?.alive_hosts ?? 0) > 0) {
        count = task.value!.alive_hosts!;
      }
    } else if (t.key === 'vuln') {
      count = summary.value!.by_category?.['vuln'] ?? 0;
      if (count === 0 && vulnTotal.value > 0) {
        count = vulnTotal.value;
      }
    } else if ('mergeTypes' in t && t.mergeTypes) {
      for (const mt of t.mergeTypes) {
        count += summary.value!.by_type[mt] ?? 0;
      }
      if (count === 0 && t.key === 'port_open' && (task.value?.open_ports ?? 0) > 0) {
        count = task.value!.open_ports!;
      }
    } else {
      count = summary.value!.by_type[t.key] ?? 0;
    }
    return { ...t, count };
  });

  return withCount
    .map((t) => {
      if (t.key === 'host_alive' && isAssetDiscoveryTask.value) {
        return { ...t, label: '存活主机', group: 'summary' as const };
      }
      return t;
    })
    .filter(
      (t) =>
        t.count !== 0 ||
        t.key === 'overview' ||
        t.key === 'all' ||
        t.key === 'vuln' ||
        t.key === 'port_open' ||
        (t.key === 'host_alive' &&
          ((task.value?.alive_hosts ?? 0) > 0 || isAssetDiscoveryTask.value)),
    );
});

const allTabCards = computed(() => {
  if (!summary.value?.by_type) return [];
  const byType = summary.value.by_type;
  const covered = new Set<string>();
  const cards: { key: string; label: string; count: number; color: string }[] = [];

  for (const tab of subTabDefs) {
    if ('isOverview' in tab && tab.isOverview) continue;
    if (tab.key === 'all') continue;
    let count = 0;
    const types = 'mergeTypes' in tab && tab.mergeTypes ? [...tab.mergeTypes] : [tab.key];
    for (const t of types) {
      count += byType[t] ?? 0;
      covered.add(t);
    }
    if (count > 0) {
      cards.push({ key: tab.key, label: tab.label, count, color: typeColors[tab.key] ?? '#718096' });
    }
  }

  let otherCount = 0;
  for (const [t, c] of Object.entries(byType)) {
    if (!covered.has(t)) otherCount += c;
  }
  if (otherCount > 0) {
    cards.push({ key: '__other', label: '其他', count: otherCount, color: '#a0aec0' });
  }

  cards.sort((a, b) => b.count - a.count);
  return cards;
});

const sortedByType = computed<[string, number][]>(() => {
  if (!summary.value?.by_type) return [];
  return Object.entries(summary.value.by_type).sort((a, b) => b[1] - a[1]);
});

const typeFilterOptions = computed(() => {
  if (!summary.value?.by_type) return [];
  return Object.entries(summary.value.by_type)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({
      label: `${typeLabels[k] ?? k} (${v})`,
      value: k,
    }));
});

function selectHost(asset: AssetSummary) {
  selectedHost.value = asset;
  selectedEndpoint.value = asset.target || asset.ip;
  filterSeverity.value = null;
  filterType.value = null;
  filterKeyword.value = '';
  findingsPage.value = 1;
  fetchFindings();
}

const severityOptions = [
  { label: '严重', value: 'critical' },
  { label: '高危', value: 'high' },
  { label: '中危', value: 'medium' },
  { label: '低危', value: 'low' },
  { label: '信息', value: 'info' },
];

const moduleOptions = computed(() => {
  if (!summary.value?.by_module) return [];
  return Object.entries(summary.value.by_module)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => ({
      label: `${moduleLabels[k] ?? k} (${v})`,
      value: k,
    }));
});

function getConfColor(conf: number): string {
  if (conf >= 90) return '#52c41a';
  if (conf >= 70) return '#faad14';
  if (conf >= 50) return '#fa8c16';
  return '#f5222d';
}

function d(row: ScanFinding, key: string): string {
  const val = row.data?.[key];
  if (val === undefined || val === null) return '';
  return typeof val === 'string' ? val : String(val);
}

function cleanTarget(raw: string): string {
  let t = raw;
  if (t.startsWith('http://')) t = t.slice(7);
  else if (t.startsWith('https://')) t = t.slice(8);
  t = t.replace(/\/+$/, '');
  const portMatch = t.match(/:(\d+)$/);
  if (portMatch) t = t.slice(0, -portMatch[0].length);
  return t;
}

/** 表格/筛选用的主机标识（不含端口，优先 data.ip） */
function findingHost(row: ScanFinding): string {
  const ip = d(row, 'ip');
  if (ip.trim()) return ip.trim();
  return cleanTarget(row.target);
}

const colTarget = {
  title: '目标', key: 'target', width: 160, ellipsis: { tooltip: true },
  render: (row: ScanFinding) => {
    let text = cleanTarget(row.target);
    if (row.port > 0) text += `:${row.port}`;
    return h('span', { style: 'font-weight: 500; font-size: 12px', title: row.target }, text);
  },
};

const colTargetHost = {
  title: '目标主机',
  key: 'host',
  width: 148,
  ellipsis: { tooltip: true },
  render: (row: ScanFinding) => {
    const host = findingHost(row);
    return h('span', {
      class: 'finding-host-cell',
      title: row.target !== host ? row.target : host,
    }, host);
  },
};
const colType = {
  title: '类型', key: 'type', width: 100,
  render: (row: ScanFinding) => {
    const color = typeColors[row.type] ?? '#718096';
    return h(NTag, { size: 'small', bordered: false, style: `background: ${color}18; color: ${color}` }, () => typeLabels[row.type] ?? row.type);
  },
};
const colSeverity = {
  title: '等级', key: 'severity', width: 64,
  render: (row: ScanFinding) => {
    const sc = severityConfig[row.severity] ?? { color: '#999', label: row.severity };
    return h(NTag, { size: 'small', bordered: false, round: true, style: `background: ${sc.color}18; color: ${sc.color}; font-weight: 500` }, () => sc.label);
  },
};
function confLabel(conf: number): string {
  if (conf >= 90) return '高';
  if (conf >= 70) return '中高';
  if (conf >= 50) return '中';
  return '低';
}

const colConfidence = {
  title: '置信度', key: 'confidence', width: 100, align: 'center' as const,
  render: (row: ScanFinding) => {
    const color = getConfColor(row.confidence);
    const badge = h('div', { class: 'conf-badge', style: `--conf-color: ${color}` }, [
      h('div', { class: 'conf-badge__bar' }, [
        h('div', { class: 'conf-badge__fill', style: `width: ${row.confidence}%` }),
      ]),
      h('span', { class: 'conf-badge__text' }, `${row.confidence}% ${confLabel(row.confidence)}`),
    ]);

    if (row.confidence_reason) {
      return h(NTooltip, { placement: 'top', style: 'max-width: 320px' }, {
        trigger: () => badge,
        default: () => h('div', { class: 'conf-tooltip' }, [
          h('div', { class: 'conf-tooltip__header' }, [
            h('span', { style: `color: ${color}; font-weight: 700` }, `${row.confidence}%`),
            h('span', { style: 'margin-left: 4px; opacity: 0.7' }, '置信度'),
          ]),
          h('div', { class: 'conf-tooltip__reason' }, row.confidence_reason),
        ]),
      });
    }
    return badge;
  },
};
const colModule = {
  title: '模块', key: 'module_id', width: 100, ellipsis: { tooltip: true },
  render: (row: ScanFinding) => h('span', { style: 'font-size: 11px; color: #666666' }, moduleLabels[row.module_id] ?? row.module_id),
};
const colTime = {
  title: '时间', key: 'created_at', width: 140,
  render: (row: ScanFinding) => h('span', { style: 'font-size: 11px' }, formatTime(row.created_at)),
};
const colActions = {
  title: '', key: 'actions', width: 72, fixed: 'right' as const,
  render: (row: ScanFinding) =>
    h(NButton, {
      size: 'tiny',
      type: 'primary',
      secondary: true,
      onClick: (e: Event) => {
        e.stopPropagation();
        openDetail(row);
      },
    }, () => '详情'),
};

const colVulnActions = {
  title: '操作', key: 'actions', width: 140, fixed: 'right' as const,
  render: (row: ScanFinding) => {
    const isHighSev = row.severity === 'critical' || row.severity === 'high';
    const isVerified = d(row, 'verified') === 'true';
    const retestType = isHighSev && !isVerified ? 'warning' as const : 'default' as const;
    const retestLabel = isHighSev && !isVerified ? '确认验证' : '回测';

    return h(NSpace, { size: 4 }, () => [
      h(NButton, {
        size: 'tiny',
        type: retestType,
        secondary: !isHighSev || isVerified,
        loading: retestingFindingId.value === row.id,
        onClick: (e: Event) => {
          e.stopPropagation();
          handleRetestFinding(row);
        },
      }, () => retestLabel),
      h(NButton, {
        size: 'tiny',
        type: 'primary',
        secondary: true,
        onClick: (e: Event) => {
          e.stopPropagation();
          openDetail(row);
        },
      }, () => '详情'),
    ]);
  },
};

function dataCol(title: string, key: string, width: number, extra?: (row: ScanFinding) => any) {
  return {
    title, key: `data_${key}`, width, ellipsis: { tooltip: true },
    render: extra ?? ((row: ScanFinding) => h('span', { style: 'font-size: 12px' }, d(row, key) || '-')),
  };
}

const sourceLabels: Record<string, string> = {
  brute_pipeline: '字典爆破', brute_permutation: '排列爆破', brute_recursive: '递归爆破', brute: '暴力枚举',
  passive_crtsh: 'CRT.sh', 'crt.sh': 'CRT.sh', passive_wayback: 'Wayback', passive_otx: 'OTX',
  passive_rapiddns: 'RapidDNS', passive_hackertarget: 'HackerTarget',
  passive_threatcrowd: 'ThreatCrowd', passive_virustotal: 'VirusTotal',
  zone_transfer: '域传送', dns_transfer: '域传送', wildcard: '泛解析检测', tls_cert: 'TLS证书',
  crawler: '爬虫', html_parse: 'HTML解析', regex: '正则提取',
  bing_search: 'Bing搜索', github_search: 'GitHub搜索',
  dns_history: 'DNS历史', cdn_bypass: 'CDN绕过',
};
function sourceLabel(row: ScanFinding): string {
  const raw = d(row, 'source');
  return sourceLabels[raw] || raw || '-';
}

const wellKnownPorts: Record<number, string> = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
  143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL',
  1521: 'Oracle', 2375: 'Docker', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
  5672: 'AMQP', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 9200: 'ES', 27017: 'MongoDB',
};
const dnsTypeColors: Record<string, string> = {
  A: '#1890ff', AAAA: '#722ed1', CNAME: '#13c2c2', MX: '#eb2f96',
  NS: '#fa8c16', TXT: '#52c41a', SOA: '#faad14', SRV: '#2f54eb', PTR: '#fa541c',
};

function portTag(row: ScanFinding) {
  const port = parseInt(d(row, 'port') || String(row.port), 10);
  if (!port || isNaN(port)) return h('span', { style: 'color: #ccc' }, '-');
  const known = wellKnownPorts[port];
  const isSensitive = [21, 23, 445, 3389, 6379, 27017, 2375].includes(port);
  const bg = isSensitive ? '#fff2f0' : '#f0f5ff';
  const color = isSensitive ? '#cf1322' : '#1890ff';
  return h('span', { style: `padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; background: ${bg}; color: ${color}; border: 1px solid ${color}20` }, [
    String(port),
    known ? h('span', { style: 'font-weight: 400; margin-left: 4px; font-size: 11px; opacity: 0.7' }, known) : null,
  ]);
}

function statusTag(row: ScanFinding) {
  const sc = parseInt(d(row, 'status_code'), 10);
  if (!sc || isNaN(sc)) return h('span', { style: 'color: #ccc' }, '-');
  const color = sc < 300 ? '#52c41a' : sc < 400 ? '#1890ff' : sc < 500 ? '#faad14' : '#ff4d4f';
  return h('span', { style: `padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; background: ${color}15; color: ${color}` }, String(sc));
}

const findingColumns = computed(() => {
  const tab = activeSubTab.value;

  if (tab === 'port_open') {
    return [
      colTargetHost,
      { title: '端口', key: 'port_tag', width: 120, render: portTag },
      dataCol('协议', 'protocol', 80, (row) => {
        const proto = d(row, 'protocol').toUpperCase() || '-';
        return h(NTag, { size: 'tiny', bordered: false, type: proto === 'TCP' ? 'info' : proto === 'UDP' ? 'warning' : 'default' }, () => proto);
      }),
      dataCol('服务', 'service', 100, (row) => {
        const svc = d(row, 'service');
        if (!svc) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-weight: 600; color: #1890ff; font-size: 12px' }, svc);
      }),
      dataCol('版本', 'version', 120, (row) => {
        const ver = d(row, 'version');
        if (!ver) return h('span', { style: 'color: #ccc' }, '-');
        return h(NTag, { size: 'tiny', bordered: false, type: 'success' }, () => ver);
      }),
      { title: 'Banner', key: 'banner', minWidth: 200, render: (row: ScanFinding) => {
        const banner = d(row, 'banner');
        if (!banner) return h('span', { class: 'finding-cell-muted' }, '-');
        return findingCellSubtext(banner, 4) ?? h('span', { class: 'finding-cell-muted' }, '-');
      }},
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'dns_record') {
    return [
      colTarget,
      { title: '类型', key: 'record_type', width: 80, render: (row: ScanFinding) => {
        const rt = d(row, 'record_type');
        const color = dnsTypeColors[rt] ?? '#666';
        return h('span', { style: `padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; background: ${color}15; color: ${color}; letter-spacing: 0.5px` }, rt || '-');
      }},
      dataCol('记录值', 'value', 280, (row) => {
        const val = d(row, 'value');
        if (!val) return h('span', { style: 'color: #ccc' }, '-');
        return h('code', { style: 'font-size: 12px; padding: 2px 6px; background: #f5f5f5; border-radius: 4px; color: #333; word-break: break-all', title: val }, val.length > 60 ? val.substring(0, 60) + '...' : val);
      }),
      dataCol('域名', 'domain', 160),
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'subdomain') {
    return [
      colTarget,
      dataCol('子域名', 'domain', 200, (row) => {
        const dom = d(row, 'domain');
        if (!dom) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-weight: 500; font-size: 12px; color: #1a1a1a' }, dom);
      }),
      dataCol('IP', 'ip', 130, (row) => {
        const ip = d(row, 'ip');
        if (!ip) return h('span', { style: 'color: #ccc' }, '-');
        return h('code', { style: 'font-size: 12px; padding: 1px 6px; background: #f5f5f5; border-radius: 3px' }, ip);
      }),
      { title: 'CNAME', key: 'cname', width: 150, ellipsis: { tooltip: true }, render: (row: ScanFinding) => {
        const cname = d(row, 'cname');
        if (!cname) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-size: 11px; color: #666' }, cname);
      }},
      { title: 'CDN', key: 'cdn', width: 100, render: (row: ScanFinding) => {
        const cdn = d(row, 'cdn');
        if (!cdn) return null;
        return h(NTag, { size: 'tiny', bordered: false, type: 'warning' }, () => cdn === 'possible_cdn' ? '疑似CDN' : cdn);
      }},
      { title: '来源', key: 'source_label', width: 100, render: (row: ScanFinding) => {
        return h(NTag, { size: 'tiny', bordered: false }, () => sourceLabel(row));
      }},
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'web_page') {
    return [
      { title: '截图', key: 'screenshot_thumb', width: 80, render: (row: ScanFinding) => {
        const img = d(row, 'screenshot');
        if (!img) return h('span', { style: 'color: #ccc; font-size: 11px' }, '无');
        return h('img', {
          src: `data:image/jpeg;base64,${img}`,
          style: 'width: 64px; height: 36px; object-fit: cover; border-radius: 4px; border: 1px solid #e8e8e8; cursor: pointer',
          title: '点击查看大图',
          onClick: (e: Event) => { e.stopPropagation(); openScreenshot(img); },
        });
      }},
      colTarget,
      { title: 'URL', key: 'url', minWidth: 240, render: (row: ScanFinding) => {
        const url = d(row, 'url');
        if (!url) return h('span', { class: 'finding-cell-muted' }, '-');
        return h('a', {
          href: url,
          target: '_blank',
          class: 'finding-cell-sub',
          style: { WebkitLineClamp: 3, color: '#1890ff', textDecoration: 'none' },
          title: url,
          onClick: (e: Event) => e.stopPropagation(),
        }, url);
      }},
      { title: '状态码', key: 'status_tag', width: 70, align: 'center' as const, render: statusTag },
      dataCol('标题', 'title', 160, (row) => {
        const title = d(row, 'title');
        if (!title) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-weight: 500; font-size: 12px; color: #333' }, title);
      }),
      dataCol('服务器', 'server', 110, (row) => {
        const server = d(row, 'server');
        if (!server) return null;
        return h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => server);
      }),
      colType, colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'form') {
    return [
      colTarget,
      dataCol('表单地址', 'action', 240, (row) => {
        const action = d(row, 'action');
        if (!action) return h('span', { style: 'color: #ccc' }, '-');
        return h('code', { style: 'font-size: 11px; padding: 2px 6px; background: #f5f5f5; border-radius: 4px; word-break: break-all', title: action }, action.length > 50 ? action.substring(0, 50) + '...' : action);
      }),
      dataCol('方法', 'method', 70, (row) => {
        const method = d(row, 'method').toUpperCase();
        if (!method) return h('span', { style: 'color: #ccc' }, '-');
        const color = method === 'POST' ? '#fa8c16' : method === 'GET' ? '#52c41a' : '#1890ff';
        return h('span', { style: `padding: 1px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; background: ${color}15; color: ${color}` }, method);
      }),
      dataCol('参数', 'inputs', 200, (row) => {
        const inputs = d(row, 'inputs');
        if (!inputs) return h('span', { style: 'color: #ccc' }, '-');
        return h('code', { style: 'font-size: 11px; color: #555; word-break: break-all', title: inputs }, inputs.length > 40 ? inputs.substring(0, 40) + '...' : inputs);
      }),
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'tech') {
    return [
      colTarget,
      dataCol('技术', 'name', 150, (row) => {
        const name = d(row, 'name');
        if (!name) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-weight: 600; font-size: 12px; color: #1a1a1a' }, name);
      }),
      dataCol('版本', 'version', 100, (row) => {
        const ver = d(row, 'version');
        if (!ver) return null;
        return h(NTag, { size: 'tiny', bordered: false, type: 'success' }, () => ver);
      }),
      dataCol('分类', 'category', 100, (row) => {
        const cat = d(row, 'category');
        if (!cat) return null;
        return h(NTag, { size: 'tiny', bordered: false, type: 'info' }, () => cat);
      }),
      dataCol('证据', 'evidence', 160, (row) => {
        const ev = d(row, 'evidence');
        if (!ev) return null;
        return h('span', { style: 'font-size: 11px; color: #888; font-style: italic', title: ev }, ev.length > 30 ? ev.substring(0, 30) + '...' : ev);
      }),
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'cert_info') {
    return [
      colTarget,
      dataCol('颁发者', 'issuer', 160, (row) => {
        const issuer = d(row, 'issuer');
        if (!issuer) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-size: 12px; color: #333' }, issuer);
      }),
      dataCol('域名', 'common_name', 160, (row) => {
        const cn = d(row, 'common_name');
        if (!cn) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-weight: 500; font-size: 12px; color: #1890ff' }, cn);
      }),
      dataCol('过期时间', 'expired_at', 140, (row) => {
        const exp = d(row, 'expired_at');
        if (!exp) return h('span', { style: 'color: #ccc' }, '-');
        const isExpired = new Date(exp) < new Date();
        const color = isExpired ? '#ff4d4f' : '#52c41a';
        return h('span', { style: `font-size: 12px; color: ${color}; font-weight: 500` }, [
          exp,
          isExpired ? h('span', { style: 'margin-left: 4px; font-size: 10px; padding: 0 4px; background: #fff2f0; border-radius: 3px; color: #ff4d4f' }, '已过期') : null,
        ]);
      }),
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'waf') {
    return [
      colTarget,
      dataCol('WAF', 'waf', 150, (row) => {
        const waf = d(row, 'waf');
        if (!waf) return h('span', { style: 'color: #ccc' }, '-');
        return h(NTag, { size: 'small', bordered: false, type: 'warning', style: 'font-weight: 600' }, () => waf);
      }),
      dataCol('分类', 'category', 120, (row) => {
        const cat = d(row, 'category');
        if (!cat) return null;
        return h(NTag, { size: 'tiny', bordered: false }, () => cat);
      }),
      dataCol('检测方式', 'method', 100),
      dataCol('证据', 'evidence', 160, (row) => {
        const ev = d(row, 'evidence');
        if (!ev) return null;
        return h('code', { style: 'font-size: 11px; padding: 2px 6px; background: #f5f5f5; border-radius: 3px; color: #666', title: ev }, ev.length > 30 ? ev.substring(0, 30) + '...' : ev);
      }),
      colConfidence, colTime, colActions,
    ];
  }
  if (tab === 'vuln') {
    return [
      colTarget,
      { title: '漏洞', key: 'vuln_title', minWidth: 320, render: (row: ScanFinding) =>
        findingCellStack(row.title || d(row, 'name'), row.description, 4),
      },
      colSeverity,
      { title: '验证状态', key: 'verification_level', width: 110, render: (row: ScanFinding) => {
        const vl = (row as any).verification_level;
        const vd = (row as any).verification_detail;
        const dataVerified = d(row, 'verified');
        const verifyDetail = d(row, 'verify_detail');
        const verifyVariants = d(row, 'verify_variants');
        const iconStyle = 'width: 12px; height: 12px; margin-right: 3px; vertical-align: -1px;';

        const children: any[] = [];

        if (vl === 'exploit') {
          children.push(h('span', { class: 'verif-chip verif-chip--exploit' }, [
            h('svg', { viewBox: '0 0 24 24', style: iconStyle, fill: 'none', stroke: 'currentColor', 'stroke-width': '2', innerHTML: '<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>' }),
            '实际利用',
          ]));
        } else {
          children.push(h('span', { class: 'verif-chip verif-chip--principle' }, [
            h('svg', { viewBox: '0 0 24 24', style: iconStyle, fill: 'none', stroke: 'currentColor', 'stroke-width': '2', innerHTML: '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>' }),
            '原理验证',
          ]));
        }

        if (dataVerified === 'true') {
          children.push(h('span', { class: 'verif-confirmed' }, [
            h('svg', { viewBox: '0 0 24 24', style: 'width: 10px; height: 10px; margin-right: 2px; vertical-align: -1px;', fill: 'none', stroke: '#52c41a', 'stroke-width': '3', innerHTML: '<polyline points="20 6 9 17 4 12"/>' }),
            '已确认',
          ]));
        } else if (dataVerified === 'false') {
          children.push(h('span', { class: 'verif-unconfirmed' }, '未确认'));
        }

        const tooltipParts: string[] = [];
        if (vd) tooltipParts.push(vd);
        if (verifyDetail) tooltipParts.push(`验证详情: ${verifyDetail}`);
        if (verifyVariants) tooltipParts.push(`变体测试: ${verifyVariants}`);

        const inner = h('div', { class: 'verif-stack' }, children);

        if (tooltipParts.length > 0) {
          return h(NTooltip, { placement: 'top', style: 'max-width: 320px' }, {
            trigger: () => inner,
            default: () => h('div', { style: 'font-size: 12px; line-height: 1.6' }, tooltipParts.join('\n')),
          });
        }
        return inner;
      }},
      colConfidence, colModule, colTime, colVulnActions,
    ];
  }
  if (tab === 'infra') {
    return [
      colTarget, colType,
      dataCol('名称', 'name', 160, (row) => {
        const name = d(row, 'name') || d(row, 'value');
        if (!name) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-weight: 500; font-size: 12px' }, name);
      }),
      dataCol('详情', 'value', 200, (row) => {
        const val = d(row, 'value') || d(row, 'ip') || d(row, 'description');
        if (!val) return h('span', { style: 'color: #ccc' }, '-');
        return h('span', { style: 'font-size: 12px; color: #555', title: val }, val.length > 40 ? val.substring(0, 40) + '...' : val);
      }),
      colSeverity, colConfidence, colModule, colTime, colActions,
    ];
  }
  if (tab === 'api_disc') {
    return [
      colTarget, colType,
      dataCol('路径', 'path', 200, (row) => {
        const path = d(row, 'path') || d(row, 'url');
        if (!path) return h('span', { style: 'color: #ccc' }, '-');
        return h('code', { style: 'font-size: 12px; padding: 2px 6px; background: #f5f5f5; border-radius: 4px; word-break: break-all', title: path }, path.length > 50 ? path.substring(0, 50) + '...' : path);
      }),
      dataCol('方法', 'method', 70, (row) => {
        const method = d(row, 'method').toUpperCase();
        if (!method) return h('span', { style: 'color: #ccc' }, '-');
        const color = method === 'POST' ? '#fa8c16' : method === 'GET' ? '#52c41a' : method === 'DELETE' ? '#ff4d4f' : '#1890ff';
        return h('span', { style: `padding: 1px 8px; border-radius: 3px; font-size: 11px; font-weight: 700; background: ${color}15; color: ${color}` }, method);
      }),
      colSeverity, colConfidence, colModule, colTime, colActions,
    ];
  }
  if (tab === 'info_collect') {
    return [
      colTarget, colType,
      { title: '发现', key: 'info_title', minWidth: 320, render: (row: ScanFinding) => {
        const title = row.title || d(row, 'name') || d(row, 'url') || d(row, 'email') || d(row, 'path') || d(row, 'value');
        return findingCellStack(title, row.description || dataHint(row), 4);
      }},
      colSeverity, colConfidence, colModule, colTime, colActions,
    ];
  }

  if (tab === 'crawler') {
    return [
      colTarget,
      dataCol('URL', 'url', 280, (row) => {
        const url = d(row, 'url') || d(row, 'path');
        if (!url) return h('span', { style: 'color: #ccc' }, '-');
        return h('a', { href: url, target: '_blank', style: 'font-size: 12px; color: #1890ff; text-decoration: none; word-break: break-all', title: url, onClick: (e: Event) => e.stopPropagation() }, url.length > 70 ? url.substring(0, 70) + '...' : url);
      }),
      { title: '状态码', key: 'status_tag', width: 70, align: 'center' as const, render: statusTag },
      dataCol('内容类型', 'content_type', 120),
      colType, colTime, colActions,
    ];
  }

  return [colTarget, colSeverity, colType, {
    title: '发现内容', key: 'content', minWidth: 340,
    render: (row: ScanFinding) => {
      const title = row.title || d(row, 'name');
      const hint = dataHint(row);
      return findingCellStack(title, hint !== title ? hint : '', 3);
    },
  }, colConfidence, colModule, colTime, colActions];
});

const assetColumns = computed(() => {
  return [
    {
      title: '#',
      key: 'index',
      width: 50,
      render: (_row: AssetSummary, index: number) => index + 1,
    },
    {
      title: '目标',
      key: 'target',
      width: 160,
      ellipsis: { tooltip: true },
      render: (row: AssetSummary) => h('span', { style: 'font-weight: 600' }, row.target),
    },
    {
      title: 'IP',
      key: 'ip',
      width: 120,
    },
    {
      title: '端口/服务',
      key: 'ports',
      width: 200,
      render: (row: AssetSummary) => {
        if (!row.ports?.length) return '-';
        return h(NSpace, { size: 4, wrap: true }, () =>
          row.ports.map((p) => {
            const label = p.service ? `${p.port} ${p.service}` : `${p.port}`;
            return h(NTag, { size: 'tiny', type: 'info', bordered: false }, () => label);
          }),
        );
      },
    },
    {
      title: '状态码',
      key: 'status_code',
      width: 70,
      align: 'center' as const,
      render: (row: AssetSummary) => {
        if (!row.status_code) return '-';
        const color = row.status_code < 400 ? '#52c41a' : '#ff4d4f';
        return h(NTag, { size: 'small', bordered: false, style: `background:${color}18;color:${color}` }, () => `${row.status_code}`);
      },
    },
    {
      title: '标题',
      key: 'title',
      minWidth: 160,
      ellipsis: { tooltip: true },
    },
    {
      title: 'Banner',
      key: 'banner',
      width: 220,
      ellipsis: { tooltip: true },
      render: (row: AssetSummary) => {
        if (!row.banner) return '-';
        const lines = row.banner.split('\n').slice(0, 4).join('\n');
        return h('pre', { style: 'font-size:11px;margin:0;white-space:pre-wrap;word-break:break-all;line-height:1.4;max-height:60px;overflow:hidden;color:#555' }, lines);
      },
    },
    {
      title: '组件指纹',
      key: 'techs',
      width: 180,
      render: (row: AssetSummary) => {
        if (!row.techs?.length) return '-';
        return h(NSpace, { size: 4, wrap: true }, () =>
          row.techs.map((t) =>
            h(NTag, { size: 'tiny', bordered: false, type: 'success' }, () => t),
          ),
        );
      },
    },
    {
      title: '时间',
      key: 'first_seen',
      width: 150,
    },
    {
      title: '操作',
      key: 'actions',
      width: 60,
      fixed: 'right' as const,
      render: (row: AssetSummary) =>
        h(NButton, { size: 'tiny', type: 'primary', secondary: true, onClick: () => openAssetDetail(row) }, () => '详情'),
    },
  ];
});

const showAssetDrawer = ref(false);
const assetDetail = ref<AssetSummary | null>(null);

function openAssetDetail(row: AssetSummary) {
  assetDetail.value = row;
  showAssetDrawer.value = true;
}

async function fetchData() {
  try {
    task.value = await getTaskDetail(route.params.id as string);
    if (!summary.value) fetchSummary();
  } catch {
    /* silent */
  } finally {
    loading.value = false;
  }
}

function handleFindingsPageChange(p: number) {
  findingsPage.value = p;
  void fetchFindings();
}

function handleFindingsPageSizeChange(ps: number) {
  findingsPageSize.value = ps;
  findingsPage.value = 1;
  void fetchFindings();
}

async function fetchFindings() {
  findingsLoading.value = true;
  try {
    const params: Record<string, any> = {
      page: findingsPage.value,
      page_size: findingsPageSize.value,
    };

    if (activeSubTab.value === 'all') {
      if (filterType.value) {
        params.type = filterType.value;
      }
    } else if (activeSubTab.value === 'vuln') {
      params.category = 'vuln';
    } else {
      const tabDef = subTabDefs.find((t) => t.key === activeSubTab.value);
      if (tabDef && 'mergeTypes' in tabDef && tabDef.mergeTypes) {
        params.type = tabDef.mergeTypes.join(',');
      } else {
        params.type = activeSubTab.value;
      }
    }

    if (selectedEndpoint.value) {
      const ignorePort = hostOnlyTabs.has(activeSubTab.value);
      const [host, port] = selectedEndpoint.value.split(':');
      if (ignorePort || !port) {
        params.target = host;
      } else {
        params.target = selectedEndpoint.value;
      }
    }

    if (filterSeverity.value) params.severity = filterSeverity.value;
    if (filterModule.value) params.module_id = filterModule.value;
    if (filterKeyword.value.trim()) params.keyword = filterKeyword.value.trim();

    const result = await getTaskFindings(route.params.id as string, params);
    findings.value = result.items ?? [];
    findingsTotal.value = result.total ?? 0;
  } finally {
    findingsLoading.value = false;
  }
}

async function fetchSummary() {
  try {
    summary.value = await getTaskFindingSummary(route.params.id as string);
  } catch {
    /* silent */
  }
}

function onSubTabChange(key: string) {
  activeSubTab.value = key;
  selectedEndpoint.value = '';
  selectedTreeNode.value = '';
  filterType.value = null;
  selectedHost.value = null;
  if (key === 'all') allTabView.value = 'grouped';
  if (key === 'port_open') portTabView.value = 'card';
  if (key === 'overview') return;
  if (!summary.value) fetchSummary();
  if (key === 'host_alive') {
    fetchAssets();
    return;
  }
  if (assets.value.length === 0) fetchAssets();
  if (key === 'all') return;
  findingsPage.value = 1;
  fetchFindings();
}

function onModuleChipClick(mod: string) {
  filterModule.value = mod;
  filterSeverity.value = null;
  filterKeyword.value = '';
  selectedEndpoint.value = '';
  cachedEndpointList.value = [];
  findings.value = [];
  activeSubTab.value = 'all';
  if (assets.value.length === 0) fetchAssets();
  findingsPage.value = 1;
  fetchFindings();
  nextTick(() => {
    tabBarRef.value?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}

async function fetchAssets() {
  if (!task.value) return;
  assetsLoading.value = true;
  try {
    assets.value = (await getTaskAssets(task.value.id)) ?? [];
  } catch {
    assets.value = [];
  } finally {
    assetsLoading.value = false;
  }
}

async function handleCancel() {
  if (!task.value) return;
  try {
    await cancelTask(task.value.id);
    message.success('任务已取消');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '取消失败');
  }
}

async function handleDelete() {
  if (!task.value) return;
  try {
    await deleteTask(task.value.id);
    message.success('已删除');
    router.push('/scan/task');
  } catch (e: any) {
    message.error(e?.message || '删除失败');
  }
}

async function handleRerun() {
  if (!task.value) return;
  try {
    const res = await rerunTask(task.value.id);
    message.success('已提交重新运行');
    if (res?.task_id) {
      router.push(`/scan/task/${res.task_id}`);
    } else {
      await fetchData();
    }
  } catch (e: any) {
    message.error(e?.message || '重新运行失败');
  }
}

async function handlePause() {
  if (!task.value) return;
  try {
    await pauseTask(task.value.id);
    message.success('任务已暂停');
    await fetchData();
  } catch (e: any) {
    message.error(e?.message || '暂停失败');
  }
}

async function handleResume() {
  if (!task.value) return;
  try {
    await resumeTask(task.value.id);
    message.success('任务已恢复');
    await fetchData();
    if (!sseConnected.value) startSSE();
  } catch (e: any) {
    message.error(e?.message || '恢复失败');
  }
}

async function handleExport(format: 'json' | 'markdown' | 'csv' | 'word' | 'pdf') {
  if (!task.value) return;
  try {
    let blob: Blob;
    if (format === 'word' || format === 'pdf') {
      blob = await downloadTaskReport(task.value.id, format);
    } else {
      const res = await exportTaskReport(task.value.id, format);
      const raw = (res as any)?.data ?? res;
      blob =
        raw instanceof Blob
          ? raw
          : new Blob([typeof raw === 'string' ? raw : JSON.stringify(raw, null, 2)]);
    }
    const ext =
      format === 'markdown' ? 'md' : format === 'word' ? 'doc' : format;
    const filename = `${task.value.name}.${ext}`;
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    message.success('报告导出成功');
  } catch {
    message.error('导出失败，请重试');
  }
}

let sseHandle: { close: () => void } | null = null;
const liveFindings = ref<ScanFinding[]>([]);
const sseConnected = ref(false);

function startSSE() {
  if (sseHandle) sseHandle.close();
  const taskId = route.params.id as string;

  sseHandle = subscribeScanEvents(taskId, {
    onFinding(payload) {
      if (payload.findings?.length) {
        const existingIds = new Set(liveFindings.value.map((f) => f.id));
        const newItems = payload.findings.filter(
          (f: ScanFinding) => !existingIds.has(f.id),
        );
        if (newItems.length) {
          liveFindings.value = [...newItems, ...liveFindings.value];
          findingsTotal.value += newItems.length;
        }
      }
      if (summary.value) {
        fetchSummary();
      }
    },
    onProgress(payload) {
      if (payload.modules_total != null || payload.modules_done != null) {
        liveModuleProgress.value = {
          done: payload.modules_done ?? liveModuleProgress.value.done,
          total: payload.modules_total ?? liveModuleProgress.value.total,
        };
      }
      if (task.value) {
        task.value.progress = payload.progress ?? task.value.progress;
        task.value.current_stage = payload.current_stage ?? task.value.current_stage;
        task.value.current_module = payload.current_module ?? task.value.current_module;
        task.value.scanned_targets = payload.scanned_targets ?? task.value.scanned_targets;
        task.value.alive_hosts = payload.alive_hosts ?? task.value.alive_hosts;
        task.value.open_ports = payload.open_ports ?? task.value.open_ports;
        task.value.vuln_critical = payload.vuln_critical ?? task.value.vuln_critical;
        task.value.vuln_high = payload.vuln_high ?? task.value.vuln_high;
        task.value.vuln_medium = payload.vuln_medium ?? task.value.vuln_medium;
        task.value.vuln_low = payload.vuln_low ?? task.value.vuln_low;
        task.value.vuln_info = payload.vuln_info ?? task.value.vuln_info;
      }
    },
    onStage(payload) {
      if (task.value) {
        task.value.current_stage = payload.stage;
      }
    },
    onLog(payload: LogPayload, eventTime?: string) {
      appendLog({
        time: formatLogTime(eventTime),
        level: payload.level,
        message: payload.message,
        stage: payload.stage,
        module: payload.module,
      });
    },
    onDone(payload) {
      sseConnected.value = false;
      stopLogPolling();
      if (task.value) {
        task.value.status = payload.status;
        task.value.progress = 100;
      }
      fetchData();
      fetchFindings();
      fetchSummary();
      fetchAssets();
    },
    onError() {
      sseConnected.value = false;
      if (!refreshTimer && isActive.value) {
        refreshTimer = setInterval(() => {
          if (isActive.value) fetchData();
        }, 5000);
      }
    },
  });

  sseConnected.value = true;
}

function stopSSE() {
  if (sseHandle) {
    sseHandle.close();
    sseHandle = null;
  }
  sseConnected.value = false;
}

const mergedFindings = computed(() => {
  let items = findings.value;
  if (liveFindings.value.length > 0 && findingsPage.value === 1) {
    const pageIds = new Set(items.map((f) => f.id));
    const extra = liveFindings.value.filter((f) => !pageIds.has(f.id));
    items = [...extra, ...items];
  }

  if (activeSubTab.value !== 'port_open') return items;

  const portTypes = new Set(['port_open', 'udp_port']);
  const grouped = new Map<string, { port: ScanFinding | null; service: ScanFinding | null }>();
  const order: string[] = [];

  for (const f of items) {
    const key = `${f.target}||${f.port || 0}`;
    if (!grouped.has(key)) {
      grouped.set(key, { port: null, service: null });
      order.push(key);
    }
    const g = grouped.get(key)!;
    if (portTypes.has(f.type)) {
      if (!g.port) g.port = f;
    } else {
      if (!g.service) g.service = f;
    }
  }

  const result: ScanFinding[] = [];
  for (const key of order) {
    const g = grouped.get(key)!;
    if (g.port && g.service) {
      const merged = { ...g.port, data: { ...g.port.data } };
      const sd = g.service.data ?? {};
      if (sd.service && !merged.data.service) merged.data.service = sd.service;
      if (sd.version && !merged.data.version) merged.data.version = sd.version;
      if (sd.banner && !merged.data.banner) merged.data.banner = sd.banner;
      if (sd.protocol && !merged.data.protocol) merged.data.protocol = sd.protocol;
      result.push(merged);
    } else {
      result.push(g.port ?? g.service!);
    }
  }
  return result;
});

const filteredByEndpoint = computed(() => {
  let rows = mergedFindings.value;
  if (selectedEndpoint.value) {
    const groupByHostOnly = hostOnlyTabs.has(activeSubTab.value);
    rows = rows.filter((f) => {
      const host = findingHost(f);
      if (groupByHostOnly) {
        return host === selectedEndpoint.value;
      }
      const port = f.port || 0;
      const key = port > 0 ? `${host}:${port}` : host;
      return key === selectedEndpoint.value;
    });
  }
  if (activeSubTab.value === 'port_open') {
    rows = [...rows].sort((a, b) => {
      const cmp = findingHost(a).localeCompare(findingHost(b));
      if (cmp !== 0) return cmp;
      return (a.port || 0) - (b.port || 0);
    });
  }
  return rows;
});

/** 开放端口/服务：按主机聚合，用于多目标时左侧筛选 */
const portServiceHostCount = computed(() => {
  if (activeSubTab.value !== 'port_open') return 0;
  const hosts = new Set<string>();
  for (const f of mergedFindings.value) {
    hosts.add(findingHost(f));
  }
  return hosts.size;
});

const showEndpointSidebar = computed(() => {
  if (activeSubTab.value === 'port_open') {
    if (portTabView.value === 'card') return false;
    return portServiceHostCount.value > 1;
  }
  return endpointList.value.length > 1;
});

interface PortCardHost {
  host: string;
  ports: Array<{ port: number; protocol: string; service: string; version: string; banner: string; confidence: number }>;
}

const portCardHosts = computed<PortCardHost[]>(() => {
  if (activeSubTab.value !== 'port_open') return [];
  const map = new Map<string, PortCardHost>();
  for (const f of mergedFindings.value) {
    const host = findingHost(f);
    if (!map.has(host)) map.set(host, { host, ports: [] });
    const entry = map.get(host)!;
    const port = f.port || parseInt(d(f, 'port'), 10) || 0;
    if (port > 0 && !entry.ports.some((p) => p.port === port)) {
      entry.ports.push({
        port,
        protocol: d(f, 'protocol') || f.protocol || 'TCP',
        service: d(f, 'service') || '',
        version: d(f, 'version') || '',
        banner: d(f, 'banner') || '',
        confidence: f.confidence,
      });
    }
  }
  for (const h of map.values()) {
    h.ports.sort((a, b) => a.port - b.port);
  }
  return Array.from(map.values()).sort((a, b) => b.ports.length - a.ports.length);
});

async function fetchLogs() {
  try {
    const taskId = route.params.id as string;
    const data = await getTaskLogs(taskId);
    if (data && data.length > 0) {
      if (liveLogs.value.length === 0) {
        liveLogs.value = data.map(scanLogToEntry);
      } else {
        mergeApiLogs(data);
      }
    }
  } catch { /* silent */ }
}

function startLogPolling() {
  if (logPollTimer) return;
  logPollTimer = setInterval(() => {
    if (isActive.value) fetchLogs();
  }, 4000);
}

function stopLogPolling() {
  if (logPollTimer) {
    clearInterval(logPollTimer);
    logPollTimer = null;
  }
}

onMounted(async () => {
  await fetchData();
  await fetchSummary();
  if (isAssetDiscoveryTask.value && !isActive.value) {
    activeSubTab.value = 'host_alive';
    await fetchAssets();
  }
  fetchLogs();
  if (isActive.value) {
    startSSE();
    startLogPolling();
  }
  refreshTimer = setInterval(() => {
    if (isActive.value && !sseConnected.value) {
      fetchData();
      if (findings.value.length > 0) fetchFindings();
    }
  }, 10000);
});

onUnmounted(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  stopLogPolling();
  stopSSE();
});
</script>

<template>
  <div class="task-detail-page">
    <NSpin :show="loading">
      <template v-if="task">
        <!-- Header Card -->
        <NCard size="small" class="header-card">
          <template #header>
            <div class="header-title-row">
              <div class="header-title-info">
                <span class="header-task-name">{{ task.name }}</span>
                <div class="header-tags">
                  <NTag :type="(taskStatusTypes[task.status] || 'default') as any" size="small" round>
                    {{ taskStatusLabels[task.status] || task.status }}
                  </NTag>
                  <NTag v-if="task.profile || task.type" size="small" :bordered="false" round style="background: #f0f5ff; color: #1890ff">
                    {{ profileLabels[task.profile ?? ''] ?? profileLabels[task.type] ?? task.profile ?? task.type }}
                  </NTag>
                  <NTag v-if="sseConnected && isActive" size="small" :bordered="false" type="success" round>
                    <span class="live-dot" />
                    实时更新中
                  </NTag>
                </div>
              </div>
            </div>
          </template>
          <template #header-extra>
            <NSpace :size="8">
              <NButton size="small" quaternary @click="fetchData">
                <template #icon><span style="font-size: 14px">&#8635;</span></template>
              </NButton>
              <NButton v-if="task.status === 'running'" size="small" @click="handlePause">暂停</NButton>
              <NButton v-if="task.status === 'paused'" size="small" type="success" @click="handleResume">恢复</NButton>
              <NPopconfirm v-if="isActive" @positive-click="handleCancel">
                <template #trigger>
                  <NButton size="small" type="warning">取消</NButton>
                </template>
                确定取消此任务？
              </NPopconfirm>
              <NButton v-if="canRerun" size="small" type="primary" @click="handleRerun">
                重新运行
              </NButton>
              <NSelect
                v-if="task.status === 'completed' || task.status === 'failed'"
                size="small"
                placeholder="导出报告"
                :options="[
                  { label: 'JSON', value: 'json' },
                  { label: 'Markdown', value: 'markdown' },
                  { label: 'CSV', value: 'csv' },
                  { label: 'Word', value: 'word' },
                  { label: 'PDF', value: 'pdf' },
                ]"
                style="width: 120px"
                @update:value="(v: string) => handleExport(v as any)"
              />
              <NPopconfirm @positive-click="handleDelete">
                <template #trigger>
                  <NButton size="small" type="error">删除</NButton>
                </template>
                确定删除此任务？
              </NPopconfirm>
            </NSpace>
          </template>

          <!-- Live Dashboard (running/queued) -->
          <div v-if="isActive" class="live-dashboard">
            <div class="live-dashboard__ring">
              <svg viewBox="0 0 120 120" class="live-ring-svg">
                <circle cx="60" cy="60" r="52" fill="none" stroke="#f0f0f0" stroke-width="8" />
                <circle
                  cx="60" cy="60" r="52" fill="none"
                  :stroke="task.status === 'failed' ? '#e88080' : '#1890ff'"
                  stroke-width="8" stroke-linecap="round"
                  :stroke-dasharray="`${(Math.round(task.progress ?? 0) / 100) * 326.7} 326.7`"
                  transform="rotate(-90 60 60)"
                  class="live-ring-progress"
                />
              </svg>
              <div class="live-ring-inner">
                <div class="live-ring-pct">{{ Math.round(task.progress ?? 0) }}<span class="live-ring-pct-sign">%</span></div>
                <div v-if="task.current_stage" class="live-ring-stage">{{ stageLabels[task.current_stage] ?? task.current_stage }}</div>
              </div>
            </div>
            <div class="live-dashboard__info">
              <div class="live-dashboard__module" v-if="task.current_module">
                <span class="live-pulse" />
                <span class="live-module-label">正在执行</span>
                <span class="live-module-name">
                  {{
                    task.current_module
                      .split(' · ')
                      .map((m: string) => moduleLabels[m.trim()] ?? m.trim())
                      .join('、')
                  }}
                </span>
              </div>
              <div v-if="liveModuleProgress.total > 0" class="live-dashboard__module-progress">
                模块进度 {{ liveModuleProgress.done }}/{{ liveModuleProgress.total }}
                <div class="live-module-bar">
                  <div class="live-module-bar__fill" :style="{ width: `${(liveModuleProgress.done / liveModuleProgress.total) * 100}%` }" />
                </div>
              </div>
              <div class="live-dashboard__counters">
                <div class="live-counter">
                  <div class="live-counter__value live-counter__value--host">{{ task.alive_hosts ?? 0 }}</div>
                  <div class="live-counter__label">存活主机</div>
                </div>
                <div class="live-counter">
                  <div class="live-counter__value live-counter__value--port">{{ task.open_ports ?? 0 }}</div>
                  <div class="live-counter__label">开放端口</div>
                </div>
                <div class="live-counter live-counter--sev">
                  <div class="live-counter__value live-counter__value--critical">{{ task.vuln_critical ?? 0 }}</div>
                  <div class="live-counter__label">严重</div>
                </div>
                <div class="live-counter live-counter--sev">
                  <div class="live-counter__value live-counter__value--high">{{ task.vuln_high ?? 0 }}</div>
                  <div class="live-counter__label">高危</div>
                </div>
                <div class="live-counter live-counter--sev">
                  <div class="live-counter__value live-counter__value--medium">{{ task.vuln_medium ?? 0 }}</div>
                  <div class="live-counter__label">中危</div>
                </div>
                <div class="live-counter live-counter--sev">
                  <div class="live-counter__value live-counter__value--low">{{ task.vuln_low ?? 0 }}</div>
                  <div class="live-counter__label">低危</div>
                </div>
              </div>
              <div v-if="task.scanned_targets" class="live-dashboard__targets">
                已扫描 {{ task.scanned_targets }} 个目标
              </div>
            </div>
          </div>

          <!-- Static Progress (non-running) -->
          <div v-else class="progress-section">
            <div class="progress-meta">
              <span class="progress-label">执行进度</span>
              <span v-if="task.current_stage" class="progress-stage">
                {{ stageLabels[task.current_stage] ?? task.current_stage }}
              </span>
              <span class="progress-pct">{{ Math.round(task.progress ?? 0) }}%</span>
            </div>
            <NProgress
              type="line"
              :percentage="Math.round(task.progress ?? 0)"
              :height="18"
              indicator-placement="inside"
              :color="task.status === 'failed' ? '#e88080' : undefined"
              :rail-color="task.status === 'failed' ? '#fce4e4' : undefined"
            />
          </div>

          <!-- Stats Summary (hidden when live dashboard is active) -->
          <div v-if="!isActive" class="stats-summary">
            <div class="stats-summary__assets">
              <div class="stats-summary__item">
                <span class="stats-summary__num">{{ task.alive_hosts ?? 0 }}</span>
                <span class="stats-summary__lbl">存活主机</span>
              </div>
              <div class="stats-summary__divider" />
              <div class="stats-summary__item">
                <span class="stats-summary__num">{{ task.open_ports ?? 0 }}</span>
                <span class="stats-summary__lbl">开放端口</span>
              </div>
              <div class="stats-summary__divider" />
              <div class="stats-summary__item">
                <span class="stats-summary__num stats-summary__num--vuln">{{ vulnTotal }}</span>
                <span class="stats-summary__lbl">漏洞总数</span>
              </div>
            </div>
            <div v-if="vulnTotal > 0" class="stats-summary__sev">
              <div class="sev-pill sev-pill--critical" :title="`严重 ${task.vuln_critical ?? 0}`">
                <span class="sev-pill__dot" />
                <span class="sev-pill__label">严重</span>
                <span class="sev-pill__count">{{ task.vuln_critical ?? 0 }}</span>
              </div>
              <div class="sev-pill sev-pill--high" :title="`高危 ${task.vuln_high ?? 0}`">
                <span class="sev-pill__dot" />
                <span class="sev-pill__label">高危</span>
                <span class="sev-pill__count">{{ task.vuln_high ?? 0 }}</span>
              </div>
              <div class="sev-pill sev-pill--medium" :title="`中危 ${task.vuln_medium ?? 0}`">
                <span class="sev-pill__dot" />
                <span class="sev-pill__label">中危</span>
                <span class="sev-pill__count">{{ task.vuln_medium ?? 0 }}</span>
              </div>
              <div class="sev-pill sev-pill--low" :title="`低危 ${task.vuln_low ?? 0}`">
                <span class="sev-pill__dot" />
                <span class="sev-pill__label">低危</span>
                <span class="sev-pill__count">{{ task.vuln_low ?? 0 }}</span>
              </div>
            </div>
            <div v-if="vulnTotal > 0" class="sev-bar-compact">
              <div v-if="(task.vuln_critical ?? 0) > 0" class="sev-bar-compact__seg sev-bar-compact__seg--critical" :style="{ flex: task.vuln_critical }" />
              <div v-if="(task.vuln_high ?? 0) > 0" class="sev-bar-compact__seg sev-bar-compact__seg--high" :style="{ flex: task.vuln_high }" />
              <div v-if="(task.vuln_medium ?? 0) > 0" class="sev-bar-compact__seg sev-bar-compact__seg--medium" :style="{ flex: task.vuln_medium }" />
              <div v-if="(task.vuln_low ?? 0) > 0" class="sev-bar-compact__seg sev-bar-compact__seg--low" :style="{ flex: task.vuln_low }" />
            </div>
          </div>
        </NCard>

        <!-- Module Overview -->
        <div v-if="summary && Object.keys(summary.by_module).length > 0" class="module-overview-card">
          <div class="module-overview-header">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#1890ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" /><rect x="14" y="3" width="7" height="7" /><rect x="14" y="14" width="7" height="7" /><rect x="3" y="14" width="7" height="7" /></svg>
            <span class="module-overview-title">模块执行概览</span>
            <span class="module-overview-count">{{ Object.keys(summary.by_module).length }} 个模块</span>
          </div>
          <div class="module-chips">
            <div
              v-for="[mod, count] in Object.entries(summary.by_module).slice(0, 8)"
              :key="mod"
              class="module-chip"
              @click="onModuleChipClick(mod)"
            >
              <span class="module-chip-name">{{ moduleLabels[mod] ?? mod }}</span>
              <span class="module-chip-count">{{ count }}</span>
            </div>
            <div 
              v-if="Object.keys(summary.by_module).length > 8" 
              class="module-chip module-chip--more"
              @click="showAllModules = true"
            >
              +{{ Object.keys(summary.by_module).length - 8 }} 更多
            </div>
          </div>
        </div>

        <!-- Tab Bar -->
        <div ref="tabBarRef" class="tab-bar">
          <template v-for="(tab, idx) in subTabsWithCount" :key="tab.key">
            <div v-if="idx > 0 && tab.group !== subTabsWithCount[idx - 1]?.group" class="tab-separator" />
            <div
              class="tab-item"
              :class="{ active: activeSubTab === tab.key, 'tab-vuln': tab.key === 'vuln' && tab.count > 0 && activeSubTab !== tab.key }"
              @click="onSubTabChange(tab.key)"
            >
              {{ tab.label }}
              <span v-if="tab.count > 0" class="tab-count" :class="{ active: activeSubTab === tab.key }">
                {{ tab.count }}
              </span>
            </div>
          </template>
        </div>

        <!-- Overview Content -->
        <template v-if="activeSubTab === 'overview'">
          <NCard title="基本信息" size="small" style="margin-bottom: 16px">
            <NDescriptions label-placement="left" bordered :column="2">
              <NDescriptionsItem label="任务 ID">
                <code style="font-size: 12px">{{ task.id }}</code>
              </NDescriptionsItem>
              <NDescriptionsItem label="扫描模式">
                {{ task.template_name ?? profileLabels[task.profile ?? ''] ?? profileLabels[task.type] ?? task.profile ?? task.type ?? '-' }}
              </NDescriptionsItem>
              <NDescriptionsItem label="目标数量">
                已扫描 {{ task.scanned_targets ?? 0 }} / 共 {{ task.total_targets ?? 0 }}
              </NDescriptionsItem>
              <NDescriptionsItem label="耗时">{{ duration }}</NDescriptionsItem>
              <NDescriptionsItem label="创建时间">{{ formatTime(task.created_at) }}</NDescriptionsItem>
              <NDescriptionsItem label="开始时间">{{ formatTime(task.started_at) }}</NDescriptionsItem>
              <NDescriptionsItem label="结束时间">{{ formatTime(task.finished_at) }}</NDescriptionsItem>
              <NDescriptionsItem label="存活/端口">
                {{ task.alive_hosts ?? 0 }} 台存活, {{ task.open_ports ?? 0 }} 个端口
              </NDescriptionsItem>
            </NDescriptions>
          </NCard>

          <NCard v-if="task.error || task.error_msg" title="错误信息" size="small" style="margin-bottom: 16px">
            <pre style="padding:12px;background:#fff1f0;border:1px solid #ffa39e;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:0">{{ task.error || task.error_msg }}</pre>
          </NCard>

          <NCard v-if="task.targets?.length" title="扫描目标" size="small" style="margin-bottom: 16px">
            <NSpace :size="6" :wrap="true">
              <NTag v-for="t in task.targets.slice(0, 100)" :key="t" size="small" :bordered="false" type="info">{{ t }}</NTag>
              <NTag v-if="task.targets.length > 100" size="small" type="warning">+{{ task.targets.length - 100 }} 更多</NTag>
            </NSpace>
          </NCard>

          <!-- Data Flow Visualization -->
          <div v-if="summary && Object.keys(summary.by_module).length > 0" class="data-flow-card">
            <div class="data-flow-header">
              <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#1890ff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
              <span class="data-flow-title">数据流向</span>
              <span class="data-flow-subtitle">目标 → 模块 → 发现</span>
            </div>
            <div class="data-flow-pipeline">
              <!-- Input node -->
              <div class="flow-node flow-node--input">
                <div class="flow-node__icon">
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#3182ce" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>
                </div>
                <div class="flow-node__label">扫描目标</div>
                <div class="flow-node__count">{{ task.total_targets ?? task.targets?.length ?? 0 }}</div>
              </div>

              <div class="flow-connector">
                <svg viewBox="0 0 40 20" width="40" height="20" class="flow-arrow-svg">
                  <line x1="0" y1="10" x2="32" y2="10" stroke="#d9d9d9" stroke-width="2" />
                  <polygon points="32,5 40,10 32,15" fill="#d9d9d9" />
                </svg>
              </div>

              <!-- Module nodes -->
              <div class="flow-modules">
                <div
                  v-for="[mod, count] in Object.entries(summary.by_module).sort((a, b) => b[1] - a[1]).slice(0, 10)"
                  :key="mod"
                  class="flow-module-row"
                >
                  <div class="flow-module-name">{{ moduleLabels[mod] ?? mod }}</div>
                  <div class="flow-module-bar-track">
                    <div
                      class="flow-module-bar-fill"
                      :style="{ width: `${Math.min(100, (count / Math.max(...Object.values(summary.by_module))) * 100)}%` }"
                    />
                  </div>
                  <div class="flow-module-count">{{ count }}</div>
                </div>
              </div>

              <div class="flow-connector">
                <svg viewBox="0 0 40 20" width="40" height="20" class="flow-arrow-svg">
                  <line x1="0" y1="10" x2="32" y2="10" stroke="#d9d9d9" stroke-width="2" />
                  <polygon points="32,5 40,10 32,15" fill="#d9d9d9" />
                </svg>
              </div>

              <!-- Output node -->
              <div class="flow-node flow-node--output">
                <div class="flow-node__icon">
                  <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#e53e3e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
                </div>
                <div class="flow-node__label">总发现</div>
                <div class="flow-node__count">{{ summary.total_findings }}</div>
                <div class="flow-severity-dots" v-if="summary.by_severity">
                  <span v-if="summary.by_severity.critical" class="flow-sev-dot flow-sev-dot--critical" :title="`严重: ${summary.by_severity.critical}`">{{ summary.by_severity.critical }}</span>
                  <span v-if="summary.by_severity.high" class="flow-sev-dot flow-sev-dot--high" :title="`高危: ${summary.by_severity.high}`">{{ summary.by_severity.high }}</span>
                  <span v-if="summary.by_severity.medium" class="flow-sev-dot flow-sev-dot--medium" :title="`中危: ${summary.by_severity.medium}`">{{ summary.by_severity.medium }}</span>
                  <span v-if="summary.by_severity.low" class="flow-sev-dot flow-sev-dot--low" :title="`低危: ${summary.by_severity.low}`">{{ summary.by_severity.low }}</span>
                </div>
              </div>
            </div>
          </div>

          <!-- Asset Summary in Overview -->
          <NCard v-if="assets.length > 0" size="small" style="margin-bottom: 16px">
            <template #header>
              <div style="display: flex; align-items: center; gap: 8px">
                <span>资产概览</span>
                <span style="font-size: 12px; color: #999; font-weight: 400">{{ assets.length }} 个资产</span>
              </div>
            </template>
            <NDataTable
              :columns="assetColumns"
              :data="assets"
              :loading="assetsLoading"
              :row-key="(row: AssetSummary) => row.target"
              :bordered="false"
              size="small"
              striped
              :max-height="300"
              :scroll-x="1200"
            />
          </NCard>

          <!-- Live Logs -->
          <NCard size="small">
            <template #header>
              <div style="display: flex; align-items: center; gap: 8px">
                <span>运行日志</span>
                <span
                  v-if="isActive && sseConnected"
                  style="width: 8px; height: 8px; border-radius: 50%; background: #52c41a; display: inline-block; animation: pulse 1.5s infinite"
                />
                <span v-if="isActive && sseConnected" style="font-size: 12px; color: #52c41a; font-weight: 400">实时</span>
                <span style="font-size: 12px; color: #999; font-weight: 400; margin-left: auto">{{ liveLogs.length }} 条</span>
              </div>
            </template>
            <div
              v-if="isActive && runStatusText"
              style="margin-bottom: 10px; padding: 8px 12px; background: #f0f5ff; border: 1px solid #d6e4ff; border-radius: 6px; font-size: 13px; color: #1d39c4; display: flex; align-items: center; gap: 8px"
            >
              <span
                style="width: 8px; height: 8px; border-radius: 50%; background: #1890ff; flex-shrink: 0; animation: pulse 1.5s infinite"
              />
              <span style="font-weight: 600">当前步骤</span>
              <span>{{ runStatusText }}</span>
            </div>
            <div
              style="max-height: 360px; overflow-y: auto; font-family: 'SF Mono', 'Consolas', 'Monaco', monospace; font-size: 12px; line-height: 1.8; background: #1e1e2e; color: #cdd6f4; border-radius: 8px; padding: 12px 16px"
            >
              <div v-if="liveLogs.length === 0" style="color: #6c7086; padding: 20px 0; text-align: center">
                {{ isActive ? '等待日志...' : '暂无运行日志' }}
              </div>
              <div
                v-for="(log, idx) in liveLogs"
                :key="log.id ?? `log-${idx}`"
                :style="{ display: 'flex', gap: '8px', padding: '2px 0', opacity: log.message.includes('执行中') ? 0.92 : 1 }"
              >
                <span style="color: #6c7086; flex-shrink: 0">{{ log.time }}</span>
                <span
                  style="flex-shrink: 0; min-width: 40px; text-align: center; border-radius: 3px; padding: 0 4px; font-size: 11px; font-weight: 600"
                  :style="{
                    background: log.level === 'error' ? '#f38ba8' : log.level === 'warn' ? '#fab387' : log.message.includes('执行中') ? '#89dceb' : '#a6e3a1',
                    color: '#1e1e2e',
                  }"
                >
                  {{ log.level === 'error' ? 'ERR' : log.level === 'warn' ? 'WARN' : log.message.includes('执行中') ? 'RUN' : 'INFO' }}
                </span>
                <span style="color: #89b4fa; flex-shrink: 0" v-if="log.stage">[{{ stageLabels[log.stage] ?? log.stage }}]</span>
                <span style="color: #f9e2af; flex-shrink: 0" v-if="log.module">{{ moduleLabels[log.module] ?? log.module }}</span>
                <span style="color: #cdd6f4; word-break: break-all">{{ log.message }}</span>
              </div>
            </div>
          </NCard>
        </template>

        <!-- Asset Cards View -->
        <template v-if="activeSubTab === 'host_alive'">
          <NSpin :show="assetsLoading">
            <NEmpty v-if="!assetsLoading && assets.length === 0" description="暂无资产信息" style="padding: 60px 0" />
            <div v-else style="display: grid; grid-template-columns: repeat(auto-fill, minmax(420px, 1fr)); gap: 16px">
              <div
                v-for="asset in assets"
                :key="asset.target"
                style="border: 1px solid #eee; border-radius: 10px; background: #fff; overflow: hidden; cursor: pointer; transition: box-shadow 0.2s, border-color 0.2s"
                class="asset-card"
                @click="openAssetDetail(asset)"
              >
                <div style="display: flex; align-items: center; gap: 10px; padding: 14px 16px; background: linear-gradient(135deg, #f0f5ff 0%, #f8fafc 100%); border-bottom: 1px solid #f0f0f0">
                  <div style="width: 36px; height: 36px; border-radius: 8px; background: #1890ff; color: #fff; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 14px; flex-shrink: 0">
                    {{ asset.target.charAt(0).toUpperCase() }}
                  </div>
                  <div style="flex: 1; min-width: 0">
                    <div style="font-size: 14px; font-weight: 600; color: #1a1a1a; overflow: hidden; text-overflow: ellipsis; white-space: nowrap" :title="asset.target">{{ asset.target }}</div>
                    <div style="font-size: 12px; color: #888; margin-top: 2px">
                      <span v-if="asset.ip && asset.ip !== asset.target">{{ asset.ip }}</span>
                      <span v-if="asset.title" :style="asset.ip && asset.ip !== asset.target ? 'margin-left: 8px' : ''">{{ asset.title }}</span>
                    </div>
                  </div>
                  <div v-if="asset.status_code" style="flex-shrink: 0">
                    <span
                      style="padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600"
                      :style="{ background: asset.status_code < 400 ? '#f6ffed' : '#fff2f0', color: asset.status_code < 400 ? '#52c41a' : '#ff4d4f' }"
                    >{{ asset.status_code }}</span>
                  </div>
                </div>

                <div style="padding: 12px 16px">
                  <div v-if="asset.ports?.length" style="margin-bottom: 10px">
                    <div style="font-size: 11px; color: #999; margin-bottom: 6px; font-weight: 500">端口/服务 ({{ asset.ports.length }})</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 4px">
                      <span
                        v-for="p in (asset.ports || []).slice(0, 8)"
                        :key="p.port"
                        style="display: inline-flex; align-items: center; gap: 3px; padding: 2px 8px; border-radius: 4px; font-size: 11px; background: #f0f5ff; color: #1890ff; border: 1px solid #d6e4ff"
                      >
                        <b>{{ p.port }}</b>
                        <span v-if="p.service" style="color: #666">{{ p.service }}</span>
                      </span>
                      <span v-if="asset.ports.length > 8" style="padding: 2px 8px; font-size: 11px; color: #999">+{{ asset.ports.length - 8 }}</span>
                    </div>
                  </div>

                  <div v-if="asset.services?.length" style="margin-bottom: 10px">
                    <div style="font-size: 11px; color: #999; margin-bottom: 6px; font-weight: 500">服务</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 4px">
                      <NTag v-for="s in (asset.services || []).slice(0, 6)" :key="s" size="tiny" :bordered="false" type="info">{{ s }}</NTag>
                      <span v-if="asset.services.length > 6" style="font-size: 11px; color: #999; line-height: 22px">+{{ asset.services.length - 6 }}</span>
                    </div>
                  </div>

                  <div v-if="asset.techs?.length" style="margin-bottom: 10px">
                    <div style="font-size: 11px; color: #999; margin-bottom: 6px; font-weight: 500">技术栈</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 4px">
                      <NTag v-for="t in (asset.techs || []).slice(0, 6)" :key="t" size="tiny" :bordered="false" type="success">{{ t }}</NTag>
                      <span v-if="asset.techs.length > 6" style="font-size: 11px; color: #999; line-height: 22px">+{{ asset.techs.length - 6 }}</span>
                    </div>
                  </div>

                  <div v-if="asset.waf" style="margin-bottom: 10px">
                    <div style="font-size: 11px; color: #999; margin-bottom: 4px; font-weight: 500">WAF</div>
                    <NTag size="tiny" :bordered="false" type="warning">{{ asset.waf }}</NTag>
                  </div>

                  <div v-if="Object.keys(asset.vuln_count ?? {}).length > 0" style="margin-bottom: 6px">
                    <div style="font-size: 11px; color: #999; margin-bottom: 6px; font-weight: 500">漏洞</div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap">
                      <span
                        v-for="(count, sev) in asset.vuln_count"
                        :key="sev"
                        style="padding: 1px 8px; border-radius: 4px; font-size: 11px; font-weight: 600"
                        :style="{
                          background: sev === 'critical' ? '#fff1f0' : sev === 'high' ? '#fff7e6' : sev === 'medium' ? '#fffbe6' : sev === 'low' ? '#f6ffed' : '#f0f5ff',
                          color: sev === 'critical' ? '#cf1322' : sev === 'high' ? '#d46b08' : sev === 'medium' ? '#d4b106' : sev === 'low' ? '#389e0d' : '#1890ff',
                        }"
                      >
                        {{ (severityConfig[sev as string] ?? { label: sev }).label }} {{ count }}
                      </span>
                    </div>
                  </div>
                </div>

                <div style="display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; background: #fafafa; border-top: 1px solid #f5f5f5; font-size: 11px; color: #999">
                  <span>发现 {{ asset.finding_ids?.length ?? 0 }} 条</span>
                  <span>{{ asset.first_seen }}</span>
                </div>
              </div>
            </div>
          </NSpin>
        </template>

        <!-- Network Topology Graph -->
        <template v-if="activeSubTab === 'nettopo'">
          <TopologyGraph :findings="mergedFindings" height="550px" />
        </template>

        <!-- Findings Content -->
        <template v-if="activeSubTab !== 'overview' && activeSubTab !== 'host_alive' && activeSubTab !== 'nettopo'">

          <!-- Port/Service Asset View -->
          <template v-if="activeSubTab === 'port_open' && portTabView === 'card'">
            <div class="fc-toolbar">
              <div class="fc-toolbar__left">
                <span class="fc-toolbar__title">资产端口概览</span>
                <span class="fc-toolbar__meta">{{ assets.length }} 台主机</span>
              </div>
              <NButton size="small" quaternary @click="portTabView = 'table'">
                <template #icon><svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M1.5 2A1.5 1.5 0 000 3.5v9A1.5 1.5 0 001.5 14h13a1.5 1.5 0 001.5-1.5v-9A1.5 1.5 0 0014.5 2h-13zM1 3.5a.5.5 0 01.5-.5h13a.5.5 0 01.5.5v1H1v-1zM1 6h14v6.5a.5.5 0 01-.5.5h-13a.5.5 0 01-.5-.5V6z"/></svg></template>
                表格视图
              </NButton>
            </div>
            <NSpin :show="assetsLoading">
              <div v-if="assets.length > 0" class="fc-asset-grid">
                <div v-for="asset in assets" :key="asset.target" class="fc-asset-card" @click="openAssetDetail(asset)">
                  <div class="fc-asset-card__head">
                    <div class="fc-asset-card__ip">{{ asset.ip || asset.target }}</div>
                    <div v-if="asset.os" class="fc-asset-card__os">{{ asset.os }}</div>
                  </div>
                  <div v-if="asset.title" class="fc-asset-card__title">{{ asset.title }}</div>
                  <div class="fc-asset-card__ports">
                    <span v-for="p in (asset.ports || []).slice(0, 12)" :key="p.port" class="fc-port-badge" :class="{ 'fc-port-badge--risk': [21,23,445,3389,6379,27017,2375].includes(p.port) }">
                      {{ p.port }}<template v-if="p.service">/{{ p.service }}</template>
                    </span>
                    <span v-if="(asset.ports || []).length > 12" class="fc-port-badge fc-port-badge--more">+{{ asset.ports.length - 12 }}</span>
                  </div>
                  <div class="fc-asset-card__foot">
                    <span v-if="asset.waf" class="fc-asset-tag fc-asset-tag--waf">WAF: {{ asset.waf }}</span>
                    <span v-for="t in (asset.techs || []).slice(0, 3)" :key="t" class="fc-asset-tag">{{ t }}</span>
                    <span v-if="Object.values(asset.vuln_count || {}).some(v => v > 0)" class="fc-asset-tag fc-asset-tag--vuln">
                      漏洞 {{ Object.values(asset.vuln_count || {}).reduce((a, b) => a + b, 0) }}
                    </span>
                  </div>
                </div>
              </div>
              <NEmpty v-if="!assetsLoading && assets.length === 0" description="暂无资产数据" style="padding: 60px 0" />
            </NSpin>
          </template>

          <!-- All Tab: Host-Centric View -->
          <template v-else-if="activeSubTab === 'all'">
            <!-- Host Grid Overview -->
            <div v-if="!selectedHost" class="fc-host-view">
              <div class="fc-toolbar">
                <div class="fc-toolbar__left">
                  <span class="fc-toolbar__title">主机总览</span>
                  <span class="fc-toolbar__meta">{{ assets.length }} 台主机，{{ summary?.total_findings ?? 0 }} 条发现</span>
                </div>
              </div>
              <!-- Severity summary -->
              <div v-if="summary?.by_severity" class="fc-sev-bar">
                <div
                  v-for="sev in ['critical', 'high', 'medium', 'low', 'info']"
                  :key="sev"
                  v-show="(summary.by_severity[sev] ?? 0) > 0"
                  class="fc-sev-chip"
                  :style="{ '--c': (severityConfig[sev] ?? { color: '#999' }).color }"
                >
                  <span class="fc-sev-chip__dot" />
                  {{ (severityConfig[sev] ?? { label: sev }).label }}
                  <span class="fc-sev-chip__num">{{ summary.by_severity[sev] ?? 0 }}</span>
                </div>
              </div>
              <NSpin :show="assetsLoading">
                <div v-if="assets.length > 0" class="fc-host-grid">
                  <div
                    v-for="asset in assets"
                    :key="asset.target"
                    class="fc-host-card"
                    @click="selectHost(asset)"
                  >
                    <div class="fc-host-card__head">
                      <span class="fc-host-card__ip">{{ asset.ip || asset.target }}</span>
                      <span v-if="asset.os" class="fc-host-card__os">{{ asset.os }}</span>
                    </div>
                    <div v-if="asset.title" class="fc-host-card__title">{{ asset.title }}</div>
                    <div class="fc-host-card__stats">
                      <span class="fc-host-stat">
                        <span class="fc-host-stat__num">{{ (asset.ports || []).length }}</span>
                        <span class="fc-host-stat__label">端口</span>
                      </span>
                      <span class="fc-host-stat">
                        <span class="fc-host-stat__num">{{ (asset.services || []).length }}</span>
                        <span class="fc-host-stat__label">服务</span>
                      </span>
                      <span v-if="Object.values(asset.vuln_count || {}).reduce((a, b) => a + b, 0) > 0" class="fc-host-stat fc-host-stat--vuln">
                        <span class="fc-host-stat__num">{{ Object.values(asset.vuln_count || {}).reduce((a, b) => a + b, 0) }}</span>
                        <span class="fc-host-stat__label">漏洞</span>
                      </span>
                    </div>
                    <div v-if="(asset.ports || []).length > 0" class="fc-host-card__ports">
                      <span v-for="p in (asset.ports || []).slice(0, 8)" :key="p.port" class="fc-port-mini" :class="{ 'fc-port-mini--risk': [21,23,445,3389,6379,27017,2375].includes(p.port) }">
                        {{ p.port }}<template v-if="p.service">/{{ p.service }}</template>
                      </span>
                      <span v-if="(asset.ports || []).length > 8" class="fc-port-mini fc-port-mini--more">+{{ (asset.ports || []).length - 8 }}</span>
                    </div>
                  </div>
                </div>
                <NEmpty v-if="!assetsLoading && assets.length === 0" description="暂无扫描数据" style="padding: 60px 0" />
              </NSpin>
            </div>

            <!-- Host Detail: Selected host findings -->
            <div v-else class="fc-host-detail">
              <div class="fc-host-detail__header">
                <NButton size="small" quaternary @click="selectedHost = null">
                  <template #icon><svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path fill-rule="evenodd" d="M11.354 1.646a.5.5 0 010 .708L5.707 8l5.647 5.646a.5.5 0 01-.708.708l-6-6a.5.5 0 010-.708l6-6a.5.5 0 01.708 0z"/></svg></template>
                  返回主机列表
                </NButton>
                <div class="fc-host-detail__info">
                  <span class="fc-host-detail__ip">{{ selectedHost.ip || selectedHost.target }}</span>
                  <span v-if="selectedHost.os" class="fc-host-detail__os">{{ selectedHost.os }}</span>
                  <span v-if="selectedHost.title" class="fc-host-detail__title">{{ selectedHost.title }}</span>
                </div>
              </div>
              <!-- Host quick stats -->
              <div class="fc-host-detail__stats">
                <span class="fc-stat-pill"><b>{{ (selectedHost.ports || []).length }}</b> 端口</span>
                <span class="fc-stat-pill"><b>{{ (selectedHost.services || []).length }}</b> 服务</span>
                <span v-for="(count, sev) in (selectedHost.vuln_count || {})" :key="sev" class="fc-stat-pill" :class="`fc-stat-pill--${sev}`">
                  <b>{{ count }}</b> {{ (severityConfig[sev as string] ?? { label: sev }).label }}
                </span>
              </div>
              <!-- Filter + Table -->
              <div class="fc-filter-bar">
                <NSelect v-model:value="filterSeverity" :options="severityOptions" placeholder="严重级别" clearable size="small" style="width: 120px" @update:value="() => { findingsPage = 1; fetchFindings(); }" />
                <NSelect v-model:value="filterType" :options="typeFilterOptions" placeholder="类型" clearable size="small" style="width: 140px" @update:value="() => { findingsPage = 1; fetchFindings(); }" />
                <NInput v-model:value="filterKeyword" placeholder="搜索" clearable size="small" style="width: 180px" @keydown.enter="() => { findingsPage = 1; fetchFindings(); }" @clear="() => { findingsPage = 1; fetchFindings(); }" />
                <NButton size="small" type="primary" @click="findingsPage = 1; fetchFindings()">搜索</NButton>
                <NButton size="small" @click="filterSeverity = null; filterType = null; filterKeyword = ''; findingsPage = 1; fetchFindings()">重置</NButton>
                <span class="fc-filter-bar__total">共 <b>{{ findingsTotal }}</b> 条</span>
              </div>
              <NDataTable
                v-if="findingsLoading || mergedFindings.length > 0"
                :columns="findingColumns"
                :data="mergedFindings"
                :loading="findingsLoading"
                :row-key="(row: ScanFinding) => row.id"
                :row-props="findingRowProps"
                :pagination="false"
                :bordered="false"
                size="small"
                striped
                :max-height="540"
                :scroll-x="findingTableScrollX"
                class="findings-result-table"
              />
              <div v-if="findingsTotal > 0" class="fc-pagination">
                <NPagination
                  :page="findingsPage"
                  :page-size="findingsPageSize"
                  :item-count="findingsTotal"
                  :page-sizes="[20, 50, 100]"
                  show-size-picker
                  @update:page="handleFindingsPageChange"
                  @update:page-size="handleFindingsPageSizeChange"
                />
              </div>
              <NEmpty v-if="!findingsLoading && mergedFindings.length === 0" description="该主机暂无发现" style="padding: 60px 0" />
            </div>
          </template>

          <!-- Other Tabs: Simple Filter + Table -->
          <template v-else>
            <div class="fc-toolbar" v-if="activeSubTab === 'port_open'">
              <div />
              <NButton size="small" quaternary @click="portTabView = 'card'">
                <template #icon><svg viewBox="0 0 16 16" width="14" height="14" fill="currentColor"><path d="M1 2.5A1.5 1.5 0 012.5 1h3A1.5 1.5 0 017 2.5v3A1.5 1.5 0 015.5 7h-3A1.5 1.5 0 011 5.5v-3zm8 0A1.5 1.5 0 0110.5 1h3A1.5 1.5 0 0115 2.5v3A1.5 1.5 0 0113.5 7h-3A1.5 1.5 0 019 5.5v-3zm-8 8A1.5 1.5 0 012.5 9h3A1.5 1.5 0 017 10.5v3A1.5 1.5 0 015.5 15h-3A1.5 1.5 0 011 13.5v-3zm8 0A1.5 1.5 0 0110.5 9h3a1.5 1.5 0 011.5 1.5v3a1.5 1.5 0 01-1.5 1.5h-3A1.5 1.5 0 019 13.5v-3z"/></svg></template>
                资产视图
              </NButton>
            </div>
            <div class="fc-filter-bar">
              <NSelect v-model:value="filterSeverity" :options="severityOptions" placeholder="严重级别" clearable size="small" style="width: 120px" @update:value="() => { findingsPage = 1; fetchFindings(); }" />
              <NSelect v-model:value="filterModule" :options="moduleOptions" placeholder="扫描模块" clearable size="small" style="width: 160px" @update:value="() => { findingsPage = 1; fetchFindings(); }" />
              <NInput v-model:value="filterKeyword" placeholder="搜索标题/目标" clearable size="small" style="width: 200px" @keydown.enter="() => { findingsPage = 1; fetchFindings(); }" @clear="() => { findingsPage = 1; fetchFindings(); }" />
              <NButton size="small" type="primary" @click="findingsPage = 1; fetchFindings()">搜索</NButton>
              <NButton size="small" @click="filterSeverity = null; filterModule = null; filterKeyword = ''; findingsPage = 1; fetchFindings()">重置</NButton>
              <span class="fc-filter-bar__total">共 <b>{{ findingsTotal }}</b> 条</span>
            </div>
            <NDataTable
              v-if="findingsLoading || mergedFindings.length > 0"
              :columns="findingColumns"
              :data="mergedFindings"
              :loading="findingsLoading"
              :row-key="(row: ScanFinding) => row.id"
              :row-props="findingRowProps"
              :pagination="false"
              :bordered="false"
              size="small"
              striped
              :max-height="640"
              :scroll-x="findingTableScrollX"
              class="findings-result-table"
            />
            <div v-if="findingsTotal > 0" class="fc-pagination">
              <NPagination
                :page="findingsPage"
                :page-size="findingsPageSize"
                :item-count="findingsTotal"
                :page-sizes="[20, 50, 100]"
                show-size-picker
                @update:page="handleFindingsPageChange"
                @update:page-size="handleFindingsPageSizeChange"
              />
            </div>
            <NEmpty v-if="!findingsLoading && mergedFindings.length === 0" description="暂无扫描发现" style="padding: 60px 0" />
          </template>
        </template>
      </template>
    </NSpin>

    <!-- Asset Detail Drawer -->
    <NDrawer v-model:show="showAssetDrawer" :width="560" placement="right">
      <NDrawerContent :title="assetDetail?.target ?? '资产详情'" closable>
        <template v-if="assetDetail">
          <NDescriptions label-placement="left" bordered :column="1" size="small" style="margin-bottom: 16px">
            <NDescriptionsItem label="目标">{{ assetDetail.target }}</NDescriptionsItem>
            <NDescriptionsItem label="IP">{{ assetDetail.ip }}</NDescriptionsItem>
            <NDescriptionsItem v-if="assetDetail.title" label="标题">{{ assetDetail.title }}</NDescriptionsItem>
            <NDescriptionsItem v-if="assetDetail.status_code" label="状态码">
              <NTag size="small" :type="assetDetail.status_code < 400 ? 'success' : 'error'">{{ assetDetail.status_code }}</NTag>
            </NDescriptionsItem>
            <NDescriptionsItem v-if="assetDetail.waf" label="WAF">{{ assetDetail.waf }}</NDescriptionsItem>
            <NDescriptionsItem label="首次发现">{{ assetDetail.first_seen }}</NDescriptionsItem>
          </NDescriptions>

          <template v-if="assetDetail.ports?.length">
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px">端口/服务</div>
            <div style="border: 1px solid #e8e8e8; border-radius: 6px; overflow: hidden; margin-bottom: 16px">
              <div v-for="(p, i) in assetDetail.ports" :key="i" style="display: flex; border-bottom: 1px solid #f0f0f0; font-size: 12px">
                <div style="width: 60px; flex-shrink: 0; padding: 6px 12px; background: #fafafa; font-weight: 600">{{ p.port }}</div>
                <div style="width: 60px; flex-shrink: 0; padding: 6px 8px; color: #666">{{ p.protocol || '-' }}</div>
                <div style="flex: 1; padding: 6px 8px">
                  <span v-if="p.service" style="color: #1890ff; font-weight: 500">{{ p.service }}</span>
                  <span v-if="p.version" style="color: #999; margin-left: 4px">{{ p.version }}</span>
                  <span v-if="!p.service" style="color: #ccc">-</span>
                </div>
              </div>
            </div>
          </template>

          <template v-if="assetDetail.techs?.length">
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px">组件指纹</div>
            <NSpace :size="6" :wrap="true" style="margin-bottom: 16px">
              <NTag v-for="t in assetDetail.techs" :key="t" size="small" type="success" :bordered="false">{{ t }}</NTag>
            </NSpace>
          </template>

          <template v-if="assetDetail.services?.length">
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px">服务</div>
            <NSpace :size="6" :wrap="true" style="margin-bottom: 16px">
              <NTag v-for="s in assetDetail.services" :key="s" size="small" type="info" :bordered="false">{{ s }}</NTag>
            </NSpace>
          </template>

          <template v-if="assetDetail.banner">
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px">Banner</div>
            <pre style="padding: 10px; background: #1a1a2e; color: #a8d8ea; border-radius: 6px; font-size: 11px; overflow-x: auto; white-space: pre-wrap; word-break: break-all; margin: 0 0 16px; line-height: 1.5; max-height: 300px">{{ assetDetail.banner }}</pre>
          </template>

          <template v-if="Object.keys(assetDetail.vuln_count ?? {}).length > 0">
            <div style="font-weight: 600; font-size: 13px; margin-bottom: 8px">漏洞统计</div>
            <NSpace :size="12" style="margin-bottom: 16px">
              <template v-for="(count, sev) in assetDetail.vuln_count" :key="sev">
                <NTag :type="(sev === 'critical' || sev === 'high') ? 'error' : sev === 'medium' ? 'warning' : 'default'" size="small">
                  {{ (severityConfig[sev as string] ?? { label: sev }).label }}: {{ count }}
                </NTag>
              </template>
            </NSpace>
          </template>
        </template>
      </NDrawerContent>
    </NDrawer>

    <ScanFindingDetailDrawer
      v-model:show="showDetail"
      :finding="detailItem"
      :module-label="detailItem ? (moduleLabels[detailItem.module_id] ?? detailItem.module_id) : ''"
      :converting-to-incident="convertingToIncident"
      :marking-fp="markingFP"
      :retesting="!!detailItem && retestingFindingId === detailItem.id"
      @retest="detailItem && handleRetestFinding(detailItem)"
      @to-incident="detailItem && convertFindingToIncident(detailItem)"
      @mark-fp="detailItem && handleMarkFP(detailItem)"
    />

    <!-- All Modules Modal -->
    <NModal v-model:show="showAllModules" preset="card" title="所有扫描模块" :style="{ width: '480px' }">
      <div style="max-height: 400px; overflow-y: auto;">
        <div v-if="summary?.by_module" class="module-chips" style="display: flex; flex-direction: column; gap: 8px;">
          <div 
            v-for="[mod, count] in Object.entries(summary.by_module).sort((a, b) => b[1] - a[1])" 
            :key="mod" 
            class="module-chip" 
            style="justify-content: space-between;"
            @click="onModuleChipClick(mod); showAllModules = false;"
          >
            <span class="module-chip-name">{{ moduleLabels[mod] ?? mod }}</span>
            <span class="module-chip-count">{{ count }}</span>
          </div>
        </div>
      </div>
    </NModal>
  </div>
</template>
<style scoped>
@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
}

.task-detail-page {
  padding: 20px 24px;
  max-width: 1440px;
  margin: 0 auto;
}

/* Header Card */
.header-card {
  margin-bottom: 16px;
  border-radius: 12px;
  border: 1px solid var(--border-color, #e8ecf1);
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04), 0 1px 2px rgba(0, 0, 0, 0.02);
}

.header-title-row {
  display: flex;
  align-items: flex-start;
  gap: 12px;
}

.header-title-info {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.header-task-name {
  font-size: 18px;
  font-weight: 700;
  color: var(--text-color-1, #1a1a2e);
  letter-spacing: -0.01em;
}

.header-tags {
  display: flex;
  align-items: center;
  gap: 6px;
}

.live-dot {
  display: inline-block;
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: #52c41a;
  margin-right: 4px;
  animation: pulse 1.5s infinite;
}

/* Live Dashboard */
.live-dashboard {
  display: flex;
  align-items: flex-start;
  gap: 28px;
  padding: 20px 0 16px;
  border-top: 1px solid #f5f5f5;
}

.live-dashboard__ring {
  position: relative;
  width: 120px;
  height: 120px;
  flex-shrink: 0;
}

.live-ring-svg {
  width: 100%;
  height: 100%;
}

.live-ring-progress {
  transition: stroke-dasharray 0.6s ease;
}

.live-ring-inner {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.live-ring-pct {
  font-size: 28px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: var(--text-color-1, #1a1a1a);
  line-height: 1;
}

.live-ring-pct-sign {
  font-size: 14px;
  font-weight: 600;
  color: #8c8c8c;
}

.live-ring-stage {
  font-size: 11px;
  color: #8c8c8c;
  margin-top: 4px;
}

.live-dashboard__info {
  flex: 1;
  min-width: 0;
}

.live-dashboard__module {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  background: #f0f5ff;
  border: 1px solid #d6e4ff;
  border-radius: 8px;
  margin-bottom: 12px;
}

.live-pulse {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #1890ff;
  flex-shrink: 0;
  animation: pulse 1.5s infinite;
}

.live-module-label {
  font-size: 12px;
  font-weight: 600;
  color: #1d39c4;
}

.live-module-name {
  font-size: 13px;
  color: #1d39c4;
}

.live-dashboard__module-progress {
  font-size: 12px;
  color: #8c8c8c;
  margin-bottom: 14px;
}

.live-module-bar {
  height: 4px;
  background: #f0f0f0;
  border-radius: 2px;
  overflow: hidden;
  margin-top: 4px;
}

.live-module-bar__fill {
  height: 100%;
  background: #1890ff;
  border-radius: 2px;
  transition: width 0.4s ease;
}

.live-dashboard__counters {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 8px;
}

.live-counter {
  text-align: center;
  padding: 8px 4px;
  background: #fafbfc;
  border-radius: 6px;
  border: 1px solid #f0f0f0;
  transition: transform 0.15s;
}

.live-counter__value {
  font-size: 20px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  line-height: 1.1;
  transition: color 0.3s;
}

.live-counter__label {
  font-size: 10px;
  color: #8c8c8c;
  margin-top: 3px;
}

.live-counter__value--host { color: var(--text-color-1, #333); }
.live-counter__value--port { color: var(--text-color-1, #333); }
.live-counter__value--critical { color: #e53e3e; }
.live-counter__value--high { color: #ed8936; }
.live-counter__value--medium { color: #d69e2e; }
.live-counter__value--low { color: #48bb78; }

.live-dashboard__targets {
  font-size: 12px;
  color: #8c8c8c;
  margin-top: 10px;
}

@keyframes pulse {
  0%, 100% { opacity: 1; }
  50% { opacity: 0.3; }
}

/* Progress */
.progress-section {
  margin-bottom: 20px;
}

.progress-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 8px;
}

.progress-label {
  font-weight: 500;
  font-size: 13px;
  color: var(--text-color-1, #333);
}

.progress-stage {
  font-size: 12px;
  color: #999;
}

.progress-pct {
  font-size: 13px;
  color: #666;
  margin-left: auto;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}

/* Stats Summary — clean, compact layout */
.stats-summary {
  padding: 14px 0 6px;
  border-top: 1px solid var(--border-color-light, #f0f0f0);
}
.stats-summary__assets {
  display: flex;
  align-items: center;
  gap: 0;
  margin-bottom: 12px;
}
.stats-summary__item {
  display: flex;
  align-items: baseline;
  gap: 6px;
  padding: 0 20px;
}
.stats-summary__item:first-child { padding-left: 0; }
.stats-summary__num {
  font-size: 28px;
  font-weight: 700;
  color: var(--text-color-1, #1a1a1a);
  font-variant-numeric: tabular-nums;
  line-height: 1;
}
.stats-summary__num--vuln {
  color: var(--text-color-1, #1a1a1a);
}
.stats-summary__lbl {
  font-size: 13px;
  color: var(--text-color-3, #8c8c8c);
  white-space: nowrap;
}
.stats-summary__divider {
  width: 1px;
  height: 24px;
  background: var(--border-color-light, #e8e8e8);
  flex-shrink: 0;
}

.stats-summary__sev {
  display: flex;
  gap: 8px;
  margin-bottom: 10px;
}
.sev-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 500;
  background: var(--bg-color-2, #fafafa);
  border: 1px solid var(--border-color-light, #eee);
  color: var(--text-color-2, #555);
}
.sev-pill__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.sev-pill__label { font-size: 12px; }
.sev-pill__count { font-weight: 700; font-variant-numeric: tabular-nums; }

.sev-pill--critical .sev-pill__dot { background: #e53e3e; }
.sev-pill--critical .sev-pill__count { color: #c53030; }
.sev-pill--high .sev-pill__dot { background: #ed8936; }
.sev-pill--high .sev-pill__count { color: #c05621; }
.sev-pill--medium .sev-pill__dot { background: #ecc94b; }
.sev-pill--medium .sev-pill__count { color: #975a16; }
.sev-pill--low .sev-pill__dot { background: #48bb78; }
.sev-pill--low .sev-pill__count { color: #276749; }

/* Compact Severity Bar */
.sev-bar-compact {
  display: flex;
  height: 6px;
  border-radius: 3px;
  overflow: hidden;
  background: var(--border-color-light, #f0f0f0);
  gap: 1px;
}
.sev-bar-compact__seg {
  transition: flex 0.4s ease;
}
.sev-bar-compact__seg--critical { background: #e53e3e; }
.sev-bar-compact__seg--high { background: #ed8936; }
.sev-bar-compact__seg--medium { background: #ecc94b; }
.sev-bar-compact__seg--low { background: #48bb78; }

/* Module Overview Card */
.module-overview-card {
  background: var(--card-color, #fff);
  border: 1px solid var(--border-color, #eef2f6);
  border-radius: 12px;
  padding: 16px 20px;
  margin-bottom: 16px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}
.module-overview-header {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 14px;
}
.module-overview-title {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-color-1, #333);
}
.module-overview-count {
  font-size: 12px;
  color: #8c8c8c;
  margin-left: auto;
}

/* Module Chips */
.module-chips {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.module-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 12px;
  background: #f8fafc;
  border-radius: 8px;
  font-size: 12px;
  border: 1px solid #eef2f6;
  transition: border-color 0.15s, box-shadow 0.15s;
  cursor: pointer;
  user-select: none;
}

.module-chip:hover {
  border-color: #d6e4ff;
  box-shadow: 0 1px 4px rgba(24, 144, 255, 0.08);
}

.module-chip-name {
  color: #1890ff;
  font-weight: 500;
}

.module-chip-count {
  background: #1890ff;
  color: #fff;
  border-radius: 10px;
  padding: 1px 8px;
  font-size: 11px;
  font-weight: 600;
  min-width: 22px;
  text-align: center;
}

.module-chip--more {
  opacity: 0.7;
  border-style: dashed;
}
.module-chip--more:hover {
  opacity: 1;
}

/* Tab Bar */
.tab-bar {
  display: flex;
  align-items: center;
  gap: 2px;
  margin-bottom: 20px;
  overflow-x: auto;
  background: #f8f9fa;
  border-radius: 10px;
  padding: 4px;
  border: 1px solid #eef2f6;
  position: sticky;
  top: 0;
  z-index: 10;
}

.tab-separator {
  width: 1px;
  height: 20px;
  background: #d9d9d9;
  margin: 0 6px;
  flex-shrink: 0;
}

.tab-item {
  padding: 7px 14px;
  cursor: pointer;
  font-size: 13px;
  white-space: nowrap;
  transition: all 0.2s;
  user-select: none;
  border-radius: 7px;
  color: #666;
}

.tab-item:hover:not(.active) {
  background: #eef2f6;
  color: #333;
}

.tab-item.tab-vuln {
  color: #cf1322;
  font-weight: 500;
}

.tab-item.active {
  background: #1890ff;
  color: #fff;
  font-weight: 600;
  box-shadow: 0 2px 8px rgba(24, 144, 255, 0.25);
}

.tab-count {
  margin-left: 3px;
  font-size: 11px;
  padding: 1px 6px;
  border-radius: 10px;
  font-weight: 600;
  background: #e8e8e8;
  color: #666;
}

.tab-count.active {
  background: rgba(255, 255, 255, 0.3);
  color: #fff;
}

/* Asset Card */
.asset-card:hover {
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.08);
  border-color: #d6e4ff !important;
}

/* Severity Bar */
.severity-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 14px;
  padding: 10px 14px;
  background: #f8f9fa;
  border-radius: 8px;
  border: 1px solid #eef2f6;
}

.severity-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 12px;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.15s;
  border: 1px solid transparent;
  user-select: none;
}

.severity-chip:hover {
  background: rgba(0, 0, 0, 0.04);
  border-color: var(--sev-color);
}

.severity-chip.active {
  background: rgba(0, 0, 0, 0.04);
  border-color: var(--sev-color);
  box-shadow: 0 0 0 1px var(--sev-color);
}

.severity-chip-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--sev-color);
  flex-shrink: 0;
}

.severity-chip-label {
  color: var(--sev-color);
  font-weight: 500;
}

.severity-chip-count {
  font-weight: 700;
  color: var(--sev-color);
}

.findings-filter-bar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
  flex-wrap: wrap;
  padding: 10px 16px;
  background: var(--body-color, linear-gradient(135deg, #f8f9fb 0%, #f0f2f5 100%));
  border-radius: 10px;
  border: 1px solid var(--border-color, #e8ecf1);
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03);
}

.findings-total-count {
  font-size: 12px;
  color: #8c8c8c;
  margin-left: auto;
}
.findings-total-count b {
  color: var(--text-color-1, #333);
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}

.finding-table-hint {
  font-size: 12px;
  color: #8c8c8c;
}

.findings-table-wrapper {
  background: var(--card-color, #fff);
  border: 1px solid var(--border-color, #e8ecf1);
  border-radius: 10px;
  overflow: hidden;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
}

.findings-pagination {
  display: flex;
  justify-content: flex-end;
  padding: 12px 16px;
  border-top: 1px solid var(--border-color-light, #f0f0f0);
  background: var(--body-color, #fafbfc);
}

:deep(.findings-result-table .n-data-table-th) {
  font-size: 11px !important;
  font-weight: 700 !important;
  color: #4a5568 !important;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  background: #f7f8fa !important;
  border-bottom: 2px solid #e2e8f0 !important;
  padding-top: 10px !important;
  padding-bottom: 10px !important;
}

:deep(.findings-result-table .n-data-table-td) {
  vertical-align: top;
  padding-top: 10px !important;
  padding-bottom: 10px !important;
  border-bottom: 1px solid #f0f0f0 !important;
  font-size: 13px;
}

:deep(.findings-result-table .n-data-table-tr) {
  border-left: 3px solid transparent;
  transition: border-color 0.15s, background 0.15s;
}

:deep(.findings-result-table .n-data-table-tr:nth-child(even)) {
  background: rgba(0, 0, 0, 0.015);
}

:deep(.findings-result-table .n-data-table-tr:hover) {
  background: rgba(24, 144, 255, 0.04);
  border-left-color: var(--row-sev-color, transparent);
}

:deep(.findings-result-table .n-data-table-tr.finding-row-high) {
  border-left-color: var(--row-sev-color, transparent);
  background: rgba(229, 62, 62, 0.02);
}
:deep(.findings-result-table .n-data-table-tr.finding-row-high:hover) {
  background: rgba(229, 62, 62, 0.05);
}

:deep(.finding-cell-stack) {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 180px;
  max-width: 480px;
  padding: 2px 0;
}

:deep(.finding-cell-title) {
  font-size: 13px;
  font-weight: 600;
  color: var(--text-color-1, #1a1a1a);
  line-height: 1.45;
  word-break: break-word;
  white-space: normal;
}

:deep(.finding-cell-sub) {
  font-size: 12px;
  color: var(--text-color-3, #666);
  line-height: 1.5;
  word-break: break-word;
  white-space: normal;
  display: -webkit-box;
  -webkit-box-orient: vertical;
  overflow: hidden;
  opacity: 0.85;
}

:deep(.finding-cell-muted) {
  color: var(--text-color-4, #ccc);
}

:deep(.finding-host-cell) {
  font-weight: 600;
  font-size: 12px;
  font-family: 'SF Mono', Consolas, Monaco, monospace;
  word-break: break-all;
  color: var(--text-color-1, #1a1a1a);
}

/* Confidence badge */
.conf-badge {
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  cursor: help;
  padding: 2px 0;
}

.conf-badge__bar {
  width: 48px;
  height: 4px;
  background: #f0f0f0;
  border-radius: 2px;
  overflow: hidden;
}

.conf-badge__fill {
  height: 100%;
  background: var(--conf-color, #52c41a);
  border-radius: 2px;
  transition: width 0.4s ease;
}

.conf-badge__text {
  font-size: 11px;
  font-weight: 600;
  color: var(--conf-color, #52c41a);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}

.conf-tooltip__header {
  font-size: 13px;
  margin-bottom: 4px;
}

.conf-tooltip__reason {
  font-size: 12px;
  line-height: 1.5;
  opacity: 0.9;
  white-space: pre-wrap;
}

/* Verification chips */
.verif-chip {
  display: inline-flex;
  align-items: center;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 500;
  cursor: default;
  transition: background 0.15s;
}

.verif-chip--exploit {
  background: #fff1f0;
  color: #cf1322;
}

.verif-chip--exploit:hover {
  background: #ffccc7;
}

.verif-chip--principle {
  background: #fff7e6;
  color: #ad6800;
}

.verif-chip--principle:hover {
  background: #ffe58f;
}

.verif-stack {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 3px;
}

.verif-confirmed {
  display: inline-flex;
  align-items: center;
  font-size: 10px;
  font-weight: 600;
  color: #389e0d;
  padding: 0 4px;
}

.verif-unconfirmed {
  display: inline-flex;
  align-items: center;
  font-size: 10px;
  color: #8c8c8c;
  padding: 0 4px;
}

/* Data Flow Visualization */
.data-flow-card {
  margin-bottom: 16px;
  padding: 16px 20px;
  background: #fff;
  border: 1px solid #f0f0f0;
  border-radius: 8px;
}

.data-flow-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
}

.data-flow-title {
  font-size: 14px;
  font-weight: 600;
  color: #1a1a2e;
}

.data-flow-subtitle {
  font-size: 12px;
  color: #8c8c8c;
  margin-left: 4px;
}

.data-flow-pipeline {
  display: flex;
  align-items: center;
  gap: 0;
  min-height: 80px;
}

.flow-node {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 12px 16px;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  min-width: 90px;
  transition: box-shadow 0.2s;
}

.flow-node:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
}

.flow-node--input {
  background: linear-gradient(135deg, #ebf8ff 0%, #bee3f8 100%);
  border-color: #90cdf4;
}

.flow-node--output {
  background: linear-gradient(135deg, #fff5f5 0%, #fed7d7 100%);
  border-color: #feb2b2;
}

.flow-node__icon {
  margin-bottom: 6px;
}

.flow-node__label {
  font-size: 11px;
  color: #718096;
  margin-bottom: 2px;
}

.flow-node__count {
  font-size: 22px;
  font-weight: 800;
  font-variant-numeric: tabular-nums;
  color: #1a202c;
  line-height: 1.1;
}

.flow-connector {
  flex-shrink: 0;
  padding: 0 2px;
  display: flex;
  align-items: center;
}

.flow-arrow-svg {
  display: block;
}

.flow-modules {
  flex: 1;
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 8px 12px;
  background: #fafbfc;
  border: 1px solid #edf2f7;
  border-radius: 8px;
  min-width: 200px;
  max-width: 600px;
}

.flow-module-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 3px 0;
}

.flow-module-name {
  font-size: 12px;
  color: #4a5568;
  min-width: 80px;
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 500;
}

.flow-module-bar-track {
  flex: 1;
  height: 6px;
  background: #edf2f7;
  border-radius: 3px;
  overflow: hidden;
}

.flow-module-bar-fill {
  height: 100%;
  background: linear-gradient(90deg, #4299e1, #667eea);
  border-radius: 3px;
  transition: width 0.6s ease;
  min-width: 2px;
}

.flow-module-count {
  font-size: 12px;
  font-weight: 600;
  color: #2d3748;
  min-width: 28px;
  text-align: right;
  font-variant-numeric: tabular-nums;
}

.flow-severity-dots {
  display: flex;
  gap: 4px;
  margin-top: 6px;
}

.flow-sev-dot {
  font-size: 10px;
  font-weight: 700;
  padding: 1px 5px;
  border-radius: 4px;
  font-variant-numeric: tabular-nums;
}

.flow-sev-dot--critical { background: #fff5f5; color: #c53030; }
.flow-sev-dot--high { background: #fffaf0; color: #c05621; }
.flow-sev-dot--medium { background: #fffff0; color: #975a16; }
.flow-sev-dot--low { background: #f0fff4; color: #276749; }

/* Type Grouped View */
.grouped-view-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.grouped-view-header__title {
  font-size: 15px;
  font-weight: 600;
  color: #1a1a1a;
}
.grouped-view-header__count {
  font-size: 12px;
  color: #999;
  margin-left: 10px;
}
.type-group-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
  gap: 10px;
}
.type-group-card {
  display: flex;
  align-items: stretch;
  border: 1px solid #eef2f6;
  border-radius: 8px;
  overflow: hidden;
  cursor: pointer;
  transition: all 0.15s;
  background: #fff;
}
.type-group-card:hover {
  border-color: #1890ff;
  box-shadow: 0 2px 8px rgba(24, 144, 255, 0.12);
  transform: translateY(-1px);
}
.type-group-card__color {
  width: 4px;
  flex-shrink: 0;
}
.type-group-card__body {
  flex: 1;
  padding: 12px 14px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.type-group-card__label {
  font-size: 12px;
  font-weight: 500;
  color: #333;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.type-group-card__count {
  font-size: 16px;
  font-weight: 700;
  color: #1a1a1a;
  flex-shrink: 0;
}

/* Port Card View */
.port-card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.port-card-header__title {
  font-size: 15px;
  font-weight: 600;
  color: #1a1a1a;
}
.port-card-header__count {
  font-size: 12px;
  color: #999;
  margin-left: 10px;
}
.port-card-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(400px, 1fr));
  gap: 14px;
}
.port-host-card {
  border: 1px solid #eef2f6;
  border-radius: 10px;
  overflow: hidden;
  background: #fff;
  transition: box-shadow 0.2s;
}
.port-host-card:hover {
  box-shadow: 0 2px 12px rgba(0, 0, 0, 0.06);
}
.port-host-card__header {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 12px 16px;
  background: linear-gradient(135deg, #f0f5ff 0%, #f8fafc 100%);
  border-bottom: 1px solid #f0f0f0;
}
.port-host-card__icon {
  width: 32px;
  height: 32px;
  border-radius: 6px;
  background: #1890ff;
  color: #fff;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 13px;
  flex-shrink: 0;
}
.port-host-card__info {
  flex: 1;
  min-width: 0;
}
.port-host-card__name {
  font-size: 14px;
  font-weight: 600;
  color: #1a1a1a;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.port-host-card__meta {
  font-size: 11px;
  color: #999;
  margin-top: 2px;
}
.port-host-card__ports {
  padding: 12px 16px;
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.port-item {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 10px;
  border-radius: 5px;
  font-size: 12px;
  background: #f5f7fa;
  border: 1px solid #e8ecf1;
  transition: background 0.1s;
}
.port-item:hover {
  background: #e6f7ff;
  border-color: #91d5ff;
}
.port-item__num {
  font-weight: 700;
  color: #1890ff;
}
.port-item__num--sensitive {
  color: #cf1322;
}
.port-item__proto {
  font-size: 10px;
  color: #999;
  font-weight: 500;
}
.port-item__svc {
  font-weight: 500;
  color: #333;
}
.port-item__ver {
  color: #52c41a;
  font-size: 11px;
}
.port-item__guess {
  color: #bbb;
  font-size: 11px;
  font-style: italic;
}
.port-host-card__banners {
  padding: 0 16px 12px;
  border-top: 1px solid #f5f5f5;
  margin-top: 4px;
  padding-top: 10px;
}
.port-banner-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  font-size: 11px;
  line-height: 1.5;
  margin-bottom: 4px;
}
.port-banner-item__port {
  flex-shrink: 0;
  font-weight: 600;
  color: #666;
  min-width: 36px;
}
.port-banner-item__text {
  color: #888;
  font-family: 'SF Mono', Consolas, monospace;
  word-break: break-all;
}

/* ===== New Findings Content Layout ===== */
.fc-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 16px;
}
.fc-toolbar__left {
  display: flex;
  align-items: baseline;
  gap: 10px;
}
.fc-toolbar__title {
  font-size: 15px;
  font-weight: 600;
  color: #1a1a1a;
}
.fc-toolbar__meta {
  font-size: 12px;
  color: #999;
}

/* Asset Grid */
.fc-asset-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 14px;
}
.fc-asset-card {
  border: 1px solid #eef0f4;
  border-radius: 10px;
  padding: 16px;
  cursor: pointer;
  transition: box-shadow 0.2s, border-color 0.2s;
  background: #fff;
}
.fc-asset-card:hover {
  border-color: #bae0ff;
  box-shadow: 0 2px 8px rgba(24, 144, 255, 0.08);
}
.fc-asset-card__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 6px;
}
.fc-asset-card__ip {
  font-size: 14px;
  font-weight: 600;
  color: #1a1a1a;
  font-family: 'SF Mono', Consolas, monospace;
}
.fc-asset-card__os {
  font-size: 11px;
  color: #8c8c8c;
  background: #f5f5f5;
  padding: 1px 6px;
  border-radius: 4px;
}
.fc-asset-card__title {
  font-size: 12px;
  color: #666;
  margin-bottom: 10px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fc-asset-card__ports {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
  margin-bottom: 10px;
}
.fc-port-badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 500;
  font-family: 'SF Mono', Consolas, monospace;
  padding: 2px 7px;
  border-radius: 4px;
  background: #f0f5ff;
  color: #2f54eb;
}
.fc-port-badge--risk {
  background: #fff1f0;
  color: #cf1322;
  font-weight: 600;
}
.fc-port-badge--more {
  background: #f5f5f5;
  color: #8c8c8c;
}
.fc-asset-card__foot {
  display: flex;
  flex-wrap: wrap;
  gap: 5px;
}
.fc-asset-tag {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 3px;
  background: #f6ffed;
  color: #389e0d;
}
.fc-asset-tag--waf {
  background: #fff7e6;
  color: #d46b08;
}
.fc-asset-tag--vuln {
  background: #fff1f0;
  color: #cf1322;
  font-weight: 600;
}

/* Split Layout (All tab) */
.fc-split {
  display: flex;
  gap: 16px;
  min-height: 500px;
}
.fc-type-panel {
  width: 220px;
  min-width: 180px;
  flex-shrink: 0;
  border: 1px solid #f0f0f0;
  border-radius: 8px;
  background: #fafbfc;
  overflow-y: auto;
  max-height: 720px;
}
.fc-type-panel__head {
  padding: 12px 14px;
  font-size: 13px;
  font-weight: 600;
  color: #333;
  border-bottom: 1px solid #f0f0f0;
  position: sticky;
  top: 0;
  background: #fafbfc;
  z-index: 1;
}
.fc-type-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 14px;
  font-size: 12px;
  cursor: pointer;
  border-bottom: 1px solid #f8f8f8;
  transition: background 0.15s;
  color: #555;
}
.fc-type-item:hover {
  background: #f0f7ff;
}
.fc-type-item--active {
  background: #e6f7ff;
  color: #1890ff;
  font-weight: 600;
}
.fc-type-item__dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.fc-type-item__label {
  flex: 1;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fc-type-item__count {
  font-size: 11px;
  font-weight: 600;
  color: #999;
  flex-shrink: 0;
  padding: 1px 6px;
  border-radius: 10px;
  background: #f0f0f0;
}
.fc-type-item--active .fc-type-item__count {
  background: rgba(24, 144, 255, 0.12);
  color: #1890ff;
}
.fc-main {
  flex: 1;
  min-width: 0;
}

/* Severity Bar */
.fc-sev-bar {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.fc-sev-chip {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: 14px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid #eee;
  background: #fff;
  transition: all 0.2s;
  color: #555;
}
.fc-sev-chip:hover {
  border-color: var(--c);
}
.fc-sev-chip--active {
  border-color: var(--c);
  background: color-mix(in srgb, var(--c) 8%, white);
  color: var(--c);
  font-weight: 600;
}
.fc-sev-chip__dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: var(--c);
}
.fc-sev-chip__num {
  font-weight: 600;
  opacity: 0.8;
}

/* Filter Bar */
.fc-filter-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  padding: 8px 12px;
  background: #fafafa;
  border-radius: 8px;
}
.fc-filter-bar__total {
  margin-left: auto;
  font-size: 12px;
  color: #999;
}
.fc-filter-bar__total b {
  color: #333;
}

/* Pagination */
.fc-pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}

/* Host Grid (All Tab) */
.fc-host-view {
  /* wrapper for host grid */
}
.fc-host-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
}
.fc-host-card {
  border: 1px solid #eef0f4;
  border-radius: 10px;
  padding: 14px 16px;
  cursor: pointer;
  transition: box-shadow 0.2s, border-color 0.2s, transform 0.15s;
  background: #fff;
}
.fc-host-card:hover {
  border-color: #91caff;
  box-shadow: 0 2px 8px rgba(24, 144, 255, 0.1);
  transform: translateY(-1px);
}
.fc-host-card__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 4px;
}
.fc-host-card__ip {
  font-size: 14px;
  font-weight: 600;
  color: #1a1a1a;
  font-family: 'SF Mono', Consolas, monospace;
}
.fc-host-card__os {
  font-size: 10px;
  color: #8c8c8c;
  background: #f5f5f5;
  padding: 1px 6px;
  border-radius: 3px;
}
.fc-host-card__title {
  font-size: 11px;
  color: #8c8c8c;
  margin-bottom: 8px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fc-host-card__stats {
  display: flex;
  gap: 12px;
  margin-bottom: 8px;
}
.fc-host-stat {
  display: flex;
  align-items: baseline;
  gap: 3px;
}
.fc-host-stat__num {
  font-size: 16px;
  font-weight: 700;
  color: #1890ff;
}
.fc-host-stat--vuln .fc-host-stat__num {
  color: #cf1322;
}
.fc-host-stat__label {
  font-size: 11px;
  color: #999;
}
.fc-host-card__ports {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.fc-port-mini {
  font-size: 10px;
  font-family: 'SF Mono', Consolas, monospace;
  padding: 1px 5px;
  border-radius: 3px;
  background: #f0f5ff;
  color: #2f54eb;
}
.fc-port-mini--risk {
  background: #fff1f0;
  color: #cf1322;
}
.fc-port-mini--more {
  background: #f5f5f5;
  color: #8c8c8c;
}

/* Host Detail View */
.fc-host-detail__header {
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid #f0f0f0;
}
.fc-host-detail__info {
  display: flex;
  align-items: center;
  gap: 10px;
}
.fc-host-detail__ip {
  font-size: 16px;
  font-weight: 700;
  color: #1a1a1a;
  font-family: 'SF Mono', Consolas, monospace;
}
.fc-host-detail__os {
  font-size: 11px;
  color: #8c8c8c;
  background: #f5f5f5;
  padding: 2px 8px;
  border-radius: 4px;
}
.fc-host-detail__title {
  font-size: 12px;
  color: #666;
}
.fc-host-detail__stats {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 14px;
}
.fc-stat-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 4px 10px;
  border-radius: 12px;
  font-size: 12px;
  background: #f0f5ff;
  color: #2f54eb;
}
.fc-stat-pill b {
  font-weight: 700;
}
.fc-stat-pill--critical {
  background: #fff1f0;
  color: #cf1322;
}
.fc-stat-pill--high {
  background: #fff7e6;
  color: #d46b08;
}
.fc-stat-pill--medium {
  background: #fffbe6;
  color: #d4b106;
}
.fc-stat-pill--low {
  background: #f6ffed;
  color: #389e0d;
}
.fc-stat-pill--info {
  background: #f0f5ff;
  color: #1890ff;
}
</style>
