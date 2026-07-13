export interface NormalizedLyEvent extends Record<string, any> {
  id: number | string;
  objText: string;
  typeText: string;
  levelText: string;
  procStatusText: string;
  aliveText: string;
  startTimeText: string;
  durationText: string;
  analysisStatus: string;
  analysisStatusText: string;
  eventCount: number;
  firstTimeText: string;
  lastTimeText: string;
  hitFrequencyText: string;
  hitFrequencyLevel: 'default' | 'error' | 'warning';
  hitSpanText: string;
  isFinal: boolean;
  aggregationStatusText: string;
}

const EVENT_TYPE_MAP: Record<string, string> = {
  black: '黑名单',
  sus: '风险通讯',
  scan: '扫描',
  port_scan: '端口扫描',
  ip_scan: 'IP扫描',
  dns: 'DNS',
  dns_tun: 'DNS隧道',
  frn_trip: '服务器外连',
  mining: '挖矿',
  icmp_tun: 'ICMP隧道',
  mo: '追踪',
  ti: '情报',
  cap: '包检测',
  dga: 'DGA',
  srv: '异常服务',
};

const EVENT_LEVEL_MAP: Record<string, string> = {
  '1': '低',
  '2': '中',
  '3': '高',
  '4': '极高',
  extra_low: '极低',
  low: '低',
  middle: '中',
  high: '高',
  critical: '极高',
};

const PROC_STATUS_MAP: Record<string, string> = {
  unprocessed: '未处理',
  processed: '已处理',
  assigned: '已确认',
};

const ANALYSIS_STATUS_MAP: Record<string, string> = {
  completed: '已生成',
  failed: '分析失败',
  llm_config_required: '需配置LLM',
  pending: '待分析',
  processing: '分析中',
};

/**
 * 剥离推理模型（DeepSeek-R1/QwQ 等）写进正文的思维链。
 * 三种形态：成对 <think>…</think>；只有开头 <think>…（被截断）；
 * 只有结尾 …</think>（<think> 在服务端 prompt 模板里，补全直接以推理开始）。
 * 后端新回复已在落库前剥离；此函数用于净化历史消息的展示与报告导出。
 */
export function stripThinkBlocks(text?: string): string {
  return String(text ?? '')
    .replaceAll(/<think>[\s\S]*?<\/think>/gi, '')
    .replace(/<think>[\s\S]*$/i, '')
    .replace(/^[\s\S]*?<\/think>/i, '')
    .trim();
}

export function formatTimestamp(value?: number | string | null, withTime = true) {
  if (value === '' || value === null || value === undefined) return '-';
  const num = Number(value);
  const date = Number.isFinite(num)
    ? new Date(String(value).length <= 10 ? num * 1000 : num)
    : new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const pad = (n: number) => String(n).padStart(2, '0');
  const text = `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
  if (!withTime) return text;
  return `${text} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

export function formatDuration(value?: number | string | null) {
  const num = Number(value ?? 0);
  if (!Number.isFinite(num) || num <= 0) return '-';
  if (num < 60) return `${num}s`;
  if (num < 3600) return `${Math.floor(num / 60)}m ${num % 60}s`;
  const h = Math.floor(num / 3600);
  const m = Math.floor((num % 3600) / 60);
  return `${h}h ${m}m`;
}

export function formatBytes(value?: number | string | null): string {
  const n = Number(value);
  if (!Number.isFinite(n) || n <= 0) return '-';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

export function translateEventType(value?: string) {
  return EVENT_TYPE_MAP[value || ''] || value || '-';
}

export function translateEventLevel(value?: number | string) {
  return EVENT_LEVEL_MAP[String(value ?? '')] || String(value ?? '-');
}

export function translateProcStatus(value?: string) {
  return PROC_STATUS_MAP[value || ''] || value || '-';
}

export function translateAnalysisStatus(value?: string) {
  return ANALYSIS_STATUS_MAP[value || ''] || value || '待分析';
}

function hitSpanSeconds(first?: string, last?: string) {
  const a = Date.parse(String(first ?? ''));
  const b = Date.parse(String(last ?? ''));
  if (!Number.isFinite(a) || !Number.isFinite(b)) return 0;
  return Math.max(0, Math.round((b - a) / 1000));
}

function humanizeSpan(sec: number) {
  if (sec <= 0) return '瞬时';
  if (sec < 60) return `${sec}秒`;
  if (sec < 3600) return `${Math.round(sec / 60)}分钟`;
  if (sec < 86_400) return `${(sec / 3600).toFixed(1)}小时`;
  return `${(sec / 86_400).toFixed(1)}天`;
}

/**
 * 命中频次指标：描述「该事件是否在某段时间内多次命中」。
 * 单次 → 仅一次；多次时给出「高频/多发 N次/时间跨度」，并按突发强度着色。
 */
export function describeHitFrequency(count: number, spanSec: number) {
  if (count <= 1) {
    return { text: '单次', level: 'default' as const };
  }
  const burst = count >= 3 && spanSec <= 600; // ≥3 次且 10 分钟内 → 突发高频
  return {
    text: `${burst ? '高频' : '多发'} ${count}次/${humanizeSpan(spanSec)}`,
    level: (burst ? 'error' : 'warning') as 'error' | 'warning',
  };
}

export function normalizeLyEvent(item: Record<string, any>): NormalizedLyEvent {
  const hitCount = Math.max(1, Number(item.event_count ?? 1) || 1);
  const hitSpan = hitSpanSeconds(item.first_time, item.last_time);
  const hitFreq = describeHitFrequency(hitCount, hitSpan);
  const objText = String(item.obj || '').split(' ')[0] || '-';
  const attackDevice = item.attackDevice || objText.split('>')[0] || '-';
  const victimDevice = item.victimDevice || objText.split('>')[1] || '-';
  const alive = item.is_alive;
  const aliveText =
    alive === true || alive === 'true' || alive === 1 || alive === '1'
      ? '活跃'
      : alive === false || alive === 'false' || alive === 0 || alive === '0'
        ? '不活跃'
        : '-';

  return {
    ...item,
    id: item.id ?? item.event_id ?? item.obj ?? '-',
    attackDevice,
    victimDevice,
    objText,
    typeText: item.typeText || translateEventType(item.type),
    levelText: translateEventLevel(item.level),
    procStatusText: translateProcStatus(item.proc_status),
    analysisStatus: item.analysis_status || item.analysisStatus || 'pending',
    analysisStatusText: translateAnalysisStatus(item.analysis_status || item.analysisStatus),
    aliveText,
    startTimeText: formatTimestamp(item.starttime || item.time || item.created_at),
    durationText: formatDuration(item.duration),
    // 聚合：发生次数与首/末次时间（同来源+目标+类型、仅时间不同的事件已合并）
    eventCount: hitCount,
    firstTimeText: formatTimestamp(
      item.first_time || item.starttime || item.time || item.created_at,
    ),
    lastTimeText: formatTimestamp(
      item.last_time || item.starttime || item.time || item.created_at,
    ),
    // 命中频次指标（替代原“处理状态”，描述是否在某段时间内多次命中）
    hitFrequencyText: hitFreq.text,
    hitFrequencyLevel: hitFreq.level,
    hitSpanText: humanizeSpan(hitSpan),
    // 收敛状态：已收敛(最终频次确定) / 进行中(可能继续)。单次事件不展示。
    isFinal: Boolean(item.is_final),
    aggregationStatusText:
      hitCount > 1 ? (item.is_final ? '已收敛' : '进行中') : '',
  };
}

export function normalizeLyEvents(list: Record<string, any>[] = []) {
  return list.map(normalizeLyEvent);
}

export function countByKey<T extends Record<string, any>>(list: T[], key: keyof T | string) {
  const map = new Map<string, number>();
  list.forEach((item) => {
    const value = String(item[key as keyof T] ?? '').trim();
    if (!value) return;
    map.set(value, (map.get(value) || 0) + 1);
  });
  return Array.from(map.entries())
    .map(([name, value]) => ({ name, value }))
    .sort((a, b) => b.value - a.value);
}

export function paginate<T>(list: T[], page: number, pageSize: number) {
  const start = (page - 1) * pageSize;
  return list.slice(start, start + pageSize);
}
