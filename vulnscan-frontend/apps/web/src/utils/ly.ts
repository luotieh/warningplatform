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

// Offset-free business times are Beijing times; explicit offsets remain absolute.
export function eventTimestampMs(value?: number | string | null): number {
  if (value === '' || value === null || value === undefined) return Number.NaN;
  const num = Number(value);
  if (Number.isFinite(num)) {
    return Math.abs(num) >= 1e14 ? num / 1000 : Math.abs(num) >= 1e11 ? num : num * 1000;
  }
  let text = String(value).trim();
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) text += 'T00:00:00+08:00';
  else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(text)) {
    text = text.replace(' ', 'T') + '+08:00';
  }
  return Date.parse(text);
}

const beijingFormatter = new Intl.DateTimeFormat('en-GB', {
  timeZone: 'Asia/Shanghai', hourCycle: 'h23',
  year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit',
});

export function formatTimestamp(value?: number | string | null, withTime = true) {
  if (value === '' || value === null || value === undefined) return '-';
  const ms = eventTimestampMs(value);
  if (!Number.isFinite(ms)) return String(value);
  const p: Record<string, string> = {};
  beijingFormatter.formatToParts(new Date(ms)).forEach(({ type, value }) => { p[type] = value; });
  const date = `${p.year}-${p.month}-${p.day}`;
  return withTime ? `${date} ${p.hour}:${p.minute}:${p.second}` : date;
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
  const a = eventTimestampMs(first);
  const b = eventTimestampMs(last);
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
  if (item.aggregation_version === 2 && item.event_count == null) {
    hitFreq.text = '统计更新中';
    hitFreq.level = 'default';
  }
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
    durationText: Number(item.duration) === 0 ? '0秒' : formatDuration(item.duration),
    convergedTimeText: formatTimestamp(item.converged_at),
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
    // 收敛状态：已收敛(最终频次确定) / 进行中(可能继续)。单次与多次命中使用相同生命周期。
    isFinal: Boolean(item.is_final),
    aggregationStatusText:
      item.is_final ? '已收敛' : '进行中',
  };
}

export function normalizeLyEvents(list: Record<string, any>[] = []) {
  return list.map(normalizeLyEvent);
}

// matchesEventKeyword 关键字/IP 过滤：空格分词后按 AND 匹配。
// 匹配字段：威胁来源/受害目标/描述/类型/event_id/IOC值/IOC类型/证据文件名。
export function matchesEventKeyword(item: Record<string, any>, keyword: string): boolean {
  const tokens = String(keyword ?? '')
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
  if (!tokens.length) return true;

  const haystack = [
    String(item.attackDevice ?? ''),
    String(item.victimDevice ?? ''),
    String(item.desc ?? ''),
    String(item.rule_desc ?? ''),
    String(item.type ?? ''),
    String(item.typeText ?? ''),
    String(item.event_id ?? ''),
    String(item.ioc?.ioc_value ?? ''),
    String(item.ioc?.ioc_type ?? ''),
    ...(Array.isArray(item.evidence_files)
      ? item.evidence_files.map((ef: any) => String(ef?.name ?? ''))
      : []),
  ]
    .join(' ')
    .toLowerCase();

  return tokens.every((token) => haystack.includes(token));
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

export function formatHexTruncated(hex: string | null | undefined, limit = 128) {
  if (!hex) return { text: '-', truncated: false };
  if (hex.length <= limit) return { text: hex, truncated: false };
  return { text: hex.slice(0, limit), truncated: true };
}

export function formatDirection(dir: string | null | undefined): string {
  const map: Record<string, string> = {
    request: '请求 (→)',
    response: '响应 (←)',
    unknown: '未知',
  };
  return map[dir ?? ''] || String(dir || '-');
}

export function formatBoolText(v: any): string {
  if (v === true || v === 'true') return '是';
  if (v === false || v === 'false' || v === undefined || v === null) return '否';
  return String(v);
}

export function formatVolumeRole(role: string | null | undefined): { text: string; color: string } {
  const map: Record<string, { text: string; color: string }> = {
    to_ioc: { text: '流向IOC（外传）', color: '#d03050' },
    from_ioc: { text: '来自IOC（下载）', color: '#f0a020' },
    client_only: { text: '仅客户端有数据', color: '#2080f0' },
    server_only: { text: '仅服务端有数据', color: '#18a058' },
    upload_to_ioc: { text: '数据外泄', color: '#d03050' },
    download_from_ioc: { text: '载荷投递', color: '#d03050' },
    bidirectional: { text: '双向等量', color: '#909399' },
  };
  return map[role ?? ''] || { text: String(role || '-'), color: '#909399' };
}
