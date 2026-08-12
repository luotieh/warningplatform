import type { MonitorExecution } from '#/api/sitemonitor';
import type { IncidentAsset, IncidentMetadata, SecurityIncident } from '#/api/incident';

export type OverviewHighlight = 'default' | 'error' | 'info' | 'success' | 'warning';

export interface OverviewStatItem {
  label: string;
  value: string;
  highlight?: OverviewHighlight;
  mono?: boolean;
}

const sourceLabels: Record<number, string> = {
  1: '站点监测',
  2: '漏洞扫描',
  3: '流量分析',
  4: '风险探测',
};

const levelLabels: Record<number, string> = {
  1: '低危',
  2: '中危',
  3: '高危',
  4: '紧急',
};

const statusLabels: Record<number, string> = {
  1: '待人工复核',
  2: '复核通过',
  3: '复核失败',
  4: '待整改',
  5: '整改中',
  6: '待验证',
  7: '已关闭',
};

const dimensionLabels: Record<string, string> = {
  availability: '可用性监测',
  blacklink: '暗链监测',
  domain_hijack: '域名劫持监测',
  sensitive_file: '敏感文件监测',
  sensitive_word: '敏感词监测',
  tamper: '篡改监测',
};

function push(
  items: OverviewStatItem[],
  label: string,
  value?: string | number | null,
  opts?: Partial<OverviewStatItem>,
) {
  if (value === undefined || value === null) return;
  const s = String(value).trim();
  if (!s || s === '-') return;
  items.push({ label, value: s, ...opts });
}

function monitorDimensionStats(
  dimension: string,
  r: Record<string, any>,
): OverviewStatItem[] {
  const items: OverviewStatItem[] = [];
  switch (dimension) {
    case 'tamper':
      push(items, '篡改判定', r.tampered ? '检测到篡改' : '未篡改', {
        highlight: r.tampered ? 'error' : 'success',
      });
      push(items, '变更项', (r.diffs?.length || 0) > 0 ? `${r.diffs.length} 处` : '', {
        highlight: (r.diffs?.length || 0) > 0 ? 'warning' : undefined,
      });
      push(items, '严重程度', r.severity, { highlight: 'warning' });
      push(items, '页面标题', r.title);
      push(items, 'HTTP', r.status_code);
      break;
    case 'availability':
      push(items, '可用性', r.available === false ? '不可用' : '可用', {
        highlight: r.available === false ? 'error' : 'success',
      });
      push(items, 'HTTP', r.status_code);
      push(
        items,
        '响应耗时',
        r.timing?.total_ms != null
          ? `${r.timing.total_ms}ms`
          : r.response_time_ms != null
            ? `${r.response_time_ms}ms`
            : '',
      );
      if (r.errors?.length) {
        push(items, '错误', `${r.errors.length} 条`, { highlight: 'error' });
      }
      break;
    case 'sensitive_word': {
      const n = r.matches?.length || r.total_matches || 0;
      push(items, '敏感词命中', `${n} 处`, { highlight: n ? 'error' : 'default' });
      const top = (r.matches || [])
        .slice(0, 2)
        .map((m: any) => m.keyword || m.word)
        .filter(Boolean);
      if (top.length) push(items, '示例词条', top.join('、'));
      break;
    }
    case 'blacklink': {
      const bl = r.blacklink_matches?.length || 0;
      const bd = r.backdoor_findings?.length || 0;
      push(items, '暗链', `${bl} 个`, { highlight: bl ? 'error' : 'default' });
      push(items, '后门特征', `${bd} 个`, { highlight: bd ? 'error' : 'default' });
      break;
    }
    case 'sensitive_file': {
      const files = r.files || r.matches || [];
      push(items, '敏感文件', `${files.length} 个`, {
        highlight: files.length ? 'error' : 'default',
      });
      break;
    }
    case 'domain_hijack':
      push(items, '域名劫持', r.hijacked ? '是' : '否', {
        highlight: r.hijacked ? 'error' : 'success',
      });
      push(items, '解析 IP', r.resolved_ip, { mono: true });
      push(items, '预期 IP', r.expected_ip, { mono: true });
      break;
    default:
      break;
  }
  return items;
}

export function buildIncidentOverviewStats(
  incident: SecurityIncident,
  options?: {
    monitorExecution?: MonitorExecution | null;
    monitorResult?: Record<string, any> | null;
    formatTime?: (t?: string) => string;
  },
): {
  primary: OverviewStatItem[];
  monitor: OverviewStatItem[];
  asset: OverviewStatItem[];
  vuln: OverviewStatItem[];
  targetUrl?: string;
} {
  const fmt = options?.formatTime || ((t?: string) => t || '');
  const meta = incident.event_metadata as IncidentMetadata | undefined;
  const asset = incident.asset_detail as IncidentAsset | undefined;

  const primary: OverviewStatItem[] = [];
  push(primary, '事件编号', incident.incident_no, { mono: true });
  push(primary, '当前状态', statusLabels[incident.status] || String(incident.status), {
    highlight:
      incident.status === 7
        ? 'success'
        : incident.status === 3
          ? 'error'
          : 'warning',
  });
  push(primary, '事件等级', levelLabels[incident.level] || String(incident.level), {
    highlight:
      incident.level >= 4 ? 'error' : incident.level >= 3 ? 'warning' : 'info',
  });
  push(primary, '发现途径', sourceLabels[incident.source] || String(incident.source));
  push(primary, '事件类型', meta?.incident_type);
  push(primary, '发现时间', fmt(meta?.discovery_time));
  push(primary, '上报时间', fmt(incident.report_time));
  push(primary, '创建时间', fmt(incident.created_at));

  let monitor: OverviewStatItem[] = [];
  let targetUrl = meta?.incident_url || '';
  const ex = options?.monitorExecution;
  const r = options?.monitorResult;
  if (ex && r) {
    targetUrl = ex.url || targetUrl;
    push(monitor, '监测维度', dimensionLabels[ex.dimension] || ex.dimension);
    push(
      monitor,
      '执行状态',
      ex.status === 'success' ? '成功' : ex.status === 'failed' ? '失败' : ex.status,
      {
        highlight:
          ex.status === 'success'
            ? 'success'
            : ex.status === 'failed'
              ? 'error'
              : 'warning',
      },
    );
    push(monitor, '安全问题', ex.has_issue ? '已发现' : '未发现', {
      highlight: ex.has_issue ? 'error' : 'success',
    });
    if (ex.started_at && ex.finished_at) {
      const ms =
        new Date(ex.finished_at).getTime() - new Date(ex.started_at).getTime();
      if (ms >= 0) push(monitor, '检测耗时', `${(ms / 1000).toFixed(1)}s`);
    }
    push(monitor, 'Agent', ex.agent_id, { mono: true });
    monitor = [...monitor, ...monitorDimensionStats(ex.dimension, r)];
  }

  const assetItems: OverviewStatItem[] = [];
  if (asset) {
    push(assetItems, '资产名称', asset.asset_name);
    push(assetItems, '系统名称', asset.system_name);
    push(assetItems, '地址', asset.domain_ip, { mono: true });
    push(assetItems, 'IP', asset.site_ip, { mono: true });
    push(assetItems, '所属单位', asset.unit);
    push(assetItems, '单位类型', asset.unit_type);
    push(assetItems, '行业', asset.industry);
    push(assetItems, '归属地', asset.region);
    push(assetItems, '等保等级', asset.mlps_level);
    push(assetItems, '等保备案号', asset.mlps_record_no, { mono: true });
    push(assetItems, '工信部备案', asset.miit_record_no, { mono: true });
  }

  const vuln: OverviewStatItem[] = [];
  if (meta) {
    push(vuln, 'CVE', meta.cve_id, { mono: true, highlight: 'error' });
    if (meta.cvss_score && meta.cvss_score > 0) {
      push(vuln, 'CVSS', meta.cvss_score.toFixed(1), { highlight: 'warning' });
    }
    push(vuln, 'OWASP', meta.owasp_category);
    push(vuln, '利用难度', meta.exploit_difficulty);
    push(vuln, '影响范围', meta.affect_scope);
  }

  return {
    primary,
    monitor,
    asset: assetItems,
    vuln,
    targetUrl: targetUrl || undefined,
  };
}
