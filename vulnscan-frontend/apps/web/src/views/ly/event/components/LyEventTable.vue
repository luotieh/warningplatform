<script lang="ts" setup>
import { computed, h, onMounted, reactive, ref } from 'vue';

import { NButton, NDataTable, NModal, NSpace, NTag } from 'naive-ui';

import { IconifyIcon } from '@vben/icons';
import { useUserStore } from '@vben/stores';

import { lyEventPushToAi, lyEventReview } from '#/api/ly';
import { deepflowEventArchiveUrl, deepflowEventEvidenceUrl, deepflowGetOccurrences } from '#/api/ly/deepflow';
import { message } from '#/adapter/naive';
import { formatBoolText, formatBytes, formatDirection, formatHexTruncated, formatTimestamp } from '#/utils/ly';
import { eventVictimAssets } from '#/utils/ly-asset';

import ReportModal from '../detail/components/ReportModal.vue';
import EvidenceDialog from '../detail/components/EvidenceDialog.vue';

defineOptions({ name: 'LyEventTable' });

const props = withDefaults(
  defineProps<{
    rows: Record<string, any>[];
    showDesc?: boolean;
    autoAnalyze?: boolean;
    loading?: boolean;
    /** 是否展示「资产」列（行内 assetText：资产名或「未登记」）。 */
    showAsset?: boolean;
    /** 资产清单：明细弹窗的「被攻击资产」按目标侧匹配展示。 */
    assets?: Record<string, any>[];
  }>(),
  { showDesc: false, autoAnalyze: false, loading: false, showAsset: false, assets: () => [] },
);

const userStore = useUserStore();

const reportVisible = ref(false);
const reportEventId = ref('');
const reportContext = ref<Record<string, any>>({});

const state = reactive({
  analyzingIds: new Set<string>(),
});

// 事件列表分页由父页面统一负责服务端分页；此组件只展示当前页数据。
const pagedRows = computed(() => props.rows);

const occVisible = ref(false);
const occLoading = ref(false);
const occCursor = ref('');
const occTotal = ref(0);
const occQuality = ref('');
const occDeclared = ref<number | undefined>();
const occSnapshot = ref(0);
const evidenceVisible = ref(false);
const evidenceHitId = ref('');
let occRequest = 0;
const occRows = ref<Array<{
  idx: number; hit_id: string; time: string; size: string; packets: string;
  message_direction: string; dns_role: string; dns_query: string;
  payload_text: string; payload_hex: string;
  payload_hex_truncated: boolean; packet_sequence: any; captured_length: any;
  wire_length: any; capture_truncated: any; capture_time: string;
  session_start_time: string; request: any; response: any;
}>>([]);

const expandedOccIndices = ref<Set<number>>(new Set());
const expandedHex = ref<Set<string>>(new Set());
const currentEventContext = ref<Record<string, any>>({});

// 明细弹窗「威胁情报」卡片的被攻击资产：目标侧命中启用资产则显示
// 「名称（地址）」，否则回退受害地址；未传资产清单时不做「未登记」断言。
const victimAssetText = computed(() => {
  const ev = currentEventContext.value;
  const victim = String(ev?.victimDevice || '');
  if (!victim) return '';
  const matched = eventVictimAssets(ev, props.assets || []);
  if (matched.length > 0) return matched.join('、');
  return (props.assets || []).length > 0 ? `未登记（${victim}）` : victim;
});

function toggleOccExpand(idx: number) {
  const next = new Set(expandedOccIndices.value);
  if (next.has(idx)) {
    next.delete(idx);
  } else {
    next.add(idx);
  }
  expandedOccIndices.value = next;
}

function toggleHex(key: string) {
  const next = new Set(expandedHex.value);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  expandedHex.value = next;
}

function buildOccRows(occ: any[], offset = 0) {
  return (occ || []).map((o, i) => {
    const item = typeof o === 'string' ? { time: o } : (o ?? {});
    return {
      idx: offset + i + 1,
      hit_id: item.hit_id || '',
      time: formatTimestamp(item.time) || '-',
      size: item.wire_bytes == null ? '-' : formatBytes(item.wire_bytes),
      packets: item.packets == null ? '-' : String(item.packets),
      message_direction: item.message_direction || '',
      dns_role: item.dns_role || '',
      dns_query: item.dns_query || '',
      payload_text: item.payload_text || '',
      payload_hex: item.payload_hex || '',
      payload_hex_truncated: Boolean(item.payload_hex_truncated),
      packet_sequence: item.packet_sequence,
      captured_length: item.captured_length,
      wire_length: item.wire_length,
      capture_truncated: item.capture_truncated,
      capture_time: item.capture_time || '',
      session_start_time: item.session_start_time || '',
      request: item.request || null,
      response: item.response || null,
    };
  });
}

async function openOccurrences(row: Record<string, any>) {
  occRows.value = [];
  occCursor.value = '';
  occTotal.value = 0;
  occQuality.value = '';
  occDeclared.value = undefined;
  occSnapshot.value = 0;
  evidenceVisible.value = false;
  expandedHex.value = new Set();
  currentEventContext.value = row;
  expandedOccIndices.value = new Set();
  occVisible.value = true;
  await loadOccurrencePage(true);
}

async function loadOccurrencePage(reset = false) {
  if (occLoading.value && !reset) return;
  const request = ++occRequest;
  occLoading.value = true;
  try {
    const page = await deepflowGetOccurrences(String(currentEventContext.value.event_id || currentEventContext.value.id), occCursor.value);
    if (request !== occRequest) return;
    occRows.value.push(...buildOccRows(page.items, occRows.value.length));
    occCursor.value = page.next_cursor || '';
    occTotal.value = page.total;
    occQuality.value = page.statistics_quality;
    occDeclared.value = page.declared_count;
    occSnapshot.value = page.snapshot_version;
  } catch (error) {
    if (request === occRequest) message.error(error instanceof Error ? error.message : '明细加载失败');
  } finally {
    if (request === occRequest) occLoading.value = false;
  }
}

function buildAnalysisPayload(row: Record<string, any>) {
  return {
    detail_type: String(row.type || '').toUpperCase(),
    duration: row.durationText || '',
    event_level: row.levelText || '',
    event_type: String(row.type || ''),
    event_type_name: row.type === 'mo' ? '追踪事件' : row.typeText || '',
    id: `#${row.id}`,
    is_active: row.aliveText || '',
    method: row.show_model || '',
    occurrence_time: row.startTimeText || '',
    hit_frequency: row.hitFrequencyText || '单次',
    hit_count: Number(row.eventCount || 1),
    first_time: row.firstTimeText || '',
    last_time: row.lastTimeText || '',
    is_final: Boolean(row.isFinal),
    aggregation_status: row.isFinal ? 'closed' : 'active',
    analysis_only: true,
    event_id: String(row.event_id || row.deepsoc_event_id || row.id),
    rule_desc: row.desc || '',
    // 研判按 event_id 定位历史事件，源目地址仅作为分析信息。
    threat_source: row.src_ip || row.attackDevice || '',
    victim_target: row.dst_ip || row.victimDevice || '',
  };
}

async function ensureAnalysis(row: Record<string, any>) {
  const rowId = String(row.id);
  if (!rowId || state.analyzingIds.has(rowId)) {
    return String(row.event_id || row.deepsoc_event_id || row.id || '');
  }
  if (row.analysisStatus === 'completed' && (row.event_id || row.deepsoc_event_id)) {
    return String(row.event_id || row.deepsoc_event_id);
  }
  state.analyzingIds.add(rowId);
  state.analyzingIds = new Set(state.analyzingIds);
  try {
    const res = await lyEventPushToAi(buildAnalysisPayload(row));
    const data = res?.data && typeof res.data === 'object' ? res.data : res;
    const deepflowEventId = String(data?.deepsoc_event_id || data?.event_id || row.event_id || row.id || '');
    row.event_id = deepflowEventId;
    row.deepsoc_event_id = deepflowEventId;
    // 推送接口是异步受理（立即返回、LLM 分析在后台跑数十秒到几分钟），
    // 此处只能如实标“分析中”；“已生成”由后端 event_status=round_finished 流转而来，
    // 否则会出现“列表已生成、报告里只有创建事件”的假状态。
    row.analysisStatus = 'processing';
    row.analysisStatusText = '分析中';
    return deepflowEventId;
  } catch (error) {
    row.analysisStatus = 'failed';
    row.analysisStatusText = '分析失败';
    throw error;
  } finally {
    state.analyzingIds.delete(rowId);
    state.analyzingIds = new Set(state.analyzingIds);
  }
}

async function analyzeHistorySequentially() {
  for (const row of props.rows || []) {
    if (row.analysisStatus === 'completed' || row.analysisStatus === 'processing') continue;
    try {
      await ensureAnalysis(row);
    } catch {
      // 保留行级状态，继续处理后续历史事件。
    }
  }
}

async function openAiDetail(row: Record<string, any>) {
  const payload = { ...buildAnalysisPayload(row) };
  const eventId = String(row.id);
  let deepflowEventId = '';
  try {
    deepflowEventId = await ensureAnalysis(row);
  } catch (error) {
    message.error(error instanceof Error ? error.message : '报告尚未生成，请检查服务和LLM配置');
    return;
  }
  reportEventId.value = deepflowEventId || eventId;
  reportContext.value = { ...payload };
  reportVisible.value = true;
}

function reviewStatusMeta(row: Record<string, any>): { text: string; type: string } {
  const map: Record<string, { text: string; type: string }> = {
    approved: { text: '已通过', type: 'success' },
    rejected: { text: '已驳回', type: 'error' },
    pending_review: { text: '待审核', type: 'warning' },
  };
  if (row.review_status && map[row.review_status]) return map[row.review_status]!;
  if (row.analysisStatus === 'completed') return map.pending_review!;
  return { text: '—', type: 'default' };
}

async function reviewEvent(row: Record<string, any>, action: 'approve' | 'reject') {
  const eventId = String(row.event_id || row.deepsoc_event_id || row.id || '');
  if (!eventId) {
    message.error('事件尚未生成分析，无法审核');
    return;
  }
  if (row.analysisStatus !== 'completed') {
    message.error('仅 AI 分析完成的事件可审核');
    return;
  }
  try {
    const res = await lyEventReview({ eventId, action, reviewedBy: userStore.userInfo?.realName || userStore.userInfo?.username || '' });
    row.review_status = res?.review_status || (action === 'approve' ? 'approved' : 'rejected');
    if (res?.circular_code) row.circular_code = res.circular_code;
    message.success(action === 'approve' ? `已推送通报处置${res?.circular_code ? '：' + res.circular_code : ''}` : '已驳回');
  } catch (error) {
    message.error(error instanceof Error ? error.message : '审核失败');
  }
}

function severityMeta(levelText?: string): { color: string; key: string } {
  switch (levelText) {
    case '极高': return { color: '#d03050', key: 'critical' };
    case '高': return { color: '#f0a020', key: 'high' };
    case '中': return { color: '#2080f0', key: 'medium' };
    default: return { color: '#909399', key: 'low' };
  }
}

// level_raw（心跳提升前的原始等级）的中文映射，用于提升标识的悬停提示。
function levelRawText(levelRaw?: string): string {
  switch (levelRaw) {
    case 'critical': return '极高';
    case 'high': return '高';
    case 'middle': return '中';
    case 'low': return '低';
    default: return levelRaw || '-';
  }
}

const TYPE_ICONS: Record<string, string> = {
  scan: 'lucide:radar', port_scan: 'lucide:radar', ip_scan: 'lucide:radar', mo: 'lucide:radar',
  dns: 'lucide:globe', dns_tun: 'lucide:globe',
  frn_trip: 'lucide:arrow-up-right',
  mining: 'lucide:pickaxe',
  black: 'lucide:ban', ti: 'lucide:crosshair', dga: 'lucide:shuffle',
  icmp_tun: 'lucide:waves', cap: 'lucide:package-search',
  sus: 'lucide:triangle-alert', srv: 'lucide:server',
};
function typeIcon(type?: string): string {
  return TYPE_ICONS[String(type ?? '')] ?? 'lucide:shield-alert';
}

function rowClass(row: Record<string, any>): string {
  return `sev-${severityMeta(row.levelText).key}`;
}

const columns = computed(() => [
  {
    title: '事件类型',
    key: 'typeText',
    minWidth: 150,
    render: (row: Record<string, any>) =>
      h('div', { style: 'display:flex;align-items:center;gap:6px' }, [
        h(IconifyIcon, { icon: typeIcon(row.type), style: 'font-size:16px;color:#909399;flex:none' }),
        h('span', row.typeText || '-'),
      ]),
  },
  ...(props.showDesc
    ? [{ title: '描述', key: 'desc', minWidth: 200, ellipsis: { tooltip: true } }]
    : []),
  {
    title: '来源 → 目标',
    key: 'flow',
    minWidth: 260,
    render: (row: Record<string, any>) =>
      h('div', { style: 'display:flex;align-items:center;gap:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;flex-wrap:wrap' }, [
        h('span', { style: 'color:#d03050' }, row.attackDevice || '-'),
        h(IconifyIcon, { icon: 'lucide:move-right', style: 'font-size:15px;color:#909399;flex:none' }),
        h('span', { style: 'color:#2080f0' }, row.victimDevice || '-'),
        row.heartbeat_detected ? h(NTag, { type: 'warning', size: 'small' }, { default: () => `心跳 ${row.heartbeat_period_sec || ''}s` }) : null,
        // 聚合事件含多个查询域名时提示，悬停列出采样到的域名，避免单域名误导。
        row.dns_domain_count > 1
          ? h(NTag, { size: 'small', round: true, type: 'info', bordered: false, title: (row.dns_queries || []).join('\n') }, { default: () => `等${row.dns_domain_count}个域名` })
          : null,
        // 列表直接展示命中的 IOC（如 DNS 应答中的 127.0.0.1），此前只在详情弹窗可见。
        row.ioc?.ioc_value
          ? h(NTag, { size: 'small', round: true, type: 'error', bordered: false, title: `${row.ioc.ioc_type || 'IOC'} 命中` }, { default: () => `IOC ${row.ioc.ioc_value}` })
          : null,
      ]),
  },
  ...(props.showAsset
    ? [
        {
          title: '资产',
          key: 'assetText',
          minWidth: 150,
          render: (row: Record<string, any>) => {
            const text = String(row.assetText || '');
            const unregistered = !text || text === '未登记';
            return h(
              NTag,
              { size: 'small', round: true, type: unregistered ? 'default' : 'info' },
              { default: () => text || '未登记' },
            );
          },
        },
      ]
    : []),
  {
    title: '严重程度',
    key: 'levelText',
    width: 110,
    render: (row: Record<string, any>) => {
      const m = severityMeta(row.levelText);
      return h('div', { style: 'display:flex;align-items:center;gap:6px' }, [
        h('span', { class: 'ly-dot', style: `background:${m.color}` }),
        h('span', row.levelText || '-'),
        // 心跳信标命中时后端已将展示等级提升一档，用 ▲ 标识并悬停说明原始等级。
        row.heartbeat_level_boost
          ? h('span', {
              title: `检测到心跳信标（约 ${row.heartbeat_period_sec || '?'}s 周期小包通信），严重程度由「${levelRawText(row.level_raw)}」提升一档`,
              style: 'color:#d03050;font-size:12px;line-height:1;cursor:help',
            }, '▲')
          : null,
      ]);
    },
  },
  {
    title: '命中频次',
    key: 'hitFrequencyText',
    width: 240,
    render: (row: Record<string, any>) => {
      const high = row.hitFrequencyLevel === 'error' || row.hitFrequencyLevel === 'warning';
      const children: any[] = [
        h(NTag, { size: 'small', round: true, type: row.hitFrequencyLevel || 'default' }, {
          default: () =>
            high
              ? h('span', { style: 'display:inline-flex;align-items:center;gap:2px' }, [
                  h(IconifyIcon, { icon: 'lucide:zap' }),
                  row.hitFrequencyText || '单次',
                ])
              : (row.hitFrequencyText || '单次'),
        }),
      ];
      if (row.aggregationStatusText) {
        children.push(
          h(NTag, { size: 'small', round: true, type: row.isFinal ? 'success' : 'info', style: 'margin-left:4px' }, { default: () => row.aggregationStatusText }),
        );
      }
      if (row.aggregation_version === 2 || (Array.isArray(row.occurrences) && row.occurrences.length > 0)) {
        children.push(
          h(NButton, { text: true, size: 'small', type: 'primary', style: 'margin-left:8px', onClick: () => openOccurrences(row) }, { default: () => '明细' }),
        );
      }
      if (row.statistics_quality && row.statistics_quality !== 'verified') {
        children.push(h(NTag, { size: 'small', type: 'warning' }, { default: () => row.statistics_quality === 'rebuilding' ? '统计更新中' : '历史统计未核验' }));
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;align-items:center;gap:4px' }, children);
    },
  },
  {
    title: '总载荷',
    key: 'totalPayloadText',
    width: 110,
    render: (row: Record<string, any>) => {
      if (row.volume_quality === 'unverified') return h('span', { title: '流累计观测值不能直接相加；实际载荷总量未核验' }, '未核验');
      const bytes = Number(row.total_payload_bytes ?? 0);
      return h(
        'span',
        { style: bytes > 0 ? 'font-family:ui-monospace,SFMono-Regular,Menlo,monospace' : '' },
        bytes > 0 ? formatBytes(bytes) : '-',
      );
    },
  },
  {
    title: '分析状态',
    key: 'analysisStatusText',
    width: 130,
    render: (row: Record<string, any>) => {
      const analyzing = state.analyzingIds.has(String(row.id));
      const status = analyzing ? 'processing' : row.analysisStatus;
      const type = status === 'completed' ? 'success' : status === 'failed' || status === 'llm_config_required' ? 'error' : status === 'processing' ? 'warning' : 'default';
      const text = analyzing ? '分析中' : row.analysisStatusText || '待分析';
      return h(NTag, { size: 'small', round: true, bordered: true, type }, { default: () => text });
    },
  },
  {
    title: '审核状态',
    key: 'review_status',
    width: 150,
    render: (row: Record<string, any>) => {
      const meta = reviewStatusMeta(row);
      const tags = [h(NTag, { size: 'small', round: true, bordered: true, type: meta.type as any }, { default: () => meta.text })];
      if (row.circular_code) {
        tags.push(h(NTag, { size: 'small', round: true, type: 'info', style: 'margin-left:4px' }, { default: () => row.circular_code }));
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;gap:4px' }, tags);
    },
  },
  {
    title: '事件时间（北京时间）',
    key: 'startTimeText',
    minWidth: 255,
    render: (row: Record<string, any>) => h('div', { style: 'line-height:1.7' }, [
      h('div', `发生：${row.firstTimeText || row.startTimeText || '-'}`),
      h('div', row.isFinal
        ? `收敛：${row.convergedTimeText || row.lastTimeText || '-'}`
        : `最近活动：${row.lastTimeText || '-'}`),
      h('div', { style: 'font-size:12px;color:#64748b' },
        `${row.isFinal ? '攻击持续' : '进行中'}：${row.durationText || '-'}`),
    ]),
  },
  {
    title: '操作',
    key: 'actions',
    width: 220,
    render: (row: Record<string, any>) => {
      const canReview = row.analysisStatus === 'completed';
      const reviewed = row.review_status === 'approved';
      return h(NSpace, { size: 4 }, {
        default: () => [
          h(NButton, { text: true, type: 'success', loading: state.analyzingIds.has(String(row.id)), onClick: () => openAiDetail(row) }, { default: () => '查看报告' }),
          h(NButton, { text: true, type: 'primary', disabled: !canReview || reviewed, onClick: () => reviewEvent(row, 'approve') }, { default: () => '审核通过' }),
          h(NButton, { text: true, type: 'error', disabled: !canReview || reviewed, onClick: () => reviewEvent(row, 'reject') }, { default: () => '驳回' }),
        ],
      });
    },
  },
]);

onMounted(() => {
  if (props.autoAnalyze) void analyzeHistorySequentially();
});
</script>

<template>
  <div>
    <EvidenceDialog v-model:visible="evidenceVisible" :event-id="String(currentEventContext.event_id || currentEventContext.id || '')" :hit-id="evidenceHitId" :version="occSnapshot" />
    <NDataTable :columns="columns" :data="pagedRows" :loading="props.loading" :bordered="false" size="small" :row-class-name="rowClass" />

    <ReportModal v-model:visible="reportVisible" :event-id="reportEventId" :context="reportContext" />

    <NModal v-model:show="occVisible" preset="card" title="命中明细" style="width: 880px; max-width: 95vw">
      <NSpace style="margin-bottom:12px" align="center">
        <span>已加载 {{ occRows.length }} / {{ occTotal }} 条明细</span>
        <NTag v-if="occQuality && occQuality !== 'verified'" type="warning">原记录 {{ occDeclared ?? '未知' }} 次；历史统计未核验</NTag>
        <NButton v-if="occCursor" :loading="occLoading" :disabled="occLoading" @click="loadOccurrencePage()">加载下一页</NButton>
        <span v-if="occLoading">正在加载明细…</span>
      </NSpace>
      <div class="occ-container">
        <div v-if="currentEventContext.session_summary" class="occ-card">
          <div class="occ-card-title">双向会话统计</div>
          <div class="occ-card-grid">
            <div class="occ-field">
              <span class="occ-label">会话时间</span>
              <span class="occ-value">{{ formatTimestamp(currentEventContext.session_summary.first_time_usec) }} ~ {{ formatTimestamp(currentEventContext.session_summary.last_time_usec) }}</span>
            </div>
            <div class="occ-field">
              <span class="occ-label">客户端 → 服务端</span>
              <span class="occ-value">{{ currentEventContext.session_summary.client_packets ?? '-' }} 包 / {{ formatBytes(currentEventContext.session_summary.client_wire_bytes) }}</span>
            </div>
            <div class="occ-field">
              <span class="occ-label">服务端 → 客户端</span>
              <span class="occ-value">{{ currentEventContext.session_summary.server_packets ?? '-' }} 包 / {{ formatBytes(currentEventContext.session_summary.server_wire_bytes) }}</span>
            </div>
            <div class="occ-field">
              <span class="occ-label">会话命中次数</span>
              <span class="occ-value">{{ currentEventContext.session_summary.hit_count ?? '-' }}</span>
            </div>
          </div>
        </div>

        <div v-if="currentEventContext.ioc" class="occ-card">
          <div class="occ-card-title">威胁情报</div>
          <div class="occ-card-grid">
            <div v-if="victimAssetText" class="occ-field occ-field-full">
              <span class="occ-label">被攻击资产</span>
              <span class="occ-value">{{ victimAssetText }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_type" class="occ-field">
              <span class="occ-label">IOC 类型</span>
              <span class="occ-value">{{ currentEventContext.ioc.ioc_type }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_value" class="occ-field">
              <span class="occ-label">IOC 值</span>
              <span class="occ-value" style="font-family:monospace">{{ currentEventContext.ioc.ioc_value }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_category" class="occ-field">
              <span class="occ-label">类别</span>
              <span class="occ-value">{{ currentEventContext.ioc.ioc_category }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_source" class="occ-field">
              <span class="occ-label">情报源</span>
              <span class="occ-value">{{ currentEventContext.ioc.ioc_source }}</span>
            </div>
            <div v-if="currentEventContext.ioc_evidence?.confidence" class="occ-field">
              <span class="occ-label">置信度</span>
              <span class="occ-value">{{ currentEventContext.ioc_evidence.confidence }}</span>
            </div>
            <div v-if="currentEventContext.ioc_evidence?.tlp" class="occ-field">
              <span class="occ-label">TLP</span>
              <span class="occ-value">{{ currentEventContext.ioc_evidence.tlp }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_expire_at" class="occ-field">
              <span class="occ-label">过期时间</span>
              <span class="occ-value">{{ formatTimestamp(currentEventContext.ioc.ioc_expire_at) }}</span>
            </div>
            <div v-if="currentEventContext.ioc_evidence?.activity" class="occ-field occ-field-full">
              <span class="occ-label">关联活动</span>
              <span class="occ-value">{{ currentEventContext.ioc_evidence.activity }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_description" class="occ-field occ-field-full">
              <span class="occ-label">描述</span>
              <span class="occ-value">{{ currentEventContext.ioc.ioc_description }}</span>
            </div>
            <div v-if="currentEventContext.ioc.ioc_tags" class="occ-field occ-field-full">
              <span class="occ-label">标签</span>
              <span class="occ-value">
                <NTag v-for="tag in (Array.isArray(currentEventContext.ioc.ioc_tags) ? currentEventContext.ioc.ioc_tags : [currentEventContext.ioc.ioc_tags])" :key="tag" size="tiny" round style="margin-right:4px;margin-bottom:2px">{{ tag }}</NTag>
              </span>
            </div>
            <div v-if="currentEventContext.ioc_evidence?.threat_labels" class="occ-field occ-field-full">
              <span class="occ-label">威胁标签</span>
              <span class="occ-value">
                <NTag v-for="tl in (Array.isArray(currentEventContext.ioc_evidence.threat_labels) ? currentEventContext.ioc_evidence.threat_labels : [currentEventContext.ioc_evidence.threat_labels])" :key="tl" size="tiny" type="error" round style="margin-right:4px;margin-bottom:2px">{{ tl }}</NTag>
              </span>
            </div>
          </div>
        </div>

        <div
          v-if="Array.isArray(currentEventContext.evidence_files) && currentEventContext.evidence_files.length"
          class="occ-card"
        >
          <div class="occ-card-title">
            证据附件
            <a
              class="evidence-archive-link"
              :href="deepflowEventArchiveUrl(String(currentEventContext.event_id || currentEventContext.id))"
              target="_blank"
              rel="noopener"
            >
              下载全部 PCAP(ZIP)
            </a>
            <span v-if="currentEventContext.evidence_truncated" class="evidence-truncated-hint">
              附件已达上限
            </span>
          </div>
          <div class="occ-list">
            <div
              v-for="(ef, idx) in currentEventContext.evidence_files"
              :key="idx"
              class="occ-item evidence-item"
            >
              <a
                class="evidence-link"
                :href="deepflowEventEvidenceUrl(String(currentEventContext.event_id || currentEventContext.id), idx)"
                target="_blank"
                rel="noopener"
              >
                {{ ef.name || `证据${idx + 1}` }}
              </a>
              <NTag v-if="ef.type" size="tiny" round type="info">{{ ef.type }}</NTag>
              <span v-if="ef.size" class="evidence-size">{{ formatBytes(ef.size) }}</span>
              <span v-if="ef.description" class="evidence-desc">{{ ef.description }}</span>
            </div>
          </div>
        </div>

        <div class="occ-section-title">命中记录</div>
        <div class="occ-list">
          <div v-for="occ in occRows" :key="occ.idx" class="occ-item">
            <div class="occ-row" @click="toggleOccExpand(occ.idx)">
              <IconifyIcon
                :icon="expandedOccIndices.has(occ.idx) ? 'lucide:chevron-down' : 'lucide:chevron-right'"
                class="occ-chevron"
              />
              <span class="occ-num">#{{ occ.idx }}</span>
              <span class="occ-time">{{ occ.time }}</span>
              <span class="occ-size">{{ occ.size }}</span>
              <span class="occ-pkts">{{ occ.packets }} 包</span>
              <NTag v-if="occ.message_direction" size="tiny" round :type="occ.message_direction === 'request' ? 'info' : 'warning'">
                {{ formatDirection(occ.message_direction) }}
              </NTag>
              <NTag v-if="occ.dns_role" size="tiny" round type="success" :bordered="false">
                DNS·{{ occ.dns_role === 'query' ? '查询' : '应答' }}
              </NTag>
            </div>
            <div v-if="expandedOccIndices.has(occ.idx)" class="occ-detail">
              <div v-if="occ.hit_id" class="occ-detail-row">
                <span class="occ-detail-label">明细 ID</span>
                <span style="overflow-wrap:anywhere">{{ occ.hit_id }}</span>
                <NButton text type="primary" size="small" @click="evidenceHitId = occ.hit_id; evidenceVisible = true">完整明细</NButton>
              </div>
              <div class="occ-detail-row">
                <span class="occ-detail-label">报文方向</span>
                <span class="occ-detail-value">{{ formatDirection(occ.message_direction) }}</span>
              </div>
              <div v-if="occ.dns_query" class="occ-detail-row">
                <span class="occ-detail-label">查询域名</span>
                <span class="occ-detail-value">{{ occ.dns_query }}</span>
              </div>
              <div v-if="occ.capture_time" class="occ-detail-row">
                <span class="occ-detail-label">捕获时间</span>
                <span class="occ-detail-value">{{ formatTimestamp(occ.capture_time) }}</span>
              </div>
              <div v-if="occ.session_start_time" class="occ-detail-row">
                <span class="occ-detail-label">流首包时间</span>
                <span class="occ-detail-value">{{ formatTimestamp(occ.session_start_time) }}</span>
              </div>
              <div class="occ-detail-row">
                <span class="occ-detail-label">包序号</span>
                <span class="occ-detail-value">{{ occ.packet_sequence ?? '-' }}</span>
              </div>
              <div class="occ-detail-row">
                <span class="occ-detail-label">捕获/线缆长度</span>
                <span class="occ-detail-value">{{ occ.captured_length ?? '-' }} / {{ occ.wire_length ?? '-' }} bytes</span>
              </div>
              <div v-if="occ.capture_truncated" class="occ-detail-row">
                <span class="occ-detail-label">截断标记</span>
                <NTag size="tiny" type="error" round>已截断</NTag>
              </div>
              <div v-if="occ.payload_text" class="occ-detail-row">
                <span class="occ-detail-label">载荷明文</span>
                <code class="occ-code-block">{{ occ.payload_text }}</code>
              </div>
              <div v-if="occ.payload_hex" class="occ-detail-row">
                <span class="occ-detail-label">载荷 HEX</span>
                <div class="occ-hex-wrap">
                  <code class="occ-hex-text">{{ expandedHex.has('payload-' + occ.idx) ? occ.payload_hex : formatHexTruncated(occ.payload_hex).text }}</code>
                  <NButton v-if="occ.payload_hex_truncated || occ.payload_hex.length > 128" text size="tiny" type="primary" @click.stop="toggleHex('payload-' + occ.idx)">
                    {{ expandedHex.has('payload-' + occ.idx) ? '收起' : '展开完整报文' }}
                  </NButton>
                </div>
              </div>
              <template v-if="occ.request">
                <div class="occ-detail-divider">TCP Request 详情</div>
                <div class="occ-detail-row">
                  <span class="occ-detail-label">SEQ</span>
                  <span class="occ-detail-value">{{ occ.request.tcp_seq ?? '-' }}</span>
                </div>
                <div class="occ-detail-row">
                  <span class="occ-detail-label">ACK</span>
                  <span class="occ-detail-value">{{ occ.request.tcp_ack ?? '-' }}</span>
                </div>
                <div class="occ-detail-row">
                  <span class="occ-detail-label">重传</span>
                  <span class="occ-detail-value">{{ formatBoolText(occ.request.retransmission) }}</span>
                </div>
              </template>
              <template v-if="occ.response">
                <div class="occ-detail-divider">TCP Response 详情</div>
                <div class="occ-detail-row">
                  <span class="occ-detail-label">SEQ</span>
                  <span class="occ-detail-value">{{ occ.response.tcp_seq ?? '-' }}</span>
                </div>
                <div class="occ-detail-row">
                  <span class="occ-detail-label">ACK</span>
                  <span class="occ-detail-value">{{ occ.response.tcp_ack ?? '-' }}</span>
                </div>
                <div class="occ-detail-row">
                  <span class="occ-detail-label">重传</span>
                  <span class="occ-detail-value">{{ formatBoolText(occ.response.retransmission) }}</span>
                </div>
              </template>
            </div>
          </div>
        </div>
      </div>
    </NModal>
  </div>
</template>

<style scoped>
.pager-wrap { display: flex; justify-content: flex-end; margin-top: 12px; }
.ly-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; flex: none; }
:deep(.n-data-table-tr.sev-critical .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #d03050; }
:deep(.n-data-table-tr.sev-high .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #f0a020; }
:deep(.n-data-table-tr.sev-medium .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #2080f0; }
:deep(.n-data-table-tr.sev-low .n-data-table-td:first-child) { box-shadow: inset 3px 0 0 #909399; }
:deep(.n-data-table-td) { padding-top: 10px; padding-bottom: 10px; }
:deep(.n-data-table-th) { font-weight: 600; }

/* 命中明细弹窗 */
.occ-container { max-height: 75vh; overflow-y: auto; }
.occ-card {
  background: var(--n-color);
  border: 1px solid var(--n-border-color);
  border-radius: 12px;
  padding: 18px 20px;
  margin-bottom: 14px;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.04);
  transition: box-shadow 0.2s;
}
.occ-card:hover {
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
}
.occ-card-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--n-text-color);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding-left: 10px;
  border-left: 3px solid #2080f0;
}
.occ-card-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 0; border: 1px solid var(--n-border-color); border-radius: 8px; overflow: hidden; }
.occ-field {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 10px 14px;
  border-bottom: 1px solid var(--n-border-color);
  font-size: 13px;
  transition: background 0.15s;
  min-width: 0;
}
.occ-field:hover { background: rgba(0, 0, 0, 0.02); }
.occ-field:nth-child(odd) { border-right: 1px solid var(--n-border-color); }
.occ-field-full { grid-column: 1 / -1; border-right: none !important; }
.occ-label { font-size: 11px; color: var(--n-text-color-3); font-weight: 500; text-transform: uppercase; letter-spacing: 0.3px; }
.occ-value { color: var(--n-text-color); word-break: break-all; }
.occ-section-title { font-size: 14px; font-weight: 600; margin: 16px 0 10px; color: var(--n-text-color); }
.occ-list { display: flex; flex-direction: column; gap: 2px; }
.occ-item { border: 1px solid var(--n-border-color); border-radius: 6px; overflow: hidden; }
.evidence-item { display: flex; align-items: center; gap: 8px; padding: 8px 10px; flex-wrap: wrap; }
.evidence-link { color: #2080f0; font-weight: 500; text-decoration: none; }
.evidence-archive-link { margin-left: auto; font-size: 12px; color: #2080f0; font-weight: 500; text-decoration: none; }
.evidence-truncated-hint { font-size: 12px; color: #e6a23c; font-weight: 400; }
.evidence-size { color: #909399; font-size: 12px; }
.evidence-desc { color: #64748b; font-size: 12px; }
.occ-row { display: flex; align-items: center; gap: 8px; padding: 8px 12px; cursor: pointer; user-select: none; transition: background .15s; }
.occ-row:hover { background: var(--n-color-target); }
.occ-chevron { font-size: 14px; color: var(--n-text-color-3); flex: none; transition: transform .15s; }
.occ-num { font-size: 12px; color: var(--n-text-color-3); font-family: monospace; min-width: 24px; }
.occ-time { font-size: 13px; color: var(--n-text-color); flex: 1; min-width: 0; }
.occ-size { font-size: 12px; color: var(--n-text-color-2); white-space: nowrap; }
.occ-pkts { font-size: 12px; color: var(--n-text-color-2); white-space: nowrap; }
.occ-detail { padding: 0 12px 12px 40px; display: flex; flex-direction: column; gap: 4px; }
.occ-detail-row { display: flex; gap: 8px; font-size: 12px; align-items: flex-start; }
.occ-detail-label { color: var(--n-text-color-3); min-width: 100px; flex: none; padding-top: 2px; }
.occ-detail-value { color: var(--n-text-color); word-break: break-all; }
.occ-detail-divider { font-size: 11px; color: var(--n-text-color-3); border-top: 1px dashed var(--n-border-color); padding-top: 6px; margin-top: 2px; font-weight: 600; }
.occ-code-block { display: block; background: var(--n-color-embedded-modal); padding: 6px 10px; border-radius: 4px; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }
.occ-hex-wrap { display: flex; flex-direction: column; gap: 4px; flex: 1; min-width: 0; }
.occ-hex-text { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 11px; word-break: break-all; white-space: pre-wrap; background: var(--n-color-embedded-modal); padding: 6px 10px; border-radius: 4px; max-height: 150px; overflow-y: auto; line-height: 1.5; }
</style>
