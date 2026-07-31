# 命中明细弹窗扩展新字段 实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在命中明细弹窗中展示 session_summary、IOC 情报、流量统计等事件级上下文卡片，以及每条命中记录的 raw_packet 报文详情（默认收起，三角展开）

**Architecture:** 后端在 `event_mapping.go` 和 `services.go` 中将新字段透传入 context/occurrences 数组；`event_service.go` 将其投射到前端；前端 `LyEventTable.vue` 重构命中明细弹窗为卡片+可展开行

**Tech Stack:** Go 1.x (Gin), Vue 3 + TypeScript + Naive UI

## Global Constraints

- 所有 ta_node 新增字段均带 `omitempty`，缺失时前端优雅展示 `-` 或不渲染
- `payload_hex` / `packet_hex` 超过 128 字符默认截断，点击「展开」后才显示完整内容
- 每条命中记录的展开状态独立，默认全部收起
- session_summary 仅在数据非 null 时显示卡片；后端 `null` → 前端不渲染该卡片

---

## 文件预定义

| 文件 | 操作 | 职责 |
|------|------|------|
| `traffic/internal/service/event_mapping.go` | 修改 | 透传 `session_summary`、`ioc_evidence`、`recommended_action` 到 context |
| `traffic/internal/service/services.go` | 修改 | `buildOccurrence` 从 `raw_packet` 提取字段到每条命中记录 |
| `traffic/event_service.go` | 修改 | `lyCompatibleEvent` 投射 `session_summary`、`flow_stats`、`ioc` 到前端响应 |
| `apps/web/src/utils/ly.ts` | 修改 | 新增 `formatHexTruncated`、`formatDirection` 格式化函数 |
| `apps/web/src/views/ly/event/components/LyEventTable.vue` | 修改 | 重构命中明细弹窗，增加卡片和可展开行 |

---

### Task 1: 后端 — event_mapping.go 透传新字段

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/event_mapping.go`

**Interfaces:**
- Produces: `context["session_summary"]`, `context["ioc_evidence"]`, `context["recommended_action"]` 在 LyEventToDeepSOC 中写入

- [ ] **Step 1: 在 event_mapping.go 中增加 session_summary 透传**

在 `LyEventToDeepSOC` 函数中，`putIfPresent(context, "schema_version", ly["schema_version"])` 之后，新增:

```go
putIfPresent(context, "session_summary", ly["session_summary"])
```

再在 IOC 段之后，local_burst 段之前，新增:

```go
if evidence, ok := ly["ioc_evidence"].(map[string]any); ok && len(evidence) > 0 {
    context["ioc_evidence"] = evidence
}
putIfPresent(context, "recommended_action", ly["recommended_action"])
```

`ioc_evidence` 是 ta_node 发出的顶层嵌套对象，需断言为 `map[string]any` 并检查非空，避免存储空 map。`recommended_action` 为字符串，`putIfPresent` 直接处理。

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

预期: 编译通过

- [ ] **Step 3: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/event_mapping.go
git commit -m "feat: 透传 session_summary/ioc_evidence/recommended_action 到 event context"
```

---

### Task 2: 后端 — buildOccurrence 扩展报文字段

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/services.go:335-348`

**Interfaces:**
- Consumes: ly["raw_packet"] 为 `map[string]any` 嵌套对象
- Produces: 每条 occurrence 新增 `message_direction`, `payload_text`, `payload_hex`, `packet_sequence`, `captured_length`, `wire_length`, `capture_truncated`, `capture_time`, `session_start_time`, `request`, `response`

- [ ] **Step 1: 添加 nestedMap 辅助函数**

在 `services.go` 的辅助函数区域（`toInt` 附近）添加:

```go
func nestedMap(m map[string]any, key string) map[string]any {
    if v, ok := m[key]; ok {
        if nm, ok := v.(map[string]any); ok {
            return nm
        }
    }
    return nil
}
```

- [ ] **Step 2: 扩展 buildOccurrence**

替换 `buildOccurrence` 函数为:

```go
func buildOccurrence(ly map[string]any) map[string]any {
    occ := map[string]any{}
    t := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
    if t != "" {
        occ["time"] = t
    }
    if v, ok := ly["wire_bytes"]; ok && v != nil {
        occ["wire_bytes"] = toInt(v)
    }
    if v, ok := ly["packets"]; ok && v != nil {
        occ["packets"] = toInt(v)
    }
    rp := nestedMap(ly, "raw_packet")
    if rp == nil {
        return occ
    }
    if v := asString(rp["message_direction"]); v != "" {
        occ["message_direction"] = v
    }
    if v := asString(rp["payload_text"]); v != "" {
        occ["payload_text"] = v
    }
    if v := asString(rp["payload_hex"]); v != "" {
        if len(v) > 1024 {
            occ["payload_hex"] = v[:1024]
            occ["payload_hex_truncated"] = true
        } else {
            occ["payload_hex"] = v
        }
    }
    if v, ok := rp["packet_sequence"]; ok && v != nil {
        occ["packet_sequence"] = toInt(v)
    }
    if v, ok := rp["captured_length"]; ok && v != nil {
        occ["captured_length"] = toInt(v)
    }
    if v, ok := rp["wire_length"]; ok && v != nil {
        occ["wire_length"] = toInt(v)
    }
    if v, ok := rp["capture_truncated"]; ok {
        occ["capture_truncated"] = v
    }
    putIfPresent(occ, "capture_time", rp["capture_time"])
    putIfPresent(occ, "session_start_time", rp["session_start_time"])
    if rm := nestedMap(rp, "request"); rm != nil {
        occ["request"] = map[string]any{
            "tcp_seq":        toInt(rm["tcp_seq"]),
            "tcp_ack":        toInt(rm["tcp_ack"]),
            "retransmission": rm["retransmission"],
        }
    }
    if rm := nestedMap(rp, "response"); rm != nil {
        occ["response"] = map[string]any{
            "tcp_seq":        toInt(rm["tcp_seq"]),
            "tcp_ack":        toInt(rm["tcp_ack"]),
            "retransmission": rm["retransmission"],
        }
    }
    return occ
}
```

- [ ] **Step 3: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

预期: 编译通过

- [ ] **Step 4: Commit**

```bash
git add vulnscan-backend/traffic/internal/service/services.go
git commit -m "feat: buildOccurrence 从 raw_packet 提取报文详细字段"
```

---

### Task 3: 后端 — event_service.go 投射新字段到前端

**Files:**
- Modify: `vulnscan-backend/traffic/event_service.go:126-189` (lyCompatibleEvent 函数)

**Interfaces:**
- Consumes: event.Context JSON 中的 `session_summary`, `flow_stats`, `ioc`, `ioc_evidence`, `recommended_action`
- Produces: 前端响应新增 `session_summary`, `flow_stats`, `ioc`, `ioc_evidence`, `recommended_action` 字段

- [ ] **Step 1: 在 lyCompatibleEvent 中投射新字段**

在 `lyCompatibleEvent` 的 return 语句中，`"occurrences": context["occurrences"]` 之后（`,review_status` 之前），新增:

```go
"session_summary":       context["session_summary"],
"flow_stats":            context["flow_stats"],
"ioc":                   context["ioc"],
"ioc_evidence":          context["ioc_evidence"],
"recommended_action":    context["recommended_action"],
```

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-backend && go build ./traffic/...
```

预期: 编译通过

- [ ] **Step 3: Commit**

```bash
git add vulnscan-backend/traffic/event_service.go
git commit -m "feat: 向前端投射 session_summary/flow_stats/ioc 等新字段"
```

---

### Task 4: 前端 — utils/ly.ts 新增格式化函数

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/utils/ly.ts`

**Interfaces:**
- Produces: `formatHexTruncated(hex: string, limit?: number): { text: string; truncated: boolean }`, `formatDirection(dir: string): string`, `formatBoolText(v: any): string`, `formatVolumeRole(role: string): { text: string; color: string }`

- [ ] **Step 1: 在 ly.ts 末尾添加格式化函数**

```typescript
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
```

- [ ] **Step 2: 验证编译**

```bash
cd vulnscan-frontend && npx tsc --noEmit -p apps/web/tsconfig.json 2>&1 | head -30
```

预期: 无新增错误

- [ ] **Step 3: Commit**

```bash
git add vulnscan-frontend/apps/web/src/utils/ly.ts
git commit -m "feat: 新增 hex/方向/volume_role 格式化辅助函数"
```

---

### Task 5: 前端 — LyEventTable.vue 重构命中明细弹窗

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue`

**Interfaces:**
- Consumes: `row.session_summary`, `row.flow_stats`, `row.ioc`, `row.ioc_evidence`, `row.recommended_action`, 以及 `occ.message_direction`, `occ.payload_text`, `occ.payload_hex`, `occ.payload_hex_truncated`, `occ.packet_sequence`, `occ.captured_length`, `occ.wire_length`, `occ.capture_truncated`, `occ.capture_time`, `occ.session_start_time`, `occ.request`, `occ.response`
- Produces: 重构后的命中明细弹窗

- [ ] **Step 1: 更新 import 语句**

在 script 头部额外引入 `IconifyIcon`（已存在）和新工具函数:

```typescript
import { formatBoolText, formatBytes, formatDirection, formatHexTruncated, formatTimestamp, formatVolumeRole, paginate } from '#/utils/ly';
```

注意: `IconifyIcon` 已在第 6 行导入，无需重复。

- [ ] **Step 2: 新增展开状态和辅助逻辑**

在 `occVisible` 和 `occRows` 之后，`buildOccRows` 之前，添加:

```typescript
const expandedOccIndices = ref<Set<number>>(new Set());

function toggleOccExpand(idx: number) {
  const next = new Set(expandedOccIndices.value);
  if (next.has(idx)) {
    next.delete(idx);
  } else {
    next.add(idx);
  }
  expandedOccIndices.value = next;
}

const currentEventContext = ref<Record<string, any>>({});

function openOccurrences(row: Record<string, any>) {
  occRows.value = buildOccRows(row.occurrences || []);
  currentEventContext.value = row;
  expandedOccIndices.value = new Set();
  occVisible.value = true;
}
```

替换原有的 `openOccurrences` 函数。

- [ ] **Step 3: 更新 buildOccRows**

替换 `buildOccRows` 以透传新字段:

```typescript
function buildOccRows(occ: any[]) {
  return (occ || []).map((o, i) => {
    const item = typeof o === 'string' ? { time: o } : (o ?? {});
    return {
      idx: i + 1,
      time: formatTimestamp(item.time) || '-',
      size: item.wire_bytes == null ? '-' : formatBytes(item.wire_bytes),
      packets: item.packets == null ? '-' : String(item.packets),
      message_direction: item.message_direction || '',
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
```

- [ ] **Step 4: 在 script 中新增 hex 展开状态**

在 script 区域末尾（`expandedOccIndices` 之后）新增:

```typescript
const expandedHex = ref<Set<string>>(new Set());

function toggleHex(key: string) {
  const next = new Set(expandedHex.value);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  expandedHex.value = next;
}
```

- [ ] **Step 5: 替换命中明细弹窗模板**

在 `<template>` 中，替换现有的 `<NModal v-model:show="occVisible" ...>` 块:

```vue
<NModal v-model:show="occVisible" preset="card" title="命中明细" style="width: 880px; max-width: 95vw">
  <div class="occ-container">
    <!-- Session Summary 卡片 -->
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

    <!-- 流量统计卡片 -->
    <div v-if="currentEventContext.flow_stats" class="occ-card">
      <div class="occ-card-title">流量统计与角色</div>
      <div class="occ-card-grid">
        <div v-if="currentEventContext.flow_stats.volume_role" class="occ-field">
          <span class="occ-label">流量角色</span>
          <span class="occ-value" :style="{ color: formatVolumeRole(currentEventContext.flow_stats.volume_role).color, fontWeight: 600 }">
            {{ formatVolumeRole(currentEventContext.flow_stats.volume_role).text }}
          </span>
        </div>
        <div v-if="currentEventContext.flow_stats.flows != null" class="occ-field">
          <span class="occ-label">流数</span>
          <span class="occ-value">{{ currentEventContext.flow_stats.flows }}</span>
        </div>
        <div v-if="currentEventContext.flow_stats.packets != null" class="occ-field">
          <span class="occ-label">包数</span>
          <span class="occ-value">{{ currentEventContext.flow_stats.packets }}</span>
        </div>
        <div v-if="currentEventContext.flow_stats.wire_bytes != null" class="occ-field">
          <span class="occ-label">在线字节</span>
          <span class="occ-value">{{ formatBytes(currentEventContext.flow_stats.wire_bytes) }}</span>
        </div>
        <div v-if="currentEventContext.flow_stats.bytes != null" class="occ-field">
          <span class="occ-label">载荷字节</span>
          <span class="occ-value">{{ formatBytes(currentEventContext.flow_stats.bytes) }}</span>
        </div>
        <div v-if="currentEventContext.flow_stats.duration_ms != null" class="occ-field">
          <span class="occ-label">持续时长</span>
          <span class="occ-value">{{ currentEventContext.flow_stats.duration_ms }} ms</span>
        </div>
      </div>
    </div>

    <!-- IOC 情报卡片 -->
    <div v-if="currentEventContext.ioc" class="occ-card">
      <div class="occ-card-title">威胁情报</div>
      <div class="occ-card-grid">
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
        <div v-if="currentEventContext.ioc.ioc_description" class="occ-field occ-field-full">
          <span class="occ-label">描述</span>
          <span class="occ-value">{{ currentEventContext.ioc.ioc_description }}</span>
        </div>
        <div v-if="currentEventContext.ioc.ioc_expire_at" class="occ-field">
          <span class="occ-label">过期时间</span>
          <span class="occ-value">{{ formatTimestamp(currentEventContext.ioc.ioc_expire_at) }}</span>
        </div>
        <div v-if="currentEventContext.ioc.ioc_tags" class="occ-field occ-field-full">
          <span class="occ-label">标签</span>
          <span class="occ-value">
            <NTag v-for="tag in (Array.isArray(currentEventContext.ioc.ioc_tags) ? currentEventContext.ioc.ioc_tags : [currentEventContext.ioc.ioc_tags])" :key="tag" size="tiny" round style="margin-right:4px;margin-bottom:2px">{{ tag }}</NTag>
          </span>
        </div>
      </div>
    </div>

    <!-- IOC 证据卡片 -->
    <div v-if="currentEventContext.ioc_evidence" class="occ-card">
      <div class="occ-card-title">情报证据</div>
      <div class="occ-card-grid">
        <div v-if="currentEventContext.ioc_evidence.confidence" class="occ-field">
          <span class="occ-label">置信度</span>
          <span class="occ-value">{{ currentEventContext.ioc_evidence.confidence }}</span>
        </div>
        <div v-if="currentEventContext.ioc_evidence.source" class="occ-field">
          <span class="occ-label">来源</span>
          <span class="occ-value">{{ currentEventContext.ioc_evidence.source }}</span>
        </div>
        <div v-if="currentEventContext.ioc_evidence.tlp" class="occ-field">
          <span class="occ-label">TLP</span>
          <span class="occ-value">{{ currentEventContext.ioc_evidence.tlp }}</span>
        </div>
        <div v-if="currentEventContext.ioc_evidence.activity" class="occ-field occ-field-full">
          <span class="occ-label">关联活动</span>
          <span class="occ-value">{{ currentEventContext.ioc_evidence.activity }}</span>
        </div>
        <div v-if="currentEventContext.ioc_evidence.threat_labels" class="occ-field occ-field-full">
          <span class="occ-label">威胁标签</span>
          <span class="occ-value">
            <NTag v-for="tl in (Array.isArray(currentEventContext.ioc_evidence.threat_labels) ? currentEventContext.ioc_evidence.threat_labels : [currentEventContext.ioc_evidence.threat_labels])" :key="tl" size="tiny" type="error" round style="margin-right:4px;margin-bottom:2px">{{ tl }}</NTag>
          </span>
        </div>
      </div>
    </div>

    <!-- recommended_action 卡片 -->
    <div v-if="currentEventContext.recommended_action" class="occ-card">
      <div class="occ-card-title">处置建议</div>
      <div class="occ-card-grid">
        <div class="occ-field occ-field-full">
          <span class="occ-value" style="font-weight:600;color:#d03050">{{ currentEventContext.recommended_action }}</span>
        </div>
      </div>
    </div>

    <!-- 命中列表 -->
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
        </div>
        <div v-if="expandedOccIndices.has(occ.idx)" class="occ-detail">
          <div class="occ-detail-row">
            <span class="occ-detail-label">报文方向</span>
            <span class="occ-detail-value">{{ formatDirection(occ.message_direction) }}</span>
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
          <!-- 载荷 HEX（可展开） -->
          <div v-if="occ.payload_hex" class="occ-detail-row">
            <span class="occ-detail-label">载荷 HEX</span>
            <div class="occ-hex-wrap">
              <code class="occ-hex-text">{{ expandedHex.has('payload-' + occ.idx) ? occ.payload_hex : formatHexTruncated(occ.payload_hex).text }}</code>
              <NButton v-if="occ.payload_hex_truncated || occ.payload_hex.length > 128" text size="tiny" type="primary" @click.stop="toggleHex('payload-' + occ.idx)">
                {{ expandedHex.has('payload-' + occ.idx) ? '收起' : '展开完整报文' }}
              </NButton>
            </div>
          </div>
          <!-- TCP 详情 (request) -->
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
          <!-- TCP 详情 (response) -->
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
```

- [ ] **Step 6: 添加 CSS 样式**

在 `<style scoped>` 末尾追加命中明细弹窗样式:

```css
/* 命中明细弹窗 */
.occ-container { max-height: 75vh; overflow-y: auto; }
.occ-card { background: var(--n-color-target); border: 1px solid var(--n-border-color); border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; }
.occ-card-title { font-size: 14px; font-weight: 600; color: var(--n-text-color); margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid var(--n-border-color); }
.occ-card-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 16px; }
.occ-field { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.occ-field-full { grid-column: 1 / -1; }
.occ-label { font-size: 12px; color: var(--n-text-color-3); }
.occ-value { font-size: 13px; color: var(--n-text-color); word-break: break-all; }
.occ-section-title { font-size: 14px; font-weight: 600; margin: 16px 0 10px; color: var(--n-text-color); }
.occ-list { display: flex; flex-direction: column; gap: 2px; }
.occ-item { border: 1px solid var(--n-border-color); border-radius: 6px; overflow: hidden; }
.occ-row { display: flex; align-items: center; gap: 8px; padding: 8px 12px; cursor: pointer; user-select: none; transition: background .15s; }
.occ-row:hover { background: var(--n-color-target); }
.occ-chevron { font-size: 14px; color: var(--n-text-color-3); flex: none; transition: transform .15s; }
.occ-chevron.rotated { transform: rotate(90deg); }
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
```

- [ ] **Step 7: 验证前端编译**

```bash
cd vulnscan-frontend && npx tsc --noEmit -p apps/web/tsconfig.json 2>&1 | head -40
```

预期: 无新增类型错误

- [ ] **Step 8: Commit**

```bash
git add vulnscan-frontend/apps/web/src/views/ly/event/components/LyEventTable.vue
git add vulnscan-frontend/apps/web/src/utils/ly.ts
git commit -m "feat: 命中明细弹窗重构 — 事件卡片 + 可展开报文详情"
```

---

### Task 6: 集成验证

- [ ] **Step 1: 启动后端并推送测试事件**

使用文档中的 JSON 示例，通过 API 推送测试事件验证后端数据通道。

```bash
curl -s -X POST http://localhost:PORT/api/traffic/internal/event/push \
  -H 'Content-Type: application/json' \
  -d @docs/event-fields-enhancement.md 中提取的 JSON 示例
```

确认后端返回 `{"success":true}` 且 event 列表中包含 `session_summary`/`flow_stats`/`ioc` 等字段。

- [ ] **Step 2: 验证前端展示**

前端事件列表页，找到有命中明细的事件，点击「明细」，确认:
- session_summary 卡片显示（有数据时）
- flow_stats 卡片显示 volume_role 等
- IOC 情报卡片显示
- 每条命中记录有三角图标，点击展开报文详情
- HEX 超过 128 字符时截断，点击「展开完整报文」显示全文
- 有 request/response 时显示 TCP 详情

- [ ] **Step 3: Commit (如有调整)**

```bash
git add -A && git commit -m "chore: 集成验证微调"
```
