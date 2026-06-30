# 命中频次点击弹窗 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 「命中频次」列加可点击「明细」入口，弹窗展示每次命中的 序号/时间/数据包大小(wire_bytes)/包数(packets)；后端按次记录 wire_bytes 与 packets。

**Architecture:** 纯流量分析侧。后端把 `context.occurrences` 从「时间字符串列表」升级为「{time,wire_bytes,packets} 对象列表」（初始映射 + 合并两处共用 `buildOccurrence`），并在 `lyCompatibleEvent` 投影暴露 `occurrences`；前端事件列表行经 `...item` 透传 occurrences，命中频次列加「明细」按钮打开 `NModal`+`NDataTable`。

**Tech Stack:** Go（database/sql、encoding/json）、Vue3 + naive-ui（vben admin）。

## Global Constraints

- **仅修改流量分析侧**：`vulnscan-backend/traffic/**` 与前端 `vulnscan-frontend/apps/web/src/{views/ly,utils}/**`。**不得**修改 `circular/`、`di/`、`scanrunner/`、`model/`，也不改 lyserver DB（`t_event_data`）路径。
- 分支：`trafficanalysis`。
- 数据包大小口径 = `wire_bytes`（在线字节，含 L2-L4 头）。
- occurrence 记录：`{ "time": <RFC3339>, "wire_bytes": <int>, "packets": <int> }`；`wire_bytes`/`packets` 缺失则**省略该键**（不写 0）。
- 保留聚合上限 `maxOccurrences = 200`。
- 向后兼容：旧库 occurrences 元素是字符串，后端原样透传，**前端**按 `{time: <string>}` 处理、字节/包数显示 `-`。
- Go module 根：`vulnscan-backend`；测试用工具链 workaround：`GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto`。

---

### Task 1: 后端 occurrence 按次记录 wire_bytes / packets

新增 `buildOccurrence` 辅助，初始映射与合并两处都用它构造对象记录。

**Files:**
- Modify: `vulnscan-backend/traffic/internal/service/event_mapping.go:65-68`（初始 occurrence 构造）
- Modify: `vulnscan-backend/traffic/internal/service/services.go:127-142`（`mergeOccurrence` 追加）
- Test: `vulnscan-backend/traffic/internal/service/occurrence_test.go`（新建）

**Interfaces:**
- Produces: `func buildOccurrence(ly map[string]any) map[string]any`（package `service`）——返回含 `time`、可选 `wire_bytes`(int)、可选 `packets`(int) 的 map。
- 复用既有同包 helper：`firstNonEmpty`、`asString`、`toInt`（均在 package `service`）。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/internal/service/occurrence_test.go`：

```go
package service

import (
	"testing"

	"vulnscan-backend/traffic/internal/store"
	"vulnscan-backend/traffic/internal/domain"
)

func TestBuildOccurrence(t *testing.T) {
	occ := buildOccurrence(map[string]any{
		"occurrence_time": "2026-06-30T09:00:00Z",
		"wire_bytes":      float64(1480),
		"packets":         float64(3),
	})
	if occ["time"] != "2026-06-30T09:00:00Z" {
		t.Fatalf("time=%v", occ["time"])
	}
	if occ["wire_bytes"] != 1480 {
		t.Fatalf("wire_bytes=%v (want int 1480)", occ["wire_bytes"])
	}
	if occ["packets"] != 3 {
		t.Fatalf("packets=%v (want int 3)", occ["packets"])
	}
}

func TestBuildOccurrenceOmitsMissing(t *testing.T) {
	occ := buildOccurrence(map[string]any{"time": "2026-06-30T10:00:00Z"})
	if occ["time"] != "2026-06-30T10:00:00Z" {
		t.Fatalf("time=%v", occ["time"])
	}
	if _, ok := occ["wire_bytes"]; ok {
		t.Fatal("wire_bytes should be omitted when missing")
	}
	if _, ok := occ["packets"]; ok {
		t.Fatal("packets should be omitted when missing")
	}
}

func TestMergeOccurrenceStoresObjects(t *testing.T) {
	st := store.NewMemoryStore()
	created, _ := st.CreateEvent(domain.Event{EventID: "evt-occ", Context: `{"occurrence_count":1,"occurrences":[{"time":"2026-06-30T09:00:00Z","wire_bytes":100,"packets":1}]}`})
	svc := Services{Store: st}
	count := svc.mergeOccurrence(created.EventID, map[string]any{
		"occurrence_time": "2026-06-30T09:05:00Z",
		"wire_bytes":      float64(250),
		"packets":         float64(2),
	})
	if count != 2 {
		t.Fatalf("count=%d want 2", count)
	}
	got, _ := st.GetEvent("evt-occ")
	// occurrences 应为对象列表，新追加项含 wire_bytes/packets
	if got.Context == "" || !containsJSON(got.Context, `"wire_bytes":250`) || !containsJSON(got.Context, `"packets":2`) {
		t.Fatalf("merged occurrence object missing: %s", got.Context)
	}
}

func containsJSON(haystack, needle string) bool {
	return len(haystack) > 0 && len(needle) > 0 && indexOf(haystack, needle) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/internal/service/ -run 'TestBuildOccurrence|TestMergeOccurrence' -v`
Expected: 编译失败（`buildOccurrence` 未定义）。

- [ ] **Step 3: 实现 buildOccurrence**

在 `services.go` 末尾（`toInt` 函数附近）新增：

```go
// buildOccurrence 从一条 ly 事件构造单次命中记录：时间 + 数据包大小(wire_bytes) + 包数(packets)。
// wire_bytes/packets 缺失时省略对应键，便于前端区分"无数据"。
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
	return occ
}
```

- [ ] **Step 4: 初始映射改用对象**

`event_mapping.go:65-68` 当前：

```go
	occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	occurrences := []any{}
	if occ != "" {
		occurrences = append(occurrences, occ)
	}
```

改为（保留 `occ` 时间字符串供下方 `first_time`/`last_time` 使用，列表元素改为对象）：

```go
	occ := firstNonEmpty(asString(ly["occurrence_time"]), asString(ly["time"]))
	occurrences := []any{}
	if occ != "" {
		occurrences = append(occurrences, buildOccurrence(ly))
	}
```

（`context` 字面量里 `"first_time": occ`、`"last_time": occ`、`"occurrences": occurrences` 等保持不变。）

- [ ] **Step 5: 合并追加改用对象**

`services.go:137-142` 当前：

```go
		occs, _ := ctx["occurrences"].([]any)
		occs = append(occs, occ)
		if len(occs) > maxOccurrences {
			occs = occs[len(occs)-maxOccurrences:]
		}
		ctx["occurrences"] = occs
```

改为（追加对象；`first_time`/`last_time` 比较仍用 `occ` 字符串，保持上方逻辑不变）：

```go
		occs, _ := ctx["occurrences"].([]any)
		occs = append(occs, buildOccurrence(ly))
		if len(occs) > maxOccurrences {
			occs = occs[len(occs)-maxOccurrences:]
		}
		ctx["occurrences"] = occs
```

- [ ] **Step 6: 运行测试确认通过**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/internal/service/ -run 'TestBuildOccurrence|TestMergeOccurrence' -v`
Expected: PASS（3 个用例）。

- [ ] **Step 7: 提交**

```bash
git add vulnscan-backend/traffic/internal/service/event_mapping.go vulnscan-backend/traffic/internal/service/services.go vulnscan-backend/traffic/internal/service/occurrence_test.go
git commit -m "feat(traffic): occurrence 按次记录 wire_bytes/packets"
```

---

### Task 2: 投影暴露 occurrences

`lyCompatibleEvent` 输出 `occurrences`，供前端弹窗使用。

**Files:**
- Modify: `vulnscan-backend/traffic/event_service.go:155-183`（`lyCompatibleEvent` 返回 map）
- Test: `vulnscan-backend/traffic/occurrences_projection_test.go`（新建）

**Interfaces:**
- Consumes: `context.occurrences`（Task 1 写入的对象列表）。
- Produces: `lyCompatibleEvent` 返回 map 新增 key `occurrences`（列表，原样透传 ctx 中的值；缺失时为 `nil`）。

- [ ] **Step 1: 写失败测试**

新建 `vulnscan-backend/traffic/occurrences_projection_test.go`：

```go
package traffic

import (
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestLyCompatibleEventExposesOccurrences(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{
		EventID: "evt-1",
		Context: `{"occurrences":[{"time":"2026-06-30T09:00:00Z","wire_bytes":1480,"packets":3}]}`,
	})
	occ, ok := row["occurrences"].([]any)
	if !ok {
		t.Fatalf("occurrences not a list: %T", row["occurrences"])
	}
	if len(occ) != 1 {
		t.Fatalf("occurrences len=%d want 1", len(occ))
	}
}

func TestLyCompatibleEventOccurrencesEmpty(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{EventID: "evt-2", Context: ""})
	// 无 context 时 occurrences 应为 nil（前端按空处理）
	if v, ok := row["occurrences"]; ok && v != nil {
		if list, isList := v.([]any); isList && len(list) != 0 {
			t.Fatalf("expected empty/nil occurrences, got %v", v)
		}
	}
}
```

- [ ] **Step 2: 运行测试确认失败**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/ -run TestLyCompatibleEventExposesOccurrences -v`
Expected: FAIL（`row["occurrences"]` 为 nil，类型断言失败）。

- [ ] **Step 3: 投影补字段**

`event_service.go` 的 `lyCompatibleEvent` 返回 map 中（`"is_final": isFinal,` 行后、`"review_status"`/`"circular_code"` 附近）追加一行：

```go
		"aggregation_status": aggregationStatus,
		"is_final":           isFinal,
		// 每次命中明细：时间 + 数据包大小(wire_bytes) + 包数(packets)，供前端命中频次弹窗
		"occurrences": context["occurrences"],
		"review_status": event.ReviewStatus,
		"circular_code": event.CircularCode,
```

> 注意：函数内局部变量名是 `context`（一个 `map[string]any`，由 `event.Context` 反序列化而来），不是标准库 context。直接取 `context["occurrences"]`，缺失时为 nil。

- [ ] **Step 4: 运行测试确认通过**

Run: `cd vulnscan-backend && GOSUMDB=sum.golang.org GOPROXY=https://goproxy.cn,direct GOTOOLCHAIN=auto go test ./traffic/ -run 'TestLyCompatibleEventExposesOccurrences|TestLyCompatibleEventOccurrencesEmpty' -v`
Expected: PASS（2 个用例）。

- [ ] **Step 5: 提交**

```bash
git add vulnscan-backend/traffic/event_service.go vulnscan-backend/traffic/occurrences_projection_test.go
git commit -m "feat(traffic): ly 投影暴露 occurrences 明细"
```

---

### Task 3: 前端命中频次「明细」弹窗

`formatBytes` 工具 + 命中频次列「明细」按钮 + `NModal`/`NDataTable` 弹窗。

**Files:**
- Modify: `vulnscan-frontend/apps/web/src/utils/ly.ts`（新增 `formatBytes`）
- Modify: `vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue`
- 校验：`pnpm --filter @vben/web run typecheck`

**Interfaces:**
- Consumes: 行字段 `occurrences`（Task 2 暴露，经 `normalizeLyEvent` 的 `...item` 透传到行）；既有 `formatTimestamp`（utils/ly.ts）。
- Produces: `export function formatBytes(value?: number | string | null): string`。

- [ ] **Step 1: 新增 formatBytes 工具**

`utils/ly.ts` 在 `formatDuration` 之后新增并导出：

```ts
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
```

- [ ] **Step 2: 列表引入工具与弹窗状态**

`views/ly/event/list/index.vue` 顶部 import 增加 `NModal`、`NDataTable`（确认已在 naive-ui import 列表，缺则补）与工具：

```ts
import { formatBytes } from '#/utils/ly';
import { countByKey, paginate } from '#/utils/ly';
```

（若已有 `import { countByKey, paginate } from '#/utils/ly';`，合并为 `import { countByKey, formatBytes, paginate } from '#/utils/ly';`，避免重复 import 同一模块。）

`<script setup>` 内（`state` 之后）新增弹窗状态与数据构造：

```ts
import { formatTimestamp } from '#/utils/ly';

const occVisible = ref(false);
const occRows = ref<Array<{ idx: number; time: string; size: string; packets: string }>>([]);

function buildOccRows(occ: any[]) {
  return (occ || []).map((o, i) => {
    const item = typeof o === 'string' ? { time: o } : (o ?? {});
    return {
      idx: i + 1,
      time: formatTimestamp(item.time) || '-',
      size: item.wire_bytes == null ? '-' : formatBytes(item.wire_bytes),
      packets: item.packets == null ? '-' : String(item.packets),
    };
  });
}

function openOccurrences(row: Record<string, any>) {
  occRows.value = buildOccRows(row.occurrences || []);
  occVisible.value = true;
}

const occColumns = [
  { title: '序号', key: 'idx', width: 70 },
  { title: '命中时间', key: 'time', minWidth: 180 },
  { title: '数据包大小', key: 'size', width: 120 },
  { title: '包数', key: 'packets', width: 90 },
];
```

> 说明：`formatTimestamp` 若已在文件顶部从 `#/utils/ly` 引入则复用，不要重复声明 import。

- [ ] **Step 3: 命中频次列加「明细」按钮（方案 B）**

`views/ly/event/list/index.vue` 的「命中频次」列（现 render 返回 `h('div', {...}, tags)`），在 `tags` 数组构造完、返回 div 前，按 occurrences 是否非空追加一个文本按钮：

```ts
  {
    title: '命中频次',
    key: 'hitFrequencyText',
    width: 240,
    render: (row: Record<string, any>) => {
      const tags = [
        h(
          NTag,
          { size: 'small', type: row.hitFrequencyLevel || 'default' },
          { default: () => row.hitFrequencyText || '单次' },
        ),
      ];
      if (row.aggregationStatusText) {
        tags.push(
          h(
            NTag,
            { size: 'small', type: row.isFinal ? 'success' : 'info', style: 'margin-left:4px' },
            { default: () => row.aggregationStatusText },
          ),
        );
      }
      if (Array.isArray(row.occurrences) && row.occurrences.length > 0) {
        tags.push(
          h(
            NButton,
            { text: true, size: 'small', type: 'primary', style: 'margin-left:8px', onClick: () => openOccurrences(row) },
            { default: () => '明细' },
          ),
        );
      }
      return h('div', { style: 'display:flex;flex-wrap:wrap;align-items:center;gap:4px' }, tags);
    },
  },
```

（`NButton` 已在文件顶部 import；列宽从 200 调整为 240 以容纳「明细」。）

- [ ] **Step 4: 模板加弹窗**

`<template>` 内，在已有 `<ReportModal .../>` 之后追加：

```vue
    <NModal
      v-model:show="occVisible"
      preset="card"
      title="命中明细"
      style="width: 640px; max-width: 90vw"
    >
      <NDataTable
        :columns="occColumns"
        :data="occRows"
        size="small"
        :max-height="420"
        :bordered="false"
      />
    </NModal>
```

- [ ] **Step 5: 前端校验**

Run: `cd vulnscan-frontend && pnpm --filter @vben/web run typecheck`
Expected: `src/views/ly/` 与 `src/utils/ly.ts` 无新增类型错误（存量无关模块错误可忽略；若环境受限无法运行，照实记录，勿改无关配置）。

- [ ] **Step 6: 手工验证**

平台事件列表中，对一条多次命中的事件：命中频次列出现「明细」链接 → 点击弹窗，表格列出每次命中的 序号/时间/数据包大小/包数；旧数据（无字节）大小与包数显示 `-`；单次/无明细事件不显示「明细」。

- [ ] **Step 7: 提交**

```bash
git add vulnscan-frontend/apps/web/src/utils/ly.ts vulnscan-frontend/apps/web/src/views/ly/event/list/index.vue
git commit -m "feat(traffic-frontend): 命中频次明细弹窗（时间/数据包大小/包数）"
```

---

## Self-Review

**1. Spec coverage:**
- §3.1 occurrence 结构 → Task 1（buildOccurrence）。✓
- §3.2 构造点（初始 + 合并）→ Task 1 Step 4/5。✓
- §3.3 投影暴露 occurrences → Task 2。✓
- §3.4 向后兼容（字符串元素）→ 后端原样透传（Task 2 透传 ctx 值）+ 前端 `typeof o === 'string'` 处理（Task 3 buildOccRows）。✓
- §4.1 数据贯通 → `normalizeLyEvent` 的 `...item` 透传（Task 3 依赖，无需改 normalize）。✓
- §4.2 命中频次入口（方案 B）→ Task 3 Step 3。✓
- §4.3 弹窗（时间/大小/包数 + formatBytes）→ Task 3 Step 1/2/4。✓
- §5 测试 → Task 1（service 单测）、Task 2（projection 单测）、Task 3（手工）。✓
- §6 YAGNI（不新增接口、不显示 bytes/方向、不回填历史、不改 lyserver DB）→ 计划未涉及这些。✓

**2. Placeholder scan:** 无 TBD/TODO；每个代码步骤含完整代码。✓

**3. Type consistency:**
- `buildOccurrence(ly map[string]any) map[string]any` — Task 1 定义并在 event_mapping/services 调用，签名一致。✓
- occurrence 键 `time`/`wire_bytes`/`packets` — Task 1 写入、Task 2 透传、Task 3 读取，键名一致。✓
- `formatBytes(value?: number|string|null): string` — Task 3 Step 1 定义、Step 2 使用，一致。✓
- 行字段 `occurrences`（数组）— Task 2 产出、Task 3 消费，一致。✓
