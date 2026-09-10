# 事件列表三项增强设计（资产归属 / IOC 受害目标修正 / 载荷·频次排序）

- 日期: 2026-08-20
- 状态: 已实施并验证（2026-08-20，后端 go test 全绿、前端 typecheck 无新增错误）
- 范围:
  - 前端：`views/ly/event/list/index.vue`、`views/ly/event/components/LyEventTable.vue`、`utils/ly-asset.ts`、`utils/ly.ts`
  - 后端：`traffic/event_service.go`（lyCompatibleEvent）、`traffic/handler.go`（ListEvents 参数）、`traffic/internal/store`（EventQuery/MySQL/Memory 排序）、`traffic/internal/service/quant_stats.go`（总载荷统计）
  - 数据源：`GET /api/traffic/events/list`（今日/归档/全局三个视图共用）

## 1. 背景

事件列表（/ly/event/list）当前存在三个问题：

1. **无资产归属信息**：事件列表看不到事件属于哪个登记资产，运营需要跳到资产页逐一核对；资产登记（traffic_assets）与事件（events）之间没有关联列。
2. **受害目标误显示 IOC 规则 IP**：IP 型 IOC 命中事件（如内网主机外连 C2，ta_node 推送 `dst_ip = ioc_value = C2 地址`）在列表「受害目标」列直接显示 C2/IOC 地址（见 docs/event-push-api.md 示例：dst_ip=192.185.86.177 即 ioc_value），把威胁地址当成受害主机，误导研判与排行。
3. **无法按体量/频次排序**：列表固定按时间倒序；排查数据外传（大载荷）、高频命中事件需要人工翻页。

## 2. 目标

1. 事件列表新增「资产」列：事件来源或目标命中启用中的登记资产则显示资产名（多个以顿号连接），否则显示「未登记」；
2. 「受害目标」列不再出现 IP 型 IOC 规则地址（`ioc_type ∈ {ip, cidr}` 且 `dst_ip == ioc_value` 的事件，受害目标改为真实受害主机）；
3. 事件列表支持按「总载荷大小」「命中频次」排序（可升降序，默认按时间倒序），并新增「总载荷」列展示每事件累计载荷。

---

## 3. 需求 1：事件列表资产字段

### 3.1 归属判定口径

- **登记资产**：`traffic_assets` 中 `status = 1`（启用）的资产 —— 与列表页现有「仅看已登记资产相关事件」筛选（`eventMatchesAnyAsset` 判定 `status === 1`）口径保持一致；
- **事件归属**：资产 `address`（归一化小写后）与事件 `attackDevice` 或 `victimDevice`（需求 2 修正后取值）任一相等，即视为该事件归属资产；
- **多资产**：来源侧与目标侧各命中不同资产时，显示全部资产名，中文顿号「、」连接；
- **未命中任何启用资产** → 显示「未登记」（灰色 NTag）；
- 停用（status=0）资产不参与匹配。

### 3.2 实现要点

- `utils/ly-asset.ts` 新增 `eventAssetNames(event, assets): string[]`（内部复用 `normalizeAddr`/匹配逻辑，仅取启用资产，返回去重资产名数组）；
- `views/ly/event/list/index.vue`：在 `baseRows` 计算中为每行写入 `assetText = eventAssetNames(item, assets.value).join('、') || '未登记'`（资产列表已在页面加载，无额外请求）；
- `LyEventTable.vue` 新增「资产」列（minWidth 160），`row.assetText` 有值时渲染资产名，否则渲染「未登记」；列通过 `showAsset` prop 控制（列表页传 true，搜索页不传则不展示，避免搜索页误显示未登记）；
- 纯前端实现，后端接口不变。

---

## 4. 需求 2：受害目标不显示 IOC 规则 IP

### 4.1 判定规则（后端 `lyCompatibleEvent`，列表/排行/研判共用同一数据源）

对每条事件解析 context 后：

```
若 ioc_type ∈ {ip, cidr} 且 dst_ip == ioc_value（IP 型 IOC 命中且目的地址即 IOC 地址）
  → 原 dst 是 IOC 规则地址，不是受害主机：
     attackDevice（威胁来源）= 原 dst（IOC 地址）
     victimDevice（受害目标） = 原 src（真实受害主机）
     obj = 同步为新的 "attack>victim"
否则 → 维持现状（src→dst）
```

**不改动的情形**：

- 源为 IOC（`src_ip == ioc_value`，如恶意 IP 主动攻击内网）：受害目标本就是 dst，保持现状；
- 域名/URL 型 IOC（ioc_type = domain/url）：ioc_value 非 IP，无法与 dst_ip 直接比对，保持现状（详情页 IOC 字段仍可查）；
- 指纹规则命中（无 ioc_value）：不受影响。

### 4.2 配套修正：研判回传不受影响

- `lyCompatibleEvent` 同时新增透传原始五元组 `src_ip`、`dst_ip`（始终为 ta_node 推送的真实流向，不做交换）；
- 前端 `LyEventTable.buildAnalysisPayload` 的 `threat_source / victim_target` 改取 `row.src_ip / row.dst_ip`（缺省回退 attackDevice/victimDevice）。
  - 原因：研判重推（`POST /traffic/internal/event/push`，analysis_only）以 `Fingerprint(src|dst|type)` 定位既有事件；若把交换后的展示值回传，指纹变为 (dst|src|type) 会匹配不到原事件、误建重复事件；
  - 交换只作用于**列表展示/排行聚合**，AI 研判仍见真实流量方向。

### 4.3 影响面

- 今日/归档/全局事件列表、总览（om）威胁来源/受害目标排行、命中明细弹窗全部以修正后取值展示；
- 需求 1 的资产匹配基于修正后的 victimDevice，IOC 命中事件的真实受害主机（内网资产）能正确关联资产。

---

## 5. 需求 3：按事件总载荷、频次排序

### 5.1 排序口径

| 排序依据 | 取值 | 说明 |
|---------|------|------|
| `time`（默认） | `created_at` | 现状，倒序 |
| `payload` | `context.quant_stats.total_payload_bytes` | 事件聚合生命周期内所有命中「载荷字节」(`ly.bytes`) 的累加值；缺失（旧事件）按 0 |
| `frequency` | `context.occurrence_count` | 聚合发生次数，与「命中频次」列一致 |

- 方向：`desc`（默认）/ `asc`；
- 排序在**服务端分页前**完成（当前分页为服务端分页，客户端排序会导致跨页错乱）；同值以 `created_at DESC, id DESC` 兜底。

### 5.2 后端实现要点

- `quant_stats.go`：`domain.QuantStats` 新增 `TotalPayloadBytes int64`（json `total_payload_bytes`），`applyHitStats` 中累加 `ly["bytes"]`（ta_node 必填字段「载荷总字节」）；随 context 序列化自动下发；
- `store.EventQuery` 新增 `Sort string`、`Order string`；
- `store/mysql.go ListEventsPage`：按 Sort 生成 ORDER BY：
  - payload → `CAST(JSON_UNQUOTE(JSON_EXTRACT(context, '$.quant_stats.total_payload_bytes')) AS UNSIGNED)`
  - frequency → `CAST(JSON_UNQUOTE(JSON_EXTRACT(context, '$.occurrence_count')) AS UNSIGNED)`
  - （MySQL 8.0 已确认支持）
- `store/memory.go ListEventsPage`：解析 context 后内存排序（保持两存储行为一致）；
- `handler.go ListEvents`：解析 `sort` / `order` 查询参数（非法值回退默认）；
- `event_service.go lyCompatibleEvent`：新增 `total_payload_bytes`、`src_ip`、`dst_ip` 字段。

### 5.3 前端实现要点

- 列表页筛选区新增两个控件：
  - 排序依据 `NSelect`：时间（默认）/ 总载荷大小 / 命中频次；
  - 方向 `NSelect`：降序（默认）/ 升序；
  - 变化即重新 `loadEvents()`（透传 `sort`、`order` 参数，服务端分页）；
- `LyEventTable.vue` 新增「总载荷」列（宽度约 110，`formatBytes(row.total_payload_bytes)` 渲染，缺失显示「-」）；
- 命中频次列已存在，无需新增。

---

## 6. 验收清单

1. **资产列**：无资产环境下列表每行显示「未登记」；登记资产后，来源/目标命中启用资产的事件显示资产名；命中多个资产显示全部名称；停用资产不匹配；搜索页不显示该列。
2. **受害目标**：构造 IP 型 IOC 命中事件（dst_ip = ioc_value，如 C2 外连），列表受害目标显示内网源 IP（真实受害主机）、威胁来源显示 IOC 地址；`from_ioc`（src=IOC）事件展示不变；域名 IOC 事件展示不变。
3. **研判不回归**：对 IOC 事件点「查看报告」，不新建重复事件（指纹仍命中原事件），报告数据方向为真实流向。
4. **排序**：选择「总载荷大小」→ 列表按 total_payload_bytes 降序（跨页整体有序）；「命中频次」→ 按 occurrence_count 降序；升序正确；切换回时间恢复倒序；今日/归档/全局三视图均生效。
5. **总载荷列**：展示与排序一致的数字（formatBytes）。
6. **回归**：现有筛选（级别/时间/关键字/资产/排行标签）、分页、命中明细、审核/查看报告功能不受影响；后端 `go build ./...`、`go test ./traffic/...` 通过；前端构建/类型检查通过。

## 7. 待确认

1. **需求 2 方案**（关键）：采用「交换源/目标」——受害目标显示真实受害主机（推荐，排行与资产关联也随之正确）？还是仅将 IOC 地址隐藏为「-」？
2. **需求 1 口径**：资产归属仅统计启用（status=1）资产（推荐，与现有筛选一致）？还是包含停用资产？
3. **需求 3 口径**：「总载荷」= 载荷字节 `bytes` 累加（推荐，与 ta_node 必填字段一致，新增 total_payload_bytes）？还是用现有线缆字节 `total_wire_bytes`（零新增字段，但含 L2-L4 头）？
4. **排序交互**：筛选区下拉（时间/总载荷/频次 + 升降序，推荐，改动小）？还是表头点击排序？