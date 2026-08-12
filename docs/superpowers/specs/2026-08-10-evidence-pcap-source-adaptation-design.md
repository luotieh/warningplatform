# 证据 PCAP 来源适配设计（ta_node evidence_files → 报告附件/下载）

- 日期: 2026-08-10
- 状态: 已确认，实施中
- 来源契约: `docs/event-push-api.md` §3.8（`evidence_files`）与 §5.4（PCAP 下载接口）

## 1. 背景与来源

融合采集节点（ta_node）在事件推送 schema v1.6 中新增 `evidence_files` 数组，
并提供证据文件下载接口：

**节点推送字段（§3.8）**

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `evidence_files[].id` | string | 附件 ID（节点本地完整路径） |
| `evidence_files[].name` | string | 文件名（如 `evt-xxx.pcap`） |
| `evidence_files[].type` | string | 当前为 `"pcap"` |
| `evidence_files[].path_ref` | string | 下载 URL 路径，管理端拼接 `http://<node_host>:<port><path_ref>` 下载 |
| `evidence_files[].sha256` | string | 文件哈希（预留） |
| `evidence_files[].size` | uint64 | 文件大小（预留） |
| `evidence_files[].description` | string | 说明 |

**节点下载接口（§5.4）**

```
GET http://<node_host>:25640/api/v1/evidence/{relative_path}
响应 Content-Type: application/vnd.tcpdump.pcap（标准 PCAP）
安全：仅 GET；拒绝包含 ".." 的路径遍历
```

**管理端现状**

- `event_mapping.go` 仅透传 `evidence_file`（单字符串），`evidence_files` 数组未透传；
- 分析 prompt 只展示 `evidence_file`，报告附件清单（六章）无 PCAP 来源；
- 前端事件详情无 PCAP 下载入口。

## 2. 目标

1. 事件推送入库时透传并保存 `evidence_files`；
2. 管理端提供 PCAP 下载代理，前端/报告可直接下载节点证据；
3. 报告模版「六、附件清单」由 `evidence_files` 自动填充；
4. LLM 分析上下文包含证据附件摘要；
5. 兼容 schema 1.5 旧事件（无 `evidence_files` 时相关功能自动隐藏）。

## 3. 数据流

```
ta_node ──POST /api/traffic/internal/event/push──▶ warning-platform
   │ event 含 evidence_files[]（path_ref=/api/v1/evidence/...）
   ▼
traffic.events.context.evidence_files（JSON 透传）
   │
   ├─▶ 报告：六、附件清单（name + 管理端代理下载 URL）
   ├─▶ 前端：事件详情附件区“下载PCAP”
   └─▶ LLM prompt：证据附件摘要（名称/大小/下载路径）
   │
   ▼ 下载时（管理端代理）
GET /api/traffic/events/:eventID/evidence/:idx
   → 读取事件 evidence_files[idx]
   → 解析节点地址（t_device.devid → ip，端口 25640）
   → 校验 path_ref（仅 /api/v1/evidence/ 前缀、无 ..）
   → GET http://<node_ip>:25640<path_ref>（超时/大小限制）
   → 流式返回 application/vnd.tcpdump.pcap
```

## 4. 管理端适配设计

### 4.1 事件映射（event_mapping.go）

在 `LyEventToDeepSOC` 中透传 `evidence_files`（数组）：

```go
if ef, ok := ly["evidence_files"].([]any); ok && len(ef) > 0 {
    context["evidence_files"] = ef
}
```

保留现有 `evidence_file` 单字符串透传（向后兼容）。`evidence_files` 元素保持节点原始结构：

```json
{
  "id": "data/evidence/.../evt-xxx.pcap",
  "name": "evt-xxx.pcap",
  "type": "pcap",
  "path_ref": "/api/v1/evidence/node-001/2026-08-06/evt-xxx.pcap",
  "sha256": "",
  "size": 0,
  "description": "触发包 PCAP 证据"
}
```

### 4.2 节点地址解析

- 优先：`t_device` 表按 `devid = event.device_id` 查询节点 `ip`，证据端口固定 `25640`（与节点契约一致）；
- 兜底：配置 `[traffic] evidence_node_base_url = "http://<ip>:25640"`（单节点部署时直接指定）；
- 无法解析节点地址时，报告/前端显示“节点离线，证据不可下载”，不影响事件其它功能。

### 4.3 管理端证据代理接口

新增只读接口（放在 traffic 模块，鉴权随现有事件接口语义）：

```
GET /api/traffic/events/:eventID/evidence/:idx
```

行为：

1. 事件不存在 → 404；`evidence_files` 为空或 `idx` 越界 → 404；
2. `path_ref` 校验：必须以 `/api/v1/evidence/` 开头，且不包含 `..`、`\`、`://`；
3. 解析节点地址（§4.2），拼 `http://<node>:25640<path_ref>`；
4. 请求节点：`GET`、`Content-Type` 校验 `application/vnd.tcpdump.pcap` 或 octet-stream、超时 10s、响应大小上限（默认 20MB）；
5. 成功：`Content-Disposition: attachment; filename=<name>` 流式返回；
6. 失败：502 + 原因（节点离线/路径非法/超时/大小超限），前端展示后端返回的 msg。

### 4.4 报告附件映射

`incident/stats` 报告构建时，把事件 context 的 `evidence_files` 映射为：

- `IncidentReportAttachment{Name: name, Path: 管理端代理URL}`；
- 报告「六、附件清单」渲染为 `- <name>：<代理URL>`；
- `type != pcap` 的附件同样保留（按 name/path 展示），为后续节点扩展留余地。

说明：事件侧附件需要随事件转通报/报告链路带到 incident 侧，具体透传点在
`scanrunner/event_bridge.go` 构造 `TransferIncidentReq` 或 incident 报告构建时读取事件证据；
本期先保证 traffic 事件详情与下载可用，incident 报告附件透传作为同一改动的一部分评估。

### 4.5 LLM 上下文

`formatAuxContext` 在「证据文件」后追加证据附件摘要：

```
- 证据附件(evidence_files)：
  - evt-xxx.pcap：type=pcap, size=xxx, 下载=/api/traffic/events/:id/evidence/0
```

### 4.6 前端

- 事件详情/报告弹窗：附件区展示 pcap 文件名与“下载PCAP”按钮（调用管理端代理，避免直连节点跨域/地址泄露）；
- 报告下载（Word）中附件清单沿用现有 Markdown 链接格式。

## 5. 安全设计

| 风险 | 对策 |
| --- | --- |
| 路径遍历 | 拒绝 `..`、`\`、`://`；仅允许 `/api/v1/evidence/` 前缀 |
| SSRF | 节点地址只来自 `t_device` 白名单（或配置单节点），不允许前端传入任意 host |
| 超大文件 | 响应大小上限 20MB，超限终止并记录 |
| 慢节点 | 请求超时 10s |
| 直连泄露 | 前端一律走管理端代理，不暴露节点地址/端口 |
| 鉴权 | 代理接口纳入现有事件接口鉴权语义（与 `events/detail` 一致） |

## 6. 兼容性

- schema 1.5 事件：`evidence_files` 为空 → 不显示附件、不渲染下载；
- 已入库旧事件：context 无 `evidence_files` → 附件区隐藏；
- `evidence_file` 旧字段保留，prompt 中继续展示。

## 7. 验收清单

1. 推送含 `evidence_files` 的事件 → `traffic.events.context.evidence_files` 完整保存；
2. `GET /api/traffic/events/:id/evidence/0` 返回节点 PCAP（200 + 正确 Content-Type）；
3. 非法 `path_ref`（含 `..`）→ 拒绝；
4. 节点离线/无 t_device 记录 → 502 且 msg 明确；
5. 事件详情/报告附件区出现“下载PCAP”并成功下载；
6. LLM 上下文含证据附件摘要；
7. 旧事件（无 evidence_files）不报错、不显示附件；
8. 构建/单测通过并部署后无新增 panic/5xx。

## 8. 待确认问题

1. 节点地址解析：**已确认走配置/节点配置映射**（`[traffic] evidence_nodes`，device_id → base_url）；
2. PCAP 下载：**已确认走管理端代理**；
3. 本期范围：**已确认仅在事件侧提供下载 PCAP 证据**（traffic 事件详情 + LLM 上下文；incident 报告附件透传不做）。
