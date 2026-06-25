# 流量分析安全事件审核 → 通报处置 对接设计

- 日期：2026-06-25
- 分支：`trafficanalysis`
- 约束：**仅修改流量分析侧（`vulnscan-backend/traffic/` 与前端 `views/ly`、`api/ly`），不改动 `circular`、`di`、`scanrunner` 等其它模块。**

## 1. 背景与目标

流量分析（traffic）业务系统会产生“安全事件”，目前事件只有 AI 自动分析的生命周期状态
（`event_status`：`pending` / `processing` / `round_finished`），**没有任何人工审核 / 处置语义**。
前端事件列表里出现的 `proc_status="unprocessed"` 是硬编码、无真实流转。

通报处置（circular）业务系统是平台已有模块，提供“安全事件流转”标准入口
`POST /api/circular/transfers`（同进程 service 为 `Circular.TransferService().ReceiveIncident`），
接收 `TransferIncidentReq`，落库为一条通报（`Source=superior_transfer`，`Status=to_be_distributed`，自动跳过核验）。
已有先例 `scanrunner/event_bridge.go` 在“本平台安全事件复核通过”后构造 `TransferIncidentReq` 推送。

**目标：** 为流量分析安全事件增加一道人工审核；通过审核的事件推送到通报处置；
并将流量分析事件字段对齐到通报处置的 `TransferIncidentReq`。

## 2. 关键设计决策（已与用户确认）

1. **集成方式：HTTP 客户端（纯 traffic 侧）。** 在 `traffic/internal/client` 新增 `CircularClient`，
   `POST {base}/api/circular/transfers`，不走同进程注入（避免改动 `di/`）。
2. **审核触发：人工。** 在事件列表点击「审核通过 / 驳回」。
3. **审核范围：仅 AI 分析完成（`event_status=round_finished`）的事件可审核、可推送。**
4. **鉴权：透传入站用户 Bearer token。** circular transfer 路由走 IAM 鉴权
   （`iamsdk.GetCurrentUser` 取 `OrganizeID`、`ActorFromContext` 取操作者），
   而 traffic 路由不经过 IAM。审核请求由前端携带用户 `Authorization: Bearer <accessToken>`，
   traffic 审核 handler 将该头**原样透传**到对 circular 的调用，使操作者/组织落到当前登录用户。
   两模块在同一 gin engine、同进程、同端口。

## 3. 数据模型变更（traffic 侧，`events` 表 / `domain.Event`）

新增字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| `review_status` | varchar(32) NOT NULL DEFAULT `''` | `''`(未到审核) / `pending_review` / `approved` / `rejected` |
| `review_comment` | text NOT NULL DEFAULT `''` | 审核意见（驳回理由 / 通过备注） |
| `reviewed_by` | varchar(128) NOT NULL DEFAULT `''` | 操作者（IAM 用户标识/账号） |
| `reviewed_at` | timestamptz NULL | 审核时间 |
| `circular_code` | varchar(70) NOT NULL DEFAULT `''` | 推送成功后通报处置返回的编号；非空即“已推送”，作幂等标志 |

改动点：
- `traffic/internal/domain/models.go`：`Event` 结构新增上述字段（含 json tag）。
- `traffic/internal/store/schema.go`：`events` 建表语句新增列。
- `traffic/internal/store/postgres.go`：`CreateEvent` INSERT 列、`scanEvent` 扫描列、
  `UpdateEvent` patch 白名单放开 `review_status` / `review_comment` / `reviewed_by` / `reviewed_at` / `circular_code`。
- `traffic/internal/store/memory.go`：对应内存实现同步。
- 兼容性：新增列均有默认值；旧库依赖 `AutoMigrate` 或 schema `IF NOT EXISTS` 增量（按现有迁移方式补 `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`）。

## 4. 审核状态流转

```
event_status=round_finished  ⟹  review_status 视为 pending_review（可审核）
  ├─ 审核通过(approve): 校验 round_finished → review_status=approved
  │                     → 构造 TransferIncidentReq → CircularClient 推送
  │                     → 成功则存 circular_code、reviewed_by/at
  └─ 驳回(reject):      review_status=rejected + review_comment，不推送，留在流量侧（可再次审核）
```

幂等：
- `circular_code` 非空时不重复推送（直接返回已推送）。
- circular 侧本身按 `IncidentNo`(=EventID) 幂等，重复调用安全。

## 5. 字段对齐（`Event` → `TransferIncidentReq`）

新增 `traffic/internal/service/circular_mapping.go`（或 `traffic/circular_mapping.go`，按模块惯例），映射规则：

| 通报侧字段 | 必填 | 流量侧来源 |
|---|---|---|
| `IncidentNo` | 是 | `Event.EventID`（幂等键） |
| `Name` | 是 | `Title` ‹fallback `EventName` / `"流量分析事件 " + EventID`› |
| `Level` | 否 | `Severity` 映射：`critical→1`(特别重大) / `high→2`(重大) / `medium`·`middle→3`(较大) / `low→4`(一般)；未知→4 |
| `AiOpinion` | 否 | 最新 AI Summary 结论（无则取 `Message`） |
| `AiConfidence` | 否 | `Context` JSON 中置信度字段（无则 0） |
| `AssetInfo.DomainIP` / `SiteIP` | 否 | Observables 中 role=destination/victim 的 IOC（ip） |
| `AssetInfo.AssetName` / `SystemName` | 否 | `Context` 中受害设备名 / 系统名（victim_target） |
| `AssetInfo.Unit` | 否 | 留空 → circular 侧 `ResolveOrganize` 回退默认组织 |
| `MetadataInfo.IncidentType` | 否 | `Category` |
| `MetadataInfo.IncidentDescription` | 否 | `Message`（rule_desc） |
| `MetadataInfo.IncidentURL` / `CveId` / `CvssScore` | 否 | `Context` 中对应字段（无则空/0） |
| `SourceSystem` | 否 | 固定 `"流量分析(trafficAnalysis)"` |

`Severity` 取值参照 `lyLevel`：critical/high/middle/low。`Context` 为 JSON 字符串，按 key 容错解析。

## 6. HTTP 接口（traffic 侧，`/api/traffic`）

- 新增 `POST /events/detail/:eventID/review`
  - body：`{ "action": "approve" | "reject", "comment"?: string }`
  - 行为：校验事件存在且 `event_status=round_finished`；落审核状态；`approve` 时透传
    入站 `Authorization` 头调用 `CircularClient.ReceiveIncident`，成功后写 `circular_code`。
  - 返回：`{ review_status, circular_code? }`。
  - 路由注册在 `traffic/traffic.go` 的 `/events` group，handler 在 `traffic/handler.go`。
- `GET /events/list` 与详情返回体补充 `review_status` / `circular_code`（`domain.Event` 已含字段，天然带出）；
  ly 兼容投影 `lyCompatibleEvent()` 增补 `review_status` / `circular_code`，供前端事件列表展示。

## 7. CircularClient（`traffic/internal/client/circular.go`）

仿现有 `DeepSOCClient`：
- 方法 `ReceiveIncident(ctx, req TransferIncidentReq, bearer string) (circularCode string, err error)`。
- `POST {base}/api/circular/transfers`，Header：`Content-Type: application/json` + `Authorization: <bearer>`（透传）。
- `base` 取自配置 `CIRCULAR_BASE_URL`（env / config.toml `[traffic]`）；**留空则由审核 handler 用入站请求的
  `scheme://host` 拼出**（同机自调）。因此 client 接受 base 作为入参，由 handler 计算后传入。
- 超时复用 `config.HTTPTimeout`。
- `TransferIncidentReq` 字段在 traffic 侧用本地等价 struct（json tag 对齐 circular contract），避免 import circular 包。

配置：`traffic/internal/config/config.go` 新增 `CircularBaseURL`（env `CIRCULAR_BASE_URL`，默认 `""`）。

## 8. 前端（`apps/web/src`）

- `api/ly/index.ts`：新增
  `lyEventReview({ eventId, action, comment })` → `POST /api/traffic/events/detail/{eventId}/review`
  （走 `post(..., prefix='/api/traffic')`，携带现有 `createHeaders()` 的 Bearer）。
- `views/ly/event/list/index.vue`：
  - 新增「审核状态」列：展示 `review_status`（待审核/已通过/已驳回）+ 已推送时显示 `circular_code`。
  - 操作列新增「审核通过 / 驳回」按钮，仅 `analysisStatus==='completed'`（=round_finished）可点；
    驳回弹框填写意见；操作后刷新行状态。
  - 事件行 `event_id` 用于定位 domain.Event（AI 分析后已回填 `event_id`/`deepsoc_event_id`）。

## 9. 测试与验证

- Go 单测：`circular_mapping` 的字段映射（各 severity→level、fallback 名称、IOC 解析、context 容错）。
- store 层：`UpdateEvent` 新字段 patch 生效（postgres + memory 两实现，至少 memory 单测）。
- 审核 handler：`round_finished` 校验、approve 触发推送（用 mock/stub CircularClient）、reject 不推送、幂等（已 `circular_code` 不重复推送）。
- 手工：事件列表点审核通过 → 通报处置出现对应通报；驳回 → 不出现、状态为已驳回。

## 10. 不做的事（YAGNI）

- 不改动 circular / di / scanrunner 任何文件。
- 不做审批多级 / 审核流配置 / 角色权限细分（沿用现有 IAM 鉴权即可）。
- 不引入新的消息队列流转（直接同步 HTTP 推送；失败返回错误由前端提示重试）。
- 不重构两套事件存储（`events` 与 `t_event_data`）；审核作用于 AI 分析主表 `events`。
