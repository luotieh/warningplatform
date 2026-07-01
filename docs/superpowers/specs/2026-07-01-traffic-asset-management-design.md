# 流量分析侧资产管理（IP/域名网站）+ 关联筛选 设计

- 日期：2026-07-01
- 分支：`trafficanalysis`
- 约束：**仅修改流量分析侧**——`vulnscan-backend/traffic/**` 与前端 `vulnscan-frontend/apps/web/src/{views/ly,api/ly,store,router/routes/modules}` 内与流量分析相关的文件。**不碰**平台 `asset/`、`assetmgr/`、`model/`、`di/`、`circular/`、`scanrunner/` 等其它模块。

## 1. 背景与目标

流量分析事件带「威胁来源(attackDevice)」与「受害目标(victimDevice)」（多为 IP，来源 threat_source/victim_target/src_ip/dst_ip）。用户希望在流量分析侧新增一个**精简资产管理**（仅 IP 资产与域名/网站资产），登记关注的资产，并用它与事件的威胁来源/受害目标做**关联筛选**。

参考平台已有「资产台账」(`asset/` 模块 + `views/asset/ledger/`) 的交互范式，但**在 traffic 侧独立实现**一个精简版（不复用平台 asset 模块），保持与既有流量分析功能一致的 traffic-only 架构。

现状要点（探查确认）：
- 事件全量加载进前端 Pinia store（`store/ly.ts` loadEvents → `/api/traffic/ly/event`），列表与排行为**纯前端过滤**（`views/ly/event/list/index.vue`）。故关联筛选可纯客户端完成。
- 事件行字段 `attackDevice`/`victimDevice` 由后端 `lyCompatibleEvent` 产出（`event_service.go`）。
- traffic 路由挂在 `/api/traffic`、**不经过 IAM**；store 有 memory/postgres 双实现（`traffic/internal/store`）。

## 2. 关键决策（已与用户确认）

1. **关联筛选交互 = 两者都要**：事件列表可按资产筛选；资产管理页展示每个资产的关联事件数并可跳转到事件列表带筛选。
2. **匹配方向 = 威胁来源或受害目标任一命中**。
3. **资产字段 = 极简**：名称 + 类型(ip/domain_site) + 地址(IP或域名) + 所属单位 + 责任人 + 备注 + 状态。
4. **需要批量导入**（.csv / .xlsx）。
5. **匹配语义 = 精确相等**（trim + 小写），v1 不做域名子串模糊。
6. **关联事件数走客户端**（用已加载的事件计数）。
7. **跳转参数** `?asset=<address>`。

## 3. 后端（traffic）

### 3.1 资产数据模型 `domain.Asset`
```go
type Asset struct {
    ID        string    `json:"id"`
    Name      string    `json:"name"`
    AssetType string    `json:"asset_type"` // "ip" | "domain_site"
    Address   string    `json:"address"`    // IP 或 域名，存储时 trim+lower 归一化，唯一
    Unit      string    `json:"unit"`
    Owner     string    `json:"owner"`
    Status    int       `json:"status"`     // 1 启用 / 0 停用
    Remark    string    `json:"remark"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

### 3.2 表 `traffic_assets`（`store/schema.go`，postgres；memory 用 map）
```sql
CREATE TABLE IF NOT EXISTS traffic_assets (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(256) NOT NULL DEFAULT '',
    asset_type VARCHAR(32) NOT NULL DEFAULT 'ip',
    address VARCHAR(256) UNIQUE NOT NULL,
    unit VARCHAR(128) NOT NULL DEFAULT '',
    owner VARCHAR(128) NOT NULL DEFAULT '',
    status INTEGER NOT NULL DEFAULT 1,
    remark TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### 3.3 store.Store 新增方法（memory + postgres）
```go
CreateAsset(a domain.Asset) (domain.Asset, error)   // address 冲突返回错误
ListAssets() []domain.Asset
GetAsset(id string) (domain.Asset, bool)
UpdateAsset(id string, patch map[string]any) (domain.Asset, bool)
DeleteAsset(id string) bool
```
批量导入在 service 层循环调用 `CreateAsset`（重复 address 记为该行错误），不新增 store 方法。

### 3.4 AssetService + Handler + 路由
- `traffic/asset_service.go`：CRUD + 归一化 + 校验（name/address 必填；asset_type ∈ {ip,domain_site}；address 按类型基本校验：ip 类型是合法 IP、domain_site 是域名/URL 主机名）+ import 解析。
- `traffic/handler.go` 新增 handler；`traffic/traffic.go` 新增 `/assets` 组（与 `/events` 同层）：
  - `GET /assets/list`（可选 keyword/type/status 过滤，全量返回）
  - `POST /assets`、`PUT /assets/:id`、`DELETE /assets/:id`
  - `POST /assets/import`（multipart `file`，.csv/.xlsx）→ `{imported:int, errors:[{row,message}]}`
  - `GET /assets/import/template`（下载 CSV 模板）
- 装配：AssetService 依赖 `store.Store`，在 `NewTraffic` 注入（仿 EventService）。
- 导入：.xlsx 用 go.mod 已有 `github.com/xuri/excelize/v2`；.csv 用标准库 `encoding/csv`。

### 3.5 导入列（精简）
模板列（中文表头）：`资产名称`、`资产类型`(IP资产/域名网站)、`地址`、`所属单位`、`责任人`、`备注`。
- 资产类型别名：`IP资产`→`ip`、`域名网站`→`domain_site`。
- 逐行校验，失败行进 `errors`，成功行入库；返回汇总。

## 4. 关联匹配（前端工具）

`utils/ly-asset.ts`（新建）：
```ts
export function normalizeAddr(v?: string): string;           // trim + toLowerCase
export function assetMatchesEvent(asset, event): boolean;    // addr === attackDevice || === victimDevice（归一化后）
export function countAssetEvents(asset, events): number;     // 命中事件数
export function eventMatchesAnyAsset(event, assets): boolean;// 任一启用资产命中
```
匹配仅比对 `event.attackDevice` / `event.victimDevice` 与 `asset.address`（均归一化）。仅 `status===1` 的资产参与「仅看已登记资产相关事件」判断。

## 5. 前端页面与路由

### 5.1 路由/菜单
`router/routes/modules/traffic-analysis.ts` 新增子路由 `/ly/assets`（name `LyAssets`，菜单「资产管理」icon `lucide:server`/`lucide:database`，order 25，介于事件列表(20)与配置(30)之间）。

### 5.2 资产管理页 `views/ly/assets/index.vue`
- 表格列：名称 / 类型(IP/域名网站) / 地址 / 所属单位 / 责任人 / 状态(启用·停用 tag) / **关联事件数** / 操作(编辑·删除)。
- 筛选：关键词(名称或地址)、类型、状态。
- 新增·编辑 Modal（表单：名称·类型·地址·所属单位·责任人·备注·状态）。
- 导入 Modal：模板下载 + 文件上传 + 导入结果（成功数 + 错误明细行）。
- 关联事件数：页面加载时确保事件已加载（`lyStore.events`，必要时 `loadEvents()`），用 `countAssetEvents` 计算；点击数字/资产 → `router.push('/ly/event/list?asset=<address>')`。

### 5.3 API `api/ly/assets.ts`（或并入 `api/ly/index.ts`）
```ts
lyAssetList(params?)        // GET /api/traffic/assets/list
lyAssetCreate(data)         // POST /api/traffic/assets
lyAssetUpdate(id, data)     // PUT /api/traffic/assets/:id
lyAssetDelete(id)           // DELETE /api/traffic/assets/:id
lyAssetImport(file)         // POST /api/traffic/assets/import (multipart)
lyAssetTemplateUrl()        // GET /api/traffic/assets/import/template
```
复用现有 `post/get`（prefix `/api/traffic`）与 `createHeaders()` 的 Bearer。

### 5.4 事件列表集成 `views/ly/event/list/index.vue`
- 顶部筛选区新增：「按资产筛选」下拉（选已登记资产，来自 `lyAssetList`）+「仅看已登记资产相关事件」开关。
- `filteredRows` 增加资产过滤：选中某资产 → 仅保留该资产命中(威胁来源或受害目标)的事件；开关开启 → 仅保留命中任一启用资产的事件。
- 读取路由 `?asset=<address>` 作为初始选中资产（跳入场景）。
- （可选）命中已登记资产的行在威胁来源/受害目标处加「资产」小标记。

## 6. 测试

- 后端单测：
  - asset store（memory）CRUD + address 唯一冲突。
  - 地址归一化与类型校验（ip 合法性、domain_site 主机名）。
  - import 解析：csv 逐行、类型别名、缺失/非法行进 errors、成功计数。
- 前端单测（vitest 若可用，否则手工）：`assetMatchesEvent`/`countAssetEvents`/`eventMatchesAnyAsset`。
- 手工：资产增删改查、导入（模板→上传→结果）、事件列表按资产筛选与开关、资产页关联数与跳转。

## 7. 不做的事（YAGNI）

- 不复用/修改平台 `asset/`、`assetmgr/`、`model/` 模块。
- 不做资产分组/地域/组织树/等保/责任部门等台账复杂维度（仅极简字段）。
- 不做域名子串/CIDR 网段模糊匹配（v1 精确相等）。
- 不做后端事件-资产关联表与后端关联查询（关联计数/筛选走客户端）。
- 不做导出、批量编辑、批量删除、在线探测、截图等台账扩展能力。
