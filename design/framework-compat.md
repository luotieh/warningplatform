# 框架兼容性设计 (对齐 template 框架)

## 1. 概述

漏扫系统的后端开发需要与现有 `template` 框架保持架构一致，复用已有的基础设施层，确保：

- 与 IAM 系统无缝集成（认证/授权/审计）
- 遵循统一的代码组织约定
- 共享数据库/缓存/配置基础设施
- 新模块可以像 `example` 模块一样快速开发

### template 框架核心依赖

| 包 | 用途 |
|----|------|
| `code.yt-security.com/public/core/v2` | 基础框架 (web/db/cache/product) |
| `code.yt-security.com/public/core/v2/web` | Gin 封装、中间件、统一响应 |
| `code.yt-security.com/public/core/v2/db` | GORM 封装、多数据库支持 |
| `code.yt-security.com/public/core/v2/cache` | 缓存接口 (Redis/Memory) |
| `code.yt-security.com/public/core/v2/product` | 产品信息/版本管理 |
| `code.yt-security.com/public/sdk` | IAM SDK (认证中间件/授权/审计) |
| `code.yt-security.com/public/sdk/authorize` | 声明式路由 + BackendItem 注册 |
| `github.com/google/wire` | 依赖注入 |
| `github.com/gin-gonic/gin` | HTTP 路由 |
| `gorm.io/gorm` | ORM |

## 2. 项目结构对齐

### 2.1 template 框架约定

```
template-backend/
├── boot/                    # 基础设施初始化
│   ├── build.go            # 产品信息
│   ├── config.go           # 配置加载
│   ├── cache.go            # 缓存初始化
│   ├── database.go         # 数据库初始化
│   ├── iam.go              # IAM SDK 初始化
│   └── web.go              # Web 引擎初始化
├── cmd/server/             # 入口
├── di/                     # Wire 依赖注入
│   ├── handlers.go         # 聚合 + 路由注册
│   ├── wire.go             # Wire 定义
│   └── wire_gen.go         # Wire 生成
├── model/                  # 全局数据模型
├── example/                # 业务模块 (可替换)
│   ├── example.go          # 模块聚合入口 + RoutesWithGroup
│   ├── example-handler.go  # Handler
│   ├── example-service.go  # Service 实现
│   ├── example-contract/   # 接口契约
│   │   └── contract.go
│   ├── category/           # 子模块
│   │   ├── category.go
│   │   ├── category-handler.go
│   │   ├── category-service.go
│   │   ├── category-contract.go
│   │   └── wire.go
│   └── wire.go             # 模块 Wire Set
└── frontend/               # 前端静态文件嵌入
```

### 2.2 漏扫系统适配后结构

```
vulnscan-backend/
├── boot/                    # ★ 复用 template 框架约定
│   ├── build.go
│   ├── config.go           # 扩展: 增加扫描引擎、调度器等配置
│   ├── cache.go
│   ├── database.go
│   ├── iam.go
│   ├── web.go
│   ├── scheduler.go        # ★ 新增: 调度器初始化
│   ├── nats.go             # ★ 新增: NATS 初始化
│   └── clickhouse.go       # ★ 新增: ClickHouse 初始化
├── cmd/
│   ├── master/             # Master 节点入口
│   └── worker/             # Worker 节点入口
├── di/
│   ├── handlers.go         # ★ 聚合所有模块 + 路由
│   ├── wire.go
│   └── wire_gen.go
├── model/                  # 全局数据模型
│   ├── asset.go
│   ├── task.go
│   ├── vulnerability.go
│   ├── template.go
│   └── ...
│
│── ── 业务模块 (每个遵循 template 约定) ── ──
│
├── asset/                  # 资产管理模块
│   ├── asset.go            # 模块入口 + RoutesWithGroup
│   ├── asset-handler.go
│   ├── asset-service.go
│   ├── asset-contract/
│   │   └── contract.go
│   └── wire.go
├── task/                   # 任务管理模块
│   ├── task.go
│   ├── task-handler.go
│   ├── task-service.go
│   ├── task-contract/
│   └── wire.go
├── scan/                   # 扫描引擎模块
│   ├── scan.go
│   ├── engine/             # 核心引擎 (非HTTP，不注册路由)
│   │   ├── pipeline.go
│   │   ├── pool.go
│   │   └── limiter.go
│   ├── module/             # 各扫描模块
│   │   ├── portscan/
│   │   ├── fingerprint/
│   │   ├── sqli/
│   │   └── ...
│   └── wire.go
├── template/               # 扫描模板模块
│   ├── template.go
│   ├── template-handler.go
│   ├── template-service.go
│   ├── template-engine.go  # 模板引擎
│   ├── template-contract/
│   └── wire.go
├── vuln/                   # 漏洞管理模块
│   ├── vuln.go
│   ├── vuln-handler.go
│   ├── vuln-service.go
│   ├── vuln-contract/
│   └── wire.go
├── report/                 # 报告模块
├── asm/                    # 攻击面管理模块
├── compliance/             # 合规检查模块
├── plugin/                 # 插件管理模块 (含沙箱)
├── intel/                  # 漏洞情报模块
├── cluster/                # 集群管理模块
├── scheduler/              # 调度器 (非HTTP，供 di 初始化)
└── frontend/               # 前端嵌入
```

## 3. 配置扩展

### 3.1 扩展 Config 结构

在 template 的 `Config` 基础上扩展漏扫专有配置：

```go
package boot

import (
    "code.yt-security.com/public/core/v2/db"
    "code.yt-security.com/public/core/v2/web"
)

type Config struct {
    // ── 复用 template 框架配置 ──
    Web   web.Config  `json:"web" toml:"web"`
    DB    db.Config   `json:"db" toml:"db"`
    Cache CacheConfig `json:"cache" toml:"cache"`
    IAM   IAMConfig   `json:"iam" toml:"iam"`
    SSO   SSOConfig   `json:"sso" toml:"sso"`

    // ── 漏扫扩展配置 ──
    Scanner    ScannerConfig    `json:"scanner" toml:"scanner"`
    Scheduler  SchedulerConfig  `json:"scheduler" toml:"scheduler"`
    NATS       NATSConfig       `json:"nats" toml:"nats"`
    ClickHouse ClickHouseConfig `json:"clickhouse" toml:"clickhouse"`
    Sandbox    SandboxConfig    `json:"sandbox" toml:"sandbox"`
}

type ScannerConfig struct {
    Mode            string `json:"mode" toml:"mode"`               // master, worker, standalone
    WorkerPoolSize  int    `json:"worker_pool_size" toml:"worker_pool_size"`
    MaxConcurrency  int    `json:"max_concurrency" toml:"max_concurrency"`
    PluginDir       string `json:"plugin_dir" toml:"plugin_dir"`
    TemplateDir     string `json:"template_dir" toml:"template_dir"`
}

type SchedulerConfig struct {
    Enabled        bool   `json:"enabled" toml:"enabled"`
    RedisQueue     string `json:"redis_queue" toml:"redis_queue"`
    PollInterval   string `json:"poll_interval" toml:"poll_interval"`
    MaxRetries     int    `json:"max_retries" toml:"max_retries"`
}

type NATSConfig struct {
    URL      string `json:"url" toml:"url"`
    Token    string `json:"token" toml:"token"`
    Cluster  string `json:"cluster" toml:"cluster"`
}

type ClickHouseConfig struct {
    DSN string `json:"dsn" toml:"dsn"`
}

type SandboxConfig struct {
    DefaultLevel    string `json:"default_level" toml:"default_level"`
    MaxMemoryPerPoc string `json:"max_memory_per_poc" toml:"max_memory_per_poc"`
    MaxExecTime     string `json:"max_exec_time" toml:"max_exec_time"`
    DenyPrivateNet  bool   `json:"deny_private_net" toml:"deny_private_net"`
}
```

### 3.2 对应 TOML 配置文件

```toml
# ── 基础配置 (与 template 保持一致) ──
[web]
port = 8080
mode = "release"

[db]
driver = "postgres"
dsn = "host=localhost user=vulnscan password=xxx dbname=vulnscan port=5432 sslmode=disable"

[cache]
host = "localhost"
port = 6379
password = ""
db = 0
prefix = "vs:"

[iam]
base_url = "https://iam.example.com"
client_id = "vulnscan"
client_secret = "xxx"
path_prefix = "/api"

[sso]
callback_uri = "/auth/callback"
success_redirect = "/"
cookie_secret = "xxx"

# ── 漏扫扩展配置 ──
[scanner]
mode = "standalone"     # master / worker / standalone
worker_pool_size = 100
max_concurrency = 50
plugin_dir = "./plugins"
template_dir = "./templates"

[scheduler]
enabled = true
redis_queue = "vs:task:queue"
poll_interval = "1s"
max_retries = 3

[nats]
url = "nats://localhost:4222"
token = ""
cluster = "vulnscan"

[clickhouse]
dsn = "clickhouse://localhost:9000/vulnscan"

[sandbox]
default_level = "L1"
max_memory_per_poc = "64MB"
max_exec_time = "60s"
deny_private_net = true
```

## 4. 模块开发约定

### 4.1 模块结构模板

每个业务模块严格遵循以下结构（以 `asset` 模块为例）：

```
asset/
├── asset.go              # 模块聚合入口
├── asset-handler.go      # HTTP Handler
├── asset-service.go      # Service 实现
├── asset-contract/       # 接口契约 (解耦 handler 和 service)
│   └── contract.go
├── sub-module/           # 可选子模块 (嵌套路由)
│   ├── sub.go
│   ├── sub-handler.go
│   ├── sub-service.go
│   ├── sub-contract.go
│   └── wire.go
└── wire.go               # Wire Provider Set
```

### 4.2 模块聚合入口 (遵循 template 的 example.go 模式)

```go
package asset

import (
    "vulnscan-backend/model"

    "code.yt-security.com/public/core/v2/db"
    "code.yt-security.com/public/sdk/authorize"
    "github.com/gin-gonic/gin"
)

type Asset struct {
    handler *HandlerAsset
}

func NewAsset(handler *HandlerAsset, database *db.DB) *Asset {
    initModel(database)
    return &Asset{handler: handler}
}

func (m *Asset) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
    return authorize.RegisterRoutes(e.Group("/asset"), []authorize.Route{
        {
            Name: "资产管理", Enabled: true,
            Children: []authorize.Route{
                {Name: "资产列表", Path: "list", Method: "GET", Handler: m.handler.List, Enabled: true},
                {Name: "资产详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
                {Name: "创建资产", Method: "POST", Handler: m.handler.Create, Enabled: true},
                {Name: "更新资产", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
                {Name: "删除资产", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},
                {Name: "批量导入", Path: "import", Method: "POST", Handler: m.handler.Import, Enabled: true},
                {Name: "资产导出", Path: "export", Method: "GET", Handler: m.handler.Export, Enabled: true},
            },
        },
    })
}

func initModel(database *db.DB) {
    session, _ := database.GetDBSession()
    _ = session.AutoMigrate(
        &model.Asset{},
        &model.AssetGroup{},
        &model.AssetTag{},
    )
}
```

### 4.3 Handler (遵循 template 的 web.Resp 响应约定)

```go
package asset

import (
    "strconv"

    assetContract "vulnscan-backend/asset/asset-contract"
    "vulnscan-backend/model"

    "code.yt-security.com/public/core/v2/web"
    iamsdk "code.yt-security.com/public/sdk"
    "code.yt-security.com/public/sdk/permission"
    "github.com/gin-gonic/gin"
)

type HandlerAsset struct {
    svc assetContract.ServiceAsset
}

func NewHandlerAsset(svc assetContract.ServiceAsset) *HandlerAsset {
    return &HandlerAsset{svc: svc}
}

func (h *HandlerAsset) List(c *gin.Context) {
    var query assetContract.AssetQuery
    if err := c.ShouldBindQuery(&query); err != nil {
        web.Resp(c, web.ParamsMissingRequired)
        return
    }

    scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
    items, count, err := h.svc.List(query, scope)
    if err != nil {
        web.Resp(c, web.InternalError)
        return
    }

    web.RespContentWithNum(c, web.Success, count, items)
}

func (h *HandlerAsset) GetByID(c *gin.Context) {
    id := c.Param("id")
    if id == "" {
        web.Resp(c, web.ParamsMissingRequired)
        return
    }

    item, err := h.svc.GetByID(id)
    if err != nil {
        web.Resp(c, web.NotFound)
        return
    }

    web.RespContent(c, web.Success, item)
}

func (h *HandlerAsset) Create(c *gin.Context) {
    var req assetContract.CreateAssetReq
    if !web.ValidationJson(c, &req) {
        return
    }

    user, _ := iamsdk.GetCurrentUser(c)

    item := model.Asset{
        Name:       req.Name,
        Type:       req.Type,
        Address:    req.Address,
        CreatedBy:  user.UserID,
        OrganizeID: user.OrganizeID,
    }

    if err := h.svc.Create(&item); err != nil {
        web.Resp(c, web.InternalError)
        return
    }

    web.RespContent(c, web.Success, item)
}
```

### 4.4 Contract (接口契约)

```go
package assetContract

import (
    "vulnscan-backend/model"
    "gorm.io/gorm"
)

type AssetQuery struct {
    Page     int    `form:"page"`
    PageSize int    `form:"page_size"`
    Keyword  string `form:"keyword"`
    Type     string `form:"type"`
    GroupID  string `form:"group_id"`
    TagID    string `form:"tag_id"`
}

type CreateAssetReq struct {
    Name    string `json:"name" binding:"required"`
    Type    string `json:"type" binding:"required"`
    Address string `json:"address" binding:"required"`
    Tags    []string `json:"tags"`
}

type ServiceAsset interface {
    List(query AssetQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Asset, int64, error)
    GetByID(id string) (*model.Asset, error)
    Create(item *model.Asset) error
    Update(id string, updates map[string]any) error
    Delete(id string) error
    Import(items []*model.Asset) (int, error)
}
```

### 4.5 Wire Set

```go
package asset

import (
    assetContract "vulnscan-backend/asset/asset-contract"
    "github.com/google/wire"
)

var WireSet = wire.NewSet(
    NewServiceAsset,
    NewHandlerAsset,
    NewAsset,
    wire.Bind(new(assetContract.ServiceAsset), new(*serviceAsset)),
)
```

## 5. DI 聚合 (handlers.go)

### 5.1 Handlers 结构

```go
package di

import (
    "context"
    "log/slog"
    "time"

    "vulnscan-backend/boot"
    "vulnscan-backend/asset"
    "vulnscan-backend/task"
    "vulnscan-backend/vuln"
    "vulnscan-backend/template"
    "vulnscan-backend/report"
    "vulnscan-backend/asm"
    "vulnscan-backend/compliance"
    "vulnscan-backend/plugin"
    "vulnscan-backend/intel"
    "vulnscan-backend/cluster"
    "vulnscan-backend/frontend"

    "code.yt-security.com/public/core/v2/cache"
    "code.yt-security.com/public/core/v2/db"
    "code.yt-security.com/public/core/v2/product"
    "code.yt-security.com/public/core/v2/web"
    iamsdk "code.yt-security.com/public/sdk"
    "code.yt-security.com/public/sdk/authorize"
)

type Handlers struct {
    Config     *boot.Config
    Web        *web.Web
    DB         *db.DB
    Cache      cache.Cache
    Product    *product.SystemProduct
    IAM        *iamsdk.Client

    // ── 业务模块 ──
    Asset      *asset.Asset
    Task       *task.Task
    Vuln       *vuln.Vuln
    Template   *template.Template
    Report     *report.Report
    ASM        *asm.ASM
    Compliance *compliance.Compliance
    Plugin     *plugin.Plugin
    Intel      *intel.Intel
    Cluster    *cluster.Cluster
}

func (h *Handlers) RouteLoad() {
    engine := h.Web.GetRawWeb()
    engine.Use(web.MiddlewareRequestResponse())

    authGroup := engine.Group("/",
        h.IAM.Middleware().Authentication(),
        h.IAM.Middleware().Authorization(),
    )

    var ssoOpts *iamsdk.SSORoutesOptions
    if h.Config.SSO.CallbackURI != "" {
        ssoOpts = &iamsdk.SSORoutesOptions{
            CallbackURI:           h.Config.SSO.CallbackURI,
            SuccessRedirect:       h.Config.SSO.SuccessRedirect,
            CookieSecret:          []byte(h.Config.SSO.CookieSecret),
            TokenRelayCallbackURI: h.Config.SSO.TokenRelayCallbackURI,
        }
    }
    h.IAM.RegisterDefaultRoutes(engine, authGroup, iamsdk.DefaultRoutesOptions{
        SSO: ssoOpts,
        Audit: &iamsdk.AuditMiddlewareOptions{
            Domain:  h.Product.GetCode(),
            Enabled: true,
        },
    })

    // ── 注册所有模块路由 ──
    var backends []authorize.BackendItem
    backends = append(backends, h.Asset.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Task.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Vuln.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Template.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Report.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.ASM.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Compliance.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Plugin.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Intel.RoutesWithGroup(authGroup)...)
    backends = append(backends, h.Cluster.RoutesWithGroup(authGroup)...)

    h.syncBackends(backends)

    frontend.SetupSPA(engine, web.MiddlewareNotFound())
}

func (h *Handlers) syncBackends(backends []authorize.BackendItem) {
    if len(backends) == 0 || h.Config.IAM.ClientID == "" {
        return
    }
    ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
    defer cancel()
    if err := h.IAM.Authorize.SyncBackends(ctx, h.Config.IAM.ClientID, backends); err != nil {
        slog.Error("sync backends to IAM failed", "err", err)
        return
    }
    slog.Info("[+] 后端接口已同步到 IAM", "count", len(backends))
}

func (h *Handlers) Shutdown() {
    h.IAM.Close()
}
```

### 5.2 Wire 定义

```go
//go:build wireinject

package di

import (
    "vulnscan-backend/boot"
    "vulnscan-backend/asset"
    "vulnscan-backend/task"
    "vulnscan-backend/vuln"
    "vulnscan-backend/template"
    "vulnscan-backend/report"
    "vulnscan-backend/asm"
    "vulnscan-backend/compliance"
    "vulnscan-backend/plugin"
    "vulnscan-backend/intel"
    "vulnscan-backend/cluster"

    "github.com/google/wire"
)

func InitializeHandlers() *Handlers {
    wire.Build(
        // 基础设施 (与 template 完全一致)
        boot.LoadConfig,
        boot.LoadProduct,
        boot.LoadCache,
        boot.LoadWeb,
        boot.LoadDB,
        boot.LoadIAM,

        // 扩展基础设施
        boot.LoadScheduler,
        boot.LoadNATS,
        boot.LoadClickHouse,

        // 业务模块
        asset.WireSet,
        task.WireSet,
        vuln.WireSet,
        template.WireSet,
        report.WireSet,
        asm.WireSet,
        compliance.WireSet,
        plugin.WireSet,
        intel.WireSet,
        cluster.WireSet,

        wire.Struct(new(Handlers), "*"),
    )
    return nil
}
```

## 6. 数据模型约定

### 6.1 GORM 模型规范 (对齐 template)

```go
package model

import "time"

type Asset struct {
    ID          string    `gorm:"primarykey;type:varchar(36)" json:"id"`
    Name        string    `gorm:"type:varchar(200);not null" json:"name"`
    Type        string    `gorm:"type:varchar(50);index" json:"type"`
    Address     string    `gorm:"type:varchar(500);not null" json:"address"`
    Status      int       `gorm:"default:1;comment:1=活跃 0=不活跃" json:"status"`
    CreatedBy   string    `gorm:"type:varchar(64)" json:"created_by"`
    OrganizeID  string    `gorm:"type:varchar(64);index" json:"organize_id"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

func (Asset) TableName() string {
    return "vs_asset"  // 前缀 vs_ 区别于其他系统
}
```

### 6.2 表名前缀约定

| 系统 | 前缀 | 说明 |
|------|------|------|
| template (示例) | `biz_` | 业务表 |
| 漏扫系统 | `vs_` | vulnscan 缩写 |

### 6.3 公共字段

所有业务表必须包含以下字段（与 template 的 `CreatedBy` + `OrganizeID` 一致，支持 IAM 数据权限过滤）：

```go
type BaseModel struct {
    ID         string    `gorm:"primarykey;type:varchar(36)" json:"id"`
    CreatedBy  string    `gorm:"type:varchar(64)" json:"created_by"`
    OrganizeID string    `gorm:"type:varchar(64);index" json:"organize_id"`
    CreatedAt  time.Time `json:"created_at"`
    UpdatedAt  time.Time `json:"updated_at"`
}
```

## 7. IAM 集成细节

### 7.1 认证中间件

复用 IAM SDK 的认证中间件，所有 API 自动获得：

- JWT Token 验证
- 用户身份解析 (`iamsdk.GetCurrentUser(c)`)
- 会话管理

### 7.2 授权 (声明式路由)

通过 `authorize.RegisterRoutes` 注册的路由自动具备：

- **接口级鉴权**：IAM 控制台配置角色-权限映射
- **数据级过滤**：`iamsdk.DataFilterScope(c, fieldMapping)` 自动注入 GORM scope

### 7.3 审计日志

通过 `AuditMiddlewareOptions` 配置后，所有写操作自动记录到 IAM 审计日志。

### 7.4 BackendItem 同步

启动时自动将所有注册的路由同步到 IAM，IAM 管理员可以在控制台看到漏扫系统的所有 API 并配置权限。

## 8. 双节点模式适配

### 8.1 Master 节点 (Web API + 调度)

```go
// cmd/master/main.go
func main() {
    h := di.InitializeHandlers()
    h.RouteLoad()

    // 启动调度器
    h.StartScheduler()

    // 启动 Web 服务
    h.Web.Run()

    // 优雅关闭
    h.Shutdown()
}
```

### 8.2 Worker 节点 (无 HTTP，纯消费)

```go
// cmd/worker/main.go
func main() {
    w := di.InitializeWorker()

    // Worker 不注册 HTTP 路由
    // 仅连接 NATS/Redis 消费任务队列
    w.Start()
    w.WaitForShutdown()
}
```

### 8.3 Standalone 模式 (单节点)

```go
// cmd/standalone/main.go
func main() {
    h := di.InitializeHandlers()
    h.RouteLoad()

    // 内嵌调度器 + Worker
    h.StartScheduler()
    h.StartEmbeddedWorker()

    h.Web.Run()
    h.Shutdown()
}
```

## 9. 数据库兼容性

### 9.1 主库 (复用 core/v2/db)

template 框架的 `db.DB` 封装支持 PostgreSQL/MySQL/SQLite，漏扫系统直接复用：

```go
func LoadDB(config *Config) *db.DB {
    db1, err := db.NewDB(config.DB)
    if err != nil {
        panic("数据库初始化失败: " + err.Error())
    }
    return db1
}
```

### 9.2 扩展存储

ClickHouse (时序数据) 和 MinIO (文件存储) 作为额外初始化，不影响核心 `db.DB`：

```go
func LoadClickHouse(config *Config) *clickhouse.Client {
    if config.ClickHouse.DSN == "" {
        return nil // ClickHouse 可选
    }
    // ...
}
```

## 10. 新模块开发清单

创建一个新的漏扫业务模块时，按以下清单操作：

```
□ 1. 创建模块目录: vulnscan-backend/<module>/
□ 2. 创建 contract: <module>/<module>-contract/contract.go (定义 Service 接口)
□ 3. 创建 model: model/<entity>.go (GORM 模型，表前缀 vs_)
□ 4. 创建 service: <module>/<module>-service.go (实现 contract 接口)
□ 5. 创建 handler: <module>/<module>-handler.go (使用 web.Resp 系列)
□ 6. 创建 entry: <module>/<module>.go (NewXxx + RoutesWithGroup)
□ 7. 创建 wire.go: <module>/wire.go (WireSet)
□ 8. 注册到 di/wire.go: 添加 <module>.WireSet
□ 9. 注册到 di/handlers.go: 
     - Handlers 结构体添加字段
     - RouteLoad() 添加 RoutesWithGroup 调用
□ 10. 运行 wire: cd di && wire
□ 11. 验证: go build ./...
```

## 11. 前端兼容

漏扫前端同样基于 `template-frontend` 结构：

```
vulnscan-frontend/
├── apps/web/              # 与 template-frontend 同构
│   ├── src/
│   │   ├── api/           # API 调用层
│   │   ├── views/         # 页面
│   │   ├── router/        # 路由
│   │   └── ...
│   └── vite.config.mts
├── packages/              # 复用 template 的 packages
└── pnpm-workspace.yaml
```

与 IAM 前端集成点：
- 复用 `@core` 的组件库和布局
- 路由鉴权通过 IAM SDK 获取用户权限
- 菜单根据 IAM 分配的前端菜单权限动态渲染
