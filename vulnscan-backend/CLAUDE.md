# CLAUDE.md - 子系统后端开发指南

Go + Gin + GORM + Wire DI | IAM SDK：`code.yt-security.com/public/sdk` | 核心库：`code.yt-security.com/public/core/v2`

## 构建

```bash
go run ./cmd/server/         # 开发
go build -o server.exe ./cmd # 编译
```

---

## RESTful API 设计规范

接口设计必须遵循 RESTful 风格：

### 路径命名

- **资源名使用复数名词**：`/orders`、`/users`、`/categories`
- **禁止在路径中出现动词**：用 HTTP Method 表达动作
- **子资源嵌套**：`/orders/:id/items`、`/examples/:id/categories`
- **路径使用 kebab-case**：`/risk-cases`、`/audit-logs`

### 标准 CRUD 映射

| 操作 | Method | 路径 | 说明 |
|------|--------|------|------|
| 列表 | GET | `/resources` | 分页查询，参数通过 Query 传递 |
| 详情 | GET | `/resources/:id` | 获取单条记录 |
| 创建 | POST | `/resources` | 请求体传 JSON |
| 更新 | PUT | `/resources/:id` | 全量/部分更新 |
| 删除 | DELETE | `/resources/:id` | 删除单条记录 |

### 非 CRUD 操作

对于不符合标准 CRUD 的动作，使用子资源或动作路径：

```
POST   /orders/:id/cancel        # 取消订单
POST   /orders/:id/approve       # 审批
POST   /resources/batch-delete    # 批量删除
POST   /resources/import          # 导入
GET    /resources/export          # 导出
```

---

## 参数绑定（必须使用 `web.Bind*` 系列）

**禁止直接使用 `c.ShouldBind*`、`c.Param` + `strconv` 手动解析。** 必须使用 core/web 包提供的泛型绑定函数，它们在校验失败时自动返回标准错误响应。

### 泛型绑定函数一览

| 函数 | 用途 | 数据来源 |
|------|------|---------|
| `web.BindJSON[T](c)` | 绑定 JSON 请求体 | Body |
| `web.BindQuery[T](c)` | 绑定 Query 参数 | URL Query |
| `web.BindUri[T](c)` | 绑定 URI 路径参数 | URL Path |
| `web.BindForm[T](c)` | 绑定 Form 表单 | Form Data |
| `web.BindJSONUri[T](c)` | 组合绑定 JSON + URI | Body + Path |
| `web.BindQueryUri[T](c)` | 组合绑定 Query + URI | Query + Path |

### 用法

```go
// ✅ 正确：使用泛型绑定
func (h *Handler) List(c *gin.Context) {
    query, ok := web.BindQuery[ListQuery](c)
    if !ok { return }
    // ...
}

func (h *Handler) GetByID(c *gin.Context) {
    uri, ok := web.BindUri[web.Id](c)
    if !ok { return }
    // 使用 uri.Id（string 类型）
}

func (h *Handler) Create(c *gin.Context) {
    req, ok := web.BindJSON[CreateReq](c)
    if !ok { return }
    // ...
}

func (h *Handler) Update(c *gin.Context) {
    uri, ok := web.BindUri[web.Id](c)
    if !ok { return }
    req, ok := web.BindJSON[UpdateReq](c)
    if !ok { return }
    // 使用 uri.Id + req
}

// ❌ 错误：手动解析
func (h *Handler) Bad(c *gin.Context) {
    id, err := strconv.ParseUint(c.Param("id"), 10, 64)  // 禁止
    var req MyReq
    if err := c.ShouldBindJSON(&req); err != nil { ... }  // 禁止
}
```

### 预定义绑定结构体

core/web 包提供常用的绑定结构体，直接使用：

```go
web.Id       // { Id string `uri:"id" binding:"required"` }
web.IdNoBind // { Id string `uri:"id"` }  -- 不带必填校验
web.Page     // { Index int `form:"index"`, Size int `form:"size" binding:"lte=100"` }
```

### 请求结构体定义规范

```go
// Query 参数 -- 使用 form tag
type ListQuery struct {
    Index   int    `form:"index"`
    Size    int    `form:"size" binding:"lte=100"`
    Keyword string `form:"keyword"`
    Status  *int   `form:"status"`
}

// JSON 请求体 -- 使用 json tag + binding 校验
type CreateReq struct {
    Name        string `json:"name" binding:"required"`
    Description string `json:"description"`
}

// 部分更新 -- 字段使用指针，nil 表示不更新
type UpdateReq struct {
    Name        *string `json:"name"`
    Description *string `json:"description"`
    Status      *int    `json:"status"`
}
```

---

## 模块目录结构

每个业务模块遵循以下约定：

```
<module>/
  ├── <module>.go              # 模块入口：NewXxx() + RoutesWithGroup()
  ├── wire.go                  # Wire 提供者集合（var WireSet = wire.NewSet(...)）
  ├── <module>-handler.go      # HTTP 处理器
  ├── <module>-service.go      # 业务逻辑 + 数据访问
  ├── <module>-contract/       # 服务接口定义（依赖倒置）
  │   └── contract.go
  └── <sub-module>/            # 子模块（可选，嵌入父模块路由树）
      ├── <sub>.go             # Routes() 返回声明
      ├── <sub>-handler.go
      ├── <sub>-service.go
      ├── <sub>-contract.go
      └── wire.go
```

---

## 路由注册（authorize.RegisterRoutes）

**使用 IAM SDK 的声明式路由注册，一次声明同时完成 Gin 路由挂载和 IAM 接口元数据收集。**

### 标准模式（`RoutesWithGroup`）

```go
func (m *MyModule) RoutesWithGroup(e *gin.RouterGroup) []authorize.BackendItem {
    return authorize.RegisterRoutes(e.Group("/orders"), []authorize.Route{
        {
            Name: "订单管理", Enabled: true,
            Children: []authorize.Route{
                {Name: "订单列表", Method: "GET", Handler: m.handler.List, Enabled: true},
                {Name: "订单详情", Path: ":id", Method: "GET", Handler: m.handler.GetByID, Enabled: true},
                {Name: "创建订单", Method: "POST", Handler: m.handler.Create, Enabled: true},
                {Name: "更新订单", Path: ":id", Method: "PUT", Handler: m.handler.Update, Enabled: true},
                {Name: "删除订单", Path: ":id", Method: "DELETE", Handler: m.handler.Delete, Enabled: true},

                // 子资源
                {
                    Name: "订单项", Path: "items", Enabled: true,
                    Children: m.itemHandler.Routes(),
                },
            },
        },
    })
}
```

### 子模块 Routes() 声明

子模块不直接创建 RouterGroup，而是返回 `[]authorize.Route` 由父模块组合：

```go
func (h *HandlerItem) Routes() []authorize.Route {
    return []authorize.Route{
        {Name: "列表", Method: "GET", Handler: h.List, Enabled: true},
        {Name: "创建", Method: "POST", Handler: h.Create, Enabled: true},
        {Name: "更新", Path: ":id", Method: "PUT", Handler: h.Update, Enabled: true},
        {Name: "删除", Path: ":id", Method: "DELETE", Handler: h.Delete, Enabled: true},
    }
}
```

### 路由聚合（di/handlers.go）

所有模块的路由在 `RouteLoad()` 中汇总并同步到 IAM：

```go
func (h *Handlers) RouteLoad() {
    engine := h.Web.GetRawWeb()
    engine.Use(web.MiddlewareRequestResponse())

    apiGroup := engine.Group("/api")
    authGroup := apiGroup.Group("/",
        h.IAM.Middleware().Authentication(),
        h.IAM.Middleware().Authorization(),
    )

    h.IAM.RegisterDefaultRoutes(engine, authGroup, iamsdk.DefaultRoutesOptions{...})

    var backends []authorize.BackendItem
    backends = append(backends, h.Order.RoutesWithGroup(authGroup)...)
    // ★ 追加新模块路由

    h.syncBackends(backends)
    frontend.SetupSPA(engine, web.MiddlewareNotFound())
}
```

**重要**：所有业务路由注册在 `authGroup`（即 `/api/` 下），前端 `VITE_GLOB_API_URL=/api` 与之对应。

---

## Handler 模式

```go
type HandlerOrder struct {
    svc orderContract.ServiceOrder
}

func NewHandlerOrder(svc orderContract.ServiceOrder) *HandlerOrder {
    return &HandlerOrder{svc: svc}
}

func (h *HandlerOrder) List(c *gin.Context) {
    query, ok := web.BindQuery[orderContract.ListQuery](c)
    if !ok {
        return
    }

    scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
    items, count, err := h.svc.List(query, scope)
    if err != nil {
        web.Fail(c).Err(err).Send()
        return
    }
    web.OK(c).List(count, items).Send()
}

func (h *HandlerOrder) GetByID(c *gin.Context) {
    uri, ok := web.BindUri[web.Id](c)
    if !ok {
        return
    }

    item, err := h.svc.GetByID(uri.Id)
    if err != nil {
        web.Err(c, web.NotFound).Send()
        return
    }
    web.OK(c).Data(item).Send()
}

func (h *HandlerOrder) Create(c *gin.Context) {
    req, ok := web.BindJSON[CreateOrderReq](c)
    if !ok {
        return
    }

    user, _ := iamsdk.GetCurrentUser(c)
    item := model.Order{
        Name:       req.Name,
        CreatedBy:  user.UserID,
        OrganizeID: user.OrganizeID,
    }

    if err := h.svc.Create(&item); err != nil {
        web.Fail(c).Err(err).Send()
        return
    }
    web.OK(c).Data(item).Send()
}

func (h *HandlerOrder) Update(c *gin.Context) {
    uri, ok := web.BindUri[web.Id](c)
    if !ok {
        return
    }
    req, ok := web.BindJSON[UpdateOrderReq](c)
    if !ok {
        return
    }

    updates := make(map[string]any)
    if req.Name != nil {
        updates["name"] = *req.Name
    }
    if len(updates) == 0 {
        web.Resp(c, web.ParamsMissingRequired)
        return
    }
    if err := h.svc.Update(uri.Id, updates); err != nil {
        web.Fail(c).Err(err).Send()
        return
    }
    web.OK(c).Send()
}

func (h *HandlerOrder) Delete(c *gin.Context) {
    uri, ok := web.BindUri[web.Id](c)
    if !ok {
        return
    }
    if err := h.svc.Delete(uri.Id); err != nil {
        web.Fail(c).Err(err).Send()
        return
    }
    web.OK(c).Send()
}
```

### 响应构建

优先使用链式 API：

```go
web.OK(c).Data(item).Send()                    // 成功 - 返回数据
web.OK(c).Send()                               // 成功 - 无数据
web.OK(c).Msg("操作完成").Send()                // 成功 - 带消息
web.OK(c).List(total, items).Send()            // 成功 - 列表（带 count）

web.Fail(c).Err(err).Send()                    // 失败 - 包装 error
web.Fail(c).Msg("参数无效").Send()              // 失败 - 自定义消息
web.Err(c, web.NotFound).Msg("资源不存在").Send() // 失败 - 指定错误码
```

### 泛型 Handler（进阶，适合简单场景）

```go
// 自动绑定 JSON + 返回响应
router.POST("/orders", web.Handle[CreateReq, Order](func(c *gin.Context, req CreateReq) (Order, error) {
    return service.Create(req)
}))

// 列表查询
router.GET("/orders", web.HandleList[ListReq, Order](func(c *gin.Context, req ListReq) ([]Order, int64, error) {
    return service.List(req)
}))

// 无请求体
router.GET("/orders/:id", web.HandleNoReq[Order](func(c *gin.Context) (Order, error) {
    return service.GetByID(c.Param("id"))
}))

// 无响应数据
router.DELETE("/orders/:id", web.HandleAction(func(c *gin.Context) error {
    return service.Delete(c.Param("id"))
}))
```

---

## Service 模式

```go
type serviceOrder struct {
    db *db.DB
}

func NewServiceOrder(database *db.DB) *serviceOrder {
    return &serviceOrder{db: database}
}

func (s *serviceOrder) session() *gorm.DB {
    session, _ := s.db.GetDBSession()
    return session
}

func (s *serviceOrder) List(query ListQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Order, int64, error) {
    var items []model.Order
    var count int64

    tx := s.session().Model(&model.Order{}).Scopes(scopes...)

    if query.Keyword != "" {
        tx = tx.Where("name LIKE ?", "%"+query.Keyword+"%")
    }

    if err := tx.Count(&count).Error; err != nil {
        return nil, 0, err
    }

    page := query.Index
    if page <= 0 { page = 1 }
    size := query.Size
    if size <= 0 || size > 100 { size = 20 }
    offset := (page - 1) * size

    if err := tx.Offset(offset).Limit(size).Order("id DESC").Find(&items).Error; err != nil {
        return nil, 0, err
    }

    return items, count, nil
}

func (s *serviceOrder) GetByID(id string) (*model.Order, error) {
    var item model.Order
    if err := s.session().First(&item, "id = ?", id).Error; err != nil {
        return nil, err
    }
    return &item, nil
}

func (s *serviceOrder) Create(item *model.Order) error {
    return s.session().Create(item).Error
}

func (s *serviceOrder) Update(id string, updates map[string]any) error {
    return s.session().Model(&model.Order{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceOrder) Delete(id string) error {
    return s.session().Where("id = ?", id).Delete(&model.Order{}).Error
}
```

### Contract 接口

```go
// order/order-contract/contract.go
type ListQuery struct {
    Index   int    `form:"index"`
    Size    int    `form:"size" binding:"lte=100"`
    Keyword string `form:"keyword"`
}

type ServiceOrder interface {
    List(query ListQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.Order, int64, error)
    GetByID(id string) (*model.Order, error)
    Create(item *model.Order) error
    Update(id string, updates map[string]any) error
    Delete(id string) error
}
```

---

## Model 定义规范

```go
type Order struct {
    ID          uint      `gorm:"primarykey" json:"id"`
    Name        string    `gorm:"type:varchar(200);not null" json:"name" binding:"required"`
    Description string    `gorm:"type:text" json:"description"`
    Status      int       `gorm:"default:1;comment:1=启用 0=禁用" json:"status"`
    CreatedBy   string    `gorm:"type:varchar(64)" json:"created_by"`
    OrganizeID  string    `gorm:"type:varchar(64);index" json:"organize_id"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

func (Order) TableName() string {
    return "biz_order"  // 表名加模块前缀避免冲突
}
```

- 使用 `binding:"required"` 配合 `web.BindJSON` 自动校验
- 表名加模块前缀避免冲突（如 `biz_order`、`biz_task`）
- ID 可使用自增 uint 或 UUID/ULID（`generate/qulid`、`generate/quuid`）
- `CreatedBy` 和 `OrganizeID` 通过 `iamsdk.GetCurrentUser(c)` 获取

---

## 数据表初始化

在模块 `NewXxx()` 中自动迁移表结构：

```go
func NewMyModule(handler *HandlerOrder, database *db.DB) *MyModule {
    session, _ := database.GetDBSession()
    _ = session.AutoMigrate(&model.Order{})
    return &MyModule{handler: handler}
}
```

---

## Wire / 依赖注入

每个模块暴露一个 `WireSet`：

```go
// order/wire.go
var WireSet = wire.NewSet(
    NewServiceOrder,
    NewHandlerOrder,
    NewOrderModule,
    wire.Bind(new(orderContract.ServiceOrder), new(*serviceOrder)),
)
```

在 `di/wire.go` 中注册：

```go
func InitializeHandlers() *Handlers {
    wire.Build(
        boot.LoadConfig,
        boot.LoadProduct,
        boot.LoadCache,
        boot.LoadWeb,
        boot.LoadDB,
        boot.LoadIAM,
        order.WireSet,
        wire.Struct(new(Handlers), "Config", "Web", "DB", "Cache", "Product", "IAM", "Order"),
    )
    return nil
}
```

修改 `wire.go` 后重新生成：`wire ./di/...`

---

## IAM SDK 集成

### 认证与授权中间件

```go
authGroup := apiGroup.Group("/",
    h.IAM.Middleware().Authentication(),
    h.IAM.Middleware().Authorization(),
)
```

### 获取当前用户

```go
user, ok := iamsdk.GetCurrentUser(c)
// user.UserID, user.Account, user.OrganizeID, user.DepartmentID
```

### 数据权限过滤

```go
scope := iamsdk.DataFilterScope(c, permission.DefaultFieldMapping)
items, count, err := h.svc.List(query, scope)
```

### 接口同步到 IAM

`RouteLoad()` 末尾调用 `syncBackends()` 将收集到的 `[]authorize.BackendItem` 推送到 IAM，实现接口级权限控制。

---

## 新增模块清单

1. 创建模块目录：`mymodule/`，包含 handler、service、contract、wire.go
2. 在 `model/` 中定义 GORM 模型
3. 在 `mymodule-contract/` 中定义服务接口
4. 实现 Service + Handler（使用 `web.Bind*` 绑定参数，RESTful 路径风格）
5. 创建模块入口 `mymodule.go`，包含 `NewMyModule()` + `RoutesWithGroup()`（资源名复数）
6. 创建 `wire.go`，定义 `WireSet`
7. 在 `di/handlers.go` 的 `Handlers` struct 中追加字段
8. 在 `di/handlers.go` 的 `RouteLoad()` 中追加 `backends = append(backends, h.MyModule.RoutesWithGroup(authGroup)...)`
9. 在 `di/wire.go` 的 `wire.Build()` 中追加 `mymodule.WireSet`，`wire.Struct` 字段列表中追加字段
10. 运行 `wire ./di/...` 重新生成依赖注入代码

---

## Core 核心库参考

项目依赖 `code.yt-security.com/public/core/v2` 核心库，**新增功能前应优先查阅核心库是否已提供相应能力，避免重复造轮子**。

### 常用模块速查

| 模块 | 导入路径 | 核心能力 |
|------|---------|---------|
| **web** | `core/v2/web` | 响应构建（`OK/Fail/Err` 链式 + `Resp` 快捷）、参数绑定（泛型 `BindJSON/BindQuery/BindUri[T]`）、泛型 Handler（`Handle/HandleList/HandleAction`）、分页（`PageFromContext`）、中间件集合、SSE/WebSocket、文件上传下载 |
| **db** | `core/v2/db` | 数据库连接（`db.New()`）、分页查询（`db.Paginate`）、空值类型（`db.NullString/NullInt64`）、存在性检查（`db.Exists`）、安全更新（`db.Updates`） |
| **cache** | `core/v2/cache` | 统一缓存接口（`cache.Cache`）、内存实现（`memory.New()`）、Redis实现（`redis.New()`） |
| **closures** | `core/v2/closures` | 树形结构处理（`BuildTree`/`FlattenTree`/`FindNode`） |
| **pkg/qconv** | `core/v2/pkg/qconv` | 类型安全转换（`ToString`/`ToInt`/`ToFloat64`/`StructToMap`） |
| **pkg/qpasswd** | `core/v2/pkg/qpasswd` | 密码哈希（bcrypt/argon2id/scrypt）、密码强度校验 |
| **pkg/qstr** | `core/v2/pkg/qstr` | 字符串工具（`CamelToSnake`/`SnakeToCamel`/`Mask`/`Truncate`） |
| **pkg/qvalid** | `core/v2/pkg/qvalid` | 数据校验（手机号/邮箱/身份证/IP/URL） |
| **pkg/qretry** | `core/v2/pkg/qretry` | 重试机制（指数退避、自定义策略） |
| **pkg/qbatch** | `core/v2/pkg/qbatch` | 批量处理（并发控制、进度回调） |
| **pkg/qpool** | `core/v2/pkg/qpool` | 协程池（动态扩缩容） |
| **pkg/qevent** | `core/v2/pkg/qevent` | 事件总线（发布/订阅） |
| **pkg/qbreaker** | `core/v2/pkg/qbreaker` | 熔断器 |
| **pkg/qratelimit** | `core/v2/pkg/qratelimit` | 限流器（令牌桶/滑动窗口） |
| **pkg/qresult** | `core/v2/pkg/qresult` | Result/Option 类型（函数式错误处理） |
| **qcrypto** | `core/v2/qcrypto/*` | AES/RSA/SM2/SM4/Ed25519/ECDSA/ChaCha20 等加密算法 |
| **storage** | `core/v2/storage` | 文件存储抽象（本地/S3/MinIO） |
| **queue** | `core/v2/queue` | 消息队列抽象（Redis/内存） |
| **generate** | `core/v2/generate/*` | ID生成（ULID/UUID/Snowflake） |

### 使用原则

- **参数绑定**：必须使用 `web.BindJSON[T]`/`web.BindQuery[T]`/`web.BindUri[T]`，禁止 `c.ShouldBind*` 或 `strconv` 手动解析
- **响应构建**：优先使用链式 `web.OK(c).Data().Send()` / `web.Fail(c).Err().Send()`
- **密码处理**：使用 `qpasswd` 而非自行实现 bcrypt
- **ID 生成**：使用 `generate/qulid` 或 `generate/quuid`，而非手动调用第三方库
- **类型转换**：使用 `qconv` 而非手写 `strconv` 调用
- **重试/熔断/限流**：使用 `qretry`/`qbreaker`/`qratelimit` 而非自行实现
- **树形数据**：使用 `closures.BuildTree` 而非手动递归构建
- **缓存操作**：通过 `cache.Cache` 接口操作，支持内存和 Redis 无缝切换
- **数据权限**：使用 `iamsdk.DataFilterScope` 而非手动拼接 WHERE 条件
- **当前用户**：使用 `iamsdk.GetCurrentUser(c)` 而非直接解析 Token

---

## 核心约定

- **RESTful API 设计**：资源名复数名词，动作通过 HTTP Method 表达，禁止路径中出现动词
- **参数绑定**：必须使用 `web.BindJSON[T]`/`web.BindQuery[T]`/`web.BindUri[T]`，禁止手动解析
- 所有 API 路由注册在 `/api` 路由组下
- 路由通过 `authorize.RegisterRoutes` 声明式注册
- Service 返回 `error`；Handler 负责判断 error 类型并选择响应码
- 响应优先使用链式 API（`web.OK`/`web.Fail`/`web.Err`）
- **优先使用 Core 核心库已有功能**，避免重复实现
