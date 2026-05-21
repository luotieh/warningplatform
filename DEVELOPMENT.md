# 开发经验与最佳实践

基于 template 框架开发业务子系统时积累的关键经验，避免重复踩坑。

## 0. 权限（只看这一节）

**IAM 管页面，子系统管 API。** 例外清单只在 `vulnscan-backend/di/module_authorization.go` 顶部注释，无其它配置文件。

| 你要做的事 | 在哪做 |
|-----------|--------|
| 发版后同步菜单 | IAM 管理员 → vulnscan → 系统初始化 → 同步 |
| 谁能看到哪些模块 | IAM → 角色 → 勾选 vulnscan 菜单 |
| 新增跨模块只读 API | 改 `module_authorization.go` 里 `supportReadGETExact` 或 organize/scan 规则 |

上线四步：注册应用 → 管理员同步菜单 → 角色勾菜单 → 用户重登。

---

## 1. 路由前缀：必须使用 `/api` 路由组

### 问题

前端 `VITE_GLOB_API_URL=/api`，所有 API 请求自动带 `/api` 前缀（如 `/api/me/profile`）。
如果后端路由直接注册在 engine 根路径下（`/me/profile`），前端请求会 404。

### 正确做法

参照 IAM 和 vulnerability-scan-new 项目：

```go
func (h *Handlers) RouteLoad() {
    engine := h.Web.GetRawWeb()
    engine.Use(web.MiddlewareRequestResponse())

    // 所有 API 路由注册在 /api 组下
    apiGroup := engine.Group("/api")

    // 仅认证：SDK 的 /me/* 等不应挂 Authorization（否则非 admin 会 403 并触发前端降级）
    apiAuthenticated := apiGroup.Group("/", h.IAM.Middleware().Authentication())
    h.IAM.RegisterDefaultRoutes(engine, apiAuthenticated, iamsdk.DefaultRoutesOptions{...})

    apiAuthorized := apiAuthenticated.Group("", h.ModuleAuthorization())
    backends = append(backends, h.YourModule.RoutesWithGroup(apiAuthorized)...)

    frontend.SetupSPA(engine, web.MiddlewareNotFound())
}
```

### 路由映射关系

| 前端请求 | 后端路由 | 注册位置 |
|---------|---------|---------|
| `/api/me/profile` | `/api/me/profile` | apiAuthenticated（SDK，仅 Authentication） |
| `/api/auth/login` | `/api/auth/login` | SDK 公开代理 |
| `/api/your-module/xxx` | `/api/your-module/xxx` | apiAuthorized |
| `/sso/login` | `/sso/login` | engine 根路径（SDK） |

### Vite 代理配置

```typescript
// vite.config.mts
proxy: {
  '/api': {
    changeOrigin: true,
    target: 'http://127.0.0.1:8090', // 后端端口
    ws: true,
    // 不需要 rewrite，因为后端路由已在 /api 下
  },
},
```

## 2. 响应链：使用 `web.OK` / `web.Fail` 链式 API

### 旧写法（不推荐）

```go
web.Resp(c, web.InternalError.SetMessage(err.Error()))
web.RespContent(c, web.Success, data)
```

### 新写法（推荐）

```go
// 成功 - 返回数据
web.OK(c).Data(data).Send()

// 成功 - 无数据
web.OK(c).Send()

// 成功 - 带消息
web.OK(c).Msg("操作完成").Send()

// 成功 - 列表（带 count）
web.OK(c).List(total, items).Send()

// 失败 - 包装 error
web.Fail(c).Err(err).Send()

// 失败 - 自定义消息
web.Fail(c).Msg("参数无效").Send()

// 失败 - 指定错误码
web.Err(c, web.NotFound).Msg("资源不存在").Send()

// 从 CodeError 构建
web.FromError(c, web.WrapError(web.InternalError, err)).Send()
```

### 参数绑定与验证

```go
// JSON 请求体验证
var req MyRequest
if !web.ValidationJson(c, &req) {
    return // 验证失败时 SDK 已自动返回错误响应
}

// 泛型绑定（推荐，更简洁）
req, ok := web.BindJSON[MyRequest](c)
if !ok {
    return
}
```

### 泛型 Handler（进阶）

```go
// 自动绑定 JSON + 返回响应
router.POST("/items", web.Handle[CreateReq, Item](func(c *gin.Context, req CreateReq) (Item, error) {
    return service.Create(req)
}))

// 列表查询
router.GET("/items", web.HandleList[ListReq, Item](func(c *gin.Context, req ListReq) ([]Item, int64, error) {
    return service.List(req)
}))

// 无请求体
router.GET("/info", web.HandleNoReq[Info](func(c *gin.Context) (Info, error) {
    return service.GetInfo()
}))

// 无响应数据
router.DELETE("/items/:id", web.HandleAction(func(c *gin.Context) error {
    return service.Delete(c.Param("id"))
}))
```

## 3. Go import 路径替换

### 步骤

1. 修改 `go.mod` 中的 module 名
2. 全局替换所有 `.go` 文件中的 import 路径
3. 运行 `go mod tidy` + `go build ./...` 验证

### PowerShell 注意事项

**不要使用** `Set-Content` 替换文件内容，它会破坏 UTF-8 编码中的非 ASCII 字符（中文注释）。

```powershell
# 错误 ❌ - 会导致 illegal UTF-8 encoding
(Get-Content file.go) -replace 'old', 'new' | Set-Content file.go

# 正确 ✅ - 指定编码
(Get-Content file.go -Raw) -replace 'old', 'new' | Set-Content file.go -Encoding UTF8NoBOM
```

推荐直接使用编辑器或脚本工具来替换。

## 4. 新增业务模块标准流程

### 后端

```
your-module/
├── wire.go              # Wire Provider Set
├── your-module.go       # NewYourModule + RoutesWithGroup
└── sub-domain/
    ├── service.go       # 业务逻辑 + GORM 操作
    └── handler.go       # Gin Handler
```

**service.go**：

```go
type Service struct {
    DB *db.DB
}

func NewService(database *db.DB) *Service {
    svc := &Service{DB: database}
    database.GetDBSession().AutoMigrate(&model.YourModel{})
    return svc
}

func (s *Service) List() ([]model.YourModel, error) {
    var items []model.YourModel
    err := s.DB.GetDBSession().Find(&items).Error
    return items, err
}
```

**handler.go**：

```go
func (h *Handler) List(c *gin.Context) {
    query, ok := web.BindQuery[ListQuery](c)
    if !ok {
        return
    }
    items, count, err := h.Service.List(query)
    if err != nil {
        web.Fail(c).Err(err).Send()
        return
    }
    web.OK(c).List(count, items).Send()
}

func (h *Handler) GetByID(c *gin.Context) {
    uri, ok := web.BindUri[web.Id](c)
    if !ok {
        return
    }
    item, err := h.Service.GetByID(uri.Id)
    if err != nil {
        web.Err(c, web.NotFound).Send()
        return
    }
    web.OK(c).Data(item).Send()
}
```

**module.go**（路由注册）：

```go
func (m *YourModule) RoutesWithGroup(group *gin.RouterGroup) []authorize.BackendItem {
    return authorize.RegisterRoutes(group.Group("/items"), []authorize.Route{
        {
            Name: "你的模块", Enabled: true,
            Children: []authorize.Route{
                {Name: "列表", Method: "GET", Handler: m.Handler.List, Enabled: true},
                {Name: "详情", Path: ":id", Method: "GET", Handler: m.Handler.GetByID, Enabled: true},
                {Name: "创建", Method: "POST", Handler: m.Handler.Create, Enabled: true},
                {Name: "更新", Path: ":id", Method: "PUT", Handler: m.Handler.Update, Enabled: true},
                {Name: "删除", Path: ":id", Method: "DELETE", Handler: m.Handler.Delete, Enabled: true},
            },
        },
    })
}
```

> **注意**：使用 `authorize.RegisterRoutes` 声明式注册，一次声明同时完成 Gin 路由挂载和 IAM 接口元数据收集。禁止手动注册 Gin 路由后遗漏 BackendItem 收集。

**集成步骤**：

1. 在 `di/wire.go` 的 `wire.Build()` 中追加 `yourmodule.WireSet`
2. 在 `di/handlers.go` 的 `Handlers` struct 中追加字段
3. 在 `RouteLoad()` 中 `backends = append(backends, h.YourModule.RoutesWithGroup(authGroup)...)`
4. 运行 `wire ./di/...` 重新生成

### 前端

1. **API 层**（`src/api/your-module/index.ts`）：

```typescript
import { requestClient } from '#/api/request';

const BASE = '/your-module';

export function listItems() {
  return requestClient.get(`${BASE}/items`);
}
export function createItem(data: any) {
  return requestClient.post(`${BASE}/items`, data);
}
```

2. **路由**（`src/router/routes/modules/your-module.ts`）：

```typescript
import type { RouteRecordRaw } from 'vue-router';
import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:box', order: 10, title: '你的模块' },
    name: 'YourModule',
    path: '/your-module',
    children: [
      {
        name: 'YourModuleList',
        path: 'list',
        component: () => import('#/views/your-module/list.vue'),
        meta: { title: '列表', icon: 'lucide:list' },
      },
    ],
  },
];
export default routes;
```

3. **页面**（`src/views/your-module/list.vue`）：使用 Naive UI 组件构建

## 5. Model 定义规范

```go
type YourModel struct {
    ID        string    `json:"id" gorm:"primaryKey;type:varchar(36)"`
    Name      string    `json:"name" gorm:"type:varchar(255);not null" binding:"required"`
    Status    string    `json:"status" gorm:"type:varchar(50);default:'active'"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}

func (YourModel) TableName() string {
    return "your_table_name"
}
```

- 使用 `binding:"required"` 配合 `web.ValidationJson` 自动校验
- 表名加模块前缀避免冲突（如 `udp_project`、`scan_task`）
- ID 建议使用 UUID 或 ULID

## 6. 开发环境端口约定

| 服务 | 端口 | 说明 |
|------|------|------|
| 前端 Vite | 5889 | HMR 开发服务器 |
| 后端 | 8090 | `config.toml` 中的 `[web] port` |
| IAM | 8080 | `config.toml` 中的 `[iam] base_url` |

确保 `vite.config.mts` 中的 proxy target 与后端 `config.toml` 中的端口一致。

## 7. 常用 web 包工具函数

```go
// 获取当前用户信息
userID := web.GetUserID(c)
account := web.GetAccount(c)
organizeID := web.GetOrganizeID(c)

// 分页
offset, limit := web.PageFromContext(c)

// 文件下载
web.DownloadFile(c, filePath, "export.xlsx")
web.DownloadBytes(c, data, "report.pdf", "application/pdf")

// 文件上传
result, err := web.UploadFile(c, "file", web.UploadOptions{...})
```
