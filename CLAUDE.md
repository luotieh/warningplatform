# CLAUDE.md - IAM 子系统模板开发指南

## 项目概述

基于 IAM 统一身份认证平台的全栈业务子系统模板。前后端合并为单一 Go 二进制，开箱即用。
- **后端**：Go + Gin + GORM + Wire DI，位于 `template-backend/`
- **前端**：Vue 3 + TypeScript + Naive UI + Vben Admin，位于 `template-frontend/apps/web/`
- **认证授权**：IAM SDK（`code.yt-security.com/public/sdk`）提供 OAuth2、SSO、Token Relay、PKCE、接口鉴权、数据权限
- **核心库**：`code.yt-security.com/public/core/v2`（提供 `web`、`db`、`cache`、`closures` 等基础能力）

## 构建与运行

```bash
# 前端开发模式（HMR）
cd template-frontend && pnpm install && pnpm dev

# 后端
cd template-backend && go run ./cmd/server/

# 一键构建（单一二进制）
make all          # Linux/macOS
.\build.ps1 all   # Windows
```

## 子项目开发指南

- **后端**：[template-backend/CLAUDE.md](template-backend/CLAUDE.md) -- 路由注册、Handler/Service 模式、Wire 依赖注入、IAM SDK 集成、Core 核心库
- **前端**：[template-frontend/CLAUDE.md](template-frontend/CLAUDE.md) -- 权限系统、API 模块规范、CRUD 页面模式、共享组件、Composables

## 核心约定

- **RESTful API 设计**：资源名使用复数名词（`/orders`），动作通过 HTTP Method 表达，禁止在路径中出现动词
- 所有 API 路由注册在 `/api` 路由组下 -- 前端 `VITE_GLOB_API_URL=/api`，路径必须匹配
- 后端路由通过 `authorize.RegisterRoutes` 声明式注册 -- 同时完成 Gin 路由挂载和 IAM 接口元数据收集
- **参数绑定**：必须使用 `web.BindJSON[T]`、`web.BindQuery[T]`、`web.BindUri[T]` 等泛型绑定函数，禁止直接使用 `c.ShouldBind*` 或 `c.Param` + `strconv` 手动解析
- Service 返回 `error` 而非 `web.Code`；Handler 负责将 error 转为响应
- 响应构建优先使用链式 API：`web.OK(c).Data(data).Send()`、`web.Fail(c).Err(err).Send()`
- 前端列表 API 使用 `baseRequestClient`（获取原始响应）；单条数据 API 使用 `requestClient`（自动解包 `data`）
- 前端权限命名空间从路由路径自动推导：`/order/list` -> `order:list`
- 前端权限通过 `meta.perms` 声明，同步菜单后由 IAM 统一管理
- **优先使用 Core 核心库已有功能**，避免重复实现
