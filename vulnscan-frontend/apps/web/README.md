# IAM 业务子系统前端模板

开箱即用的 Vue 前端模板，登录/权限/菜单由 IAM 统一管理，业务子系统只需关注自己的业务代码。

## 目录结构

```
src/
├── api/                    # API 接口
│   ├── core/               # [内置] IAM 核心接口（登录/用户/菜单/权限）
│   ├── request.ts          # [内置] HTTP 请求客户端（Token 自动注入）
│   └── example/            # [示例] 你的业务接口写在这里
├── composables/            # 可复用逻辑
│   ├── usePerm.ts          # [内置] 权限判断 composable
│   ├── usePolling.ts       # [内置] 智能轮询 composable
│   ├── use-theme-sync.ts   # [内置] 主题同步（IAM → 子系统）
│   └── ...
├── directives/             # [内置] v-perm 等自定义指令
├── layouts/                # [内置] 布局组件
├── locales/                # [内置] 国际化
├── router/
│   ├── guard.ts            # [内置] 路由守卫（认证/权限/SSO 跳转）
│   ├── access.ts           # [内置] 动态路由生成
│   └── routes/
│       ├── core.ts         # [内置] 框架路由（登录/404/SSO 回调）
│       └── modules/        # ★ 你的业务路由写在这里
│           └── example.ts  # [示例] 示例路由
├── store/
│   ├── auth.ts             # [内置] 认证状态管理（支持 SSO）
│   └── index.ts
├── utils/
│   └── sso.ts              # [内置] SSO 单点登录工具
└── views/
    ├── _core/              # [内置] 框架页面（登录/SSO 回调/个人中心）
    └── example/            # ★ 你的业务页面写在这里
```

## 快速开始

### 1. 安装依赖

```bash
# 在 monorepo 根目录
pnpm install
```

### 2. 启动开发服务器

```bash
pnpm --filter @vben/web-template dev
```

### 3. 配置

编辑 `.env` 中的配置项：

```dotenv
# 应用标题
VITE_APP_TITLE=我的业务系统

# 登录模式：local（本地登录页）| sso（跳转 IAM 统一登录）
VITE_AUTH_MODE=sso

# IAM 基础地址
VITE_IAM_BASE_URL=http://localhost:5888

# OAuth2 Client ID（在 IAM 后台"应用管理"中注册后获取）
VITE_SSO_CLIENT_ID=your-client-id
```

编辑 `.env.development` 中的 API 代理：

```dotenv
VITE_GLOB_API_URL=/api
```

## SSO 单点登录

### 模式一：纯前端 SSO（默认，推荐）

设置 `VITE_AUTH_MODE=sso` 后，模板自动执行以下流程：

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  子系统前端   │     │   IAM 登录页  │     │  IAM OAuth2  │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │  检测未登录          │                    │
       ├────────────────────►│                    │
       │  302 跳转 authorize  │                    │
       │                     │  用户登录成功         │
       │                     ├───────────────────►│
       │                     │  返回 code + state   │
       │◄────────────────────┤                    │
       │  /auth/sso-callback │                    │
       │                     │                    │
       ├─────────────────────────────────────────►│
       │  POST /auth/oauth2/token (code + PKCE)   │
       │◄─────────────────────────────────────────┤
       │  access_token + refresh_token             │
       │                                           │
       │  拉取用户信息 + 权限码，进入首页              │
```

**安全特性：**
- PKCE (Proof Key for Code Exchange)：防止授权码劫持
- State 参数：防止 CSRF 攻击
- Token 存储在内存/sessionStorage 中，不暴露在 URL

### 模式二：后端 Token Relay（使用 Go SDK）

适用于子系统有自己的 Go 后端的场景：

```go
import (
    auth "code.yt-security.com/public/iam-sdk/auth"
)

// 注册路由
r.GET("/sso/login", client.SSO.LoginRedirect(auth.SSOCallbackOptions{
    RedirectURI: "https://api.my-app.com/sso/callback",
    UsePKCE:     true,
}, auth.LoginHandlerOptions{}))

r.GET("/sso/callback", client.SSO.CallbackHandler(auth.SSOCallbackOptions{
    RedirectURI:     "https://api.my-app.com/sso/callback",
    SuccessRedirect: "https://my-app.com/",
    TokenDelivery:   auth.TokenDeliveryFragment,
    FetchUserInfo:   true,
    OnSuccess: func(c *gin.Context, tokens *auth.SSOTokenResponse, user *auth.SSOUserInfo) {
        // 写 cookie 或 session
    },
}))
```

使用此模式时，前端设置 `VITE_AUTH_MODE=local`，并在登录页添加"使用 IAM 登录"按钮跳转到后端 `/sso/login`。

### 模式三：本地登录（调试用）

设置 `VITE_AUTH_MODE=local`，模板使用内置登录页直接调 IAM 的 `loginApi`。

## 主题同步

子系统自动同步 IAM 主框架的主题配置，支持两种场景：

### iframe 嵌入

IAM 主框架通过 `postMessage` 实时推送主题变更：

```typescript
// IAM 主框架中
import { postThemeToIframe } from '#/composables/use-theme-sync';

// 主题变更时
postThemeToIframe(iframe.contentWindow, {
  mode: 'dark',
  colorPrimary: '#1890ff',
  radius: '6px',
});
```

子系统自动监听 `window.message` 事件并应用主题。

### 独立部署

通过 URL 参数或 localStorage 传递主题：

```
https://my-app.com/?iam_theme={"mode":"dark","colorPrimary":"#1890ff"}
```

或预写入 localStorage：

```javascript
localStorage.setItem('iam_theme', JSON.stringify({
  mode: 'dark',
  colorPrimary: '#1890ff',
}));
```

优先级：URL 参数 > localStorage > 默认值。

## 业务开发指南

### 添加业务路由

在 `src/router/routes/modules/` 下创建新的路由文件：

```typescript
import type { RouteRecordRaw } from 'vue-router';
import { BasicLayout } from '#/layouts';

const routes: RouteRecordRaw[] = [
  {
    component: BasicLayout,
    meta: { icon: 'lucide:box', order: 10, title: '我的模块' },
    name: 'MyModule',
    path: '/my-module',
    children: [
      {
        name: 'MyModuleList',
        path: 'list',
        component: () => import('#/views/my-module/list.vue'),
        meta: {
          title: '列表页',
          perms: [
            { action: 'create', label: '新建' },
            { action: 'update', label: '编辑' },
            { action: 'delete', label: '删除' },
          ],
        },
      },
    ],
  },
];

export default routes;
```

### 权限控制

按钮级权限使用 `v-perm` 指令：

```vue
<NButton v-perm="'my-module:list:create'" type="primary">新建</NButton>
```

路由 `meta.perms` 声明的权限在菜单同步时自动创建权限码。

### 调用业务 API

```typescript
import { requestClient } from '#/api/request';

export function getList(params?: Record<string, any>) {
  return requestClient.get('/my-module/list', { params });
}
```

Token 注入、401 跳转、错误处理均已内置。

## 模板内置能力

| 能力 | 说明 |
|------|------|
| SSO 单点登录 | OAuth2 Authorization Code + PKCE，纯前端实现 |
| 本地登录 | 对接 IAM 登录接口，支持验证码、WebAuthn |
| Token 管理 | 自动注入 Bearer Token，过期自动刷新或跳登录 |
| 动态菜单 | 从 IAM 后端拉取菜单，前端路由自动注册 |
| 权限控制 | `v-perm` 指令 + `usePerm()` composable |
| 主题同步 | 自动同步 IAM 主题（postMessage / URL / localStorage） |
| 国际化 | 内置中/英文，可扩展 |
| 错误处理 | 全局错误拦截，认证失效自动跳 SSO |

## 在 IAM 后台配置子系统

1. **应用管理** → 新建应用 → 获取 `Client ID`
2. **配置回调地址**：`https://your-app.com/auth/sso-callback`
3. **菜单管理** → 选择子系统应用 → 配置菜单和按钮权限
4. **角色管理** → 为角色分配子系统的菜单和权限

## 注意事项

- 确保 IAM 后端中已注册你的子系统应用
- `VITE_SSO_CLIENT_ID` 必须与 IAM 后台注册的一致
- 不要修改 `api/core/`、`store/auth.ts`、`router/guard.ts`、`utils/sso.ts` 等内置文件
- 子系统的 API 请求会自动携带 IAM Token，后端可通过 SDK 验证
