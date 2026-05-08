# Frontend Template

子系统前端模板，基于 [Vben Admin](https://doc.vben.pro) (Vue 3 + Naive UI) 构建，集成 IAM SDK SSO 认证。

## 技术栈

- **框架**: Vue 3.5 + TypeScript 5.9
- **UI**: Naive UI 2.x
- **构建**: Vite 7.x
- **状态管理**: Pinia 3.x
- **样式**: TailwindCSS 3.x

## 快速开始

```bash
# 安装依赖（需要 pnpm >= 10 & Node >= 20.19）
pnpm install

# 启动开发服务器
pnpm dev

# 构建生产版本
pnpm build
```

## 项目结构

```
├── apps/web/              # 应用入口与业务代码
│   ├── src/
│   │   ├── api/           # API 接口定义
│   │   ├── views/         # 页面视图
│   │   ├── router/        # 路由配置
│   │   ├── store/         # 业务 Store
│   │   ├── composables/   # 组合函数
│   │   ├── layouts/       # 布局组件（含 EmbedLayout）
│   │   └── utils/         # 工具函数（含 SSO）
│   └── vite.config.mts    # Vite 配置
├── packages/              # Vben Admin 内部包
├── internal/              # 构建工具链
└── scripts/               # 辅助脚本
```

## 内置特性

- **SSO 认证**: 支持 IAM OAuth2 Authorization Code + PKCE 流程
- **Token 解析**: 同时支持 URL Query 和 Hash Fragment 两种 Token 传递方式
- **Embed 模式**: URL 携带 `?embed` 参数时隐藏顶栏，保留侧边栏，适用于 IAM 嵌入
- **API 降级**: IAM 接口不可用时优雅降级，不阻塞应用启动
- **权限系统**: 基于角色/权限码的细粒度控制（v-perm 指令）

## 开发代理

开发模式下 `/api` 请求代理到 `http://127.0.0.1:8080`（子系统后端）。

修改 `apps/web/vite.config.mts` 中的 `server.proxy.target` 调整目标地址。
