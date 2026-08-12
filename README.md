# Warning Platform — 漏洞扫描与安全预警平台

## 1. 项目概述

Warning Platform 是一套**自研、高性能、分布式**的漏洞扫描与安全预警平台，覆盖 Web 应用、网络服务、主机安全、API 安全、合规检查等扫描维度，并提供资产管理、漏洞闭环、通报流转、站点监测、流量分析等完整的安全运营能力。

### 核心设计原则

| 原则 | 说明 |
|------|------|
| 自主可控 | Go 自研扫描引擎，不依赖 Nmap/Nuclei/ZAP 等外部二进制，仅使用 Go 标准库和轻量级 SDK |
| 分布式优先 | Master-Worker 架构，支持水平扩展、任务分片、无单点瓶颈 |
| 插件化 | 扫描能力通过 Plugin 注册，支持 YAML PoC / Go 插件 |
| 高性能 | Goroutine 池 + 连接池 + 异步流水线，单节点万级并发探测 |
| 安全隔离 | 扫描流量隔离、结果加密存储、操作审计、授权白名单 |

---

## 2. 技术架构

### 2.1 整体架构

```
┌──────────────────────────────────────────────────────────────────┐
│                     前端 (Vue3 + Naive UI + TypeScript)            │
│  Dashboard │ 资产管理 │ 任务中心 │ 漏洞库 │ 报告 │ 站点监测 │ 通报 │
└────────────────────────────┬─────────────────────────────────────┘
                             │ REST / WebSocket
┌────────────────────────────▼─────────────────────────────────────┐
│                    API Gateway (Go + Gin)                          │
│  认证鉴权(IAM) │ 限流 │ 路由分发 │ WebSocket Hub │ /metrics        │
└──────┬─────────┬──────────┬─────────────┬────────────────────────┘
       │         │          │             │
       ▼         ▼          ▼             ▼
┌───────────┐ ┌────────┐ ┌─────────┐ ┌──────────────┐
│  Master   │ │ Asset  │ │  Vuln   │ │   Report     │
│ Scheduler │ │Service │ │ Service │ │   Service    │
│ 任务编排  │ │ 资产   │ │ 漏洞库  │ │ 报告生成     │
│ 分片分发  │ │ 发现   │ │ 知识库  │ │ PDF/DOCX     │
│ 状态追踪  │ │ 指纹库 │ │ 去重    │ │ 导出         │
└─────┬─────┘ └────────┘ └─────────┘ └──────────────┘
      │
      │ NATS / RabbitMQ / gRPC
      │
┌─────▼────────────────────────────────────────────────┐
│               Worker Cluster (N 个节点)                │
│                                                       │
│  ┌─────────────────────────────────────────────────┐  │
│  │              Scan Engine (每个 Worker)           │  │
│  │                                                 │  │
│  │  Pipeline:                                      │  │
│  │  [Target] → [Discovery] → [Fingerprint]        │  │
│  │          → [PluginMatch] → [Exploit/Verify]     │  │
│  │          → [Report]                             │  │
│  │                                                 │  │
│  │  Modules:                                       │  │
│  │  PortScan · ServiceProbe · WebCrawl · DirScan   │  │
│  │  SQLi · XSS · SSRF · WeakPass · CertCheck       │  │
│  │  InfoLeak · APIFuzz · SubDomain · Fingerprint   │  │
│  └─────────────────────────────────────────────────┘  │
│                                                       │
│  Goroutine Pool │ Connection Pool │ Rate Limiter       │
└───────────────────────────────────────────────────────┘
      │
      ▼
┌──────────────────────────────────────────────────────────┐
│                        存储层                              │
│  MySQL / PostgreSQL (主数据)  │  Redis (缓存/队列/锁)     │
│  IAM Storage (报告/截图/附件) │  NATS / RabbitMQ (消息)   │
└──────────────────────────────────────────────────────────┘
```

### 2.2 后端技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| 语言 | Go 1.26+ | 并发原生支持、网络编程能力强、交叉编译 |
| Web 框架 | Gin | 轻量高性能 HTTP 框架 |
| ORM | GORM | 数据库操作与迁移 |
| 消息队列 | NATS / RabbitMQ | Master-Worker 通信、任务分发 |
| 主数据库 | MySQL 8.0+ | 主业务数据存储 |
| 缓存 | Redis 7+ | 缓存、分布式锁、会话管理 |
| 依赖注入 | Google Wire | 编译时 DI 代码生成 |
| 定时任务 | robfig/cron | Cron 调度 |
| 监控 | Prometheus | `/metrics` 端点暴露指标 |
| 浏览器引擎 | Chromium (go-rod) | 无头浏览器截图 |
| 配置格式 | TOML | 配置文件格式 |

### 2.3 前端技术栈

| 层级 | 技术 | 说明 |
|------|------|------|
| 框架 | Vue 3.5+ | Composition API |
| 语言 | TypeScript 5.9+ | 类型安全 |
| UI 库 | Naive UI + Ant Design Vue | 企业级组件 |
| 构建 | Vite 7+ | 极速开发与构建 |
| 包管理 | pnpm 10+ (monorepo) | 工作空间管理 |
| 状态管理 | Pinia 3+ | Vue 官方推荐 |
| 图表 | ECharts 6+ | 数据可视化 |
| 表格 | VXE Table | 高性能表格 |
| 路由 | Vue Router 4+ | SPA 路由 |
| HTTP | Axios | API 请求 |
| CSS | TailwindCSS 3 | 原子化 CSS |
| 国际化 | Vue I18n | 多语言支持 |
| PWA | vite-plugin-pwa | 离线支持 |

### 2.4 后端核心业务模块

| 模块 | 包路径 | 功能 |
|------|--------|------|
| **asset** | `vulnscan-backend/asset/` | 资产管理：CRUD、导入导出、在线同步、截图、指纹、模板校验 |
| **task** | `vulnscan-backend/task/` | 扫描任务管理：创建、调度、状态追踪 |
| **vuln** | `vulnscan-backend/vuln/` | 漏洞管理：查看、处置、去重、关联资产 |
| **cluster** | `vulnscan-backend/cluster/` | 集群管理：Worker 注册、心跳、节点管理、WebSocket 通信 |
| **scanrunner** | `vulnscan-backend/scanrunner/` | 扫描运行器：调度器、知识库注册 |
| **agent** | `vulnscan-backend/agent/` | 扫描代理：Agent 运行时配置、凭证管理、执行器、调度 |
| **asm** | `vulnscan-backend/asm/` | 攻击面管理：子域名、端口、指纹、CyberSpace 采集、告警、风险评分 |
| **sitemonitor** | `vulnscan-backend/sitemonitor/` | 站点监测：页面篡改检测、截图对比 |
| **circular** | `vulnscan-backend/circular/` | 通报流转：分发、处置、复核、转办、台账 |
| **incident** | `vulnscan-backend/incident/` | 事件管理：事件登记、处置、关联 |
| **dashboard** | `vulnscan-backend/dashboard/` | 仪表盘：数据聚合、统计 |
| **compliance** | `vulnscan-backend/compliance/` | 合规检查：基线检查、合规检测 |
| **report** | `vulnscan-backend/report/` | 报告管理：PDF/DOCX 生成、导出 |
| **notify** | `vulnscan-backend/notify/` | 通知服务：邮件、Webhook、站内信 |
| **traffic** | `vulnscan-backend/traffic/` | 流量分析：LLM 驱动的流量分析子系统 |
| **federation** | `vulnscan-backend/federation/` | 联邦管理：多级联动 |
| **organize** | `vulnscan-backend/organize/` | 组织管理：组织架构 |
| **tagging** | `vulnscan-backend/tagging/` | 标签管理 |
| **dispatch** | `vulnscan-backend/dispatch/` | 调度分发 |
| **exclusion** | `vulnscan-backend/exclusion/` | 排除规则 |
| **fprule** | `vulnscan-backend/fprule/` | 误报规则 |
| **monitoragent** | `vulnscan-backend/monitoragent/` | 内嵌监控 Agent |
| **formdesign** | `vulnscan-backend/formdesign/` | 表单设计器 |
| **systemdict** | `vulnscan-backend/systemdict/` | 系统字典 |
| **setting** | `vulnscan-backend/setting/` | 系统设置 |
| **health** | `vulnscan-backend/health/` | 健康检查 |
| **schedule** | `vulnscan-backend/schedule/` | Cron 定时调度 |

### 2.5 依赖注入架构

项目使用 Google Wire 进行编译时依赖注入，入口在 `di/wire.go`：

```
boot.LoadConfig()        → Config（TOML 配置）
boot.LoadWeb(config)     → Web Engine（Gin）
boot.LoadDB(config)      → DB（MySQL via GORM）
boot.LoadCache(config)   → Cache（Redis）
boot.LoadIAM(config, ...)→ IAM Client（认证鉴权 SDK）
boot.LoadProduct(config) → Product（产品元数据）

各业务模块通过 Wire Provider Set 注入，最后组装为 Handlers struct
```

### 2.6 路由架构

```
engine (Gin)
├── /api                          ← API 路由组
│   ├── /iam/*                    ← IAM 代理路由
│   ├── /me/*                     ← 用户信息（仅认证）
│   ├── /asset/*                  ← 资产管理（需授权）
│   ├── /task/*                   ← 任务管理
│   ├── /vuln/*                   ← 漏洞管理
│   ├── /cluster/*                ← 集群管理
│   ├── /asm/*                    ← 攻击面管理
│   ├── /site-monitor/*           ← 站点监测
│   ├── /circular/*               ← 通报流转
│   ├── /incident/*               ← 事件管理
│   ├── /dashboard/*              ← 仪表盘
│   ├── /compliance/*             ← 合规检查
│   ├── /report/*                 ← 报告管理
│   ├── /knowledge/*              ← 知识库
│   ├── /template/*               ← 模板管理
│   ├── /intel/*                  ← 威胁情报
│   ├── /traffic/*                ← 流量分析（独立鉴权）
│   ├── /system/*                 ← 系统设置
│   ├── /nodes                    ← 节点列表
│   ├── /ws                       ← WebSocket
│   └── ...
├── /sso/login                    ← SSO 登录
├── /callback                     ← SSO 回调
├── /healthz, /readyz             ← 健康检查
└── /metrics                      ← Prometheus 指标
```

---

## 3. 部署要求

### 3.1 环境依赖

#### 必需组件

| 组件 | 最低版本 | 用途 |
|------|----------|------|
| Go | 1.26+ | 后端编译与运行 |
| Node.js | 20.19+ | 前端构建 |
| pnpm | 10.0+ | 前端包管理 |
| MySQL | 8.0+ | 主业务数据库 |
| Redis | 7.0+ | 缓存、分布式锁 |
| IAM 服务 | — | 统一认证鉴权（内部服务 `code.yt-security.com/public/access`） |

#### 可选组件

| 组件 | 用途 | 说明 |
|------|------|------|
| NATS | 消息队列 (Master-Worker 通信) | 分布式部署推荐；单机可不用 |
| RabbitMQ | 消息队列备选 | 流量分析模块可选 |
| PostgreSQL | 流量分析存储后端 | 当 `traffic.store_backend=postgres` 时必需 |
| Chromium | 无头浏览器截图 | 站点监测功能需要；Docker 镜像已内置 |
| Prometheus | 监控指标采集 | 通过 `/metrics` 端点暴露 |

### 3.2 配置文件说明

项目使用 TOML 格式配置，分两个环境：

- `config.toml` — 生产环境配置（默认端口 8090）
- `dev.config.toml` — 开发环境配置（默认端口 8080）

#### 配置结构

```toml
[web]           # Web 服务：host / port / cert / key / debug
[db]            # 数据库：MySQL 连接参数 (host/port/user/passwd/dbname)
[iam]           # IAM 认证：base_url / client_id / client_secret / path_prefix
[sso]           # SSO 单点登录：callback_uri / success_redirect / cookie_secret
[cache]         # Redis 缓存：host / port / username / password / db / prefix
[nats]          # NATS 消息队列：url / token / user / password
[cluster]       # 集群：public_master_url / internal_master_url
[traffic]       # 流量分析：store_backend / database_url / llm 配置 / mq 配置
```

#### 关键环境变量

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `LOG_LEVEL` | 日志级别 (debug/info/warn/error) | info |
| `LOG_FORMAT` | 日志格式 (text/json) | text |
| `LOG_QUIET` | 静默模式 (仅输出 error) | false |
| `VULNSCAN_METRICS_ENABLED` | 启用 Prometheus /metrics | false |

### 3.3 端口约定

| 服务 | 端口 | 说明 |
|------|------|------|
| 前端 Vite (开发) | 5889 | HMR 开发服务器 |
| 后端 (生产) | 8090 | `config.toml` 中 `[web] port` |
| 后端 (开发) | 8080 | `dev.config.toml` 中 `[web] port` |
| IAM 服务 | 32000 (内部) | `[iam] base_url` |
| MySQL | 3306 | 数据库 |

### 3.4 Docker 部署

#### 构建镜像

项目采用单二进制 + Alpine 运行时的 Docker 镜像，内置 Chromium 支持。

```bash
# 后端构建
cd vulnscan-backend
make build
# 产出: vulnscan-server 可执行文件

# Docker 构建（需先构建对应平台的 server 二进制）
# Dockerfile 按 TARGETPLATFORM 选择 server-{amd64|arm64}
docker build -t warning-platform:latest -f docker/Dockerfile .
```

#### 一键部署

```bash
# 将镜像 tar 包拷贝到目标机器后
./deploy.sh warning-platform-arm64.tar
# 自动完成：加载镜像 → 更新 docker-compose.yaml → 重启容器
```

#### Docker Compose 示例

```yaml
services:
  warning-platform:
    image: warning-platform:latest
    ports:
      - "8090:8080"
    environment:
      - LOG_LEVEL=info
    volumes:
      - ./config.toml:/app/config.toml:ro
    depends_on:
      - mysql
      - redis

  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: yourpassword
      MYSQL_DATABASE: vulnerability
    volumes:
      - mysql_data:/var/lib/mysql

  redis:
    image: redis:7-alpine

volumes:
  mysql_data:
```

### 3.5 开发环境搭建

#### 后端

```bash
cd vulnscan-backend

# 安装依赖
go mod download

# 生成 Wire DI 代码
make wire    # 即 cd di && wire

# 运行（开发模式）
make run
# 或指定配置文件: go run ./cmd/server   # 默认读取 config.toml

# 构建
make build
# 产出: vulnscan-server

# 测试
go test ./... -v

# 代码检查
make tidy
```

#### 前端

```bash
cd vulnscan-frontend

# 安装依赖（必须使用 pnpm）
pnpm install

# 开发模式（端口 5889，代理到后端 8090）
pnpm dev

# 类型检查
pnpm typecheck

# 生产构建
pnpm build

# 预览构建结果
pnpm preview
```

#### 完整开发环境联动

1. 启动 IAM 服务（内部依赖）
2. 启动 MySQL 和 Redis
3. 复制 `dev.config.toml` 为 `config.toml`（或通过环境变量指定）
4. `cd vulnscan-backend && make run` 启动后端
5. `cd vulnscan-frontend && pnpm dev` 启动前端
6. 浏览器访问 `http://127.0.0.1:5889`

---

## 4. 项目结构

```
warning-platform/
├── design/                          # 设计文档
│   ├── architecture.md              #   总体架构设计
│   ├── modules.md                   #   扫描模块详细设计
│   ├── api.md                       #   API 接口设计
│   ├── deployment.md                #   部署与运维设计
│   ├── database.md                  #   数据库设计
│   ├── scan-engine.md               #   扫描引擎设计
│   ├── scheduler.md                 #   调度器设计
│   ├── asm.md                       #   攻击面管理设计
│   ├── compliance.md                #   合规检查设计
│   ├── federation.md                #   联邦管理设计
│   ├── vuln-intel.md                #   漏洞情报设计
│   └── ...
├── vulnscan-backend/                # 后端 (Go)
│   ├── cmd/
│   │   ├── server/main.go           #   主服务入口
│   │   └── agent/                   #   Agent 入口
│   ├── di/                          #   依赖注入
│   │   ├── wire.go                  #     Wire 定义
│   │   ├── wire_gen.go              #     Wire 生成代码
│   │   ├── handlers.go              #     Handlers 组装与路由
│   │   └── ...
│   ├── boot/                        #   启动引导
│   │   ├── config.go                #     配置加载
│   │   ├── database.go              #     数据库初始化
│   │   ├── web.go                   #     Web 引擎初始化
│   │   ├── cache.go                 #     缓存初始化
│   │   ├── iam.go                   #     IAM 客户端初始化
│   │   └── ...
│   ├── agent/                       #   Agent（扫描节点）
│   │   ├── agent.go                 #     Agent 核心
│   │   ├── executor.go              #     任务执行器
│   │   ├── scheduler.go             #     本地调度器
│   │   ├── scanner/                 #     扫描器模块
│   │   └── monitor/                 #     监控模块
│   ├── asset/                       #   资产管理
│   ├── task/                        #   任务管理
│   ├── vuln/                        #   漏洞管理
│   ├── cluster/                     #   集群管理
│   ├── scanrunner/                  #   扫描运行器
│   ├── asm/                         #   攻击面管理
│   ├── sitemonitor/                 #   站点监测
│   ├── circular/                    #   通报流转
│   ├── incident/                    #   事件管理
│   ├── dashboard/                   #   仪表盘
│   ├── compliance/                  #   合规检查
│   ├── report/                      #   报告管理
│   ├── notify/                      #   通知服务
│   ├── traffic/                     #   流量分析
│   ├── federation/                  #   联邦管理
│   ├── organize/                    #   组织管理
│   ├── tagging/                     #   标签管理
│   ├── dispatch/                    #   调度分发
│   ├── exclusion/                   #   排除规则
│   ├── fprule/                      #   误报规则
│   ├── monitoragent/                #   内嵌监控 Agent
│   ├── formdesign/                  #   表单设计器
│   ├── systemdict/                  #   系统字典
│   ├── setting/                     #   系统设置
│   ├── knowledge/                   #   知识库
│   ├── template/                    #   模板管理
│   ├── intel/                       #   威胁情报
│   ├── cyberquery/                  #   Cyber 查询
│   ├── health/                      #   健康检查
│   ├── schedule/                    #   Cron 定时调度
│   ├── model/                       #   数据模型
│   ├── migration/                   #   数据库迁移
│   ├── pkg/                         #   公共工具包
│   ├── config.toml                  #   生产配置
│   ├── dev.config.toml              #   开发配置
│   ├── go.mod                       #   Go 模块定义
│   ├── Makefile                     #   构建脚本
│   └── Dockerfile                   #   (已移至 docker/ 目录)
├── vulnscan-frontend/               # 前端 (Vue3 + TS)
│   ├── apps/web/                    #   Web 应用
│   │   ├── src/
│   │   │   ├── api/                 #     API 层
│   │   │   ├── router/              #     路由配置
│   │   │   ├── views/               #     页面组件
│   │   │   ├── store/               #     状态管理
│   │   │   └── ...
│   │   ├── vite.config.mts          #     Vite 配置
│   │   └── .env.development         #     开发环境变量
│   ├── packages/                    #   共享包 (monorepo)
│   │   ├── @core/                   #     核心模块
│   │   ├── effects/                 #     效果模块
│   │   └── business/                #     业务模块
│   ├── internal/                    #   内部工具
│   ├── package.json                 #   根 package.json
│   └── pnpm-workspace.yaml          #   pnpm 工作空间配置
├── docker/
│   └── Dockerfile                   # 生产 Docker 镜像
├── docs/                            # 文档
├── tools/                           # 工具脚本
├── deploy.sh                        # 一键部署脚本
├── DEVELOPMENT.md                   # 开发经验与最佳实践
└── .editorconfig                    # 编辑器配置
```

---

## 5. 非功能指标

| 维度 | 目标 |
|------|------|
| **性能** | 单 Worker 节点：1000+ 并发探测连接，10000+ IP/分钟端口扫描 |
| **扩展性** | 线性水平扩展，10 Worker 节点扫描能力为单节点 ~10 倍 |
| **可用性** | Master 多副本，Worker 无状态可随时替换，任务故障自动重试 |
| **延迟** | 漏洞发现 → 入库 → 通知 < 5 秒 |
| **存储** | 支持 100 万+ 资产、1000 万+ 漏洞记录 |
| **安全** | IAM Token 认证、RBAC 权限、HTTPS、扫描流量隔离、结果加密、操作全审计 |

---

## 6. 容量规划参考

| 规模 | 目标数 | Worker 数 | CPU | 内存 | 数据库 | Redis |
|------|--------|-----------|-----|------|--------|-------|
| 小型 | <1K | 1 (standalone) | 2C | 4G | 单实例 | 单实例 |
| 中型 | 1K-10K | 2-4 | 4C×4 | 8G×4 | 单实例 | 单实例 |
| 大型 | 10K-100K | 5-20 | 8C×20 | 16G×20 | 主备 | 哨兵 |
| 超大 | 100K+ | 20-100 | 8C×100 | 16G×100 | 集群 | 集群 |

---

## 7. 相关文档

- [总体架构设计](design/architecture.md)
- [扫描模块详细设计](design/modules.md)
- [API 接口设计](design/api.md)
- [部署与运维设计](design/deployment.md)
- [开发经验与最佳实践](DEVELOPMENT.md)
