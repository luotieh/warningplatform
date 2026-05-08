# 漏洞扫描系统 — 总体架构设计

## 1. 系统定位

一套**自研、高性能、分布式**的漏洞扫描平台，覆盖 Web 应用、网络服务、主机安全、API 安全等扫描维度。

**核心设计原则：**

| 原则 | 说明 |
|------|------|
| 自主可控 | Go 自研扫描引擎，不依赖 Nmap/Nuclei/ZAP 等外部二进制，仅使用 Go 标准库和轻量级 SDK |
| 分布式优先 | Master-Worker 架构，水平扩展，任务分片，无单点瓶颈 |
| 插件化 | 扫描能力通过 Plugin 注册，支持热加载 YAML/Go 插件 |
| 高性能 | Goroutine 池 + 连接池 + 异步流水线，单节点万级并发探测 |
| 安全隔离 | 扫描流量隔离、结果加密存储、操作审计 |

## 2. 整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        前端 (Vue3 + Naive UI)                    │
│  Dashboard │ 资产管理 │ 任务中心 │ 漏洞库 │ 报告中心 │ 系统设置   │
└──────────────────────────┬──────────────────────────────────────┘
                           │ REST / WebSocket
┌──────────────────────────▼──────────────────────────────────────┐
│                    API Gateway (Go + Gin)                        │
│  认证鉴权 │ 限流 │ 路由分发 │ WebSocket Hub │ OpenAPI 文档       │
└─────┬──────────┬───────────┬─────────────┬──────────────────────┘
      │          │           │             │
      ▼          ▼           ▼             ▼
┌──────────┐ ┌────────┐ ┌─────────┐ ┌──────────────┐
│  Master   │ │ Asset  │ │  Vuln   │ │   Report     │
│ Scheduler │ │ Service│ │ Service │ │   Service    │
│           │ │        │ │         │ │              │
│ 任务编排  │ │ 资产   │ │ 漏洞库  │ │ 报告生成     │
│ 分片分发  │ │ 发现   │ │ 知识库  │ │ PDF/HTML     │
│ 状态追踪  │ │ 指纹库 │ │ 去重    │ │ 导出         │
└─────┬─────┘ └────────┘ └─────────┘ └──────────────┘
      │
      │ gRPC / NATS
      │
┌─────▼─────────────────────────────────────────────┐
│              Worker Cluster (N 个节点)              │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │            Scan Engine (每个 Worker)          │  │
│  │                                              │  │
│  │  Pipeline:                                   │  │
│  │  [Target] → [Discovery] → [Fingerprint]     │  │
│  │          → [PluginMatch] → [Exploit/Verify]  │  │
│  │          → [Report]                          │  │
│  │                                              │  │
│  │  Plugins:                                    │  │
│  │  • PortScan     • WebCrawler                 │  │
│  │  • ServiceProbe • VulnCheck (YAML PoC)       │  │
│  │  • DirBrute     • SQLi / XSS / SSRF         │  │
│  │  • WeakPass     • CertCheck                  │  │
│  │  • APIFuzz      • InfoLeak                   │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Goroutine Pool │ Connection Pool │ Rate Limiter   │
└────────────────────────────────────────────────────┘
      │
      ▼
┌─────────────────────────────────────────────────────┐
│                   存储层                             │
│  PostgreSQL (主数据)  │  Redis (缓存/队列/锁)       │
│  MinIO/S3 (报告/附件) │  ClickHouse (扫描日志/统计) │
└─────────────────────────────────────────────────────┘
```

## 3. 核心组件

### 3.1 Master Scheduler (调度主控)

| 能力 | 实现 |
|------|------|
| 任务创建 | 接收 API 请求，解析目标范围，拆分子任务 |
| 分片策略 | 按 IP 段/域名/端口范围分片，均匀分配到 Worker |
| Worker 管理 | 心跳检测、负载感知、故障转移 |
| 进度汇聚 | 实时聚合各 Worker 进度，推送到前端 |
| 去重调度 | 同一目标短期内不重复扫描 |
| 优先级队列 | 支持 P0-P3 优先级，紧急任务插队 |

**选型决策：**
- 消息传递：**NATS**（轻量、Go 原生、支持 JetStream 持久化）
- 如果不想引入 NATS，可退化为 **Redis Stream** 作为消息队列
- 分布式锁：Redis RedLock

### 3.2 Worker (扫描节点)

每个 Worker 是一个独立进程，包含完整的扫描引擎：

```
Worker 启动流程：
1. 连接 Master，注册自身（CPU/内存/带宽/地理位置）
2. 加载插件库（YAML PoC + Go 插件）
3. 进入事件循环：
   - 拉取任务 → 解析目标 → 执行 Pipeline → 上报结果
   - 定时心跳 → 上报负载指标
```

**关键设计：**
- **Goroutine 池**：`ants` 库或自实现 worker pool，限制并发数
- **连接池**：HTTP/TCP 连接复用，减少 TIME_WAIT
- **速率控制**：per-target 令牌桶，防止打挂目标
- **优雅关闭**：收到信号后等待当前任务完成

### 3.3 Scan Engine (扫描引擎)

扫描引擎是核心组件，采用 **Pipeline（流水线）** 模型：

```
Stage 1: Target Resolution
  DNS 解析 / IP 归属 / CDN 检测

Stage 2: Port Discovery
  自研 SYN/TCP Connect 扫描器
  Top 1000 端口 + 自定义端口

Stage 3: Service Fingerprint
  Banner Grab + Probe 匹配
  HTTP 指纹（Server / X-Powered-By / favicon hash / body hash）
  TLS 证书解析

Stage 4: Vulnerability Detection
  基于指纹匹配 PoC 集合
  执行 YAML PoC（自定义 DSL）
  Fuzz 模块（SQLi / XSS / SSRF / Command Injection）

Stage 5: Result Aggregation
  去重、评分（CVSS）、关联资产
  写入数据库、触发通知
```

### 3.4 Plugin System (插件系统)

```yaml
# 插件定义格式 (YAML PoC)
id: CVE-2024-XXXX
info:
  name: "Apache Struts2 RCE"
  severity: critical
  cvss: 9.8
  tags: [rce, apache, struts]
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2024-XXXX

match:
  - type: fingerprint
    service: http
    product: "Apache Struts"

requests:
  - method: POST
    path: /
    headers:
      Content-Type: "multipart/form-data"
    body: |
      ...payload...
    matchers:
      - type: status
        status: [200]
      - type: body
        words: ["uid="]
        condition: and
    extractors:
      - type: regex
        regex: "(uid=\\d+)"
```

**插件分类：**

| 类别 | 说明 | 数量级 |
|------|------|--------|
| PoC 检测 | CVE/CNVD 漏洞验证 | 5000+ |
| 弱口令 | SSH/FTP/MySQL/Redis/RDP 等 | 30+ 协议 |
| 目录扫描 | 敏感路径/备份文件发现 | 内置字典 |
| 信息泄露 | .git/.svn/env/phpinfo 等 | 50+ |
| API 安全 | BOLA/IDOR/认证绕过 | 持续增长 |
| 合规检查 | TLS 版本/HSTS/CSP 等 | 20+ |

## 4. 数据流

```
[创建任务]
    │
    ▼
[Master: 解析目标 → 生成子任务 → 推送队列]
    │
    ▼ (NATS / Redis Stream)
[Worker 拉取子任务]
    │
    ▼
[Pipeline: 探测 → 指纹 → PoC匹配 → 验证]
    │
    ├─→ [实时进度] ──→ Master ──→ WebSocket ──→ 前端
    │
    └─→ [漏洞结果] ──→ Vuln Service ──→ PostgreSQL
                                      ──→ 通知服务 (邮件/webhook/钉钉)
```

## 5. 技术选型

| 层级 | 技术 | 理由 |
|------|------|------|
| 语言 | Go 1.22+ | 并发原生支持、网络编程能力强、交叉编译 |
| Web 框架 | Gin | 轻量高性能 |
| RPC | gRPC + Protobuf | Master-Worker 通信，强类型 |
| 消息队列 | NATS JetStream / Redis Stream | 轻量、Go 生态原生 |
| 主数据库 | PostgreSQL | 复杂查询、JSONB、稳定 |
| 缓存 | Redis | 队列、分布式锁、会话、计数 |
| 时序/日志 | ClickHouse | 扫描日志高写入、聚合分析 |
| 对象存储 | MinIO | 报告/截图/附件 |
| 前端 | Vue3 + TypeScript + Naive UI | 与 IAM 技术栈一致 |
| 容器化 | Docker + Docker Compose | 开发和部署 |
| 编排 | K8s (可选) | 大规模集群部署 |

### 自研替代清单（避免外部工具依赖）

| 能力 | 不用 | 自研方案 |
|------|------|----------|
| 端口扫描 | Nmap | Go `net.Dial` / `syscall` 实现 TCP Connect / SYN scan |
| 漏洞检测 | Nuclei | 自研 YAML PoC 引擎（兼容 Nuclei DSL 子集） |
| Web 爬虫 | Crawlergo | Go `colly` + headless chrome (可选) |
| 目录爆破 | Dirsearch | Go goroutine 池 + 字典 |
| SQL 注入 | SQLMap | 自研检测引擎（布尔/时间盲注/报错注入） |
| 子域名 | Subfinder | DNS 枚举 + 证书透明度 + 搜索引擎 API |
| 弱口令 | Hydra | Go 实现各协议 auth（SSH/FTP/MySQL/Redis 等） |
| 指纹识别 | WhatWeb | HTTP 特征匹配引擎 + 指纹库 |

## 6. 项目结构

```
vulnerability-scan-new/
├── design/                  # 设计文档
├── cmd/                     # 入口
│   ├── master/              # 调度主控
│   ├── worker/              # 扫描节点
│   ├── api/                 # API 服务
│   └── cli/                 # 命令行工具
├── internal/
│   ├── model/               # 数据模型
│   ├── repository/          # 数据访问层
│   ├── service/             # 业务逻辑
│   │   ├── asset/           # 资产管理
│   │   ├── task/            # 任务管理
│   │   ├── vuln/            # 漏洞管理
│   │   └── report/          # 报告管理
│   ├── scheduler/           # 调度器
│   │   ├── dispatcher.go    # 任务分发
│   │   ├── shard.go         # 分片策略
│   │   └── tracker.go       # 进度追踪
│   ├── engine/              # 扫描引擎核心
│   │   ├── pipeline.go      # 流水线
│   │   ├── pool.go          # Goroutine 池
│   │   ├── ratelimit.go     # 速率控制
│   │   └── stage/           # 各阶段
│   │       ├── resolve.go   # DNS 解析
│   │       ├── portscan.go  # 端口扫描
│   │       ├── fingerprint.go # 指纹识别
│   │       └── vulncheck.go # 漏洞检测
│   ├── plugin/              # 插件系统
│   │   ├── loader.go        # 插件加载
│   │   ├── executor.go      # 插件执行
│   │   ├── dsl/             # YAML DSL 解析
│   │   └── builtin/         # 内置插件
│   ├── scanner/             # 各扫描模块
│   │   ├── portscan/        # 端口扫描器
│   │   ├── webcrawl/        # Web 爬虫
│   │   ├── dirscan/         # 目录扫描
│   │   ├── sqli/            # SQL 注入
│   │   ├── xss/             # XSS 检测
│   │   ├── ssrf/            # SSRF 检测
│   │   ├── weakpass/        # 弱口令
│   │   ├── subdomain/       # 子域名发现
│   │   ├── certcheck/       # 证书检查
│   │   └── infoleak/        # 信息泄露
│   ├── transport/           # 通信层
│   │   ├── grpc/            # gRPC 定义
│   │   ├── nats/            # NATS 客户端
│   │   └── ws/              # WebSocket Hub
│   ├── notify/              # 通知
│   │   ├── email.go
│   │   ├── webhook.go
│   │   └── dingtalk.go
│   └── pkg/                 # 公共工具
│       ├── netutil/         # 网络工具
│       ├── fingerdb/        # 指纹库
│       ├── dictdb/          # 字典库
│       ├── cidr/            # CIDR 解析
│       └── crypto/          # 加密工具
├── plugins/                 # YAML PoC 仓库
│   ├── cve/
│   ├── cnvd/
│   ├── weakpass/
│   └── infoleak/
├── web/                     # 前端
├── configs/                 # 配置文件
├── deploy/                  # 部署脚本
│   ├── docker/
│   └── k8s/
├── scripts/                 # 脚本工具
├── go.mod
├── go.sum
└── Makefile
```

## 7. 非功能需求

| 维度 | 目标 |
|------|------|
| **性能** | 单 Worker 节点：1000+ 并发探测连接，10000+ IP/分钟端口扫描 |
| **扩展性** | 线性水平扩展，10 Worker 节点扫描能力为单节点 ~10 倍 |
| **可用性** | Master 多副本，Worker 无状态可随时替换，任务故障自动重试 |
| **延迟** | 漏洞发现 → 入库 → 通知 < 5 秒 |
| **存储** | 支持 100 万+ 资产、1000 万+ 漏洞记录 |
| **安全** | API Token 认证、RBAC 权限、扫描流量隔离、结果加密 |
| **合规** | 扫描操作全审计、支持授权白名单 |

## 8. 部署模式

### 8.1 单机模式 (All-in-One)

开发/小规模场景，Master + Worker + API 在同一进程：

```bash
./vulnscan serve --mode=standalone
```

### 8.2 分布式模式

生产环境，各组件独立部署：

```
┌─────────┐   ┌─────────┐   ┌─────────┐
│ API x2  │   │Master x2│   │Worker xN│
│ (LB)    │   │(主备)   │   │(无状态) │
└────┬────┘   └────┬────┘   └────┬────┘
     │             │             │
     └─────────────┼─────────────┘
                   │
    ┌──────────────┼──────────────┐
    │         NATS Cluster        │
    └──────────────┼──────────────┘
                   │
    ┌──────┬───────┼───────┬──────┐
    │  PG  │ Redis │ MinIO │  CH  │
    └──────┴───────┴───────┴──────┘
```

### 8.3 K8s 模式

Worker 作为 Deployment，根据队列积压量自动 HPA 扩缩容。
