# 漏洞扫描系统 — 中心主控与分主控联邦架构设计

## 1. 架构定位

### 1.1 背景与目标

当前系统为单主控（Master）+ 多 Worker 架构，适用于单组织/单机房场景。当系统需要交付给多个客户、或在多个隔离网段部署时，面临以下问题：

| 问题 | 描述 |
|------|------|
| PoC/指纹分发 | 客户节点无法自行获取最新 PoC 和指纹规则 |
| 数据隔离 | 不同客户的扫描数据不能混在一个库中 |
| 网络隔离 | 客户内网环境可能无法直连中心主控 |
| 离线运行 | 客户环境可能断网，需要本地自治能力 |
| 集中管控 | 运营方需要全局掌握所有节点的状态和汇总数据 |
| 许可证/配额 | 需要按客户控制扫描目标数量、Worker 数、功能模块 |

### 1.2 目标架构

```
                     ┌─────────────────────────────────┐
                     │     Central Master (中心主控)     │
                     │                                 │
                     │  ▸ PoC/指纹/规则权威仓库           │
                     │  ▸ 全局租户管理                    │
                     │  ▸ 许可证签发与配额管控             │
                     │  ▸ 全局数据聚合仪表盘              │
                     │  ▸ 分主控注册与健康监控             │
                     │  ▸ 全局任务下发（可选）             │
                     └──────┬──────────────┬────────────┘
                            │  HTTPS/mTLS  │
              ┌─────────────┘              └──────────────┐
              │                                           │
    ┌─────────▼───────────┐                 ┌─────────────▼─────────┐
    │  Sub-Master A        │                │  Sub-Master B          │
    │  (客户A / 机房A)     │                 │  (客户B / 机房B)       │
    │                      │                │                        │
    │  ▸ 本地完整主控能力   │                 │  ▸ 本地完整主控能力    │
    │  ▸ PoC/指纹增量同步  │                 │  ▸ PoC/指纹增量同步    │
    │  ▸ 本地任务调度      │                 │  ▸ 本地任务调度         │
    │  ▸ 本地数据存储      │                 │  ▸ 本地数据存储         │
    │  ▸ 断网自治运行      │                 │  ▸ 断网自治运行         │
    │  ▸ 数据上报（可选）  │                 │  ▸ 数据上报（可选）     │
    └──┬─────┬─────┬──────┘                 └──┬─────┬─────┬────────┘
       │     │     │                            │     │     │
    Worker Worker Worker                     Worker Worker Worker
```

### 1.3 核心设计原则

| 原则 | 说明 |
|------|------|
| **分主控自治** | 分主控是完整的主控实例，断网时仍可独立运行 |
| **数据主权** | 扫描数据归属分主控，上报中心需显式授权 |
| **增量同步** | PoC/指纹同步采用版本号增量拉取，避免全量传输 |
| **安全通信** | 中心与分主控之间 HTTPS + mTLS + API Token |
| **降级容错** | 中心不可达时分主控使用本地缓存继续工作 |
| **许可证驱动** | 分主控能力（Worker数、模块、目标数）由许可证控制 |

---

## 2. 角色定义

### 2.1 中心主控 (Central Master)

运营方部署，是整个联邦的权威节点。

**核心职责：**

```
┌─────────────────────────────────────────────────────────┐
│                  Central Master 服务层                    │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ 数据仓库服务  │  │ 租户管理服务  │  │ 许可证服务    │  │
│  │              │  │              │  │              │  │
│  │ PoC CRUD     │  │ 分主控注册   │  │ 签发许可证   │  │
│  │ 指纹 CRUD    │  │ 分主控分组   │  │ 配额控制     │  │
│  │ 规则 CRUD    │  │ 健康监控     │  │ 功能开关     │  │
│  │ 版本管理     │  │ 访问控制     │  │ 到期续费     │  │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
│         │                 │                 │          │
│  ┌──────▼─────────────────▼─────────────────▼───────┐  │
│  │                同步分发引擎                        │  │
│  │                                                   │  │
│  │  增量版本计算 → 差异打包 → 签名 → 分发队列         │  │
│  └───────────────────────────────────────────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │              全局聚合服务                         │    │
│  │                                                 │    │
│  │  ▸ 漏洞汇总仪表盘                               │    │
│  │  ▸ 资产统计总览                                  │    │
│  │  ▸ 扫描任务全局视图                               │    │
│  │  ▸ 节点健康地图                                   │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

**数据库表（中心主控独有）：**

| 表名 | 用途 |
|------|------|
| `cm_tenant` | 租户（客户）管理 |
| `cm_sub_master` | 分主控注册信息 |
| `cm_license` | 许可证配置 |
| `cm_sync_version` | 各数据类型的当前版本号 |
| `cm_sync_log` | 同步历史日志 |
| `cm_aggregate_vuln` | 漏洞汇总（由分主控上报） |
| `cm_aggregate_asset` | 资产统计汇总 |
| `cm_aggregate_scan` | 扫描任务统计汇总 |

### 2.2 分主控 (Sub-Master)

客户现场部署，是具备完整扫描能力的独立节点。

**与现有 Master 的关系：**

分主控 = 现有 Master 全部能力 + 联邦同步模块 + 许可证验证模块

```
┌─────────────────────────────────────────────────────────┐
│                   Sub-Master 服务层                       │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │          现有 Master 全部能力 (不变)               │   │
│  │                                                  │   │
│  │  Scheduler │ Cluster │ Runner │ API │ WebSocket  │   │
│  │  TaskQueue │ Worker 管理 │ Persist │ Cron       │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ 联邦同步模块  │  │ 许可证验证    │  │ 数据上报模块  │  │
│  │  (新增)      │  │  (新增)      │  │  (新增)      │  │
│  │              │  │              │  │              │  │
│  │ PoC 拉取     │  │ 许可证解析   │  │ 漏洞摘要     │  │
│  │ 指纹拉取     │  │ 配额检查     │  │ 资产统计     │  │
│  │ 规则拉取     │  │ 功能限制     │  │ 任务状态     │  │
│  │ 版本追踪     │  │ 离线宽限     │  │ 健康状态     │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 3. 通信协议

### 3.1 传输层

| 层级 | 选型 | 说明 |
|------|------|------|
| 传输协议 | HTTPS (TLS 1.3) | 中心 ↔ 分主控 |
| 认证方式 | mTLS + API Token | 双向证书认证 + Token 鉴权 |
| 序列化 | JSON | 通用、可调试 |
| 压缩 | gzip | 大批量同步时启用 |

### 3.2 API 设计

所有 Federation API 前缀为 `/federation/v1/`。

#### 3.2.1 分主控 → 中心主控 (上行)

```
# 注册/心跳
POST   /federation/v1/register         # 分主控注册（首次上线）
POST   /federation/v1/heartbeat        # 周期性心跳（30s）

# 数据拉取
GET    /federation/v1/sync/poc         # 拉取 PoC 增量
GET    /federation/v1/sync/fingerprint # 拉取指纹增量
GET    /federation/v1/sync/rule        # 拉取规则增量
GET    /federation/v1/sync/manifest    # 拉取版本清单

# 数据上报
POST   /federation/v1/report/vuln      # 上报漏洞摘要
POST   /federation/v1/report/asset     # 上报资产统计
POST   /federation/v1/report/scan      # 上报扫描统计
POST   /federation/v1/report/health    # 上报健康状态

# 许可证
GET    /federation/v1/license/check    # 验证许可证有效性
GET    /federation/v1/license/renew    # 续期许可证
```

#### 3.2.2 中心主控 → 分主控 (下行，可选)

```
# 远程控制（通过分主控心跳的 Response 携带命令）
命令类型:
  - force_sync          # 强制立即同步
  - disable_module      # 禁用某模块
  - update_quota        # 更新配额
  - revoke_license      # 吊销许可证
  - create_task         # 远程下发扫描任务
  - drain               # 排干任务准备维护
```

### 3.3 认证流程

```
┌────────────┐                              ┌────────────────┐
│ Sub-Master │                              │ Central Master │
└─────┬──────┘                              └───────┬────────┘
      │                                             │
      │  1. POST /federation/v1/register            │
      │  Body: {                                    │
      │    sub_master_id,                           │
      │    hostname,                                │
      │    client_cert (mTLS),                      │
      │    license_key,                             │
      │    capabilities,                            │
      │    version                                  │
      │  }                                          │
      │ ─────────────────────────────────────────► │
      │                                             │
      │                    验证 license_key          │
      │                    验证 client_cert          │
      │                    生成 api_token            │
      │                    记录 sub_master 信息      │
      │                                             │
      │  Response: {                                │
      │    api_token,                               │
      │    sync_interval,                           │
      │    quota: { ... },                          │
      │    current_versions: { ... }                │
      │  }                                          │
      │ ◄───────────────────────────────────────── │
      │                                             │
      │  2. 后续请求                                 │
      │  Header: Authorization: Bearer <api_token>  │
      │  + mTLS 证书                                 │
      │ ─────────────────────────────────────────► │
```

---

## 4. 数据同步机制

### 4.1 版本号体系

每种数据类型维护一个单调递增的版本号（int64）。中心主控是版本号的唯一颁发者。

```
数据类型：
  poc         → version: 1527    (最后一个 PoC 变更的版本)
  fingerprint → version: 892     (最后一个指纹变更的版本)
  rule        → version: 356     (最后一个规则变更的版本)
```

**版本号生成规则：**

| 操作 | 版本号行为 |
|------|-----------|
| 新增 PoC | poc_version++ |
| 修改 PoC | poc_version++（同一记录获得新版本号） |
| 禁用 PoC | poc_version++（标记 `deleted_at`） |
| 删除 PoC | poc_version++（标记 `deleted_at`） |

每条数据记录携带字段：

```go
type SyncableRecord struct {
    SyncVersion  int64      `gorm:"index;not null"`       // 变更时的版本号
    DeletedAt    *time.Time `gorm:"index"`                // 软删除标记
}
```

### 4.2 增量拉取流程

```
分主控                                     中心主控
  │                                          │
  │  GET /sync/poc?since_version=1500        │
  │       &limit=500                         │
  │ ────────────────────────────────────►    │
  │                                          │
  │   SELECT * FROM vs_poc_template          │
  │   WHERE sync_version > 1500              │
  │   ORDER BY sync_version ASC              │
  │   LIMIT 500                              │
  │                                          │
  │  Response: {                             │
  │    items: [                              │
  │      { sync_version: 1501,               │
  │        poc_id: "CVE-2026-1234",          │
  │        action: "upsert",                 │
  │        content: "..." },                 │
  │      { sync_version: 1502,               │
  │        poc_id: "old-poc-001",            │
  │        action: "delete" },               │
  │      ...                                 │
  │    ],                                    │
  │    latest_version: 1527,                 │
  │    has_more: true                        │
  │  }                                       │
  │ ◄──────────────────────────────────────  │
  │                                          │
  │  应用变更到本地数据库:                     │
  │  upsert → 插入或更新本地 PoC             │
  │  delete → 软删除本地 PoC                 │
  │  更新本地 since_version = max(items)     │
  │                                          │
  │  如果 has_more=true，继续拉取             │
  │  GET /sync/poc?since_version=1505...     │
  │ ────────────────────────────────────►    │
```

### 4.3 同步策略

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `sync_interval` | 10min | 常规同步间隔 |
| `sync_batch_size` | 500 | 每次拉取批量大小 |
| `sync_retry_max` | 3 | 失败重试次数 |
| `sync_retry_backoff` | 1s → 2s → 4s | 指数退避 |
| `force_full_sync_threshold` | 10000 | 版本差距超过此值时强制全量同步 |

### 4.4 冲突处理

| 场景 | 策略 |
|------|------|
| 中心修改了分主控也有的 PoC | 中心版本覆盖（中心为权威源） |
| 分主控本地新增 PoC | 仅存储在本地，不影响同步 |
| 分主控修改了中心同步的 PoC | 下次同步被中心版本覆盖（可选配置） |
| 同步中断恢复 | 基于 `since_version` 断点续传 |

### 4.5 离线模式

```
┌─────────────────────────────────────────────────────┐
│ 分主控离线运行规则                                     │
│                                                     │
│ 1. 中心不可达时:                                      │
│    ✅ 继续使用本地已同步的 PoC/指纹/规则                │
│    ✅ 继续本地任务调度和扫描                            │
│    ✅ 数据上报队列本地缓存                              │
│    ⚠️ 许可证离线宽限期（默认 30 天）                    │
│    ❌ 无法获取新增的 PoC/指纹更新                       │
│                                                     │
│ 2. 恢复连接后:                                        │
│    → 自动增量同步（从断开时的版本号继续）                 │
│    → 批量上报缓存的数据                                │
│    → 刷新许可证有效期                                   │
│                                                     │
│ 3. 许可证过期后:                                       │
│    → 进入只读模式（可查看历史数据，不能启动新扫描）       │
│    → Worker 停止接受新任务                              │
│    → 界面提示续费/联系运营方                             │
└─────────────────────────────────────────────────────┘
```

---

## 5. 许可证系统

### 5.1 许可证结构

```go
type License struct {
    LicenseID     string    `json:"license_id"`
    TenantID      string    `json:"tenant_id"`       // 租户
    SubMasterID   string    `json:"sub_master_id"`   // 绑定的分主控
    
    // 配额
    MaxWorkers    int       `json:"max_workers"`     // 最大 Worker 数
    MaxTargets    int       `json:"max_targets"`     // 最大目标数
    MaxScansDay   int       `json:"max_scans_day"`   // 每日最大扫描次数
    
    // 功能开关
    Modules       []string  `json:"modules"`         // 允许使用的扫描模块
    Features      []string  `json:"features"`        // 允许使用的功能特性
    
    // 有效期
    IssuedAt      time.Time `json:"issued_at"`
    ExpiresAt     time.Time `json:"expires_at"`
    GracePeriod   int       `json:"grace_period"`    // 离线宽限天数
    
    // 签名
    Signature     string    `json:"signature"`       // RSA-SHA256 签名
}
```

### 5.2 许可证验证流程

```
分主控启动
    │
    ▼
读取本地许可证文件
    │
    ├─ 验证 RSA 签名 → 签名无效 → 拒绝启动
    │
    ├─ 检查到期时间 → 已过期
    │       │
    │       ├─ 在宽限期内 → 降级运行（标记 degraded）
    │       │
    │       └─ 超过宽限期 → 只读模式
    │
    ├─ 在线验证（尝试）
    │       │
    │       ├─ 成功 → 更新本地许可证缓存
    │       │
    │       └─ 失败 → 使用本地缓存（记录离线开始时间）
    │
    └─ 正常运行
        │
        └─ 周期性检查（每小时）
            ├─ 在线验证 + 续期
            └─ 配额检查（Worker 数、目标数、扫描次数）
```

### 5.3 配额执行

| 检查点 | 配额项 | 行为 |
|--------|--------|------|
| Worker 注册 | `max_workers` | 超限拒绝注册 |
| 创建扫描任务 | `max_targets` | 超限拒绝创建 |
| 启动扫描 | `max_scans_day` | 超限排队等待次日 |
| 模块加载 | `modules` | 未授权模块跳过 |
| 功能入口 | `features` | 未授权功能返回 403 |

---

## 6. 数据上报

### 6.1 上报内容（分主控 → 中心主控）

上报是**可选行为**，由中心主控配置决定，分主控可在设置中关闭。

| 数据类型 | 上报内容 | 频率 | 隐私级别 |
|---------|---------|------|---------|
| 健康状态 | CPU/内存/Worker数/任务数 | 30s（随心跳） | 低 |
| 扫描统计 | 任务数/目标数/漏洞计数(按severity) | 5min | 低 |
| 资产摘要 | 资产总数/分布统计 | 1h | 中 |
| 漏洞摘要 | 漏洞统计(按severity/类型) | 1h | 中 |
| 漏洞详情 | 完整漏洞记录（脱敏可选） | 按需 | 高 |

### 6.2 上报数据结构

```go
// 漏洞摘要上报
type VulnSummaryReport struct {
    SubMasterID  string                 `json:"sub_master_id"`
    ReportAt     time.Time              `json:"report_at"`
    Period       string                 `json:"period"`          // "hourly", "daily"
    TotalVulns   int64                  `json:"total_vulns"`
    BySeverity   map[string]int64       `json:"by_severity"`     // {"critical":5,"high":23,...}
    ByType       map[string]int64       `json:"by_type"`         // {"sqli":10,"xss":8,...}
    NewVulns     int64                  `json:"new_vulns"`       // 本周期新增
    FixedVulns   int64                  `json:"fixed_vulns"`     // 本周期修复
}

// 扫描统计上报
type ScanStatsReport struct {
    SubMasterID   string    `json:"sub_master_id"`
    ReportAt      time.Time `json:"report_at"`
    ActiveTasks   int64     `json:"active_tasks"`
    CompletedDay  int64     `json:"completed_today"`
    TotalTargets  int64     `json:"total_targets"`
    ActiveWorkers int64     `json:"active_workers"`
    AvgScanTime   float64   `json:"avg_scan_time_sec"`
}
```

### 6.3 上报缓冲

分主控在本地维护上报缓冲队列，中心不可达时数据不丢失：

```
┌──────────────────────────────────────────────┐
│            上报缓冲机制                        │
│                                              │
│  汇总数据 → 本地缓冲队列 (SQLite/BadgerDB)   │
│                  │                           │
│              ┌───▼───┐                       │
│              │ 中心   │                       │
│              │ 可达？ │                       │
│              └┬─────┬┘                       │
│           是  │     │ 否                      │
│          ┌────▼┐  ┌─▼────┐                   │
│          │发送  │  │排队   │                   │
│          │成功  │  │等待   │                   │
│          └──┬──┘  └──┬───┘                   │
│             │        │                       │
│        清除队列   恢复连接后                   │
│                  批量发送                      │
│                                              │
│  缓冲上限: 10000条 / 100MB                    │
│  超限策略: 丢弃最早的统计数据（保留详情数据）    │
└──────────────────────────────────────────────┘
```

---

## 7. 数据模型

### 7.1 中心主控新增表

```sql
-- 租户管理
CREATE TABLE cm_tenant (
    id          VARCHAR(36) PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    code        VARCHAR(100) UNIQUE NOT NULL,   -- 租户编码
    contact     VARCHAR(200),
    email       VARCHAR(200),
    phone       VARCHAR(50),
    status      VARCHAR(20) DEFAULT 'active',   -- active, suspended, expired
    config      JSONB DEFAULT '{}',             -- 租户级别配置
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW()
);

-- 分主控注册
CREATE TABLE cm_sub_master (
    id              VARCHAR(36) PRIMARY KEY,
    tenant_id       VARCHAR(36) REFERENCES cm_tenant(id),
    sub_master_id   VARCHAR(100) UNIQUE NOT NULL,  -- 分主控自报 ID
    name            VARCHAR(200),
    hostname        VARCHAR(200),
    ip_address      VARCHAR(50),
    version         VARCHAR(50),                    -- 软件版本号
    status          VARCHAR(20) DEFAULT 'offline',  -- online, offline, degraded, maintenance
    
    -- 同步状态
    poc_version         BIGINT DEFAULT 0,
    fingerprint_version BIGINT DEFAULT 0,
    rule_version        BIGINT DEFAULT 0,
    last_sync_at        TIMESTAMP,
    
    -- 健康数据
    last_heartbeat_at   TIMESTAMP,
    cpu_percent         FLOAT DEFAULT 0,
    mem_percent         FLOAT DEFAULT 0,
    worker_count        INT DEFAULT 0,
    active_tasks        INT DEFAULT 0,
    
    -- 配额使用
    current_targets     INT DEFAULT 0,
    scans_today         INT DEFAULT 0,
    
    -- 许可证
    license_id          VARCHAR(36),
    license_expires_at  TIMESTAMP,
    
    -- 能力声明
    capabilities        JSONB DEFAULT '[]',
    labels              JSONB DEFAULT '{}',
    
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_sub_master_tenant ON cm_sub_master(tenant_id);
CREATE INDEX idx_sub_master_status ON cm_sub_master(status);

-- 许可证管理
CREATE TABLE cm_license (
    id              VARCHAR(36) PRIMARY KEY,
    tenant_id       VARCHAR(36) REFERENCES cm_tenant(id),
    sub_master_id   VARCHAR(36),           -- 绑定到具体分主控，NULL 表示租户级
    license_key     VARCHAR(500) UNIQUE NOT NULL,
    
    max_workers     INT DEFAULT 5,
    max_targets     INT DEFAULT 1000,
    max_scans_day   INT DEFAULT 50,
    modules         JSONB DEFAULT '[]',    -- 允许的模块列表
    features        JSONB DEFAULT '[]',    -- 允许的功能列表
    
    issued_at       TIMESTAMP NOT NULL,
    expires_at      TIMESTAMP NOT NULL,
    grace_period    INT DEFAULT 30,        -- 天
    
    status          VARCHAR(20) DEFAULT 'active',  -- active, expired, revoked
    signature       TEXT NOT NULL,          -- RSA-SHA256 签名
    
    created_at  TIMESTAMP DEFAULT NOW(),
    updated_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_license_tenant ON cm_license(tenant_id);

-- 同步版本追踪
CREATE TABLE cm_sync_version (
    data_type       VARCHAR(50) PRIMARY KEY,    -- poc, fingerprint, rule
    current_version BIGINT DEFAULT 0,
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- 同步日志
CREATE TABLE cm_sync_log (
    id              VARCHAR(36) PRIMARY KEY,
    sub_master_id   VARCHAR(100) NOT NULL,
    data_type       VARCHAR(50) NOT NULL,
    from_version    BIGINT NOT NULL,
    to_version      BIGINT NOT NULL,
    record_count    INT NOT NULL,
    status          VARCHAR(20),    -- success, partial, failed
    error_message   TEXT,
    duration_ms     INT,
    synced_at       TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_sync_log_sub_master ON cm_sync_log(sub_master_id, synced_at);

-- 聚合数据
CREATE TABLE cm_aggregate_vuln (
    id              VARCHAR(36) PRIMARY KEY,
    sub_master_id   VARCHAR(100) NOT NULL,
    tenant_id       VARCHAR(36) NOT NULL,
    report_at       TIMESTAMP NOT NULL,
    period          VARCHAR(20) NOT NULL,   -- hourly, daily
    total_vulns     BIGINT DEFAULT 0,
    by_severity     JSONB DEFAULT '{}',
    by_type         JSONB DEFAULT '{}',
    new_vulns       BIGINT DEFAULT 0,
    fixed_vulns     BIGINT DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_agg_vuln_tenant ON cm_aggregate_vuln(tenant_id, report_at);

CREATE TABLE cm_aggregate_scan (
    id              VARCHAR(36) PRIMARY KEY,
    sub_master_id   VARCHAR(100) NOT NULL,
    tenant_id       VARCHAR(36) NOT NULL,
    report_at       TIMESTAMP NOT NULL,
    active_tasks    BIGINT DEFAULT 0,
    completed_today BIGINT DEFAULT 0,
    total_targets   BIGINT DEFAULT 0,
    active_workers  BIGINT DEFAULT 0,
    avg_scan_time   FLOAT DEFAULT 0,
    created_at      TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_agg_scan_tenant ON cm_aggregate_scan(tenant_id, report_at);
```

### 7.2 现有表扩展

在 `vs_poc_template` 表增加同步字段：

```sql
ALTER TABLE vs_poc_template ADD COLUMN sync_version BIGINT DEFAULT 0;
ALTER TABLE vs_poc_template ADD COLUMN source_type VARCHAR(20) DEFAULT 'local';
  -- local: 本地创建
  -- central: 中心同步
  -- community: 社区导入

CREATE INDEX idx_poc_sync_version ON vs_poc_template(sync_version);
```

对 `vs_service_fingerprint` 和 `vs_scan_rule` 做同样的扩展。

### 7.3 分主控新增表

```sql
-- 联邦同步状态（分主控本地）
CREATE TABLE federation_sync_state (
    data_type       VARCHAR(50) PRIMARY KEY,
    local_version   BIGINT DEFAULT 0,     -- 本地已同步到的版本号
    last_sync_at    TIMESTAMP,
    last_error      TEXT,
    retry_count     INT DEFAULT 0
);

-- 上报缓冲队列
CREATE TABLE federation_report_buffer (
    id          VARCHAR(36) PRIMARY KEY,
    report_type VARCHAR(50) NOT NULL,     -- vuln_summary, scan_stats, etc.
    payload     JSONB NOT NULL,
    status      VARCHAR(20) DEFAULT 'pending',  -- pending, sending, sent, failed
    retry_count INT DEFAULT 0,
    created_at  TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_report_buffer_status ON federation_report_buffer(status, created_at);
```

---

## 8. 同步数据结构扩展

### 8.1 PocTemplate 扩展

现有 `model.PocTemplate` 增加同步字段：

```go
type PocTemplate struct {
    // ... 现有字段 ...
    
    // 联邦同步字段
    SyncVersion int64  `gorm:"index;default:0"`          // 中心主控分配的版本号
    SourceType  string `gorm:"type:varchar(20);default:'local'"` // local/central/community
}
```

### 8.2 同步响应格式

```go
// 通用同步响应
type SyncResponse struct {
    Items         []SyncItem `json:"items"`
    LatestVersion int64      `json:"latest_version"`  // 当前最新版本
    HasMore       bool       `json:"has_more"`         // 是否还有更多
    ServerTime    time.Time  `json:"server_time"`      // 服务器时间（用于时钟偏差校正）
}

// 同步条目
type SyncItem struct {
    SyncVersion int64           `json:"sync_version"`
    Action      string          `json:"action"`       // "upsert" 或 "delete"
    DataType    string          `json:"data_type"`     // "poc", "fingerprint", "rule"
    DataID      string          `json:"data_id"`       // 数据唯一标识
    Content     json.RawMessage `json:"content"`       // 完整数据（upsert时）
    Checksum    string          `json:"checksum"`      // SHA256 校验（可选）
}
```

---

## 9. 运行模式变更

### 9.1 新增运行模式

在现有 `standalone`, `master`, `worker` 基础上新增：

| 模式 | 启动命令 | 说明 |
|------|---------|------|
| `central` | `--mode=central` | 中心主控模式 |
| `sub-master` | `--mode=sub-master` | 分主控模式 |

### 9.2 模式能力矩阵

```
                 standalone  master  worker  central  sub-master
Web API             ✅        ✅      ❌       ✅        ✅
Scheduler           ✅        ✅      ❌       ❌        ✅
Worker Manager      ✅        ✅      ❌       ❌        ✅
Scan Engine         ✅        ❌      ✅       ❌        ❌(Worker做)
Federation Server   ❌        ❌      ❌       ✅        ❌
Federation Client   ❌        ❌      ❌       ❌        ✅
License Server      ❌        ❌      ❌       ✅        ❌
License Client      ❌        ❌      ❌       ❌        ✅
Data Aggregation    ❌        ❌      ❌       ✅        ❌
Data Reporting      ❌        ❌      ❌       ❌        ✅
```

### 9.3 配置变更

```toml
# config.toml 新增 [federation] 段

[federation]
# 当 mode = central 时生效
enabled = true
listen_addr = ":9443"           # Federation API 监听地址（独立端口）
tls_cert = "./certs/server.crt"
tls_key = "./certs/server.key"
ca_cert = "./certs/ca.crt"       # 用于验证分主控的客户端证书
license_private_key = "./certs/license.key"  # 许可证签名私钥

# 当 mode = sub-master 时生效
[federation.upstream]
central_url = "https://central.example.com:9443"
api_token = ""                   # 注册后获取，也可预配置
tls_cert = "./certs/client.crt"  # 客户端证书
tls_key = "./certs/client.key"
ca_cert = "./certs/ca.crt"
license_file = "./license.json"  # 本地许可证文件
sync_interval = "10m"
report_interval = "5m"
offline_grace_days = 30
```

---

## 10. 安全设计

### 10.1 通信安全

```
┌─────────────────────────────────────────────────────┐
│                  安全层级                             │
│                                                     │
│  Layer 1: mTLS（双向证书认证）                        │
│    ▸ 中心主控持有 CA 根证书                           │
│    ▸ 每个分主控持有唯一客户端证书                      │
│    ▸ 证书吊销列表(CRL) 实时生效                       │
│                                                     │
│  Layer 2: API Token（应用层认证）                     │
│    ▸ 注册时签发，周期性轮转                           │
│    ▸ HMAC-SHA256 签名                               │
│    ▸ 短有效期(24h) + 自动续期                        │
│                                                     │
│  Layer 3: 许可证签名（功能授权）                      │
│    ▸ RSA-2048 / Ed25519 签名                        │
│    ▸ 防篡改、防伪造                                  │
│    ▸ 绑定分主控硬件指纹（可选）                       │
│                                                     │
│  Layer 4: 数据完整性                                 │
│    ▸ 同步数据 SHA256 校验                            │
│    ▸ 传输 gzip 压缩                                 │
│    ▸ 防重放（Nonce + Timestamp）                     │
└─────────────────────────────────────────────────────┘
```

### 10.2 数据隔离

| 隔离维度 | 实现方式 |
|---------|---------|
| 租户数据隔离 | 每个分主控独立数据库 |
| 上报数据隔离 | 中心主控按 `tenant_id` 隔离存储 |
| PoC 可见性 | 中心可控制哪些 PoC 对哪些租户可见 |
| 扫描结果 | 分主控本地存储，上报摘要可脱敏 |

### 10.3 审计日志

```go
type FederationAuditLog struct {
    ID            string    `json:"id"`
    SubMasterID   string    `json:"sub_master_id"`
    TenantID      string    `json:"tenant_id"`
    Action        string    `json:"action"`           // sync, report, register, license_check
    DataType      string    `json:"data_type"`
    Detail        string    `json:"detail"`
    IP            string    `json:"ip"`
    UserAgent     string    `json:"user_agent"`
    Status        string    `json:"status"`           // success, failed
    ErrorMessage  string    `json:"error_message"`
    CreatedAt     time.Time `json:"created_at"`
}
```

---

## 11. 实现路线图

### Phase 1: 基础联邦框架（核心）

| 任务 | 文件/模块 | 预估工作量 |
|------|----------|-----------|
| 中心主控 Federation Server | `federation/server/` | 3 天 |
| 分主控 Federation Client | `federation/client/` | 2 天 |
| 数据同步引擎（PoC/指纹/规则增量同步） | `federation/sync/` | 3 天 |
| 分主控注册 + 心跳 | `federation/` | 1 天 |
| mTLS + API Token 认证 | `federation/auth/` | 1 天 |
| 数据模型 + 迁移 | `model/federation.go` | 1 天 |
| 配置 + 运行模式 | `boot/`, `cmd/` | 0.5 天 |

**Phase 1 产出：** 分主控可以从中心主控拉取 PoC/指纹/规则更新。

### Phase 2: 许可证系统

| 任务 | 文件/模块 | 预估工作量 |
|------|----------|-----------|
| 许可证生成 + RSA 签名 | `federation/license/` | 1.5 天 |
| 许可证验证 + 配额执行 | `federation/license/` | 1.5 天 |
| 许可证管理 API（中心） | `federation/server/` | 1 天 |
| 离线宽限 + 降级逻辑 | `federation/client/` | 1 天 |

**Phase 2 产出：** 配额控制 + 离线运行能力。

### Phase 3: 数据上报

| 任务 | 文件/模块 | 预估工作量 |
|------|----------|-----------|
| 上报数据采集器 | `federation/reporter/` | 1 天 |
| 上报缓冲队列 | `federation/reporter/` | 1 天 |
| 中心数据聚合 + 存储 | `federation/aggregator/` | 1.5 天 |
| 全局仪表盘 API | `federation/server/` | 1.5 天 |

**Phase 3 产出：** 中心主控可以看到所有分主控的汇总数据。

### Phase 4: 运维与高级功能

| 任务 | 文件/模块 | 预估工作量 |
|------|----------|-----------|
| 远程命令下发 | `federation/` | 1 天 |
| 全局任务下发到分主控 | `federation/server/` | 1.5 天 |
| 租户管理 UI/API | 中心主控 | 2 天 |
| PoC 发布管理（按租户/标签推送） | 中心主控 | 1.5 天 |
| 健康监控 + 告警 | `federation/monitor/` | 1 天 |

---

## 12. 部署拓扑示例

### 12.1 运营方 + 多客户

```
运营方数据中心
┌─────────────────────────────────────┐
│  Central Master                     │
│  PostgreSQL + Redis                 │
│  PoC 库 (50000+)                    │
│  指纹库 (10000+)                    │
│  全局仪表盘                          │
└──────────┬──────────────────────────┘
           │ Internet (HTTPS/mTLS)
     ┌─────┼──────────────────┐
     │     │                  │
┌────▼─────┴─┐      ┌────────▼──────┐
│ 客户A内网   │      │ 客户B内网      │
│            │      │               │
│ Sub-Master │      │ Sub-Master    │
│ + 3 Worker │      │ + 10 Worker   │
│ + PG + Redis│     │ + PG + Redis  │
│            │      │               │
│ 许可证:     │      │ 许可证:        │
│  5 Worker  │      │  15 Worker    │
│  5K 目标   │      │  50K 目标     │
│  全模块     │      │  全模块        │
└────────────┘      └───────────────┘
```

### 12.2 单组织多机房

```
总部机房
┌──────────────────────┐
│ Central Master       │
│ (也是 Sub-Master)    │  ← 总部既是中心也是分主控
│ + Workers            │
└───────┬──────────────┘
        │ 专线 / VPN
  ┌─────┼──────────┐
  │     │          │
┌─▼────┐│  ┌──────▼──────┐
│机房B  ││  │ 机房C        │
│Sub   ││  │ Sub-Master  │
│Master││  │ + Workers   │
│+Work ││  └─────────────┘
└──────┘│
```

---

## 13. 与现有代码的集成点

| 现有模块 | 集成方式 | 改动量 |
|---------|---------|--------|
| `cmd/` | 新增 `cmd/central/main.go` 入口 | 新增 |
| `boot/config.go` | 新增 `[federation]` 配置段 | 小改 |
| `model/poc.go` | 新增 `SyncVersion`, `SourceType` 字段 | 小改 |
| `model/fingerprint.go` | 同上 | 小改 |
| `model/scan_rule.go` | 同上 | 小改 |
| `nuclei/store.go` | 新增 `LoadBySyncVersion` 方法 | 小改 |
| `di/handlers.go` | 分主控模式注册 Federation Client | 小改 |
| `cluster/` | 无直接改动（分主控复用现有 cluster） | 无 |
| `scheduler/` | 许可证配额检查点 | 小改 |

**核心设计原则：新增代码为主，尽量不改动现有已稳定的代码。**

<function_calls>
<invoke name="CallMcpTool">
<parameter name="server">project-0-iam-CursorMCP对话插件