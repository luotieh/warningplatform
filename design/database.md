# 漏洞扫描系统 — 数据模型与数据库设计

## 1. 存储分层

| 存储 | 用途 | 数据特征 |
|------|------|----------|
| PostgreSQL | 资产、任务、漏洞、用户、配置 | 结构化、强一致、复杂查询 |
| Redis | 任务队列、分布式锁、会话缓存、限流计数 | 高频读写、TTL |
| ClickHouse | 扫描日志、探测记录、统计分析 | 高写入、海量聚合 |
| MinIO/S3 | 报告文件、截图、附件 | 大文件、对象存储 |

## 2. PostgreSQL 核心表

### 2.1 资产管理

```sql
-- 资产组（项目/业务线维度）
CREATE TABLE asset_groups (
    id          VARCHAR(26) PRIMARY KEY,          -- ULID
    name        VARCHAR(200) NOT NULL,
    description TEXT DEFAULT '',
    parent_id   VARCHAR(26) REFERENCES asset_groups(id),
    tags        JSONB DEFAULT '[]',
    created_by  VARCHAR(50) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 资产
CREATE TABLE assets (
    id              VARCHAR(26) PRIMARY KEY,
    group_id        VARCHAR(26) REFERENCES asset_groups(id),
    type            VARCHAR(20) NOT NULL,            -- ip, domain, url, cidr, host
    value           VARCHAR(500) NOT NULL,            -- 资产值（IP/域名/URL）
    label           VARCHAR(200) DEFAULT '',
    ip              INET,                             -- 解析后的 IP
    port            INT,
    protocol        VARCHAR(20),                      -- http, https, tcp, udp
    os              VARCHAR(100) DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'active', -- active, inactive, removed
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tags            JSONB DEFAULT '[]',
    extra           JSONB DEFAULT '{}',               -- 扩展信息
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_assets_type ON assets(type);
CREATE INDEX idx_assets_group ON assets(group_id);
CREATE INDEX idx_assets_ip ON assets(ip);
CREATE INDEX idx_assets_value ON assets(value);
CREATE INDEX idx_assets_status ON assets(status);

-- 资产指纹
CREATE TABLE asset_fingerprints (
    id          VARCHAR(26) PRIMARY KEY,
    asset_id    VARCHAR(26) NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    category    VARCHAR(50) NOT NULL,              -- os, webserver, framework, cms, language, waf, cdn
    product     VARCHAR(200) NOT NULL,
    version     VARCHAR(100) DEFAULT '',
    confidence  SMALLINT NOT NULL DEFAULT 80,      -- 0-100
    raw_banner  TEXT DEFAULT '',
    source      VARCHAR(50) NOT NULL,              -- portscan, http_header, favicon, body_hash, cert
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(asset_id, category, product)
);
CREATE INDEX idx_fingerprints_asset ON asset_fingerprints(asset_id);
CREATE INDEX idx_fingerprints_product ON asset_fingerprints(product);

-- 域名记录
CREATE TABLE domains (
    id              VARCHAR(26) PRIMARY KEY,
    group_id        VARCHAR(26) REFERENCES asset_groups(id),
    domain          VARCHAR(500) NOT NULL UNIQUE,
    parent_domain   VARCHAR(500) DEFAULT '',
    source          VARCHAR(50) NOT NULL,          -- manual, subdomain_enum, cert_transparency, dns_brute
    resolved_ips    JSONB DEFAULT '[]',
    cname           VARCHAR(500) DEFAULT '',
    is_wildcard     BOOLEAN DEFAULT FALSE,
    status          VARCHAR(20) NOT NULL DEFAULT 'active',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_domains_group ON domains(group_id);
CREATE INDEX idx_domains_parent ON domains(parent_domain);
```

### 2.2 任务系统

```sql
-- 扫描任务（用户创建的顶层任务）
CREATE TABLE scan_tasks (
    id              VARCHAR(26) PRIMARY KEY,
    name            VARCHAR(200) NOT NULL,
    description     TEXT DEFAULT '',
    type            VARCHAR(30) NOT NULL,           -- full, port, web, vuln, subdomain, custom
    status          VARCHAR(20) NOT NULL DEFAULT 'pending',
                    -- pending, queued, running, paused, completed, failed, cancelled
    priority        SMALLINT NOT NULL DEFAULT 2,    -- 0(highest) - 3(lowest)
    targets         JSONB NOT NULL,                 -- ["192.168.1.0/24", "example.com"]
    target_count    INT NOT NULL DEFAULT 0,
    config          JSONB NOT NULL DEFAULT '{}',    -- 扫描配置
    -- config 结构:
    -- {
    --   "ports": "top1000" | "1-65535" | "80,443,8080",
    --   "rate_limit": 1000,
    --   "timeout_ms": 5000,
    --   "modules": ["portscan", "fingerprint", "vuln"],
    --   "poc_tags": ["rce", "sqli"],
    --   "exclude_ips": ["10.0.0.1"],
    --   "schedule": { "cron": "0 2 * * *", "enabled": true }
    -- }
    progress        JSONB DEFAULT '{}',             -- 实时进度
    -- {
    --   "total_subtasks": 100,
    --   "completed": 45,
    --   "hosts_scanned": 1200,
    --   "vulns_found": 23,
    --   "current_stage": "vuln_check"
    -- }
    result_summary  JSONB DEFAULT '{}',             -- 完成后的结果摘要
    group_id        VARCHAR(26) REFERENCES asset_groups(id),
    scheduled_task_id VARCHAR(26),                  -- 关联定时任务
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ,
    created_by      VARCHAR(50) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tasks_status ON scan_tasks(status);
CREATE INDEX idx_tasks_type ON scan_tasks(type);
CREATE INDEX idx_tasks_created ON scan_tasks(created_at DESC);
CREATE INDEX idx_tasks_group ON scan_tasks(group_id);

-- 子任务（Master 分片后分配给 Worker 的执行单元）
CREATE TABLE scan_subtasks (
    id          VARCHAR(26) PRIMARY KEY,
    task_id     VARCHAR(26) NOT NULL REFERENCES scan_tasks(id) ON DELETE CASCADE,
    worker_id   VARCHAR(100),                      -- 分配到的 Worker 节点
    shard_index INT NOT NULL,                      -- 分片序号
    shard_total INT NOT NULL,
    targets     JSONB NOT NULL,                    -- 本分片的目标列表
    modules     JSONB NOT NULL DEFAULT '[]',       -- 需要执行的模块
    status      VARCHAR(20) NOT NULL DEFAULT 'pending',
    progress    JSONB DEFAULT '{}',
    error       TEXT DEFAULT '',
    retry_count SMALLINT DEFAULT 0,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_subtasks_task ON scan_subtasks(task_id);
CREATE INDEX idx_subtasks_worker ON scan_subtasks(worker_id);
CREATE INDEX idx_subtasks_status ON scan_subtasks(status);

-- 定时扫描任务
CREATE TABLE scheduled_tasks (
    id          VARCHAR(26) PRIMARY KEY,
    name        VARCHAR(200) NOT NULL,
    cron_expr   VARCHAR(100) NOT NULL,             -- cron 表达式
    task_config JSONB NOT NULL,                    -- 创建 scan_task 的模板
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    last_run_at TIMESTAMPTZ,
    next_run_at TIMESTAMPTZ,
    created_by  VARCHAR(50) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 2.3 漏洞管理

```sql
-- 漏洞记录
CREATE TABLE vulnerabilities (
    id              VARCHAR(26) PRIMARY KEY,
    task_id         VARCHAR(26) REFERENCES scan_tasks(id),
    asset_id        VARCHAR(26) REFERENCES assets(id),
    plugin_id       VARCHAR(200) NOT NULL,          -- 触发的插件 ID（如 CVE-2024-XXXX）
    name            VARCHAR(500) NOT NULL,
    severity        VARCHAR(20) NOT NULL,           -- critical, high, medium, low, info
    cvss_score      NUMERIC(3,1) DEFAULT 0,
    type            VARCHAR(50) NOT NULL,           -- sqli, xss, rce, ssrf, info_leak, weak_pass, misconfig, ...
    target          VARCHAR(1000) NOT NULL,         -- 目标 URL/IP:Port
    detail          JSONB NOT NULL DEFAULT '{}',    -- 漏洞详情
    -- {
    --   "url": "https://example.com/api/v1/users",
    --   "method": "POST",
    --   "param": "id",
    --   "payload": "1' OR '1'='1",
    --   "evidence": "HTTP 200, response contains 'admin'",
    --   "request": "...",
    --   "response": "...",
    --   "screenshot_url": ""
    -- }
    solution        TEXT DEFAULT '',                 -- 修复建议
    references      JSONB DEFAULT '[]',             -- CVE/CNVD/参考链接
    status          VARCHAR(20) NOT NULL DEFAULT 'open',
                    -- open, confirmed, fixed, ignored, false_positive
    verified        BOOLEAN DEFAULT FALSE,
    verified_at     TIMESTAMPTZ,
    verified_by     VARCHAR(50),
    first_found_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_found_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fixed_at        TIMESTAMPTZ,
    fingerprint     VARCHAR(64) NOT NULL,           -- 去重指纹 (SHA256 of plugin_id + target + param)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(fingerprint)
);
CREATE INDEX idx_vulns_task ON vulnerabilities(task_id);
CREATE INDEX idx_vulns_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX idx_vulns_type ON vulnerabilities(type);
CREATE INDEX idx_vulns_status ON vulnerabilities(status);
CREATE INDEX idx_vulns_plugin ON vulnerabilities(plugin_id);
CREATE INDEX idx_vulns_target ON vulnerabilities(target);
CREATE INDEX idx_vulns_found ON vulnerabilities(first_found_at DESC);

-- 漏洞知识库（PoC 元数据）
CREATE TABLE vuln_templates (
    id              VARCHAR(200) PRIMARY KEY,       -- 如 CVE-2024-XXXX
    name            VARCHAR(500) NOT NULL,
    severity        VARCHAR(20) NOT NULL,
    cvss_score      NUMERIC(3,1) DEFAULT 0,
    type            VARCHAR(50) NOT NULL,
    description     TEXT DEFAULT '',
    solution        TEXT DEFAULT '',
    references      JSONB DEFAULT '[]',
    tags            JSONB DEFAULT '[]',
    affected        JSONB DEFAULT '[]',             -- 受影响的产品/版本
    poc_file        VARCHAR(500) DEFAULT '',        -- YAML PoC 文件路径
    enabled         BOOLEAN DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_templates_severity ON vuln_templates(severity);
CREATE INDEX idx_templates_type ON vuln_templates(type);
CREATE INDEX idx_templates_tags ON vuln_templates USING GIN(tags);
```

### 2.4 报告系统

```sql
-- 扫描报告
CREATE TABLE scan_reports (
    id          VARCHAR(26) PRIMARY KEY,
    task_id     VARCHAR(26) REFERENCES scan_tasks(id),
    name        VARCHAR(200) NOT NULL,
    type        VARCHAR(20) NOT NULL,              -- full, executive, compliance, diff
    format      VARCHAR(10) NOT NULL,              -- pdf, html, json, csv
    status      VARCHAR(20) NOT NULL DEFAULT 'generating',
    file_url    VARCHAR(500) DEFAULT '',           -- MinIO/S3 地址
    file_size   BIGINT DEFAULT 0,
    summary     JSONB DEFAULT '{}',                -- 报告摘要数据
    created_by  VARCHAR(50) NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### 2.5 系统与集群

```sql
-- Worker 节点注册
CREATE TABLE worker_nodes (
    id              VARCHAR(100) PRIMARY KEY,       -- 节点标识
    hostname        VARCHAR(200) NOT NULL,
    ip              VARCHAR(45) NOT NULL,
    port            INT NOT NULL DEFAULT 9090,
    version         VARCHAR(50) DEFAULT '',
    status          VARCHAR(20) NOT NULL DEFAULT 'online',  -- online, offline, draining
    capacity        JSONB DEFAULT '{}',             -- { "max_concurrent": 500, "cpu_cores": 8, "memory_gb": 16 }
    current_load    JSONB DEFAULT '{}',             -- { "running_tasks": 12, "cpu_percent": 45, "mem_percent": 60 }
    labels          JSONB DEFAULT '{}',             -- { "region": "cn-east", "network": "internal" }
    last_heartbeat  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 操作审计
CREATE TABLE audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    user_id     VARCHAR(50) NOT NULL,
    action      VARCHAR(50) NOT NULL,              -- task.create, task.start, vuln.confirm, report.export
    resource    VARCHAR(50) NOT NULL,              -- task, vuln, asset, report, user
    resource_id VARCHAR(50) DEFAULT '',
    detail      JSONB DEFAULT '{}',
    ip          VARCHAR(45) DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created ON audit_logs(created_at DESC);

-- 通知记录
CREATE TABLE notifications (
    id          VARCHAR(26) PRIMARY KEY,
    type        VARCHAR(30) NOT NULL,              -- vuln_found, task_completed, task_failed
    channel     VARCHAR(20) NOT NULL,              -- email, webhook, dingtalk, feishu
    target      VARCHAR(500) NOT NULL,             -- 接收者
    subject     VARCHAR(500) DEFAULT '',
    content     TEXT DEFAULT '',
    status      VARCHAR(20) NOT NULL DEFAULT 'pending',
    error       TEXT DEFAULT '',
    sent_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

## 3. ClickHouse 扫描日志表

```sql
CREATE TABLE scan_probe_logs (
    event_time  DateTime,
    task_id     String,
    subtask_id  String,
    worker_id   String,
    target_ip   String,
    target_port UInt16,
    protocol    String,
    module      String,          -- portscan, fingerprint, vuln_check
    action      String,          -- syn_send, connect, http_request, poc_execute
    status      String,          -- open, closed, filtered, success, error, timeout
    latency_ms  UInt32,
    detail      String,          -- JSON 扩展字段
    INDEX idx_task task_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_target target_ip TYPE bloom_filter GRANULARITY 4
) ENGINE = MergeTree()
  PARTITION BY toYYYYMM(event_time)
  ORDER BY (event_time, task_id, target_ip)
  TTL event_time + INTERVAL 90 DAY;
```

## 4. Redis 数据结构

```
# 任务队列（优先级）
ZSET  task:queue:p0         # P0 紧急队列
ZSET  task:queue:p1         # P1 高优先级
ZSET  task:queue:p2         # P2 普通
ZSET  task:queue:p3         # P3 低优先级

# Worker 心跳
HASH  worker:{id}:info      # hostname, ip, version, capacity
SET   worker:online          # 在线 Worker ID 集合

# 分布式锁
SET   lock:task:{task_id}           # 任务级别锁
SET   lock:target:{ip}:{port}      # 目标级别锁（防并行扫描同一目标）

# 实时进度
HASH  task:{task_id}:progress       # total, completed, vulns_found, ...

# 限流
STRING  rate:{target}:{minute}      # 每分钟请求计数
STRING  rate:worker:{id}:{minute}   # Worker 维度限流

# 去重布隆过滤器
BF.ADD  scan:dedup:{task_id}        # 已扫描目标去重
```

## 5. 关键索引策略

| 查询场景 | 索引 |
|----------|------|
| 按状态查任务列表 | `idx_tasks_status` |
| 按严重程度查漏洞 | `idx_vulns_severity` |
| 按资产查关联漏洞 | `idx_vulns_asset` |
| 漏洞去重（upsert） | `UNIQUE(fingerprint)` |
| 资产指纹查询 | `idx_fingerprints_product` |
| 域名按父域查子域 | `idx_domains_parent` |
| 审计日志时间线 | `idx_audit_created` |
| PoC 模板按标签筛选 | `GIN(tags)` |

## 6. 数据生命周期

| 数据 | 保留策略 | 归档 |
|------|----------|------|
| 扫描任务 | 永久 | - |
| 漏洞记录 | 永久 | 已修复超1年 → 归档表 |
| 资产 | 永久 | 已移除超半年 → 归档表 |
| 扫描日志 (ClickHouse) | 90 天 TTL | 自动清理 |
| 报告文件 | 1 年 | MinIO lifecycle |
| 审计日志 | 2 年 | 归档到 ClickHouse |
