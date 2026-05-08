# 攻击面管理 (Attack Surface Management)

## 1. 概述

攻击面管理 (ASM) 是漏扫系统从「被动扫描」向「持续安全运营」演进的关键能力。核心目标：**自动发现→持续监控→变化告警→增量扫描**，形成闭环。

### 与现有模块关系

```
资产管理 (database.md)          → ASM 的数据底座
子域名/端口/指纹 (modules.md)   → ASM 的探测执行器
调度系统 (scheduler.md)         → ASM 定时任务的调度引擎
漏洞检测 (scan-engine.md)       → ASM 变化发现后触发的下游
告警通知 (api.md /notifications)→ ASM 变化通知的出口
```

## 2. ASM 生命周期

```
┌─────────┐     ┌──────────┐     ┌──────────┐     ┌───────────┐     ┌──────────┐
│  种子    │────→│  发现    │────→│  资产    │────→│  变化     │────→│  响应    │
│  输入    │     │  引擎    │     │  画像    │     │  检测     │     │  联动    │
└─────────┘     └──────────┘     └──────────┘     └───────────┘     └──────────┘
   域名            子域名           服务画像          Diff算法           增量扫描
   IP段            端口扫描         指纹信息          变化分类           告警推送
   ASN             CDN/WAF检测      关联关系          风险评分           工单创建
```

## 3. 种子输入

### 3.1 种子类型

| 种子类型 | 格式 | 说明 |
|---------|------|------|
| 根域名 | `example.com` | 自动枚举所有子域名 |
| IP/CIDR | `192.168.1.0/24` | 枚举范围内所有IP |
| ASN | `AS12345` | 查询归属IP段后展开 |
| URL | `https://api.example.com` | 单点监控 |
| 关键词 | `Example Corp` | CT日志/WHOIS反查关联资产 |

### 3.2 种子数据模型

```go
type ASMSeed struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    ProjectID   string    `json:"project_id" gorm:"index"`
    Type        string    `json:"type"`        // domain, cidr, asn, url, keyword
    Value       string    `json:"value"`
    Config      JSONMap   `json:"config"`      // 特定种子的配置
    Enabled     bool      `json:"enabled" gorm:"default:true"`
    LastRunAt   time.Time `json:"last_run_at"`
    NextRunAt   time.Time `json:"next_run_at" gorm:"index"`
    Schedule    string    `json:"schedule"`    // cron表达式
    CreatedAt   time.Time `json:"created_at"`
}

type ASMProject struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    Name        string    `json:"name"`
    Description string    `json:"description"`
    OwnerID     string    `json:"owner_id"`
    Config      JSONMap   `json:"config"`      // 全局策略
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}
```

## 4. 发现引擎

### 4.1 多维度资产发现

```
发现引擎
├── DNS枚举
│   ├── 字典爆破 (内置 + 自定义字典)
│   ├── DNS Zone Transfer (AXFR)
│   ├── DNS 递归暴力枚举
│   └── 泛解析检测与过滤
├── 被动信息收集
│   ├── CT (Certificate Transparency) 日志
│   ├── WHOIS 反查
│   ├── 搜索引擎语法 (site:xxx)
│   ├── 公开数据集 (Rapid7 OpenData, Censys)
│   └── GitHub/GitLab 代码泄露检索
├── 网络层发现
│   ├── TCP SYN/Connect 端口扫描
│   ├── UDP 常用端口扫描
│   ├── ICMP 存活探测
│   └── IPv6 邻居发现 (可选)
├── 应用层发现
│   ├── HTTP/HTTPS 服务探测
│   ├── Web 爬虫 (同域链接发现)
│   ├── JS 文件中的 API 端点提取
│   └── robots.txt / sitemap.xml 解析
└── 云资产发现
    ├── S3 Bucket 枚举
    ├── Azure Blob 枚举
    └── 云厂商 API 元数据检测
```

### 4.2 发现器接口

```go
type Discoverer interface {
    Name() string
    SeedTypes() []string                    // 支持的种子类型
    Discover(ctx context.Context, seed *ASMSeed, out chan<- *DiscoveredAsset) error
    Priority() int                          // 执行优先级
}

type DiscoveredAsset struct {
    Type        string            // ip, domain, subdomain, url, port, service
    Value       string
    Attributes  map[string]string // 附加属性
    Source      string            // 发现来源
    Confidence  float64           // 置信度 0~1
    DiscoveredAt time.Time
}
```

### 4.3 发现编排

对于一个根域名种子，发现引擎按依赖关系自动编排：

```
Phase 1: DNS枚举 + CT日志 + WHOIS → 子域名列表
Phase 2: DNS解析 → IP列表 (去重 + CDN/WAF标记)
Phase 3: 端口扫描 → 开放端口列表
Phase 4: 服务探测 + Web指纹 → 服务画像
Phase 5: Web爬虫 + JS分析 → API端点 + 隐藏路径
```

各 Phase 之间通过 channel pipeline 连接，支持流式处理：

```go
type DiscoveryPipeline struct {
    phases []DiscoveryPhase
}

type DiscoveryPhase struct {
    Name        string
    Discoverers []Discoverer
    InputTypes  []string        // 接受的资产类型
    OutputTypes []string        // 产出的资产类型
    Concurrency int
}

func (p *DiscoveryPipeline) Run(ctx context.Context, seeds []*ASMSeed) (<-chan *DiscoveredAsset, error) {
    // Phase间 channel 传递
    // 每个 Phase 内部并发执行多个 Discoverer
    // 结果去重后传入下一 Phase
}
```

## 5. 资产画像

### 5.1 统一资产模型

每个发现的资产最终归一化为统一画像：

```go
type ASMAsset struct {
    ID           string    `json:"id" gorm:"primaryKey"`
    ProjectID    string    `json:"project_id" gorm:"index"`
    Type         string    `json:"type" gorm:"index"` // ip, domain, subdomain, url, service
    Value        string    `json:"value" gorm:"index"`
    ParentID     string    `json:"parent_id"`          // 父资产 (subdomain→domain, port→ip)

    // 画像数据
    IP           string    `json:"ip"`
    Port         int       `json:"port"`
    Protocol     string    `json:"protocol"`            // tcp, udp, http, https
    Service      string    `json:"service"`             // nginx, apache, mysql...
    Version      string    `json:"version"`
    OS           string    `json:"os"`
    CDN          string    `json:"cdn"`                 // 检测到的CDN
    WAF          string    `json:"waf"`                 // 检测到的WAF
    Fingerprints JSONArray `json:"fingerprints"`        // 指纹列表
    Technologies JSONArray `json:"technologies"`        // 技术栈

    // 安全属性
    RiskScore    int       `json:"risk_score"`          // 0~100
    ExposureType string    `json:"exposure_type"`       // external, internal, cloud
    Tags         JSONArray `json:"tags"`

    // 状态
    Status       string    `json:"status"`              // active, inactive, removed
    FirstSeenAt  time.Time `json:"first_seen_at"`
    LastSeenAt   time.Time `json:"last_seen_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}
```

### 5.2 资产关系图

资产之间通过 `parent_id` 和关联表建立拓扑关系：

```
example.com (domain)
├── api.example.com (subdomain)
│   └── 203.0.113.10 (ip)
│       ├── :443/tcp (port) → nginx/1.24 (service)
│       │   ├── /api/v1 (endpoint)
│       │   └── /admin (endpoint)
│       └── :22/tcp (port) → OpenSSH/9.0 (service)
├── www.example.com (subdomain)
│   └── [Cloudflare CDN]
│       └── :443/tcp → React SPA + Express
└── db.internal.example.com (subdomain)
    └── 10.0.1.5 (ip)
        └── :5432/tcp → PostgreSQL/15
```

## 6. 变化检测

### 6.1 Diff 算法

每次定期扫描完成后，对比本次快照与上次快照的差异：

```go
type AssetDiff struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    ProjectID   string    `json:"project_id" gorm:"index"`
    ScanID      string    `json:"scan_id"`
    AssetID     string    `json:"asset_id"`
    ChangeType  string    `json:"change_type" gorm:"index"` // new, removed, modified, reappeared
    Field       string    `json:"field"`                     // 变化字段 (port, service, version...)
    OldValue    string    `json:"old_value"`
    NewValue    string    `json:"new_value"`
    RiskDelta   int       `json:"risk_delta"`                // 风险分变化
    DetectedAt  time.Time `json:"detected_at" gorm:"index"`
}
```

### 6.2 变化分类与风险评分

| 变化类型 | 风险加权 | 说明 |
|---------|---------|------|
| 新端口开放 | +20~+40 | 高危端口 (如3389, 6379) 加权更高 |
| 新子域名出现 | +10 | 可能的影子IT |
| 服务版本变化 | +5~+15 | 降级或已知漏洞版本加权更高 |
| TLS证书变化 | +5 | 可能的中间人风险 |
| 新技术栈出现 | +5~+10 | 未纳管的新应用 |
| CDN/WAF移除 | +30 | 安全防护降级 |
| 资产消失 | -5 | 减少攻击面 (仍需确认是否误报) |
| 资产重新出现 | +15 | 之前下线的资产重新暴露 |

### 6.3 变化告警规则

```go
type AlertRule struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    ProjectID   string    `json:"project_id"`
    Name        string    `json:"name"`
    Condition   string    `json:"condition"`   // CEL表达式
    Severity    string    `json:"severity"`    // critical, high, medium, low, info
    Actions     JSONArray `json:"actions"`     // notify, scan, ticket
    Enabled     bool      `json:"enabled" gorm:"default:true"`
}
```

CEL 告警条件示例：

```
// 新开放高危端口
diff.change_type == "new" && asset.type == "port" && asset.port in [22, 3389, 6379, 27017, 9200]

// CDN/WAF 移除
diff.change_type == "modified" && diff.field == "waf" && diff.new_value == ""

// 新发现的子域名
diff.change_type == "new" && asset.type == "subdomain"

// 风险分突增
diff.risk_delta >= 30
```

## 7. 响应联动

### 7.1 联动动作

| 动作 | 触发条件 | 执行 |
|------|---------|------|
| 增量漏洞扫描 | 新资产/新端口/服务变化 | 自动创建扫描任务 (scheduler) |
| 通知推送 | 匹配告警规则 | Webhook/邮件/钉钉/飞书 |
| 工单创建 | 高危变化 | 集成ITSM/Jira/自建工单 |
| 标签更新 | 资产画像变化 | 自动打标/更新分组 |
| 快照归档 | 每次扫描完成 | 历史版本存档便于回溯 |

### 7.2 联动编排

```go
type ActionOrchestrator struct {
    rules   []AlertRule
    actions map[string]ActionExecutor
}

type ActionExecutor interface {
    Type() string
    Execute(ctx context.Context, alert *Alert, diff *AssetDiff, asset *ASMAsset) error
}

// 内置 Action 实现
type ScanActionExecutor struct{}      // 创建增量扫描任务
type NotifyActionExecutor struct{}    // 推送通知
type TicketActionExecutor struct{}    // 创建工单
type TagActionExecutor struct{}       // 更新标签
```

## 8. 定时调度

### 8.1 调度策略

ASM 任务复用 `scheduler.md` 的分布式调度系统：

| 任务类型 | 默认周期 | 说明 |
|---------|---------|------|
| 全量发现 | 每周 | 从种子重新完整发现 |
| 增量端口检测 | 每日 | 对已知IP检测端口变化 |
| 服务存活检查 | 每4小时 | HTTP/TCP 健康检测 |
| CT日志监控 | 每小时 | 新签发证书告警 |
| 变化Diff计算 | 每次扫描后 | 自动触发 |

### 8.2 自适应调度

根据资产重要性和变化频率动态调整扫描频率：

```go
type AdaptiveScheduler struct {
    baseInterval time.Duration
}

func (s *AdaptiveScheduler) NextInterval(asset *ASMAsset, recentDiffs int) time.Duration {
    interval := s.baseInterval

    // 高风险资产更频繁
    if asset.RiskScore >= 80 {
        interval = interval / 4
    } else if asset.RiskScore >= 50 {
        interval = interval / 2
    }

    // 近期变化频繁的资产更频繁
    if recentDiffs >= 5 {
        interval = interval / 3
    } else if recentDiffs >= 2 {
        interval = interval / 2
    }

    // 最小间隔 1 小时，最大 7 天
    return clamp(interval, 1*time.Hour, 7*24*time.Hour)
}
```

## 9. API 端点

```
ASM API
├── /api/v1/asm/projects
│   ├── POST   /                     创建监控项目
│   ├── GET    /                     项目列表
│   ├── GET    /:id                  项目详情
│   ├── PUT    /:id                  更新项目配置
│   └── DELETE /:id                  删除项目
├── /api/v1/asm/seeds
│   ├── POST   /                     添加种子
│   ├── GET    /?project_id=xxx      种子列表
│   ├── PUT    /:id                  更新种子
│   ├── DELETE /:id                  删除种子
│   └── POST   /:id/run              手动触发发现
├── /api/v1/asm/assets
│   ├── GET    /?project_id=xxx      资产列表 (支持筛选/排序/分页)
│   ├── GET    /:id                  资产详情 (含历史画像)
│   ├── GET    /:id/history          资产变化历史
│   ├── GET    /:id/relations        资产关系图
│   ├── PUT    /:id/tags             更新标签
│   └── POST   /export               导出资产列表
├── /api/v1/asm/diffs
│   ├── GET    /?project_id=xxx      变化列表
│   ├── GET    /timeline             变化时间线
│   └── GET    /stats                变化统计
├── /api/v1/asm/alerts
│   ├── POST   /rules                创建告警规则
│   ├── GET    /rules                告警规则列表
│   ├── PUT    /rules/:id            更新告警规则
│   └── GET    /                     告警记录列表
└── /api/v1/asm/dashboard
    ├── GET    /overview              ASM 总览 (资产数/变化数/风险分布)
    ├── GET    /trend                 攻击面趋势图
    └── GET    /top-risks             高风险资产 Top N
```

## 10. 与现有架构集成

### 10.1 共享基础设施

- **数据库**：ASM 表与现有 `assets` / `vulnerabilities` 表通过 `asset_id` 外键关联
- **调度器**：ASM 定时任务注册到 `scheduler` 模块的 cron 调度
- **扫描引擎**：变化检测触发增量扫描时，复用 `scan-engine` 的 Pipeline
- **消息队列**：ASM 事件通过 NATS 发布，告警通知模块订阅处理

### 10.2 数据流

```
ASM定时任务 → 发现引擎 → 资产画像更新 → Diff计算 → 告警规则匹配
                                                         │
                                          ┌──────────────┤
                                          ↓              ↓
                                    增量扫描任务    通知/工单
                                          ↓
                                    漏洞检测 → 漏洞报告
```
