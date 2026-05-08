# 数据可视化与报告引擎设计

## 1. 概述

数据可视化是漏扫系统的「表达层」，将海量扫描数据转化为可操作的安全洞察。本设计覆盖三个层面：

- **实时仪表盘** — 运营人员的安全态势感知
- **分析看板** — 安全管理者的趋势分析和决策支持
- **报告引擎** — 面向不同受众的自动化安全报告生成

## 2. 仪表盘体系

### 2.1 仪表盘分层

```
┌────────────────────────────────────────────────────────────────┐
│                     Dashboard System                            │
│                                                                │
│  ┌──────────────────┐  ┌───────────────┐  ┌────────────────┐  │
│  │ 运营总览         │  │ 专项分析      │  │ 自定义看板     │  │
│  │ (Security Ops)   │  │ (Analytics)   │  │ (Custom)       │  │
│  │                  │  │               │  │                │  │
│  │ · 安全态势       │  │ · 资产分析    │  │ · 拖拽编排     │  │
│  │ · 实时扫描       │  │ · 漏洞趋势    │  │ · 自定义图表   │  │
│  │ · 告警面板       │  │ · 合规概览    │  │ · 数据源绑定   │  │
│  │ · 任务状态       │  │ · 攻击面变化  │  │ · 权限隔离     │  │
│  └──────────────────┘  │ · 代理池状态  │  └────────────────┘  │
│                        │ · 集群监控    │                       │
│                        └───────────────┘                       │
└────────────────────────────────────────────────────────────────┘
```

### 2.2 安全态势总览 (Security Posture Dashboard)

核心指标卡片 + 趋势图 + 分布图的组合：

```
┌─────────────────────────────────────────────────────────────────────┐
│                        安全态势总览                                   │
│                                                                     │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│  │ 资产总数 │ │ 漏洞总数 │ │ 高危漏洞 │ │ 合规评分 │ │ 风险评分 │ │
│  │  1,247   │ │   856    │ │   47↑3   │ │  B (78)  │ │  68/100  │ │
│  │ +15 本周 │ │ -32 本周 │ │ ⚠ 需关注 │ │ ↑2 本月  │ │ ↓5 本周  │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
│                                                                     │
│  ┌─────────────────────────────┐ ┌────────────────────────────────┐ │
│  │   漏洞严重度分布 (环形图)   │ │    漏洞趋势 (30天折线图)       │ │
│  │                             │ │                                │ │
│  │    ████ Critical  12       │ │  ─── Total                     │ │
│  │    ████ High      47       │ │  ─── Critical+High             │ │
│  │    ████ Medium   289       │ │  ─── New (新增)                │ │
│  │    ████ Low      412       │ │  ─── Fixed (已修复)            │ │
│  │    ████ Info      96       │ │                                │ │
│  └─────────────────────────────┘ └────────────────────────────────┘ │
│                                                                     │
│  ┌─────────────────────────────┐ ┌────────────────────────────────┐ │
│  │  资产类型分布 (柱状图)       │ │  Top 10 高危资产 (表格)        │ │
│  │                             │ │                                │ │
│  │  Web   ████████ 523        │ │  Host        Vulns  Risk Score │ │
│  │  Host  ██████ 412          │ │  db.prod     12     95         │ │
│  │  API   ███ 187             │ │  admin.web   8      88         │ │
│  │  DB    ██ 89               │ │  gateway     6      82         │ │
│  │  IoT   █ 36                │ │  ...                           │ │
│  └─────────────────────────────┘ └────────────────────────────────┘ │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │              最近告警 (实时滚动)                                  │ │
│  │  ⚠ 09:32  新高危漏洞: CVE-2024-xxxxx 影响 api.prod 等 3 台资产 │ │
│  │  ● 09:28  扫描完成: Web全量扫描 #1247 发现 12 个新漏洞          │ │
│  │  ▲ 09:15  攻击面变化: 新发现子域名 staging.example.com          │ │
│  └─────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.3 实时扫描监控面板

```
┌─────────────────────────────────────────────────────────────┐
│                    实时扫描监控                               │
│                                                             │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐          │
│  │ 运行中  │ │ 排队中  │ │ 已完成  │ │ 失败    │          │
│  │   8     │ │  23     │ │  1,247  │ │   3     │          │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘          │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ 进行中的扫描任务                                      │  │
│  │                                                      │  │
│  │ #1255 Web全量扫描   ████████████░░░░░ 72%  ETA 8m   │  │
│  │   → 当前阶段: 漏洞检测 (SQLi: 45/120 endpoints)     │  │
│  │                                                      │  │
│  │ #1254 等保三级       ██████░░░░░░░░░░░ 38%  ETA 23m  │  │
│  │   → 当前阶段: 安全计算环境 (身份鉴别检查)            │  │
│  │                                                      │  │
│  │ #1253 红队模拟       ████░░░░░░░░░░░░░ 25%  ETA 1h   │  │
│  │   → 当前阶段: 武器化 (Nuclei scanning)               │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌────────────────────────┐ ┌────────────────────────────┐ │
│  │ 扫描速率 (实时)        │ │ Worker 负载分布 (热力图)    │ │
│  │                        │ │                            │ │
│  │ 请求/秒: 1,247        │ │ W1 ████ 85%               │ │
│  │ 发现/分: 3.2 vulns    │ │ W2 ███ 62%                │ │
│  │ 代理池:  847/1000     │ │ W3 ████ 78%               │ │
│  └────────────────────────┘ │ W4 ██ 45%                 │ │
│                              └────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 2.4 其他专项看板

#### 漏洞分析看板

```
数据面板:
├── 漏洞类型分布 (OWASP Top 10 雷达图)
├── 漏洞年龄分布 (发现多久未修复, 柱状图)
├── MTTR 趋势 (平均修复时间, 折线图)
├── 漏洞发现 vs 修复 (双轴折线图)
├── Top 漏洞类型 (按频率, 水平柱状图)
├── 漏洞地理分布 (如有多地域资产, 地图)
└── CVSS 评分分布 (直方图)
```

#### 攻击面变化看板

```
数据面板:
├── 攻击面面积趋势 (资产数 × 暴露端口, 面积图)
├── 变化类型分布 (新增/移除/修改, 环形图)
├── 高风险变化时间线 (时间轴)
├── 子域名增长曲线 (折线图)
├── CDN/WAF 覆盖率变化 (堆叠柱状图)
└── 技术栈分布变化 (桑基图 / 矩形树图)
```

#### 合规看板

```
数据面板:
├── 各框架合规评分 (仪表盘 / 多指标卡)
├── 合规趋势 (各框架评分折线图)
├── 不合规项分布 (按等保域/CIS分类, 堆叠柱状图)
├── 修复进度 (已修复 / 待修复 / 已忽略, 甘特图)
├── 高危不合规项列表 (表格)
└── 对比 (本次 vs 上次, 分项对比柱状图)
```

#### 集群与代理池看板

```
数据面板:
├── Worker 节点状态 (在线/离线/负载, 拓扑图)
├── 任务队列深度 (实时折线图)
├── 代理池可用率 (仪表盘)
├── 代理延迟分布 (直方图)
├── 代理地域分布 (地图)
├── 代理封禁统计 (按目标, 柱状图)
└── 资源使用 (CPU/内存/网络, 面积图)
```

## 3. 数据聚合层

### 3.1 聚合 API 设计

所有看板的数据通过统一的聚合 API 提供：

```go
type DashboardService struct {
    db        *db.DB
    cache     cache.Cache
    clickhouse *clickhouse.Client
}

type MetricQuery struct {
    Metric      string            `json:"metric"`       // vuln_count, asset_count, scan_rate...
    GroupBy     string            `json:"group_by"`     // severity, type, date, target...
    TimeRange   TimeRange         `json:"time_range"`
    Filters     map[string]string `json:"filters"`
    Interval    string            `json:"interval"`     // 1h, 1d, 1w (聚合粒度)
    Limit       int               `json:"limit"`
}

type TimeRange struct {
    Start time.Time `json:"start"`
    End   time.Time `json:"end"`
    Preset string   `json:"preset"` // last_24h, last_7d, last_30d, last_90d, custom
}

type MetricResult struct {
    Metric  string        `json:"metric"`
    Labels  []string      `json:"labels"`
    Series  []DataSeries  `json:"series"`
    Summary *MetricSummary `json:"summary,omitempty"`
}

type DataSeries struct {
    Name   string      `json:"name"`
    Values []DataPoint `json:"values"`
    Color  string      `json:"color,omitempty"`
}

type DataPoint struct {
    Timestamp time.Time   `json:"timestamp,omitempty"`
    Label     string      `json:"label,omitempty"`
    Value     float64     `json:"value"`
}

type MetricSummary struct {
    Total     float64 `json:"total"`
    Average   float64 `json:"average"`
    Max       float64 `json:"max"`
    Min       float64 `json:"min"`
    Change    float64 `json:"change"`     // 与上一周期对比
    ChangePct float64 `json:"change_pct"` // 变化百分比
}
```

### 3.2 预计算与缓存策略

```go
type MetricAggregator struct {
    db    *db.DB
    cache cache.Cache
}

type AggregationTask struct {
    Metric    string
    Interval  string
    TTL       time.Duration
}

var aggregationTasks = []AggregationTask{
    // 实时性要求高: 短缓存
    {Metric: "active_scans", Interval: "realtime", TTL: 10 * time.Second},
    {Metric: "scan_rate", Interval: "1m", TTL: 30 * time.Second},
    {Metric: "proxy_pool_status", Interval: "realtime", TTL: 15 * time.Second},

    // 中等实时性: 分钟级缓存
    {Metric: "vuln_severity_dist", Interval: "5m", TTL: 5 * time.Minute},
    {Metric: "asset_type_dist", Interval: "5m", TTL: 5 * time.Minute},
    {Metric: "recent_alerts", Interval: "1m", TTL: 1 * time.Minute},

    // 趋势数据: 小时/天级缓存
    {Metric: "vuln_trend_30d", Interval: "1d", TTL: 1 * time.Hour},
    {Metric: "compliance_trend", Interval: "1d", TTL: 1 * time.Hour},
    {Metric: "asm_change_trend", Interval: "1d", TTL: 1 * time.Hour},
    {Metric: "mttr_trend", Interval: "1w", TTL: 6 * time.Hour},
}

func (a *MetricAggregator) GetOrCompute(ctx context.Context, query *MetricQuery) (*MetricResult, error) {
    cacheKey := a.buildCacheKey(query)

    // 缓存命中
    if cached, err := a.cache.Get(ctx, cacheKey); err == nil {
        var result MetricResult
        if json.Unmarshal([]byte(cached), &result) == nil {
            return &result, nil
        }
    }

    // 计算
    result, err := a.compute(ctx, query)
    if err != nil {
        return nil, err
    }

    // 写缓存
    ttl := a.findTTL(query.Metric)
    data, _ := json.Marshal(result)
    a.cache.Set(ctx, cacheKey, string(data), ttl)

    return result, nil
}
```

### 3.3 实时推送 (WebSocket)

```go
type DashboardWSHandler struct {
    upgrader websocket.Upgrader
    hub      *WSHub
}

type WSHub struct {
    clients    map[*WSClient]bool
    broadcast  chan *WSMessage
    register   chan *WSClient
    unregister chan *WSClient
}

type WSMessage struct {
    Type    string      `json:"type"`    // metric_update, alert, scan_progress
    Metric  string      `json:"metric"`
    Data    interface{} `json:"data"`
}

func (h *DashboardWSHandler) HandleWS(c *gin.Context) {
    conn, err := h.upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        return
    }

    client := &WSClient{
        conn:      conn,
        send:      make(chan []byte, 256),
        subscribed: make(map[string]bool),
    }

    h.hub.register <- client

    go client.writePump()
    go client.readPump(h.hub)
}

// 客户端可以订阅特定指标
type WSSubscription struct {
    Action  string   `json:"action"`   // subscribe, unsubscribe
    Metrics []string `json:"metrics"`  // ["scan_rate", "active_scans", "recent_alerts"]
}
```

## 4. 图表组件库

### 4.1 前端图表技术选型

| 图表类型 | 推荐库 | 适用场景 |
|---------|--------|---------|
| 通用图表 | ECharts | 折线图/柱状图/饼图/雷达图/热力图 |
| 拓扑/关系图 | D3.js / AntV G6 | 资产关系图/攻击链/网络拓扑 |
| 地图 | ECharts Map / AntV L7 | 资产地理分布/代理地域分布 |
| 表格 | VXETable / AG-Grid | 大数据量漏洞列表/资产列表 |
| 仪表盘 | ECharts Gauge | 合规评分/风险评分/代理池健康度 |
| 时间轴 | vis-timeline | 攻击面变化时间线/漏洞生命周期 |

### 4.2 通用图表封装

```typescript
// 统一的图表配置接口
interface ChartConfig {
  type: 'line' | 'bar' | 'pie' | 'radar' | 'gauge' | 'heatmap' | 'scatter' | 'treemap' | 'sankey';
  title?: string;
  dataSource: {
    api: string;          // /api/v1/dashboard/metrics
    query: MetricQuery;
    refreshInterval?: number;  // 自动刷新间隔 (秒)
    websocket?: boolean;       // 是否使用 WebSocket 实时推送
  };
  options?: Record<string, any>;  // 图表库特定选项
}

// 通用看板面板
interface DashboardPanel {
  id: string;
  title: string;
  type: 'chart' | 'metric_card' | 'table' | 'alert_feed' | 'progress';
  chart?: ChartConfig;
  position: { x: number; y: number; w: number; h: number };
}

interface Dashboard {
  id: string;
  name: string;
  panels: DashboardPanel[];
  refreshInterval: number;
  timeRange: TimeRange;
}
```

### 4.3 自定义看板

用户可以自行创建看板，拖拽选择图表组件和数据源：

```go
type CustomDashboard struct {
    ID          string            `json:"id" gorm:"primaryKey"`
    Name        string            `json:"name"`
    Description string            `json:"description"`
    Panels      []DashboardPanel  `json:"panels" gorm:"serializer:json"`
    Layout      string            `json:"layout"`   // grid, freeform
    TimeRange   string            `json:"time_range"`
    RefreshSec  int               `json:"refresh_sec"`
    IsDefault   bool              `json:"is_default"`
    OwnerID     string            `json:"owner_id"`
    SharedWith  []string          `json:"shared_with" gorm:"serializer:json"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}
```

## 5. 报告引擎

### 5.1 架构

```
┌───────────────────────────────────────────────────────────┐
│                    Report Engine                           │
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │ 模板管理    │  │  数据采集    │  │  渲染引擎       │ │
│  │             │  │              │  │                 │ │
│  │ · 内置模板  │  │ · 扫描结果   │  │ · HTML模板      │ │
│  │ · 自定义    │  │ · 漏洞数据   │  │ · PDF生成       │ │
│  │ · 模板语法  │  │ · 合规数据   │  │ · Word (docx)   │ │
│  │ · 多语言    │  │ · 聚合统计   │  │ · JSON/CSV      │ │
│  └─────────────┘  │ · 图表截图   │  │ · Markdown      │ │
│                   └──────────────┘  └─────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

### 5.2 报告模板模型

```go
type ReportTemplate struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    Name        string    `json:"name"`
    Code        string    `json:"code" gorm:"uniqueIndex"`
    Category    string    `json:"category"`   // scan, compliance, asm, executive, custom
    Format      string    `json:"format"`     // html, pdf, docx, markdown
    Language    string    `json:"language"`   // zh-CN, en-US
    Content     string    `json:"content" gorm:"type:text"` // Go template 内容
    Sections    []string  `json:"sections" gorm:"serializer:json"`
    Styles      string    `json:"styles" gorm:"type:text"`  // CSS
    Builtin     bool      `json:"builtin"`
    CreatedAt   time.Time `json:"created_at"`
}

type ReportJob struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    TemplateID  string    `json:"template_id"`
    DataSource  JSONMap   `json:"data_source" gorm:"serializer:json"` // scan_id, compliance_scan_id, asm_project_id
    Format      string    `json:"format"`     // pdf, html, docx
    Status      string    `json:"status"`     // pending, generating, completed, failed
    FilePath    string    `json:"file_path"`
    FileSize    int64     `json:"file_size"`
    GeneratedAt *time.Time `json:"generated_at"`
    CreatedBy   string    `json:"created_by"`
    CreatedAt   time.Time `json:"created_at"`
}
```

### 5.3 报告数据上下文

```go
type ReportContext struct {
    // 基本信息
    Title        string    `json:"title"`
    GeneratedAt  time.Time `json:"generated_at"`
    GeneratedBy  string    `json:"generated_by"`
    Company      string    `json:"company"`
    Logo         string    `json:"logo"`

    // 扫描概要
    ScanSummary  *ScanSummaryData  `json:"scan_summary"`

    // 各章节数据
    Sections     map[string]interface{} `json:"sections"`
}

type ScanSummaryData struct {
    TaskID        string    `json:"task_id"`
    TemplateName  string    `json:"template_name"`
    TargetCount   int       `json:"target_count"`
    StartTime     time.Time `json:"start_time"`
    EndTime       time.Time `json:"end_time"`
    Duration      string    `json:"duration"`

    // 漏洞统计
    VulnTotal     int       `json:"vuln_total"`
    VulnCritical  int       `json:"vuln_critical"`
    VulnHigh      int       `json:"vuln_high"`
    VulnMedium    int       `json:"vuln_medium"`
    VulnLow       int       `json:"vuln_low"`
    VulnInfo      int       `json:"vuln_info"`

    // 风险评分
    RiskScore     float64   `json:"risk_score"`
    RiskLevel     string    `json:"risk_level"` // critical, high, medium, low
}
```

### 5.4 内置报告章节

```go
var builtinSections = map[string]SectionGenerator{
    "executive_summary":    &ExecutiveSummaryGen{},
    "vulnerability_details": &VulnDetailsGen{},
    "risk_matrix":          &RiskMatrixGen{},
    "remediation_plan":     &RemediationPlanGen{},
    "technical_appendix":   &TechnicalAppendixGen{},
    "asset_inventory":      &AssetInventoryGen{},
    "compliance_score":     &ComplianceScoreGen{},
    "djcp_overview":        &DJCPOverviewGen{},
    "djcp_section_scores":  &DJCPSectionScoresGen{},
    "djcp_gap_analysis":    &DJCPGapAnalysisGen{},
    "djcp_evidence":        &DJCPEvidenceGen{},
    "api_inventory":        &APIInventoryGen{},
    "owasp_api_coverage":   &OWASPAPICoverageGen{},
    "attack_narrative":     &AttackNarrativeGen{},
    "kill_chain_mapping":   &KillChainMappingGen{},
    "emergency_summary":    &EmergencySummaryGen{},
    "affected_assets":      &AffectedAssetsGen{},
}

type SectionGenerator interface {
    Name() string
    Generate(ctx context.Context, dataSource JSONMap) (interface{}, error)
}
```

### 5.5 PDF 生成

```go
type PDFRenderer struct {
    chromeURL string // headless Chrome URL (用于 HTML→PDF)
}

func (r *PDFRenderer) Render(ctx context.Context, reportCtx *ReportContext, tmpl *ReportTemplate) ([]byte, error) {
    // 1. 渲染 HTML
    htmlContent, err := r.renderHTML(reportCtx, tmpl)
    if err != nil {
        return nil, err
    }

    // 2. HTML → PDF (通过 headless Chrome)
    // 使用 chromedp 或 rod 库
    pdfBytes, err := r.htmlToPDF(ctx, htmlContent)
    if err != nil {
        return nil, err
    }

    return pdfBytes, nil
}

func (r *PDFRenderer) renderHTML(reportCtx *ReportContext, tmpl *ReportTemplate) (string, error) {
    t, err := template.New("report").Funcs(reportFuncMap()).Parse(tmpl.Content)
    if err != nil {
        return "", err
    }

    var buf bytes.Buffer
    if err := t.Execute(&buf, reportCtx); err != nil {
        return "", err
    }

    return buf.String(), nil
}
```

### 5.6 内置报告类型

| 报告类型 | 受众 | 内容重点 |
|---------|------|---------|
| **高管摘要报告** | CTO/CISO | 风险评分、关键数字、趋势、建议 |
| **技术详细报告** | 安全工程师 | 漏洞详情、PoC、修复步骤、技术证据 |
| **合规评估报告** | 审计/合规 | 等保评分、差距分析、整改建议、证据 |
| **攻击面报告** | 安全运营 | 资产清单、变化记录、风险分布 |
| **应急响应报告** | 管理层+技术 | 受影响资产、漏洞影响、修复状态 |
| **定期安全报告** | 管理层 | 周/月/季度安全态势汇总 |

## 6. 数据导出

### 6.1 导出格式

```go
type ExportService struct {
    db *db.DB
}

type ExportRequest struct {
    Type        string            `json:"type"`    // vulnerabilities, assets, compliance, scans
    Format      string            `json:"format"`  // csv, json, xlsx, sarif
    Filters     map[string]string `json:"filters"`
    Fields      []string          `json:"fields"`  // 指定导出字段
    TimeRange   *TimeRange        `json:"time_range"`
}

func (s *ExportService) Export(ctx context.Context, req *ExportRequest) (io.Reader, string, error) {
    switch req.Format {
    case "csv":
        return s.exportCSV(ctx, req)
    case "json":
        return s.exportJSON(ctx, req)
    case "xlsx":
        return s.exportXLSX(ctx, req)
    case "sarif":
        return s.exportSARIF(ctx, req) // OASIS SARIF 标准格式
    default:
        return nil, "", fmt.Errorf("unsupported format: %s", req.Format)
    }
}
```

### 6.2 SARIF 输出

支持 SARIF (Static Analysis Results Interchange Format) 标准，可以导入到 GitHub/GitLab/Azure DevOps：

```go
type SARIFExporter struct{}

func (e *SARIFExporter) Export(ctx context.Context, vulns []*model.Vulnerability) (*sarif.Report, error) {
    report, _ := sarif.New(sarif.Version210)

    run := sarif.NewRun("VulnScan", "https://github.com/your-org/vulnscan")
    run.Tool.Driver.Version = stringPtr("1.0.0")

    for _, v := range vulns {
        rule := run.AddRule(v.CVEID).
            WithDescription(v.Description).
            WithHelpURI(v.Reference)

        location := sarif.NewPhysicalLocation().
            WithArtifactLocation(sarif.NewArtifactLocation().WithURI(v.Target))

        result := run.CreateResultForRule(rule.ID).
            WithLevel(cvssToSARIFLevel(v.Severity)).
            WithMessage(sarif.NewTextMessage(v.Title)).
            AddLocation(sarif.NewLocation().WithPhysicalLocation(location))

        _ = result
    }

    report.AddRun(run)
    return report, nil
}
```

## 7. API 端点

```
Visualization & Reports
├── /api/v1/dashboard
│   ├── GET    /metrics              通用指标查询 (MetricQuery)
│   ├── GET    /security-posture     安全态势概览
│   ├── GET    /scan-monitor         实时扫描监控
│   ├── GET    /vuln-analytics       漏洞分析数据
│   ├── GET    /asm-overview         攻击面概览
│   ├── GET    /compliance-overview  合规概览
│   ├── GET    /cluster-status       集群状态
│   ├── GET    /proxy-pool-status    代理池状态
│   └── WS     /ws                   WebSocket 实时推送
├── /api/v1/dashboard/custom
│   ├── POST   /                     创建自定义看板
│   ├── GET    /                     看板列表
│   ├── GET    /:id                  看板详情
│   ├── PUT    /:id                  更新看板
│   ├── DELETE /:id                  删除看板
│   └── POST   /:id/share            分享看板
├── /api/v1/reports
│   ├── GET    /templates            报告模板列表
│   ├── POST   /templates            创建自定义模板
│   ├── PUT    /templates/:id        更新模板
│   ├── POST   /generate             生成报告
│   │   Body: { template_id, data_source, format }
│   ├── GET    /jobs                  报告任务列表
│   ├── GET    /jobs/:id             任务详情
│   ├── GET    /jobs/:id/download    下载报告
│   └── POST   /schedule             定时报告
└── /api/v1/export
    ├── POST   /vulnerabilities      导出漏洞数据
    ├── POST   /assets               导出资产数据
    ├── POST   /compliance           导出合规数据
    └── POST   /scans                导出扫描记录
```

## 8. 配置

```yaml
visualization:
  dashboard:
    default_time_range: "last_7d"
    refresh_interval: 30        # 默认刷新间隔 (秒)
    websocket:
      enabled: true
      ping_interval: "30s"
    cache:
      metric_ttl: "5m"
      trend_ttl: "1h"
    max_custom_dashboards: 50

  reports:
    output_dir: "./reports"
    max_concurrent_gen: 5
    chrome:
      url: "ws://localhost:9222"   # headless Chrome (PDF 生成)
      timeout: "60s"
    default_format: "pdf"
    company_name: ""
    company_logo: ""

  export:
    max_rows: 100000
    formats: ["csv", "json", "xlsx", "sarif"]
    sarif:
      tool_name: "VulnScan"
      tool_version: "1.0.0"
```
