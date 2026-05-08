# 扫描模板化设计

## 1. 概述

扫描模板化将不同类型的安全专项任务封装为**可复用、可组合、可参数化**的扫描模板。用户可以「选模板→填参数→一键启动」，也可以基于模板自定义组合出新的专项任务。

### 核心价值

| 传统方式 | 模板化方式 |
|---------|-----------|
| 每次手动选择扫描模块和参数 | 选模板一键执行 |
| 新人不知道怎么配置专项扫描 | 内置最佳实践模板 |
| 相似任务反复配置 | 模板复用 + 参数覆盖 |
| 扫描策略无法版本管理 | 模板可导出/导入/版本化 |

## 2. 模板体系架构

```
┌────────────────────────────────────────────────────────────┐
│                     Template Engine                         │
│                                                            │
│  ┌─────────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ 模板库 (内置)   │  │ 模板编辑器   │  │ 模板运行时   │  │
│  │                 │  │              │  │              │  │
│  │ · Web专项      │  │ · 可视化编排 │  │ · 参数解析   │  │
│  │ · 主机专项     │  │ · 模块组合   │  │ · 阶段调度   │  │
│  │ · 等保专项     │  │ · 参数定义   │  │ · 上下文传递 │  │
│  │ · 红队专项     │  │ · 条件分支   │  │ · 结果聚合   │  │
│  │ · API专项      │  │ · 导入/导出  │  │ · 报告生成   │  │
│  │ · 应急响应     │  │              │  │              │  │
│  └─────────────────┘  └──────────────┘  └──────────────┘  │
│                              │                             │
│                              ↓                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         扫描引擎 (scan-engine.md) / 调度器 (scheduler)│  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

## 3. 模板数据模型

### 3.1 核心模型

```go
type ScanTemplate struct {
    ID          string          `json:"id" gorm:"primaryKey"`
    Name        string          `json:"name"`
    Code        string          `json:"code" gorm:"uniqueIndex"` // web_full, host_baseline, djcp_l3
    Category    string          `json:"category"`     // web, host, network, compliance, redteam, api, emergency
    Description string          `json:"description"`
    Icon        string          `json:"icon"`
    Tags        JSONArray       `json:"tags"`

    // 模板内容
    Stages      []TemplateStage `json:"stages" gorm:"serializer:json"`
    Parameters  []TemplateParam `json:"parameters" gorm:"serializer:json"`
    Variables   JSONMap         `json:"variables" gorm:"serializer:json"`    // 内置变量
    Conditions  []Condition     `json:"conditions" gorm:"serializer:json"`  // 条件分支

    // 报告配置
    ReportTemplate string       `json:"report_template"`    // 报告模板ID
    ReportSections []string     `json:"report_sections" gorm:"serializer:json"`

    // 元数据
    Builtin     bool            `json:"builtin" gorm:"default:false"`
    Version     string          `json:"version"`
    AuthorID    string          `json:"author_id"`
    ParentID    string          `json:"parent_id"`       // 基于哪个模板派生
    Enabled     bool            `json:"enabled" gorm:"default:true"`
    UsageCount  int64           `json:"usage_count"`
    CreatedAt   time.Time       `json:"created_at"`
    UpdatedAt   time.Time       `json:"updated_at"`
}
```

### 3.2 模板阶段

每个模板由一个或多个有序阶段 (Stage) 组成，每个阶段包含一组扫描模块：

```go
type TemplateStage struct {
    Name        string           `json:"name"`          // 信息收集, 漏洞扫描, 深度验证
    Order       int              `json:"order"`
    Modules     []StageModule    `json:"modules"`
    Condition   string           `json:"condition"`     // CEL: 满足条件才执行此阶段
    OnFailure   string           `json:"on_failure"`    // continue, skip_rest, abort
    Timeout     string           `json:"timeout"`       // 阶段超时
    Parallel    bool             `json:"parallel"`      // 阶段内模块是否并行
}

type StageModule struct {
    ModuleID    string          `json:"module_id"`     // port_scan, fingerprint, sqli...
    Enabled     bool            `json:"enabled"`
    Config      JSONMap         `json:"config"`        // 模块级参数覆盖
    Weight      int             `json:"weight"`        // 在阶段内的执行权重/优先级
    Condition   string          `json:"condition"`     // CEL: 模块级条件
    DependsOn   []string        `json:"depends_on"`    // 依赖的前置模块
}
```

### 3.3 参数定义

模板暴露可配置的参数，用户启动时可以覆盖默认值：

```go
type TemplateParam struct {
    Name         string      `json:"name"`          // target, ports, threads
    Label        string      `json:"label"`         // 扫描目标, 端口范围, 并发数
    Type         string      `json:"type"`          // string, int, bool, select, multi_select, textarea, cidr
    Default      interface{} `json:"default"`
    Required     bool        `json:"required"`
    Validation   string      `json:"validation"`    // 正则或CEL验证
    Options      []ParamOption `json:"options"`      // select/multi_select 的选项
    Group        string      `json:"group"`         // 参数分组 (基础/高级/专家)
    Description  string      `json:"description"`
    DependsOn    string      `json:"depends_on"`    // 依赖其他参数的值
}

type ParamOption struct {
    Value string `json:"value"`
    Label string `json:"label"`
}
```

### 3.4 条件分支

```go
type Condition struct {
    Name        string `json:"name"`
    Expression  string `json:"expression"`   // CEL: stages.recon.found_ports > 100
    TrueAction  string `json:"true_action"`  // enable_stage:deep_scan
    FalseAction string `json:"false_action"` // skip_stage:deep_scan
}
```

## 4. 内置模板库

### 4.1 Web 应用全量扫描

```yaml
id: "builtin-web-full"
name: "Web 应用全量扫描"
code: "web_full"
category: "web"
description: "全面的 Web 应用安全评估，覆盖 OWASP Top 10"
tags: ["web", "owasp", "full"]

parameters:
  - name: "target"
    label: "目标 URL"
    type: "string"
    required: true
    validation: "^https?://"
  - name: "scan_depth"
    label: "扫描深度"
    type: "select"
    default: "standard"
    options:
      - { value: "quick", label: "快速 (仅指纹+高危)" }
      - { value: "standard", label: "标准 (推荐)" }
      - { value: "deep", label: "深度 (含Fuzzing)" }
  - name: "auth"
    label: "认证信息"
    type: "textarea"
    required: false
    group: "advanced"
    description: "Cookie 或 Bearer Token"
  - name: "exclude_paths"
    label: "排除路径"
    type: "textarea"
    required: false
    group: "advanced"
    description: "不扫描的路径，每行一个"

stages:
  - name: "信息收集"
    order: 1
    parallel: true
    modules:
      - module_id: "web_fingerprint"
        enabled: true
      - module_id: "web_crawl"
        enabled: true
        config:
          max_depth: 3
          max_pages: 500
      - module_id: "dir_scan"
        enabled: true
        config:
          wordlist: "common"
      - module_id: "cert_check"
        enabled: true

  - name: "漏洞检测"
    order: 2
    parallel: true
    condition: "stages['信息收集'].status == 'completed'"
    modules:
      - module_id: "sqli"
        enabled: true
        config:
          techniques: ["error", "time", "boolean"]
      - module_id: "xss"
        enabled: true
        config:
          types: ["reflected"]
      - module_id: "ssrf"
        enabled: true
      - module_id: "info_leak"
        enabled: true
      - module_id: "nuclei_scan"
        enabled: true
        config:
          tags: ["cve", "tech", "misconfig"]
          severity: ["critical", "high", "medium"]

  - name: "深度验证"
    order: 3
    condition: "params.scan_depth == 'deep'"
    parallel: true
    modules:
      - module_id: "api_fuzz"
        enabled: true
      - module_id: "weak_pass"
        enabled: true
        config:
          targets: ["web_login"]
      - module_id: "nuclei_scan"
        enabled: true
        config:
          tags: ["fuzzing", "default-login"]

report_sections:
  - "executive_summary"
  - "vulnerability_details"
  - "risk_matrix"
  - "remediation_plan"
  - "technical_appendix"
```

### 4.2 主机安全检查

```yaml
id: "builtin-host-security"
name: "主机安全检查"
code: "host_security"
category: "host"
description: "Linux/Windows 主机安全评估"

parameters:
  - name: "targets"
    label: "目标主机"
    type: "textarea"
    required: true
    description: "IP 或 CIDR，每行一个"
  - name: "credential"
    label: "SSH/WinRM 凭据"
    type: "select"
    required: false
    description: "选择已保存的凭据"
  - name: "os_type"
    label: "操作系统类型"
    type: "select"
    default: "auto"
    options:
      - { value: "auto", label: "自动检测" }
      - { value: "linux", label: "Linux" }
      - { value: "windows", label: "Windows" }

stages:
  - name: "网络探测"
    order: 1
    parallel: true
    modules:
      - module_id: "port_scan"
        config:
          ports: "1-65535"
          technique: "syn"
      - module_id: "service_probe"
        depends_on: ["port_scan"]

  - name: "服务漏洞"
    order: 2
    parallel: true
    modules:
      - module_id: "weak_pass"
        config:
          targets: ["ssh", "rdp", "mysql", "redis", "ftp"]
      - module_id: "nuclei_scan"
        config:
          tags: ["network", "service"]

  - name: "基线检查"
    order: 3
    condition: "params.credential != ''"
    modules:
      - module_id: "compliance_check"
        config:
          framework: "CIS_auto"
          categories: ["authentication", "authorization", "audit", "network"]

report_sections:
  - "executive_summary"
  - "asset_inventory"
  - "vulnerability_details"
  - "compliance_score"
  - "remediation_plan"
```

### 4.3 等保 2.0 专项

```yaml
id: "builtin-djcp-level3"
name: "等保三级检测"
code: "djcp_l3"
category: "compliance"
description: "等保 2.0 三级安全测评"

parameters:
  - name: "targets"
    label: "被测系统"
    type: "textarea"
    required: true
  - name: "credentials"
    label: "主机凭据"
    type: "select"
    required: true
  - name: "sections"
    label: "检测范围"
    type: "multi_select"
    default: ["all"]
    options:
      - { value: "all", label: "全部" }
      - { value: "network", label: "安全通信网络" }
      - { value: "boundary", label: "安全区域边界" }
      - { value: "computing", label: "安全计算环境" }
      - { value: "management", label: "安全管理中心" }

stages:
  - name: "资产发现"
    order: 1
    modules:
      - module_id: "port_scan"
      - module_id: "service_probe"
      - module_id: "web_fingerprint"

  - name: "安全通信网络"
    order: 2
    condition: "params.sections.contains('all') || params.sections.contains('network')"
    modules:
      - module_id: "cert_check"
        config:
          check_weak_cipher: true
          check_tls_version: true
      - module_id: "compliance_check"
        config:
          framework: "DJCP_Level3"
          categories: ["communication"]

  - name: "安全区域边界"
    order: 3
    condition: "params.sections.contains('all') || params.sections.contains('boundary')"
    modules:
      - module_id: "port_scan"
        config: { ports: "1-65535" }
      - module_id: "compliance_check"
        config:
          framework: "DJCP_Level3"
          categories: ["boundary"]

  - name: "安全计算环境"
    order: 4
    condition: "params.sections.contains('all') || params.sections.contains('computing')"
    modules:
      - module_id: "weak_pass"
      - module_id: "info_leak"
      - module_id: "compliance_check"
        config:
          framework: "DJCP_Level3"
          categories: ["identity", "access_control", "audit", "intrusion", "malware"]

  - name: "漏洞验证"
    order: 5
    modules:
      - module_id: "nuclei_scan"
        config:
          severity: ["critical", "high"]
      - module_id: "sqli"
      - module_id: "xss"

report_sections:
  - "djcp_overview"
  - "djcp_section_scores"
  - "djcp_gap_analysis"
  - "vulnerability_details"
  - "remediation_plan"
  - "djcp_evidence"
```

### 4.4 红队模拟

```yaml
id: "builtin-redteam"
name: "红队模拟评估"
code: "redteam"
category: "redteam"
description: "模拟攻击者视角的全链路安全评估"

parameters:
  - name: "seed_domains"
    label: "种子域名"
    type: "textarea"
    required: true
  - name: "aggressiveness"
    label: "攻击强度"
    type: "select"
    default: "moderate"
    options:
      - { value: "passive", label: "被动 (仅信息收集)" }
      - { value: "moderate", label: "中等 (含安全验证)" }
      - { value: "aggressive", label: "激进 (含Exploit尝试)" }
  - name: "scope"
    label: "范围限制"
    type: "textarea"
    group: "advanced"
    description: "允许的 IP/域名范围，每行一个"

stages:
  - name: "侦察"
    order: 1
    parallel: true
    modules:
      - module_id: "subdomain_enum"
      - module_id: "port_scan"
        config: { technique: "syn", ports: "top1000" }
      - module_id: "web_fingerprint"
      - module_id: "web_crawl"
        config: { extract_js_endpoints: true }

  - name: "武器化"
    order: 2
    parallel: true
    condition: "params.aggressiveness != 'passive'"
    modules:
      - module_id: "nuclei_scan"
        config:
          tags: ["cve", "rce", "lfi", "ssrf", "sqli"]
          severity: ["critical", "high"]
      - module_id: "sqli"
        config: { techniques: ["error", "time", "union"] }
      - module_id: "ssrf"
      - module_id: "weak_pass"
        config:
          targets: ["ssh", "mysql", "redis", "ftp", "web_login"]
      - module_id: "api_security"

  - name: "深度利用"
    order: 3
    condition: "params.aggressiveness == 'aggressive' && stages['武器化'].found_vulns > 0"
    modules:
      - module_id: "nuclei_scan"
        config:
          tags: ["exploit", "intrusive"]

report_sections:
  - "attack_narrative"
  - "kill_chain_mapping"
  - "vulnerability_details"
  - "risk_assessment"
  - "remediation_priority"
```

### 4.5 API 安全专项

```yaml
id: "builtin-api-security"
name: "API 安全专项检测"
code: "api_security"
category: "api"
description: "REST / GraphQL API 全面安全评估"

parameters:
  - name: "spec_source"
    label: "API 规范"
    type: "select"
    required: true
    options:
      - { value: "url", label: "OpenAPI/Swagger URL" }
      - { value: "upload", label: "上传文件" }
      - { value: "crawl", label: "自动发现" }
  - name: "spec_url"
    label: "规范 URL"
    type: "string"
    depends_on: "spec_source == 'url'"
  - name: "auth_contexts"
    label: "认证角色"
    type: "multi_select"
    description: "选择已配置的认证上下文"

stages:
  - name: "API 发现"
    order: 1
    modules:
      - module_id: "api_discovery"
      - module_id: "shadow_api_detection"

  - name: "OWASP API Top 10"
    order: 2
    parallel: true
    modules:
      - module_id: "bola_detection"
      - module_id: "auth_bypass_detection"
      - module_id: "mass_assignment_detection"
      - module_id: "rate_limit_detection"
      - module_id: "privilege_escalation_detection"

  - name: "注入测试"
    order: 3
    parallel: true
    modules:
      - module_id: "api_sqli"
      - module_id: "api_xss"
      - module_id: "api_ssrf"

report_sections:
  - "api_inventory"
  - "owasp_api_coverage"
  - "vulnerability_details"
  - "remediation_plan"
```

### 4.6 应急响应

```yaml
id: "builtin-emergency"
name: "应急响应快速排查"
code: "emergency"
category: "emergency"
description: "针对新爆漏洞的快速全网排查"

parameters:
  - name: "vuln_id"
    label: "漏洞编号"
    type: "string"
    required: true
    description: "CVE-XXXX-XXXXX 或内部编号"
  - name: "target_scope"
    label: "排查范围"
    type: "select"
    default: "all_assets"
    options:
      - { value: "all_assets", label: "全部已知资产" }
      - { value: "affected_only", label: "仅受影响技术栈" }
      - { value: "custom", label: "自定义范围" }
  - name: "custom_targets"
    label: "自定义目标"
    type: "textarea"
    depends_on: "target_scope == 'custom'"

stages:
  - name: "资产筛选"
    order: 1
    modules:
      - module_id: "asset_filter"
        config:
          match_cpe: true        # 根据CVE的CPE匹配受影响资产
          match_fingerprint: true

  - name: "快速验证"
    order: 2
    modules:
      - module_id: "nuclei_scan"
        config:
          template_ids: ["{{vuln_id}}"]
          severity: ["critical", "high"]
      - module_id: "inference_scan"
        config:
          vuln_id: "{{vuln_id}}"

  - name: "确认验证"
    order: 3
    condition: "stages['快速验证'].found_vulns > 0"
    modules:
      - module_id: "active_verify"
        config:
          vuln_id: "{{vuln_id}}"

report_sections:
  - "emergency_summary"
  - "affected_assets"
  - "confirmed_vulnerable"
  - "remediation_urgency"
```

## 5. 模板引擎

### 5.1 模板编译与实例化

```go
type TemplateEngine struct {
    registry    *ModuleRegistry
    celEnv      *cel.Env
    paramParser *ParamParser
}

type TemplateInstance struct {
    Template    *ScanTemplate
    Parameters  map[string]interface{}  // 用户提供的实际参数
    Variables   map[string]interface{}  // 运行时变量
    StageResults map[string]*StageResult // 阶段执行结果
}

func (e *TemplateEngine) Instantiate(tpl *ScanTemplate, params map[string]interface{}) (*TemplateInstance, error) {
    // 1. 参数验证
    if err := e.validateParams(tpl.Parameters, params); err != nil {
        return nil, fmt.Errorf("parameter validation failed: %w", err)
    }

    // 2. 参数填充默认值
    merged := e.mergeDefaults(tpl.Parameters, params)

    // 3. 变量模板替换 ({{ vuln_id }} → CVE-2024-xxxxx)
    resolved, err := e.resolveVariables(tpl, merged)
    if err != nil {
        return nil, err
    }

    // 4. 条件评估，标记跳过的阶段
    instance := &TemplateInstance{
        Template:     tpl,
        Parameters:   resolved,
        Variables:    tpl.Variables,
        StageResults: make(map[string]*StageResult),
    }

    return instance, nil
}
```

### 5.2 阶段执行器

```go
type StageExecutor struct {
    engine      *TemplateEngine
    scheduler   *Scheduler
}

func (e *StageExecutor) Execute(ctx context.Context, instance *TemplateInstance) error {
    for _, stage := range instance.Template.Stages {
        // 评估阶段条件
        if stage.Condition != "" {
            shouldRun, err := e.engine.evaluateCondition(stage.Condition, instance)
            if err != nil {
                return fmt.Errorf("stage %s condition error: %w", stage.Name, err)
            }
            if !shouldRun {
                instance.StageResults[stage.Name] = &StageResult{Status: "skipped"}
                continue
            }
        }

        // 执行阶段
        result, err := e.executeStage(ctx, stage, instance)
        if err != nil {
            instance.StageResults[stage.Name] = &StageResult{Status: "failed", Error: err.Error()}

            switch stage.OnFailure {
            case "abort":
                return fmt.Errorf("stage %s failed, aborting: %w", stage.Name, err)
            case "skip_rest":
                return nil
            default: // continue
                continue
            }
        }

        instance.StageResults[stage.Name] = result
    }

    return nil
}

func (e *StageExecutor) executeStage(ctx context.Context, stage TemplateStage, instance *TemplateInstance) (*StageResult, error) {
    if stage.Timeout != "" {
        timeout, _ := time.ParseDuration(stage.Timeout)
        var cancel context.CancelFunc
        ctx, cancel = context.WithTimeout(ctx, timeout)
        defer cancel()
    }

    result := &StageResult{Name: stage.Name, StartedAt: time.Now()}

    if stage.Parallel {
        return e.executeParallel(ctx, stage.Modules, instance)
    }
    return e.executeSequential(ctx, stage.Modules, instance)
}
```

### 5.3 模块注册表

```go
type ModuleRegistry struct {
    modules map[string]ScanModule
}

type ScanModule interface {
    ID() string
    Name() string
    Category() string
    DefaultConfig() JSONMap
    ValidateConfig(config JSONMap) error
    Execute(ctx context.Context, target *ScanTarget, config JSONMap) (*ModuleResult, error)
}

func (r *ModuleRegistry) Register(module ScanModule) {
    r.modules[module.ID()] = module
}

func (r *ModuleRegistry) Get(moduleID string) (ScanModule, bool) {
    m, ok := r.modules[moduleID]
    return m, ok
}
```

## 6. 模板管理

### 6.1 模板版本控制

```go
type TemplateVersion struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    TemplateID  string    `json:"template_id" gorm:"index"`
    Version     string    `json:"version"`
    Content     string    `json:"content" gorm:"type:text"`  // YAML 内容
    ChangeLog   string    `json:"change_log"`
    AuthorID    string    `json:"author_id"`
    CreatedAt   time.Time `json:"created_at"`
}
```

### 6.2 模板导入/导出

```go
type TemplateExporter struct{}

func (e *TemplateExporter) ExportYAML(tpl *ScanTemplate) ([]byte, error) {
    return yaml.Marshal(tpl)
}

func (e *TemplateExporter) ImportYAML(data []byte) (*ScanTemplate, error) {
    var tpl ScanTemplate
    if err := yaml.Unmarshal(data, &tpl); err != nil {
        return nil, err
    }
    return &tpl, e.validate(&tpl)
}

func (e *TemplateExporter) ExportBundle(templates []*ScanTemplate) ([]byte, error) {
    // 导出为 tar.gz 包，含多个模板 + 依赖的 PoC
    return nil, nil
}
```

### 6.3 模板市场

```go
type TemplateMarketplace struct {
    remoteURL string
}

type MarketplaceItem struct {
    ID           string    `json:"id"`
    Name         string    `json:"name"`
    Author       string    `json:"author"`
    Downloads    int64     `json:"downloads"`
    Rating       float64   `json:"rating"`
    Version      string    `json:"version"`
    Description  string    `json:"description"`
    Tags         []string  `json:"tags"`
    PreviewURL   string    `json:"preview_url"`
}

func (m *TemplateMarketplace) Search(ctx context.Context, query string) ([]MarketplaceItem, error) {
    return nil, nil
}

func (m *TemplateMarketplace) Install(ctx context.Context, itemID string) (*ScanTemplate, error) {
    return nil, nil
}
```

## 7. 执行记录

### 7.1 任务实例

```go
type TemplateScanJob struct {
    ID            string            `json:"id" gorm:"primaryKey"`
    TemplateID    string            `json:"template_id" gorm:"index"`
    TemplateName  string            `json:"template_name"`
    Parameters    JSONMap           `json:"parameters" gorm:"serializer:json"`
    Status        string            `json:"status"`     // pending, running, paused, completed, failed, cancelled
    Progress      float64           `json:"progress"`   // 0~100
    CurrentStage  string            `json:"current_stage"`
    StageProgress JSONMap           `json:"stage_progress" gorm:"serializer:json"`

    TotalTargets  int               `json:"total_targets"`
    ScannedTargets int              `json:"scanned_targets"`
    VulnCount     map[string]int    `json:"vuln_count" gorm:"serializer:json"`  // critical:2, high:5...

    CreatedBy     string            `json:"created_by"`
    StartedAt     *time.Time        `json:"started_at"`
    FinishedAt    *time.Time        `json:"finished_at"`
    CreatedAt     time.Time         `json:"created_at"`
}
```

## 8. API 端点

```
Template System
├── /api/v1/templates
│   ├── GET    /                     模板列表 (分类/标签筛选)
│   ├── GET    /categories           模板分类列表
│   ├── GET    /:id                  模板详情
│   ├── POST   /                     创建自定义模板
│   ├── PUT    /:id                  更新模板
│   ├── DELETE /:id                  删除模板
│   ├── POST   /:id/clone            克隆模板
│   ├── POST   /import               导入模板 (YAML)
│   ├── GET    /:id/export           导出模板 (YAML)
│   └── GET    /:id/versions         模板版本历史
├── /api/v1/templates/:id/execute
│   ├── POST   /                     启动模板扫描
│   │   Body: { parameters: {...}, schedule?: "cron_expr" }
│   ├── POST   /preview              预览执行计划 (不实际执行)
│   └── POST   /validate-params      验证参数
├── /api/v1/template-jobs
│   ├── GET    /                     任务列表
│   ├── GET    /:id                  任务详情
│   ├── GET    /:id/progress         实时进度 (WebSocket)
│   ├── POST   /:id/pause            暂停
│   ├── POST   /:id/resume           恢复
│   ├── POST   /:id/cancel           取消
│   └── GET    /:id/report           查看报告
└── /api/v1/template-marketplace
    ├── GET    /                     市场模板列表
    ├── GET    /:id                  模板详情
    └── POST   /:id/install          安装模板
```

## 9. 与现有模块的关系

```
scan-template.md (本文档)
├── 使用 → scan-engine.md    (Stage 中的 Module 最终调用扫描引擎)
├── 使用 → scheduler.md      (定时扫描、任务分发)
├── 使用 → modules.md        (各扫描模块作为 StageModule)
├── 使用 → compliance.md     (等保专项模板调用合规检查)
├── 使用 → api-security.md   (API专项模板调用API安全检测)
├── 使用 → nuclei-compat.md  (Nuclei PoC 作为模块)
├── 使用 → asm.md            (红队模板的侦察阶段可调用ASM发现)
└── 使用 → advanced-detection.md (推理/验证扫描作为模块)
```
