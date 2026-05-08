# 合规基线检查设计

## 1. 概述

合规基线检查从「防御者视角」评估目标系统的安全配置是否符合行业标准和法规要求，与漏洞检测（攻击者视角）形成互补。核心目标：**自动化检查→合规评分→差距分析→修复指引**。

### 支持的基线标准

| 标准 | 来源 | 覆盖范围 |
|------|------|---------|
| **CIS Benchmark** | Center for Internet Security | OS、数据库、Web服务器、云平台、容器 |
| **等保 2.0** | GB/T 22239-2019 | 网络安全、主机安全、应用安全、数据安全 |
| **PCI-DSS 4.0** | PCI SSC | 支付卡行业数据安全标准 |
| **HIPAA** | HHS | 医疗保健信息安全 |
| **SOC 2** | AICPA | 服务组织控制 |
| **自定义基线** | 用户 | 企业内部安全策略 |

## 2. 架构

```
┌───────────────────────────────────────────────────────────┐
│                 Compliance Engine                          │
│                                                           │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐ │
│  │ 基线库管理  │  │  采集器      │  │  检查引擎       │ │
│  │             │  │              │  │                 │ │
│  │ · CIS      │  │ · SSH Agent  │  │ · 规则匹配      │ │
│  │ · 等保2.0  │  │ · WinRM     │  │ · 配置对比      │ │
│  │ · PCI-DSS  │  │ · HTTP API  │  │ · 脚本检查      │ │
│  │ · 自定义   │  │ · SNMP      │  │ · 评分计算      │ │
│  └─────────────┘  │ · Cloud API │  └────────┬────────┘ │
│                   └──────────────┘           │          │
│                                              ↓          │
│  ┌───────────────────────────────────────────────────┐  │
│  │              报告 & 修复                            │  │
│  │  ┌──────────┐  ┌──────────┐  ┌─────────────────┐ │  │
│  │  │ 合规评分 │  │ 差距分析 │  │ 修复指引生成    │ │  │
│  │  │          │  │          │  │                 │ │  │
│  │  │ 分项得分 │  │ 不合规项 │  │ 步骤指引       │ │  │
│  │  │ 总体评级 │  │ 风险等级 │  │ 脚本/Playbook  │ │  │
│  │  │ 趋势对比 │  │ 优先级   │  │ 验证方法       │ │  │
│  │  └──────────┘  └──────────┘  └─────────────────┘ │  │
│  └───────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────┘
```

## 3. 基线规则模型

### 3.1 规则定义

```go
type ComplianceFramework struct {
    ID          string    `json:"id" gorm:"primaryKey"`
    Name        string    `json:"name"`          // CIS_Ubuntu_22.04, DJCP_Level3
    Version     string    `json:"version"`       // v1.0.0
    Standard    string    `json:"standard"`      // CIS, DJCP, PCI_DSS
    TargetType  string    `json:"target_type"`   // linux, windows, mysql, nginx, k8s, aws
    Description string    `json:"description"`
    TotalRules  int       `json:"total_rules"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

type ComplianceRule struct {
    ID           string   `json:"id" gorm:"primaryKey"`
    FrameworkID  string   `json:"framework_id" gorm:"index"`
    Section      string   `json:"section"`        // 1.1.1
    Title        string   `json:"title"`          // Ensure mounting of cramfs filesystems is disabled
    Description  string   `json:"description"`
    Rationale    string   `json:"rationale"`      // 为什么需要此检查
    Severity     string   `json:"severity"`       // critical, high, medium, low
    Category     string   `json:"category"`       // access_control, audit, network, crypto...
    
    // 检查逻辑
    CheckType    string   `json:"check_type"`     // command, file_content, file_perm, registry, api
    CheckConfig  JSONMap  `json:"check_config"`   // 检查参数

    // 修复指引
    Remediation  string   `json:"remediation"`    // 修复步骤 (Markdown)
    RemediationScript string `json:"remediation_script"` // 自动修复脚本
    
    // 审计映射
    CISControl   string   `json:"cis_control"`    // CIS Control ID
    NISTMapping  string   `json:"nist_mapping"`   // NIST SP 800-53 映射
    DJCPMapping  string   `json:"djcp_mapping"`   // 等保条款映射
    
    Enabled      bool     `json:"enabled" gorm:"default:true"`
}
```

### 3.2 检查配置类型

```go
type CheckConfig struct {
    // command 类型: 执行命令并匹配输出
    Command         string `json:"command,omitempty"`
    ExpectedOutput  string `json:"expected_output,omitempty"`
    ExpectedRegex   string `json:"expected_regex,omitempty"`
    NotExpected     string `json:"not_expected,omitempty"`

    // file_content 类型: 检查文件内容
    FilePath        string `json:"file_path,omitempty"`
    Contains        string `json:"contains,omitempty"`
    NotContains     string `json:"not_contains,omitempty"`
    RegexMatch      string `json:"regex_match,omitempty"`

    // file_perm 类型: 检查文件权限
    FilePermission  string `json:"file_permission,omitempty"` // 如 "0600"
    FileOwner       string `json:"file_owner,omitempty"`      // 如 "root"
    FileGroup       string `json:"file_group,omitempty"`      // 如 "root"

    // registry 类型 (Windows): 注册表检查
    RegistryPath    string `json:"registry_path,omitempty"`
    RegistryKey     string `json:"registry_key,omitempty"`
    RegistryValue   string `json:"registry_value,omitempty"`

    // api 类型: HTTP API 检查
    APIEndpoint     string `json:"api_endpoint,omitempty"`
    APIMethod       string `json:"api_method,omitempty"`
    APIHeaders      map[string]string `json:"api_headers,omitempty"`
    APIExpectedCode int    `json:"api_expected_code,omitempty"`
    APIExpectedBody string `json:"api_expected_body,omitempty"`
}
```

### 3.3 YAML 规则示例

```yaml
# CIS Ubuntu 22.04 - 1.1.1.1 Ensure mounting of cramfs is disabled
- id: "CIS-Ubuntu-22.04-1.1.1.1"
  framework: "CIS_Ubuntu_22.04"
  section: "1.1.1.1"
  title: "Ensure mounting of cramfs filesystems is disabled"
  severity: "medium"
  category: "filesystem"
  check_type: "command"
  check_config:
    command: "modprobe -n -v cramfs 2>&1"
    expected_output: "install /bin/true"
    not_expected: "insmod"
  remediation: |
    编辑 `/etc/modprobe.d/cramfs.conf`，添加：
    ```
    install cramfs /bin/true
    blacklist cramfs
    ```
    然后执行: `rmmod cramfs 2>/dev/null`
  remediation_script: |
    echo "install cramfs /bin/true" > /etc/modprobe.d/cramfs.conf
    echo "blacklist cramfs" >> /etc/modprobe.d/cramfs.conf
    rmmod cramfs 2>/dev/null || true
  nist_mapping: "CM-7"
  djcp_mapping: "安全计算环境-入侵防范"

# 等保2.0 三级 - 安全计算环境-身份鉴别
- id: "DJCP-L3-AUTH-001"
  framework: "DJCP_Level3"
  section: "安全计算环境-身份鉴别-a"
  title: "应对登录的用户进行身份标识和鉴别，身份标识具有唯一性"
  severity: "high"
  category: "authentication"
  check_type: "multi"
  checks:
    - type: "file_content"
      file_path: "/etc/shadow"
      not_contains: "::0:"    # 无空密码账户
    - type: "command"
      command: "awk -F: '($2 == \"\") {print $1}' /etc/shadow"
      expected_output: ""      # 输出应为空 (无空密码)
    - type: "command"
      command: "grep -c '^UID_MIN' /etc/login.defs"
      expected_output: "1"     # UID_MIN 配置存在
  remediation: |
    1. 检查并删除空密码账户: `passwd -l <username>`
    2. 确保 `/etc/login.defs` 中 `UID_MIN` 配置正确
    3. 启用密码复杂度策略
  djcp_mapping: "8.1.4.1-a"
```

## 4. 数据采集器

### 4.1 采集接口

```go
type Collector interface {
    Name() string
    TargetType() string           // linux, windows, mysql, nginx...
    Connect(ctx context.Context, target *CollectorTarget) error
    Execute(ctx context.Context, check *CheckConfig) (*CollectResult, error)
    Close() error
}

type CollectorTarget struct {
    Host       string            `json:"host"`
    Port       int               `json:"port"`
    Protocol   string            `json:"protocol"`   // ssh, winrm, http, snmp
    Credential *Credential       `json:"credential"`
    Options    map[string]string `json:"options"`
}

type CollectResult struct {
    RawOutput  string `json:"raw_output"`
    ExitCode   int    `json:"exit_code"`
    Error      string `json:"error,omitempty"`
}
```

### 4.2 SSH 采集器 (Linux)

```go
type SSHCollector struct {
    client *ssh.Client
}

func (c *SSHCollector) Execute(ctx context.Context, check *CheckConfig) (*CollectResult, error) {
    session, err := c.client.NewSession()
    if err != nil {
        return nil, err
    }
    defer session.Close()

    var stdout, stderr bytes.Buffer
    session.Stdout = &stdout
    session.Stderr = &stderr

    // 超时控制
    done := make(chan error, 1)
    go func() {
        done <- session.Run(check.Command)
    }()

    select {
    case err := <-done:
        exitCode := 0
        if err != nil {
            if exitErr, ok := err.(*ssh.ExitError); ok {
                exitCode = exitErr.ExitStatus()
            }
        }
        return &CollectResult{
            RawOutput: stdout.String() + stderr.String(),
            ExitCode:  exitCode,
        }, nil
    case <-ctx.Done():
        return nil, fmt.Errorf("command timed out: %s", check.Command)
    }
}
```

### 4.3 云 API 采集器

```go
type CloudCollector struct {
    provider string  // aws, azure, gcp, aliyun, tencentcloud
}

func (c *CloudCollector) Execute(ctx context.Context, check *CheckConfig) (*CollectResult, error) {
    switch c.provider {
    case "aws":
        return c.executeAWS(ctx, check)
    case "aliyun":
        return c.executeAliyun(ctx, check)
    default:
        return nil, fmt.Errorf("unsupported cloud provider: %s", c.provider)
    }
}

// AWS 示例: 检查 S3 Bucket 公开访问
func (c *CloudCollector) executeAWS(ctx context.Context, check *CheckConfig) (*CollectResult, error) {
    // 调用 AWS API 获取 S3 Bucket 的公开访问配置
    // 检查 BlockPublicAccess 是否全部开启
    // 返回检查结果
    return nil, nil
}
```

## 5. 检查引擎

### 5.1 规则执行器

```go
type ComplianceChecker struct {
    collectors map[string]Collector
    rules      []*ComplianceRule
}

type CheckResult struct {
    RuleID      string    `json:"rule_id"`
    Status      string    `json:"status"`    // pass, fail, error, skip, not_applicable
    Severity    string    `json:"severity"`
    Evidence    string    `json:"evidence"`  // 实际采集到的值
    Expected    string    `json:"expected"`  // 期望值
    Message     string    `json:"message"`
    CheckedAt   time.Time `json:"checked_at"`
}

func (c *ComplianceChecker) Check(ctx context.Context, rule *ComplianceRule) (*CheckResult, error) {
    collector, ok := c.collectors[rule.FrameworkID]
    if !ok {
        return &CheckResult{
            RuleID: rule.ID,
            Status: "error",
            Message: "no collector available for this target type",
        }, nil
    }

    result, err := collector.Execute(ctx, &rule.CheckConfig)
    if err != nil {
        return &CheckResult{
            RuleID: rule.ID,
            Status: "error",
            Message: err.Error(),
        }, nil
    }

    return c.evaluate(rule, result), nil
}

func (c *ComplianceChecker) evaluate(rule *ComplianceRule, collected *CollectResult) *CheckResult {
    config := rule.CheckConfig
    output := strings.TrimSpace(collected.RawOutput)

    result := &CheckResult{
        RuleID:   rule.ID,
        Severity: rule.Severity,
        Evidence: output,
    }

    switch rule.CheckType {
    case "command":
        if config.ExpectedOutput != "" {
            result.Expected = config.ExpectedOutput
            if strings.Contains(output, config.ExpectedOutput) {
                result.Status = "pass"
            } else {
                result.Status = "fail"
            }
        }
        if config.NotExpected != "" && strings.Contains(output, config.NotExpected) {
            result.Status = "fail"
            result.Message = fmt.Sprintf("found unexpected pattern: %s", config.NotExpected)
        }
        if config.ExpectedRegex != "" {
            re := regexp.MustCompile(config.ExpectedRegex)
            if re.MatchString(output) {
                result.Status = "pass"
            } else {
                result.Status = "fail"
                result.Expected = config.ExpectedRegex
            }
        }

    case "file_perm":
        result.Expected = fmt.Sprintf("owner=%s group=%s perm=%s", config.FileOwner, config.FileGroup, config.FilePermission)
        // 解析 stat 输出并对比
        result.Status = c.evaluateFilePermission(output, config)

    case "file_content":
        if config.Contains != "" {
            if strings.Contains(output, config.Contains) {
                result.Status = "pass"
            } else {
                result.Status = "fail"
                result.Expected = fmt.Sprintf("should contain: %s", config.Contains)
            }
        }
    }

    if result.Status == "" {
        result.Status = "pass"
    }

    return result
}
```

### 5.2 批量检查调度

```go
type ComplianceScan struct {
    ID          string            `json:"id" gorm:"primaryKey"`
    FrameworkID string            `json:"framework_id" gorm:"index"`
    TargetID    string            `json:"target_id" gorm:"index"`
    Status      string            `json:"status"`     // pending, running, completed, failed
    TotalRules  int               `json:"total_rules"`
    PassCount   int               `json:"pass_count"`
    FailCount   int               `json:"fail_count"`
    ErrorCount  int               `json:"error_count"`
    SkipCount   int               `json:"skip_count"`
    Score       float64           `json:"score"`       // 0~100
    Grade       string            `json:"grade"`       // A, B, C, D, F
    StartedAt   time.Time         `json:"started_at"`
    FinishedAt  time.Time         `json:"finished_at"`
    CreatedAt   time.Time         `json:"created_at"`
}

func (c *ComplianceChecker) RunScan(ctx context.Context, scan *ComplianceScan) error {
    rules, err := c.loadRules(scan.FrameworkID)
    if err != nil {
        return err
    }

    scan.TotalRules = len(rules)
    scan.Status = "running"

    sem := make(chan struct{}, 10) // 并发度控制
    var mu sync.Mutex
    var results []*CheckResult

    var wg sync.WaitGroup
    for _, rule := range rules {
        wg.Add(1)
        go func(r *ComplianceRule) {
            defer wg.Done()

            sem <- struct{}{}
            defer func() { <-sem }()

            result, err := c.Check(ctx, r)
            if err != nil {
                result = &CheckResult{RuleID: r.ID, Status: "error", Message: err.Error()}
            }

            mu.Lock()
            results = append(results, result)
            switch result.Status {
            case "pass":
                scan.PassCount++
            case "fail":
                scan.FailCount++
            case "error":
                scan.ErrorCount++
            case "skip", "not_applicable":
                scan.SkipCount++
            }
            mu.Unlock()
        }(rule)
    }

    wg.Wait()

    // 计算合规评分
    applicable := scan.TotalRules - scan.SkipCount
    if applicable > 0 {
        scan.Score = float64(scan.PassCount) / float64(applicable) * 100
    }
    scan.Grade = scoreToGrade(scan.Score)
    scan.Status = "completed"
    scan.FinishedAt = time.Now()

    return c.saveResults(scan, results)
}

func scoreToGrade(score float64) string {
    switch {
    case score >= 90: return "A"
    case score >= 80: return "B"
    case score >= 70: return "C"
    case score >= 60: return "D"
    default:          return "F"
    }
}
```

## 6. 等保 2.0 专项

### 6.1 等保检查域映射

```
等保 2.0 三级
├── 安全通信网络
│   ├── 网络架构 → 网络拓扑、安全域划分
│   ├── 通信传输 → TLS配置、加密算法
│   └── 可信验证 → 设备可信启动
├── 安全区域边界
│   ├── 边界防护 → 防火墙规则、ACL
│   ├── 访问控制 → 网络访问策略
│   ├── 入侵防范 → IDS/IPS配置
│   └── 恶意代码防范 → 病毒防护
├── 安全计算环境
│   ├── 身份鉴别 → 密码策略、MFA、登录失败锁定
│   ├── 访问控制 → 账户权限、sudo配置、文件权限
│   ├── 安全审计 → 审计日志配置、日志保留
│   ├── 入侵防范 → 补丁管理、最小安装
│   └── 恶意代码防范 → 杀毒软件配置
├── 安全管理中心
│   ├── 系统管理 → 集中管控能力
│   ├── 审计管理 → 集中审计能力
│   └── 安全管理 → 安全策略统一
└── 安全建设管理 / 安全运维管理
    └── (文档/流程类，本系统标记为手动检查)
```

### 6.2 等保合规报告

```go
type DJCPReport struct {
    Level          int                       `json:"level"`          // 等保等级 (2/3)
    OverallScore   float64                   `json:"overall_score"`
    OverallGrade   string                    `json:"overall_grade"`
    Sections       map[string]*SectionResult `json:"sections"`
    HighRiskItems  []*CheckResult            `json:"high_risk_items"`
    Recommendations []string                 `json:"recommendations"`
    GeneratedAt    time.Time                 `json:"generated_at"`
}

type SectionResult struct {
    Name       string   `json:"name"`
    Score      float64  `json:"score"`
    Total      int      `json:"total"`
    Passed     int      `json:"passed"`
    Failed     int      `json:"failed"`
    FailedItems []*CheckResult `json:"failed_items"`
}
```

## 7. CIS Benchmark 自动同步

### 7.1 基线库更新

```go
type BenchmarkUpdater struct {
    sources []BenchmarkSource
}

type BenchmarkSource interface {
    Name() string
    FetchLatest(ctx context.Context) ([]*ComplianceFramework, error)
    FetchRules(ctx context.Context, frameworkID string) ([]*ComplianceRule, error)
}

// CIS 基线源 (从 OVAL/XCCDF 解析)
type CISBenchmarkSource struct {
    baseURL string
}

// 自定义基线: YAML 格式导入
type CustomBenchmarkSource struct {
    directory string
}
```

### 7.2 自定义基线

用户可以创建自定义基线，组合多个标准的规则：

```yaml
# 自定义基线示例: 内部 Web 服务器安全基线
id: "CUSTOM-WEB-001"
name: "内部Web服务器安全基线"
version: "1.0"
target_type: "linux"
description: "适用于公司内部 Web 服务器的安全基线"

rules:
  # 引用 CIS 规则
  - ref: "CIS-Ubuntu-22.04-1.1.1.1"
  - ref: "CIS-Ubuntu-22.04-5.2.1"

  # 自定义规则
  - id: "CUSTOM-WEB-001-01"
    title: "确保 Nginx 隐藏版本号"
    severity: "medium"
    check_type: "command"
    check_config:
      command: "nginx -V 2>&1 | grep 'server_tokens'"
      expected_output: "server_tokens off"
    remediation: "在 nginx.conf 的 http 块中添加: server_tokens off;"

  - id: "CUSTOM-WEB-001-02"
    title: "确保 Web 根目录权限正确"
    severity: "high"
    check_type: "file_perm"
    check_config:
      file_path: "/var/www/html"
      file_owner: "www-data"
      file_group: "www-data"
      file_permission: "0755"
```

## 8. 修复指引与自动修复

### 8.1 修复管理

```go
type RemediationPlan struct {
    ID          string              `json:"id" gorm:"primaryKey"`
    ScanID      string              `json:"scan_id"`
    TargetID    string              `json:"target_id"`
    Items       []*RemediationItem  `json:"items"`
    Priority    string              `json:"priority"`    // critical_first, score_impact, category
    Status      string              `json:"status"`      // draft, approved, executing, completed
    CreatedAt   time.Time           `json:"created_at"`
}

type RemediationItem struct {
    RuleID         string `json:"rule_id"`
    Title          string `json:"title"`
    Severity       string `json:"severity"`
    Steps          string `json:"steps"`          // Markdown 修复步骤
    Script         string `json:"script"`         // 自动修复脚本
    ScoreImpact    float64 `json:"score_impact"`  // 修复后预期分数提升
    AutoFixable    bool   `json:"auto_fixable"`
    Status         string `json:"status"`         // pending, fixed, skipped, verified
    VerifyCommand  string `json:"verify_command"` // 修复后验证命令
}
```

### 8.2 安全的自动修复

```go
type AutoRemediation struct {
    dryRun     bool
    collector  Collector
    backupDir  string
}

func (r *AutoRemediation) Apply(ctx context.Context, item *RemediationItem) (*RemediationResult, error) {
    // 1. 备份当前配置
    backup, err := r.backup(ctx, item)
    if err != nil {
        return nil, fmt.Errorf("backup failed: %w", err)
    }

    // 2. Dry-run 模式 (默认)
    if r.dryRun {
        return &RemediationResult{
            Status:  "dry_run",
            Preview: item.Script,
            Backup:  backup,
        }, nil
    }

    // 3. 执行修复脚本
    result, err := r.collector.Execute(ctx, &CheckConfig{Command: item.Script})
    if err != nil {
        // 回滚
        r.rollback(ctx, backup)
        return nil, fmt.Errorf("remediation failed, rolled back: %w", err)
    }

    // 4. 验证修复效果
    verifyResult, err := r.collector.Execute(ctx, &CheckConfig{Command: item.VerifyCommand})
    if err != nil || verifyResult.ExitCode != 0 {
        r.rollback(ctx, backup)
        return nil, fmt.Errorf("post-fix verification failed, rolled back")
    }

    return &RemediationResult{
        Status:     "fixed",
        Output:     result.RawOutput,
        Verified:   true,
        BackupPath: backup,
    }, nil
}
```

## 9. 合规趋势与对比

### 9.1 历史数据

```go
type ComplianceTrend struct {
    TargetID    string    `json:"target_id"`
    FrameworkID string    `json:"framework_id"`
    Score       float64   `json:"score"`
    PassCount   int       `json:"pass_count"`
    FailCount   int       `json:"fail_count"`
    ScannedAt   time.Time `json:"scanned_at" gorm:"index"`
}
```

### 9.2 对比分析

```go
type ComplianceComparator struct{}

type ComparisonResult struct {
    Improved    []*RuleChange `json:"improved"`    // fail → pass
    Regressed   []*RuleChange `json:"regressed"`   // pass → fail
    Unchanged   int           `json:"unchanged"`
    ScoreDelta  float64       `json:"score_delta"`
}

type RuleChange struct {
    RuleID    string `json:"rule_id"`
    Title     string `json:"title"`
    OldStatus string `json:"old_status"`
    NewStatus string `json:"new_status"`
}

func (c *ComplianceComparator) Compare(previous, current *ComplianceScan) *ComparisonResult {
    // 对比两次扫描结果的差异
    // 识别改善项和退化项
    // 计算分数变化
    return nil
}
```

## 10. API 端点

```
Compliance
├── /api/v1/compliance/frameworks
│   ├── GET    /                     基线框架列表
│   ├── GET    /:id                  框架详情
│   ├── GET    /:id/rules            框架规则列表
│   ├── POST   /import               导入自定义基线 (YAML)
│   └── POST   /sync                 同步官方基线更新
├── /api/v1/compliance/scans
│   ├── POST   /                     创建合规扫描
│   │   Body: { framework_id, target, credential, options }
│   ├── GET    /                     扫描记录列表
│   ├── GET    /:id                  扫描详情 (含所有检查项结果)
│   ├── GET    /:id/results          分页查看检查结果 (筛选: status/severity/category)
│   ├── GET    /:id/report           合规报告 (PDF/HTML/JSON)
│   └── GET    /:id/compare/:other   两次扫描对比
├── /api/v1/compliance/remediation
│   ├── POST   /plan                 生成修复计划
│   ├── GET    /plan/:id             修复计划详情
│   ├── POST   /plan/:id/apply       执行自动修复 (需确认)
│   ├── POST   /plan/:id/verify      验证修复效果
│   └── PUT    /plan/:id/items/:rid  更新修复项状态
├── /api/v1/compliance/dashboard
│   ├── GET    /overview              合规总览 (各框架评分分布)
│   ├── GET    /trend                 评分趋势
│   ├── GET    /gap-analysis          差距分析 (不合规项按严重度分布)
│   └── GET    /targets               各目标合规状态
└── /api/v1/compliance/custom-rules
    ├── POST   /                     创建自定义规则
    ├── GET    /                     自定义规则列表
    ├── PUT    /:id                  更新自定义规则
    ├── DELETE /:id                  删除自定义规则
    └── POST   /:id/test             测试自定义规则
```

## 11. 配置

```yaml
compliance:
  scan:
    default_concurrency: 10
    command_timeout: "30s"
    connect_timeout: "10s"
    retry_count: 2

  collectors:
    ssh:
      key_path: "/etc/scanner/ssh_key"
      known_hosts: "/etc/scanner/known_hosts"
      max_sessions: 5
    winrm:
      use_https: true
      insecure_skip_verify: false

  remediation:
    dry_run_default: true
    auto_backup: true
    backup_retention: "30d"
    require_approval: true       # 自动修复需管理员审批

  reporting:
    default_format: "html"
    include_evidence: true
    logo_path: ""
    company_name: ""

  scheduling:
    full_scan_cron: "0 2 * * 0"   # 每周日凌晨2点
    drift_check_cron: "0 */6 * * *"  # 每6小时配置漂移检测
```
