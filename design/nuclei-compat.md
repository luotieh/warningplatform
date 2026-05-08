# 漏洞扫描系统 — Nuclei 模板兼容层设计

## 1. 设计目标

| 目标 | 说明 |
|------|------|
| 兼容 Nuclei YAML 模板 | 直接加载 nuclei-templates 仓库中的 YAML PoC，无需改写 |
| 指纹库兼容 | 兼容 Nuclei 的指纹匹配机制 |
| 自有扩展 | 在兼容基础上扩展自有 DSL 能力（如数据库协议探测） |
| 无外部依赖 | 不调用 nuclei 二进制，纯 Go 实现解析和执行 |

## 2. Nuclei 模板结构解析

### 2.1 模板格式 (Nuclei v3)

```yaml
id: CVE-2021-41773

info:
  name: Apache HTTP Server 2.4.49 - Path Traversal
  author: madrobot
  severity: critical
  description: ...
  reference:
    - https://nvd.nist.gov/vuln/detail/CVE-2021-41773
  classification:
    cvss-metrics: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
    cvss-score: 7.5
    cve-id: CVE-2021-41773
    cwe-id: CWE-22
  tags: apache,rce,lfi,kev
  metadata:
    max-request: 2
    shodan-query: "Apache/2.4.49"
    fofa-query: server="Apache/2.4.49"

http:
  - raw:
      - |
        GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
        Host: {{Hostname}}

    matchers-condition: and
    matchers:
      - type: regex
        regex:
          - "root:.*:0:0:"
      - type: status
        status:
          - 200

    extractors:
      - type: regex
        name: content
        regex:
          - "root:.*:0:0:.*"
```

### 2.2 兼容范围

| Nuclei 特性 | 兼容状态 | 说明 |
|-------------|----------|------|
| `http` 协议 | ✅ 完全 | 支持 raw、method/path/body、多步骤请求 |
| `dns` 协议 | ✅ 完全 | DNS 查询探测 |
| `tcp` 协议 | ✅ 完全 | TCP 原始数据发送/接收 |
| `file` 协议 | ✅ 完全 | 本地文件匹配（用于主机扫描） |
| `headless` 协议 | ⚠️ 部分 | 需 chromedp，标记为可选依赖 |
| `code` 协议 | ❌ 不兼容 | Nuclei v3 的 Go code 执行，安全风险过高 |
| `javascript` 协议 | ⚠️ 部分 | 基于 goja 执行简单 JS |
| `ssl` 协议 | ✅ 完全 | TLS 证书/密码套件检查 |
| matchers | ✅ 完全 | status, word, regex, binary, dsl, size |
| extractors | ✅ 完全 | regex, kval, json, xpath, dsl |
| `{{Variables}}` | ✅ 完全 | 内置变量 + 提取变量 |
| `matchers-condition` | ✅ 完全 | and / or |
| `flow` 多步骤 | ✅ 完全 | 请求链、条件跳转 |
| `payloads` | ✅ 完全 | 字典注入 |
| CEL 表达式 | ✅ 完全 | 使用 `github.com/google/cel-go` |
| `stop-at-first-match` | ✅ | - |
| `self-contained` | ✅ | 不需要目标 URL 的独立模板 |
| 模板签名校验 | ⚠️ 可选 | 社区模板签名验证 |

## 3. 兼容层架构

```
┌────────────────────────────────────────────────────────┐
│                    Plugin Executor                       │
│                                                         │
│   ┌──────────────────────────────────────────────┐     │
│   │  模板加载器 (TemplateLoader)                   │     │
│   │                                              │     │
│   │  ┌─────────────┐  ┌─────────────────────┐  │     │
│   │  │ Nuclei YAML │  │ 自研扩展 YAML        │  │     │
│   │  │ Parser      │  │ Parser               │  │     │
│   │  │             │  │ (兼容 Nuclei +       │  │     │
│   │  │ 完整兼容    │  │  额外字段扩展)        │  │     │
│   │  └──────┬──────┘  └──────────┬──────────┘  │     │
│   │         │                     │              │     │
│   │         └──────────┬──────────┘              │     │
│   │                    ▼                          │     │
│   │         ┌─────────────────┐                  │     │
│   │         │ Unified Template │  ← 统一内部表示  │     │
│   │         │ (Go Struct)      │                  │     │
│   │         └────────┬────────┘                  │     │
│   └──────────────────┼───────────────────────────┘     │
│                      │                                  │
│   ┌──────────────────▼───────────────────────────┐     │
│   │  执行引擎 (ExecutionEngine)                    │     │
│   │                                              │     │
│   │  ┌──────┐ ┌──────┐ ┌──────┐ ┌──────────┐  │     │
│   │  │ HTTP │ │ TCP  │ │ DNS  │ │ SSL/TLS  │  │     │
│   │  │ Exec │ │ Exec │ │ Exec │ │ Exec     │  │     │
│   │  └──────┘ └──────┘ └──────┘ └──────────┘  │     │
│   │                                              │     │
│   │  ┌──────────────┐  ┌──────────────────────┐ │     │
│   │  │ Matcher      │  │ Extractor Engine     │ │     │
│   │  │ Engine       │  │                      │ │     │
│   │  │ (status,word,│  │ (regex,json,kval,   │ │     │
│   │  │  regex,dsl)  │  │  xpath,dsl)          │ │     │
│   │  └──────────────┘  └──────────────────────┘ │     │
│   │                                              │     │
│   │  ┌──────────────────────────────────────┐   │     │
│   │  │  DSL / CEL 表达式引擎                  │   │     │
│   │  │  github.com/google/cel-go             │   │     │
│   │  └──────────────────────────────────────┘   │     │
│   └──────────────────────────────────────────────┘     │
└────────────────────────────────────────────────────────┘
```

## 4. 核心数据结构

```go
// UnifiedTemplate 统一模板（兼容 Nuclei + 自研扩展）
type UnifiedTemplate struct {
    // === Nuclei 标准字段 ===
    ID   string       `yaml:"id"`
    Info TemplateInfo `yaml:"info"`

    // 协议请求
    HTTP       []HTTPRequest  `yaml:"http"`
    TCP        []TCPRequest   `yaml:"tcp"`
    DNS        []DNSRequest   `yaml:"dns"`
    SSL        []SSLRequest   `yaml:"ssl"`
    File       []FileRequest  `yaml:"file"`
    Headless   []HeadlessReq  `yaml:"headless"`

    // 多步骤流控
    Flow       string         `yaml:"flow"`
    Variables  map[string]any `yaml:"variables"`

    // Nuclei 辅助字段
    SelfContained    bool   `yaml:"self-contained"`
    StopAtFirstMatch bool   `yaml:"stop-at-first-match"`

    // === 自研扩展字段 ===
    Match    []FingerprintMatch `yaml:"match"`     // 前置指纹匹配
    Metadata ExtendedMetadata   `yaml:"x-metadata"` // 扩展元数据
}

type TemplateInfo struct {
    Name           string            `yaml:"name"`
    Author         string            `yaml:"author"`
    Severity       string            `yaml:"severity"`
    Description    string            `yaml:"description"`
    Reference      []string          `yaml:"reference"`
    Classification Classification    `yaml:"classification"`
    Tags           string            `yaml:"tags"` // 逗号分隔
    Metadata       map[string]string `yaml:"metadata"`
    Remediation    string            `yaml:"remediation"`
}

type Classification struct {
    CVSSMetrics string  `yaml:"cvss-metrics"`
    CVSSScore   float64 `yaml:"cvss-score"`
    CVEID       string  `yaml:"cve-id"`
    CWEID       string  `yaml:"cwe-id"`
}

// HTTPRequest 兼容 Nuclei HTTP 请求格式
type HTTPRequest struct {
    // 标准模式
    Method  string            `yaml:"method"`
    Path    []string          `yaml:"path"`
    Headers map[string]string `yaml:"headers"`
    Body    string            `yaml:"body"`

    // Raw 模式（优先）
    Raw []string `yaml:"raw"`

    // Payload 注入
    Payloads      map[string]interface{} `yaml:"payloads"`
    AttackType    string                  `yaml:"attack"` // batteringram, pitchfork, clusterbomb

    // 请求选项
    MaxRedirects    int  `yaml:"max-redirects"`
    FollowRedirects bool `yaml:"redirects"`
    CookieReuse     bool `yaml:"cookie-reuse"`

    // 匹配 & 提取
    MatchersCondition string      `yaml:"matchers-condition"` // and / or
    Matchers          []Matcher   `yaml:"matchers"`
    Extractors        []Extractor `yaml:"extractors"`
}

type Matcher struct {
    Type      string   `yaml:"type"`      // status, word, regex, binary, size, dsl
    Words     []string `yaml:"words"`
    Regex     []string `yaml:"regex"`
    Binary    []string `yaml:"binary"`
    Status    []int    `yaml:"status"`
    DSL       []string `yaml:"dsl"`
    Size      []int    `yaml:"size"`
    Part      string   `yaml:"part"`      // body, header, all, response
    Negative  bool     `yaml:"negative"`
    Condition string   `yaml:"condition"` // and / or
    Internal  bool     `yaml:"internal"`
}

type Extractor struct {
    Type    string   `yaml:"type"`    // regex, kval, json, xpath, dsl
    Name    string   `yaml:"name"`
    Regex   []string `yaml:"regex"`
    KVal    []string `yaml:"kval"`
    JSON    []string `yaml:"json"`
    XPath   []string `yaml:"xpath"`
    DSL     []string `yaml:"dsl"`
    Part    string   `yaml:"part"`
    Group   int      `yaml:"group"`
    Internal bool    `yaml:"internal"`
}
```

## 5. Nuclei 模板同步

```go
type NucleiTemplateSyncer struct {
    repoURL   string // https://github.com/projectdiscovery/nuclei-templates
    localDir  string // ./plugins/nuclei-templates/
    db        TemplateStore
}

func (s *NucleiTemplateSyncer) Sync(ctx context.Context) error {
    // 1. Git clone/pull 最新模板
    // 2. 解析所有 YAML 文件
    // 3. 入库（去重、索引）
    // 4. 更新版本号
}

// 目录结构（与 nuclei-templates 保持一致）
// plugins/nuclei-templates/
// ├── cves/
// │   ├── 2024/
// │   │   ├── CVE-2024-XXXX.yaml
// │   │   └── ...
// │   ├── 2023/
// │   └── ...
// ├── vulnerabilities/
// ├── misconfiguration/
// ├── exposures/
// ├── technologies/
// ├── default-logins/
// ├── file/
// ├── network/
// └── ssl/
```

## 6. 指纹→PoC 自动关联

```go
// FingerprintPoCLinker 基于指纹匹配自动选择 PoC
type FingerprintPoCLinker struct {
    templates []UnifiedTemplate
    tagIndex  map[string][]int     // tag → template indices
    cpeIndex  map[string][]int     // cpe_prefix → template indices
    nameIndex map[string][]int     // product_name → template indices
}

func (l *FingerprintPoCLinker) FindMatchingPoCs(fingerprints []Fingerprint) []UnifiedTemplate {
    candidates := make(map[int]bool)

    for _, fp := range fingerprints {
        // 1. 按产品名称匹配 tags
        tags := productToTags(fp.Product)
        for _, tag := range tags {
            for _, idx := range l.tagIndex[tag] {
                candidates[idx] = true
            }
        }

        // 2. 按 CPE 匹配（如果有 classification.cve-id）
        if fp.CPE != "" {
            prefix := extractCPEPrefix(fp.CPE) // cpe:/a:apache:http_server
            for _, idx := range l.cpeIndex[prefix] {
                t := l.templates[idx]
                if versionInRange(fp.Version, t) {
                    candidates[idx] = true
                }
            }
        }

        // 3. 按 match 字段精确匹配（自研扩展模板）
        for i, t := range l.templates {
            if matchFingerprint(fp, t.Match) {
                candidates[i] = true
            }
        }
    }

    var result []UnifiedTemplate
    for idx := range candidates {
        result = append(result, l.templates[idx])
    }

    // 按严重程度排序：critical > high > medium > low
    sort.Slice(result, func(i, j int) bool {
        return severityOrder(result[i].Info.Severity) > severityOrder(result[j].Info.Severity)
    })

    return result
}

func productToTags(product string) []string {
    m := map[string][]string{
        "Apache HTTP Server": {"apache", "httpd"},
        "Nginx":             {"nginx"},
        "WordPress":         {"wordpress", "wp"},
        "Spring Boot":       {"spring", "springboot"},
        "Tomcat":            {"tomcat"},
        "Jenkins":           {"jenkins"},
        "GitLab":            {"gitlab"},
        // ... 常见产品名→tag映射
    }
    product = strings.ToLower(product)
    for name, tags := range m {
        if strings.Contains(strings.ToLower(name), product) {
            return tags
        }
    }
    return []string{strings.ToLower(strings.ReplaceAll(product, " ", "-"))}
}
```

## 7. DSL / CEL 表达式引擎

```go
import "github.com/google/cel-go/cel"

type DSLEngine struct {
    env *cel.Env
}

func NewDSLEngine() *DSLEngine {
    env, _ := cel.NewEnv(
        cel.Variable("body", cel.StringType),
        cel.Variable("header", cel.StringType),
        cel.Variable("status_code", cel.IntType),
        cel.Variable("content_length", cel.IntType),
        cel.Variable("content_type", cel.StringType),
        cel.Variable("all_headers", cel.MapType(cel.StringType, cel.StringType)),
        // Nuclei 内置函数
        cel.Function("contains", ...),
        cel.Function("regex", ...),
        cel.Function("md5", ...),
        cel.Function("sha256", ...),
        cel.Function("base64", ...),
        cel.Function("url_decode", ...),
        cel.Function("html_escape", ...),
        cel.Function("to_lower", ...),
        cel.Function("to_upper", ...),
        cel.Function("len", ...),
    )
    return &DSLEngine{env: env}
}

// Evaluate 执行 DSL 表达式
func (e *DSLEngine) Evaluate(expr string, vars map[string]interface{}) (bool, error) {
    ast, issues := e.env.Compile(expr)
    if issues != nil && issues.Err() != nil {
        return false, issues.Err()
    }
    prg, err := e.env.Program(ast)
    if err != nil {
        return false, err
    }
    out, _, err := prg.Eval(vars)
    if err != nil {
        return false, err
    }
    return out.Value().(bool), nil
}
```

## 8. 自研 PoC 扩展字段

在兼容 Nuclei 的基础上，自研模板可额外包含以下字段：

```yaml
id: custom-poc-001

info:
  name: "Custom Detection"
  severity: high

# === 自研扩展 ===

# 前置指纹匹配（比 Nuclei tags 更精确）
match:
  - type: fingerprint
    product: "Apache Tomcat"
    version: ">=9.0, <9.0.62"
    category: webserver
  - type: port
    ports: [8080, 8443]

# 扩展元数据
x-metadata:
  cpe: "cpe:/a:apache:tomcat"
  cnvd_id: "CNVD-2022-XXXXX"
  affected_versions: "9.0.0 ~ 9.0.61"
  fix_version: "9.0.62"
  fix_url: "https://tomcat.apache.org/security-9.html"
  risk_level: "high"   # 与 severity 区分，可能有合规等级
  compliance:          # 合规映射
    - "等保三级-7.1.4"
    - "OWASP-A06:2021"

# 标准 Nuclei HTTP 检测（完全兼容）
http:
  - method: GET
    path:
      - "{{BaseURL}}/.env"
    matchers:
      - type: word
        words:
          - "DB_PASSWORD"
          - "APP_KEY"
        condition: or
```
