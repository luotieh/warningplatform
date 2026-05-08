# API 安全专项检测设计

## 1. 概述

现代应用普遍采用 API 驱动架构（REST/GraphQL/gRPC），API 安全已成为攻击面的主要暴露点。本模块目标：**从 API 定义文档出发，自动化发现 API 安全风险**，覆盖 OWASP API Security Top 10。

### OWASP API Security Top 10 (2023) 覆盖

| # | 风险 | 模块覆盖 |
|---|------|---------|
| API1 | 对象级授权失效 (BOLA/IDOR) | ✅ IDOR 检测 |
| API2 | 认证失效 | ✅ 认证检测 |
| API3 | 对象属性级授权失效 | ✅ 批量赋值/过度暴露 |
| API4 | 不受限的资源消耗 | ✅ 速率限制检测 |
| API5 | 功能级授权失效 | ✅ 权限绕过检测 |
| API6 | 服务端请求伪造 (SSRF) | ✅ (modules.md 已有) |
| API7 | 安全配置错误 | ✅ 配置检测 |
| API8 | 缺乏对自动化威胁的防护 | ✅ 速率限制/反自动化 |
| API9 | 资产管理不当 | ✅ 影子API/版本检测 |
| API10 | 不安全的 API 消费 | ✅ 第三方集成检测 |

## 2. 架构

```
┌──────────────────────────────────────────────────────────────┐
│                    API Security Scanner                       │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────────┐ │
│  │ API 发现    │  │  规范解析器   │  │ 测试用例生成器       │ │
│  │             │  │              │  │                     │ │
│  │ · 爬虫提取  │→│ · OpenAPI 3  │→│ · OWASP API Top10  │ │
│  │ · 流量分析  │  │ · Swagger 2  │  │ · 自定义规则       │ │
│  │ · 文档导入  │  │ · GraphQL    │  │ · Fuzzing策略      │ │
│  │ · HAR导入   │  │ · Postman    │  │                     │ │
│  └─────────────┘  │ · gRPC proto │  └──────────┬──────────┘ │
│                   └──────────────┘             │            │
│                                                ↓            │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  执行引擎                              │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │   │
│  │  │ 认证管理 │  │ 参数变异 │  │ 响应分析/判定    │   │   │
│  │  │          │  │          │  │                  │   │   │
│  │  │ Token    │  │ SQLi     │  │ 状态码对比      │   │   │
│  │  │ Cookie   │  │ XSS      │  │ 响应体Diff      │   │   │
│  │  │ API Key  │  │ IDOR     │  │ 时间差异        │   │   │
│  │  │ mTLS     │  │ Type     │  │ 错误信息匹配    │   │   │
│  │  │ OAuth2   │  │ Boundary │  │ 业务逻辑判定    │   │   │
│  │  └──────────┘  └──────────┘  └──────────────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           ↓                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              结果汇总 & 报告                          │   │
│  └──────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────┘
```

## 3. API 发现

### 3.1 发现来源

```go
type APIDiscoverer interface {
    Name() string
    Discover(ctx context.Context, target string) ([]*APIEndpoint, error)
}

type APIEndpoint struct {
    Method      string            `json:"method"`       // GET, POST, PUT, DELETE, PATCH
    Path        string            `json:"path"`         // /api/v1/users/{id}
    Summary     string            `json:"summary"`
    Parameters  []APIParameter    `json:"parameters"`
    RequestBody *APIRequestBody   `json:"request_body"`
    Responses   map[string]*APIResponse `json:"responses"`
    Security    []SecurityScheme  `json:"security"`
    Tags        []string          `json:"tags"`
    Source      string            `json:"source"`       // openapi, crawl, traffic, har
}
```

### 3.2 OpenAPI/Swagger 解析

```go
type OpenAPIParser struct{}

func (p *OpenAPIParser) Parse(ctx context.Context, source string) (*APISpec, error) {
    // 支持 URL 或本地文件
    data, err := fetchSpec(ctx, source)
    if err != nil {
        return nil, err
    }

    // 自动检测版本
    version := detectVersion(data)

    switch {
    case strings.HasPrefix(version, "3"):
        return p.parseOpenAPI3(data)
    case strings.HasPrefix(version, "2"):
        return p.parseSwagger2(data)
    default:
        return nil, fmt.Errorf("unsupported spec version: %s", version)
    }
}
```

### 3.3 智能 API 端点爬取

对于没有规范文档的目标，通过爬虫和流量分析发现 API：

```go
type APICrawler struct {
    maxDepth    int
    maxPages    int
    jsAnalyzer  *JSEndpointExtractor
}

func (c *APICrawler) Discover(ctx context.Context, baseURL string) ([]*APIEndpoint, error) {
    var endpoints []*APIEndpoint

    // 1. 常见路径探测
    commonPaths := []string{
        "/swagger.json", "/swagger/v1/swagger.json",
        "/openapi.json", "/api-docs",
        "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
        "/graphql", "/.well-known/openapi.json",
        "/docs", "/redoc",
    }

    // 2. HTML 爬取 + JS 分析
    // 从页面 JS 中提取 fetch/axios/XMLHttpRequest 的 URL 模式
    jsEndpoints := c.jsAnalyzer.ExtractFromJS(ctx, baseURL)

    // 3. 响应头分析
    // 检查 Link header, X-API-Version 等
    headerEndpoints := c.analyzeHeaders(ctx, baseURL)

    // 4. 去重合并
    endpoints = mergeAndDedup(commonPaths, jsEndpoints, headerEndpoints)

    return endpoints, nil
}
```

### 3.4 GraphQL 自省

```go
type GraphQLIntrospector struct{}

func (g *GraphQLIntrospector) Discover(ctx context.Context, endpoint string) ([]*APIEndpoint, error) {
    // 自省查询
    introspectionQuery := `{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name args { name type { name kind ofType { name } } } type { name kind ofType { name } } } } } }"}`

    resp, err := httpPost(ctx, endpoint, introspectionQuery)
    if err != nil {
        return nil, err
    }

    // 如果自省被禁用，尝试字段建议 (Field Suggestion)
    if isIntrospectionDisabled(resp) {
        return g.discoverByFieldSuggestion(ctx, endpoint)
    }

    return g.parseIntrospectionResult(resp)
}
```

## 4. 测试用例生成

### 4.1 测试生成策略

```go
type TestGenerator interface {
    Name() string
    Category() string       // owasp_api_top10, injection, business_logic
    Generate(endpoint *APIEndpoint, auth *AuthContext) []*TestCase
}

type TestCase struct {
    ID          string            `json:"id"`
    Name        string            `json:"name"`
    Category    string            `json:"category"`
    Endpoint    *APIEndpoint      `json:"endpoint"`
    Method      string            `json:"method"`
    Path        string            `json:"path"`
    Headers     map[string]string `json:"headers"`
    QueryParams map[string]string `json:"query_params"`
    Body        interface{}       `json:"body"`
    AuthContext *AuthContext       `json:"auth_context"`
    Assertion   *Assertion        `json:"assertion"`
    Severity    string            `json:"severity"`
}

type Assertion struct {
    Type         string `json:"type"`          // status_code, body_contains, body_not_contains, response_time, header_exists
    Operator     string `json:"operator"`      // eq, ne, gt, lt, contains, matches
    Expected     string `json:"expected"`
    Description  string `json:"description"`
}
```

### 4.2 BOLA/IDOR 检测

```go
type BOLAGenerator struct{}

func (g *BOLAGenerator) Generate(endpoint *APIEndpoint, auth *AuthContext) []*TestCase {
    var tests []*TestCase

    // 检测路径中的 ID 参数 (如 /users/{id})
    pathParams := extractPathParams(endpoint.Path)
    for _, param := range pathParams {
        if isIDParam(param) {
            // 测试 1: 使用用户A的token访问用户B的资源
            tests = append(tests, &TestCase{
                Name:     fmt.Sprintf("BOLA: Access other user's %s via %s", endpoint.Path, param.Name),
                Category: "API1:BOLA",
                Method:   endpoint.Method,
                Path:     replaceParam(endpoint.Path, param.Name, "OTHER_USER_RESOURCE_ID"),
                AuthContext: auth,
                Assertion: &Assertion{
                    Type:     "status_code",
                    Operator: "eq",
                    Expected: "403",
                    Description: "Accessing another user's resource should return 403",
                },
                Severity: "high",
            })

            // 测试 2: ID 遍历
            tests = append(tests, &TestCase{
                Name:     fmt.Sprintf("BOLA: Enumerate %s IDs", param.Name),
                Category: "API1:BOLA",
                Method:   endpoint.Method,
                Path:     replaceParam(endpoint.Path, param.Name, "{{iterate:1:100}}"),
                AuthContext: auth,
                Assertion: &Assertion{
                    Type:        "status_code",
                    Operator:    "ne",
                    Expected:    "200",
                    Description: "Sequential ID enumeration should not return 200 for unauthorized resources",
                },
                Severity: "high",
            })
        }
    }

    return tests
}

func isIDParam(param APIParameter) bool {
    name := strings.ToLower(param.Name)
    idPatterns := []string{"id", "uid", "user_id", "account_id", "order_id", "record_id"}
    for _, p := range idPatterns {
        if strings.Contains(name, p) {
            return true
        }
    }
    // 检查参数类型是否为 integer/uuid
    return param.Schema.Type == "integer" || param.Schema.Format == "uuid"
}
```

### 4.3 认证绕过检测

```go
type AuthBypassGenerator struct{}

func (g *AuthBypassGenerator) Generate(endpoint *APIEndpoint, auth *AuthContext) []*TestCase {
    var tests []*TestCase

    if len(endpoint.Security) == 0 {
        // 未声明安全要求的端点本身就是风险
        tests = append(tests, &TestCase{
            Name:     fmt.Sprintf("NoAuth: %s %s has no security requirement", endpoint.Method, endpoint.Path),
            Category: "API2:AUTH",
            Severity: "medium",
        })
        return tests
    }

    // 测试 1: 完全无认证访问
    tests = append(tests, &TestCase{
        Name:     "Auth Bypass: No credentials",
        Category: "API2:AUTH",
        Method:   endpoint.Method,
        Path:     endpoint.Path,
        Headers:  map[string]string{}, // 无 Authorization header
        Assertion: &Assertion{
            Type:     "status_code",
            Operator: "eq",
            Expected: "401",
        },
        Severity: "critical",
    })

    // 测试 2: 过期 Token
    tests = append(tests, &TestCase{
        Name:     "Auth Bypass: Expired token",
        Category: "API2:AUTH",
        Headers:  map[string]string{"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxfQ."},
        Assertion: &Assertion{
            Type:     "status_code",
            Operator: "eq",
            Expected: "401",
        },
        Severity: "critical",
    })

    // 测试 3: JWT alg:none
    tests = append(tests, &TestCase{
        Name:     "Auth Bypass: JWT algorithm none",
        Category: "API2:AUTH",
        Headers:  map[string]string{"Authorization": "Bearer " + craftAlgNoneJWT(auth)},
        Assertion: &Assertion{
            Type:     "status_code",
            Operator: "ne",
            Expected: "200",
        },
        Severity: "critical",
    })

    // 测试 4: HTTP Method 替换 (GET vs POST vs PUT)
    alternativeMethods := []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
    for _, method := range alternativeMethods {
        if method != endpoint.Method {
            tests = append(tests, &TestCase{
                Name:     fmt.Sprintf("Auth Bypass: Method override %s→%s", endpoint.Method, method),
                Category: "API5:FUNC_AUTH",
                Method:   method,
                Path:     endpoint.Path,
                Assertion: &Assertion{
                    Type:     "status_code",
                    Operator: "ne",
                    Expected: "200",
                },
                Severity: "medium",
            })
        }
    }

    return tests
}
```

### 4.4 批量赋值检测

```go
type MassAssignmentGenerator struct{}

func (g *MassAssignmentGenerator) Generate(endpoint *APIEndpoint, auth *AuthContext) []*TestCase {
    var tests []*TestCase

    // 仅检查 POST/PUT/PATCH
    if endpoint.Method != "POST" && endpoint.Method != "PUT" && endpoint.Method != "PATCH" {
        return tests
    }

    if endpoint.RequestBody == nil {
        return tests
    }

    // 在请求体中注入敏感额外字段
    sensitiveFields := []struct {
        Field string
        Value interface{}
    }{
        {"role", "admin"},
        {"is_admin", true},
        {"permissions", []string{"*"}},
        {"verified", true},
        {"balance", 99999},
        {"price", 0},
        {"discount", 100},
        {"status", "approved"},
    }

    for _, sf := range sensitiveFields {
        body := cloneRequestBody(endpoint.RequestBody.Example)
        body[sf.Field] = sf.Value

        tests = append(tests, &TestCase{
            Name:     fmt.Sprintf("Mass Assignment: inject %s=%v", sf.Field, sf.Value),
            Category: "API3:PROPERTY",
            Method:   endpoint.Method,
            Path:     endpoint.Path,
            Body:     body,
            AuthContext: auth,
            Assertion: &Assertion{
                Type:        "body_not_contains",
                Operator:    "ne",
                Expected:    fmt.Sprintf("%v", sf.Value),
                Description: fmt.Sprintf("Response should not reflect injected %s", sf.Field),
            },
            Severity: "high",
        })
    }

    return tests
}
```

### 4.5 速率限制检测

```go
type RateLimitGenerator struct{}

func (g *RateLimitGenerator) Generate(endpoint *APIEndpoint, auth *AuthContext) []*TestCase {
    return []*TestCase{
        {
            Name:     fmt.Sprintf("Rate Limit: Burst %d requests", 100),
            Category: "API4:RATE_LIMIT",
            Method:   endpoint.Method,
            Path:     endpoint.Path,
            AuthContext: auth,
            Assertion: &Assertion{
                Type:        "status_code",
                Operator:    "eq",
                Expected:    "429",
                Description: "Should return 429 after burst requests",
            },
            Severity: "medium",
        },
    }
}
```

## 5. 参数变异引擎

### 5.1 变异策略

```go
type MutationEngine struct {
    strategies []MutationStrategy
}

type MutationStrategy interface {
    Name() string
    Mutate(param *APIParameter, original interface{}) []interface{}
}

// 内置变异策略
type SQLInjectionMutation struct{}     // ' OR 1=1 --, UNION SELECT ...
type XSSMutation struct{}              // <script>alert(1)</script>, onerror=...
type TypeConfusionMutation struct{}    // string→int, int→array, null
type BoundaryMutation struct{}         // MAX_INT, 0, -1, 超长字符串
type FormatStringMutation struct{}     // %s, %x, {{template}}
type PathTraversalMutation struct{}    // ../../../etc/passwd
type UnicodeBypassMutation struct{}    // 利用Unicode正规化绕过过滤
type JSONInjectionMutation struct{}    // 嵌套JSON, 数组注入
```

### 5.2 智能参数推断

根据参数名、类型、示例值自动选择最佳变异策略：

```go
func (e *MutationEngine) SelectStrategies(param *APIParameter) []MutationStrategy {
    var strategies []MutationStrategy

    name := strings.ToLower(param.Name)

    // 基于参数名推断
    switch {
    case containsAny(name, "id", "uid", "user_id"):
        strategies = append(strategies, &IDORMutation{})
    case containsAny(name, "url", "uri", "link", "redirect", "callback"):
        strategies = append(strategies, &SSRFMutation{}, &OpenRedirectMutation{})
    case containsAny(name, "file", "path", "filename", "upload"):
        strategies = append(strategies, &PathTraversalMutation{}, &FileUploadMutation{})
    case containsAny(name, "query", "search", "q", "keyword", "filter"):
        strategies = append(strategies, &SQLInjectionMutation{}, &NoSQLInjectionMutation{})
    case containsAny(name, "email", "name", "comment", "message", "title"):
        strategies = append(strategies, &XSSMutation{})
    case containsAny(name, "cmd", "command", "exec", "run"):
        strategies = append(strategies, &CommandInjectionMutation{})
    }

    // 基于类型
    switch param.Schema.Type {
    case "integer", "number":
        strategies = append(strategies, &BoundaryMutation{}, &TypeConfusionMutation{})
    case "string":
        strategies = append(strategies, &SQLInjectionMutation{}, &XSSMutation{}, &FormatStringMutation{})
    case "array":
        strategies = append(strategies, &ArrayOverflowMutation{})
    }

    // 所有参数都进行通用变异
    strategies = append(strategies, &TypeConfusionMutation{}, &BoundaryMutation{})

    return dedupStrategies(strategies)
}
```

## 6. 认证上下文管理

### 6.1 多角色认证

API 安全测试需要多个角色的凭据来验证授权逻辑：

```go
type AuthManager struct {
    contexts map[string]*AuthContext
}

type AuthContext struct {
    Name     string            `json:"name"`      // admin, user, viewer, anonymous
    Type     string            `json:"type"`       // bearer, basic, api_key, cookie, oauth2
    Token    string            `json:"token"`
    Headers  map[string]string `json:"headers"`
    Cookies  []*http.Cookie    `json:"cookies"`
    UserID   string            `json:"user_id"`
    Roles    []string          `json:"roles"`
}

func (m *AuthManager) GetContextPairs() [][2]*AuthContext {
    // 返回所有权限对 (高权限, 低权限) 用于越权测试
    // (admin, user), (admin, viewer), (user, viewer), (user, anonymous)
    var pairs [][2]*AuthContext
    sorted := m.sortByPrivilege()
    for i := 0; i < len(sorted); i++ {
        for j := i + 1; j < len(sorted); j++ {
            pairs = append(pairs, [2]*AuthContext{sorted[i], sorted[j]})
        }
    }
    return pairs
}
```

### 6.2 自动认证流程

```go
type AuthFlow interface {
    Name() string
    Authenticate(ctx context.Context, config *AuthConfig) (*AuthContext, error)
    Refresh(ctx context.Context, current *AuthContext) (*AuthContext, error)
}

type BearerTokenFlow struct{}     // Authorization: Bearer <token>
type BasicAuthFlow struct{}       // Authorization: Basic <base64>
type APIKeyFlow struct{}          // X-API-Key: <key> 或 ?api_key=<key>
type OAuth2Flow struct{}          // OAuth2 授权码/客户端凭据流程
type CookieSessionFlow struct{}   // 登录获取 session cookie
```

## 7. 响应分析

### 7.1 差异分析器

通过对比不同认证上下文的响应来判定漏洞：

```go
type ResponseAnalyzer struct{}

type AnalysisResult struct {
    IsVulnerable bool     `json:"is_vulnerable"`
    Confidence   float64  `json:"confidence"` // 0~1
    Evidence     []string `json:"evidence"`
    Category     string   `json:"category"`
}

func (a *ResponseAnalyzer) Analyze(
    baseline *http.Response,
    testResp *http.Response,
    testCase *TestCase,
) *AnalysisResult {
    result := &AnalysisResult{}

    // 1. 状态码分析
    if testCase.Assertion != nil {
        result.IsVulnerable = a.checkAssertion(testResp, testCase.Assertion)
    }

    // 2. 响应体差异分析 (用于 BOLA/越权)
    if baseline != nil {
        similarity := a.bodySimilarity(baseline.Body, testResp.Body)
        if similarity > 0.8 && testResp.StatusCode == 200 {
            result.IsVulnerable = true
            result.Confidence = similarity
            result.Evidence = append(result.Evidence,
                fmt.Sprintf("Response similarity %.0f%% suggests unauthorized access", similarity*100))
        }
    }

    // 3. 敏感信息检测
    sensitivePatterns := a.detectSensitiveData(testResp.Body)
    if len(sensitivePatterns) > 0 {
        result.Evidence = append(result.Evidence,
            fmt.Sprintf("Sensitive data in response: %v", sensitivePatterns))
    }

    // 4. 错误信息泄露
    errorLeaks := a.detectErrorLeaks(testResp.Body)
    if len(errorLeaks) > 0 {
        result.Evidence = append(result.Evidence,
            fmt.Sprintf("Error information leak: %v", errorLeaks))
    }

    return result
}
```

### 7.2 敏感数据检测模式

```go
var sensitivePatterns = []SensitivePattern{
    {Name: "JWT Token",      Pattern: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`},
    {Name: "API Key",        Pattern: `(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}`},
    {Name: "Password Hash",  Pattern: `\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}`},   // bcrypt
    {Name: "Private Key",    Pattern: `-----BEGIN (RSA |EC )?PRIVATE KEY-----`},
    {Name: "AWS Key",        Pattern: `AKIA[0-9A-Z]{16}`},
    {Name: "Email",          Pattern: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`},
    {Name: "Phone (CN)",     Pattern: `1[3-9]\d{9}`},
    {Name: "ID Card (CN)",   Pattern: `[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]`},
    {Name: "Stack Trace",    Pattern: `(?i)(traceback|stack.?trace|at .+\(.+:\d+\))`},
    {Name: "SQL Error",      Pattern: `(?i)(syntax error|mysql|postgresql|ORA-\d+|SQLSTATE)`},
    {Name: "Internal Path",  Pattern: `(?i)(/usr/|/var/|/home/|/opt/|C:\\|D:\\)[\w/\\.-]+`},
}
```

## 8. 影子 API 检测

发现未在规范文档中声明但实际存在的 API 端点：

```go
type ShadowAPIDetector struct {
    knownEndpoints map[string]bool
}

func (d *ShadowAPIDetector) Detect(ctx context.Context, baseURL string, spec *APISpec) ([]*ShadowAPI, error) {
    var shadows []*ShadowAPI

    // 1. 版本枚举: /api/v1/ → /api/v2/, /api/v3/, /api/beta/
    versionShadows := d.enumerateVersions(ctx, baseURL, spec)
    shadows = append(shadows, versionShadows...)

    // 2. 调试端点: /debug/, /metrics, /health, /actuator/
    debugShadows := d.probeDebugEndpoints(ctx, baseURL)
    shadows = append(shadows, debugShadows...)

    // 3. 管理端点: /admin/, /internal/, /management/
    adminShadows := d.probeAdminEndpoints(ctx, baseURL)
    shadows = append(shadows, adminShadows...)

    // 4. 对比文档与实际 (缺失的端点)
    for _, endpoint := range spec.Endpoints {
        d.knownEndpoints[endpoint.Method+" "+endpoint.Path] = true
    }

    // 5. 通过 JS 分析发现的但不在文档中的端点
    jsEndpoints := d.jsAnalyzer.ExtractFromJS(ctx, baseURL)
    for _, ep := range jsEndpoints {
        key := ep.Method + " " + ep.Path
        if !d.knownEndpoints[key] {
            shadows = append(shadows, &ShadowAPI{
                Endpoint: ep,
                Source:   "javascript_analysis",
                Risk:     "medium",
            })
        }
    }

    return shadows, nil
}
```

## 9. 测试执行引擎

### 9.1 执行器

```go
type APITestExecutor struct {
    httpClient  *http.Client
    authManager *AuthManager
    limiter     *rate.Limiter
    results     chan<- *TestResult
}

type TestResult struct {
    TestCase    *TestCase        `json:"test_case"`
    Request     *RequestLog      `json:"request"`
    Response    *ResponseLog     `json:"response"`
    Analysis    *AnalysisResult  `json:"analysis"`
    Duration    time.Duration    `json:"duration"`
    ExecutedAt  time.Time        `json:"executed_at"`
}

func (e *APITestExecutor) Execute(ctx context.Context, testCase *TestCase) (*TestResult, error) {
    // 1. 构建请求
    req, err := e.buildRequest(ctx, testCase)
    if err != nil {
        return nil, err
    }

    // 2. 应用认证
    if testCase.AuthContext != nil {
        e.applyAuth(req, testCase.AuthContext)
    }

    // 3. 速率限制
    if err := e.limiter.Wait(ctx); err != nil {
        return nil, err
    }

    // 4. 发送请求
    start := time.Now()
    resp, err := e.httpClient.Do(req)
    duration := time.Since(start)
    if err != nil {
        return &TestResult{
            TestCase: testCase,
            Duration: duration,
            Analysis: &AnalysisResult{Evidence: []string{fmt.Sprintf("request failed: %v", err)}},
        }, nil
    }
    defer resp.Body.Close()

    // 5. 记录请求和响应
    result := &TestResult{
        TestCase: testCase,
        Request:  logRequest(req),
        Response: logResponse(resp),
        Duration: duration,
        ExecutedAt: start,
    }

    // 6. 分析响应
    analyzer := &ResponseAnalyzer{}
    result.Analysis = analyzer.Analyze(nil, resp, testCase)

    return result, nil
}
```

### 9.2 越权检测执行流

```go
func (e *APITestExecutor) ExecutePrivilegeEscalation(ctx context.Context, spec *APISpec) error {
    authPairs := e.authManager.GetContextPairs()

    for _, endpoint := range spec.Endpoints {
        for _, pair := range authPairs {
            highPriv, lowPriv := pair[0], pair[1]

            // 先用高权限获取 baseline
            baselineCase := &TestCase{
                Method:      endpoint.Method,
                Path:        endpoint.Path,
                AuthContext:  highPriv,
            }
            baseline, err := e.Execute(ctx, baselineCase)
            if err != nil || baseline.Response.StatusCode != 200 {
                continue
            }

            // 用低权限访问同一资源
            testCase := &TestCase{
                Name:        fmt.Sprintf("PrivEsc: %s→%s on %s %s", lowPriv.Name, highPriv.Name, endpoint.Method, endpoint.Path),
                Category:    "API5:FUNC_AUTH",
                Method:      endpoint.Method,
                Path:        endpoint.Path,
                AuthContext:  lowPriv,
                Severity:    "high",
            }
            result, err := e.Execute(ctx, testCase)
            if err != nil {
                continue
            }

            // 对比分析
            analyzer := &ResponseAnalyzer{}
            result.Analysis = analyzer.Analyze(baseline.Response.Raw, result.Response.Raw, testCase)

            e.results <- result
        }
    }

    return nil
}
```

## 10. GraphQL 专项检测

```go
type GraphQLSecurityTester struct{}

func (t *GraphQLSecurityTester) GenerateTests(schema *GraphQLSchema) []*TestCase {
    var tests []*TestCase

    // 1. 自省泄露
    tests = append(tests, t.testIntrospectionExposure()...)

    // 2. 查询深度攻击 (DoS)
    tests = append(tests, t.testQueryDepthAttack(schema)...)

    // 3. 批量查询攻击 (Batching)
    tests = append(tests, t.testBatchingAttack()...)

    // 4. 字段级授权 (通过 mutation 修改不应有权修改的字段)
    tests = append(tests, t.testFieldLevelAuth(schema)...)

    // 5. 别名滥用 (使用别名绕过速率限制)
    tests = append(tests, t.testAliasAbuse(schema)...)

    // 6. 指令注入
    tests = append(tests, t.testDirectiveInjection()...)

    return tests
}

func (t *GraphQLSecurityTester) testQueryDepthAttack(schema *GraphQLSchema) []*TestCase {
    // 找到可递归的类型关系 (如 User.friends -> [User])
    recursiveFields := findRecursiveFields(schema)

    var tests []*TestCase
    for _, field := range recursiveFields {
        deepQuery := buildDeepQuery(field, 20) // 20层嵌套
        tests = append(tests, &TestCase{
            Name:     fmt.Sprintf("GraphQL DoS: Deep query on %s.%s (depth=20)", field.Parent, field.Name),
            Category: "API4:RATE_LIMIT",
            Method:   "POST",
            Body:     map[string]string{"query": deepQuery},
            Assertion: &Assertion{
                Type:     "status_code",
                Operator: "ne",
                Expected: "200",
                Description: "Deep nested queries should be rejected",
            },
            Severity: "medium",
        })
    }

    return tests
}
```

## 11. API 端点

```
API Security Testing
├── /api/v1/api-security/specs
│   ├── POST   /                     导入API规范 (OpenAPI/Swagger/GraphQL/HAR)
│   ├── GET    /                     规范列表
│   ├── GET    /:id                  规范详情 (含端点列表)
│   ├── DELETE /:id                  删除规范
│   └── POST   /:id/refresh          重新拉取/解析规范
├── /api/v1/api-security/scans
│   ├── POST   /                     创建API安全扫描
│   │   Body: { spec_id, auth_contexts, test_categories, config }
│   ├── GET    /                     扫描列表
│   ├── GET    /:id                  扫描详情
│   ├── GET    /:id/results          扫描结果 (含所有测试结果)
│   ├── POST   /:id/stop             停止扫描
│   └── GET    /:id/report           生成扫描报告
├── /api/v1/api-security/auth
│   ├── POST   /contexts             添加认证上下文
│   ├── GET    /contexts             认证上下文列表
│   ├── PUT    /contexts/:id         更新认证上下文
│   └── POST   /contexts/:id/test    测试认证是否有效
├── /api/v1/api-security/shadows
│   ├── POST   /detect               触发影子API检测
│   └── GET    /                     影子API列表
└── /api/v1/api-security/dashboard
    ├── GET    /overview              安全概览
    ├── GET    /coverage              API安全覆盖率
    └── GET    /trends                趋势图
```

## 12. 配置

```yaml
api_security:
  discovery:
    auto_crawl: true
    js_analysis: true
    max_crawl_depth: 3
    common_path_probe: true

  testing:
    categories:
      - "API1:BOLA"
      - "API2:AUTH"
      - "API3:PROPERTY"
      - "API4:RATE_LIMIT"
      - "API5:FUNC_AUTH"
      - "API7:MISCONFIG"
      - "API9:SHADOW"
    
    rate_limit: 50                  # 每秒最大请求
    max_test_cases_per_endpoint: 200
    timeout_per_request: "10s"
    
    bola:
      id_range: [1, 100]
      test_other_user: true
    
    rate_limit_test:
      burst_count: 100
      window: "1m"
    
    mass_assignment:
      sensitive_fields:
        - "role"
        - "is_admin"
        - "permissions"
        - "verified"
        - "balance"

  graphql:
    max_query_depth: 20
    test_introspection: true
    test_batching: true
    test_alias_abuse: true

  reporting:
    include_request_response: true
    redact_credentials: true
    severity_threshold: "low"
```
