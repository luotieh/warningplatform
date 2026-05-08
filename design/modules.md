# 漏洞扫描系统 — 扫描模块详细设计

## 模块总览

| 模块 | 包路径 | 功能 | 核心依赖 |
|------|--------|------|----------|
| **ICMPPing** | `scan/module/icmp` | ICMP 存活探测 + TCP Ping 回退 | `net` (raw socket) |
| **PortScan** | `scan/module/portscan` | TCP Full Connect 端口扫描 | `net` |
| **SYNScan** | `scan/module/synscan` | SYN 半开扫描 (需root) + TCP回退 | `gopacket`, `net` |
| **UDPScan** | `scan/module/udpscan` | UDP 端口扫描 (协议探针) | `net` |
| ServiceProbe | `scan/module/serviceprobe` | 服务识别 + Banner 抓取 | `net`, `crypto/tls` |
| WebCrawl | `scanner/webcrawl` | Web 爬虫 + URL 提取 | `net/http`, `html` |
| DirScan | `scan/module/dirscan` | 目录/文件路径枚举 | `net/http` |
| Fingerprint | `scan/module/fingerprint` | Web 指纹识别 | `net/http`, `crypto/md5` |
| SubDomain | `scanner/subdomain` | 子域名发现 | `net`, DNS |
| SQLi | `scan/module/sqli` | SQL 注入检测 (Error/Boolean/Time) | `net/http` |
| XSS | `scan/module/xss` | 反射型 XSS 检测 (Canary 探针) | `net/http` |
| SSRF | `scanner/ssrf` | SSRF 检测 | `net/http` |
| WeakPass | `scan/module/weakpass` | 弱口令 (SSH/MySQL/PG/Redis/FTP/Mongo) | `x/crypto/ssh`, `net` |
| CertCheck | `scan/module/certcheck` | TLS/SSL 证书检查 | `crypto/tls` |
| InfoLeak | `scan/module/infoleak` | 信息泄露检测 (12项) | `net/http` |
| APIFuzz | `scanner/apifuzz` | API 接口模糊测试 | `net/http` |

---

## 1. 端口扫描 (PortScan)

### 1.1 扫描模式

**TCP Connect Scan（默认，无需 root 权限）：**

```go
type TCPConnectScanner struct {
    pool     *WorkerPool
    limiter  *RateLimiter
    timeout  time.Duration
    resultCh chan PortResult
}

func (s *TCPConnectScanner) ScanPort(ctx context.Context, host string, port int) PortResult {
    addr := fmt.Sprintf("%s:%d", host, port)
    conn, err := net.DialTimeout("tcp", addr, s.timeout)
    if err != nil {
        if isTimeout(err) || isRefused(err) {
            return PortResult{Host: host, Port: port, State: "closed"}
        }
        return PortResult{Host: host, Port: port, State: "filtered"}
    }
    conn.Close()
    return PortResult{Host: host, Port: port, State: "open"}
}

func (s *TCPConnectScanner) ScanHost(ctx context.Context, host string, ports []int) []PortResult {
    var results []PortResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, port := range ports {
        wg.Add(1)
        p := port
        s.pool.Submit(func() {
            defer wg.Done()
            result := s.ScanPort(ctx, host, p)
            if result.State == "open" {
                mu.Lock()
                results = append(results, result)
                mu.Unlock()
            }
        })
    }
    wg.Wait()
    return results
}
```

**SYN Scan（需要 root 权限，更快更隐蔽）：**

```go
type SYNScanner struct {
    rawConn *ipv4.RawConn    // 使用 golang.org/x/net/ipv4
    timeout time.Duration
    srcPort int
}

// 发送 SYN 包，监听 SYN-ACK 响应
// 实现要点：
// 1. 构造 TCP SYN 包（手动构建 IP + TCP 头）
// 2. 通过 raw socket 发送
// 3. 监听回包，SYN-ACK = open, RST = closed, 超时 = filtered
// 4. 不完成三次握手（不发 ACK），减少目标日志记录
```

### 1.2 端口列表策略

```go
var (
    Top100Ports  = []int{...}  // 最常见 100 端口
    Top1000Ports = []int{...}  // Nmap top 1000 端口列表（硬编码）
    WebPorts     = []int{80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000}
    DBPorts      = []int{3306, 5432, 27017, 6379, 1521, 1433, 9200}
    FullRange    = generateRange(1, 65535)
)

func ParsePorts(spec string) []int {
    switch spec {
    case "top100":  return Top100Ports
    case "top1000": return Top1000Ports
    case "web":     return WebPorts
    case "db":      return DBPorts
    case "full":    return FullRange
    default:        return parseCustomPorts(spec) // "80,443,8000-9000"
    }
}
```

---

## 2. 服务探测 (ServiceProbe)

```go
type ServiceProber struct {
    probes  []ServiceProbe
    timeout time.Duration
}

type ServiceProbe struct {
    Name       string
    SendData   []byte            // 探测发送的数据
    MatchRules []ProbeMatchRule  // 匹配规则
}

type ProbeMatchRule struct {
    Service string         // 服务名
    Pattern *regexp.Regexp // Banner 匹配正则
    Version string         // 版本提取正则
}

func (sp *ServiceProber) Probe(ctx context.Context, host string, port int) ServiceInfo {
    addr := fmt.Sprintf("%s:%d", host, port)

    // Step 1: 空探测（直接连接读取 Banner）
    banner := sp.grabBanner(ctx, addr)
    if info := sp.matchBanner(banner); info.Service != "" {
        return info
    }

    // Step 2: 发送协议探测包
    for _, probe := range sp.probes {
        resp := sp.sendProbe(ctx, addr, probe.SendData)
        for _, rule := range probe.MatchRules {
            if rule.Pattern.Match(resp) {
                version := extractVersion(resp, rule.Version)
                return ServiceInfo{
                    Service: rule.Service,
                    Version: version,
                    Banner:  string(resp[:min(512, len(resp))]),
                }
            }
        }
    }

    // Step 3: 基于端口号的默认猜测
    return ServiceInfo{Service: guessServiceByPort(port)}
}

// 内置探测规则示例
var defaultProbes = []ServiceProbe{
    {Name: "HTTP", SendData: []byte("GET / HTTP/1.1\r\nHost: target\r\n\r\n")},
    {Name: "SSH",  SendData: nil}, // SSH 主动发送 Banner
    {Name: "FTP",  SendData: nil}, // FTP 主动发送 Banner
    {Name: "SMTP", SendData: nil},
    {Name: "MySQL", SendData: nil}, // MySQL 主动发送握手包
    {Name: "Redis", SendData: []byte("PING\r\n")},
    {Name: "TLS",  SendData: nil}, // TLS ClientHello
}
```

---

## 3. Web 指纹识别 (Fingerprint)

```go
type WebFingerprinter struct {
    db      *FingerprintDB
    client  *http.Client
}

func (wf *WebFingerprinter) Fingerprint(ctx context.Context, target *Target) []Fingerprint {
    var results []Fingerprint

    // 1. HTTP 响应头分析
    resp, body, err := wf.fetchURL(ctx, target.URL())
    if err != nil {
        return nil
    }

    // Server / X-Powered-By / X-Generator 等
    results = append(results, wf.analyzeHeaders(resp.Header)...)

    // 2. HTML 元信息
    results = append(results, wf.analyzeHTML(body)...)

    // 3. Favicon hash
    faviconHash := wf.getFaviconHash(ctx, target.URL())
    if fp := wf.db.MatchFavicon(faviconHash); fp != nil {
        results = append(results, *fp)
    }

    // 4. URL 路径特征
    results = append(results, wf.probePaths(ctx, target)...)

    // 5. Cookie 特征
    results = append(results, wf.analyzeCookies(resp.Cookies())...)

    // 6. JS/CSS 特征
    results = append(results, wf.analyzeStaticResources(body)...)

    // 7. TLS 证书
    if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
        results = append(results, wf.analyzeCert(resp.TLS.PeerCertificates[0])...)
    }

    return dedupAndScore(results)
}

// 指纹库示例（YAML 格式，启动时加载编译）
//
// - product: "Nginx"
//   category: "webserver"
//   matchers:
//     - type: header
//       field: server
//       keywords: ["nginx"]
//     - type: body
//       regex: "nginx/([\\d.]+)"
//       extract: version
//   confidence: 95
//
// - product: "WordPress"
//   category: "cms"
//   matchers:
//     - type: body
//       keywords: ["wp-content", "wp-includes"]
//     - type: header
//       field: x-pingback
//       keywords: ["xmlrpc.php"]
//   confidence: 90
```

---

## 4. 子域名发现 (SubDomain)

```go
type SubdomainScanner struct {
    resolvers  []string         // DNS 服务器列表
    dictPath   string           // 字典文件路径
    pool       *WorkerPool
    limiter    *RateLimiter
}

func (s *SubdomainScanner) Discover(ctx context.Context, domain string) []SubdomainResult {
    var results []SubdomainResult
    var mu sync.Mutex

    // 1. DNS 字典枚举
    dictResults := s.dnsEnum(ctx, domain)
    results = append(results, dictResults...)

    // 2. 证书透明度日志 (CT Log)
    ctResults := s.queryCTLogs(ctx, domain)
    results = append(results, ctResults...)

    // 3. DNS 区域传送尝试
    if axfrResults := s.tryAXFR(ctx, domain); len(axfrResults) > 0 {
        results = append(results, axfrResults...)
    }

    // 4. 搜索引擎收录（可选，需 API Key）
    // 暂时跳过，避免外部依赖

    return dedup(results)
}

// DNS 枚举
func (s *SubdomainScanner) dnsEnum(ctx context.Context, domain string) []SubdomainResult {
    words := loadDict(s.dictPath)
    var results []SubdomainResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, word := range words {
        wg.Add(1)
        w := word
        s.pool.Submit(func() {
            defer wg.Done()
            fqdn := fmt.Sprintf("%s.%s", w, domain)

            // 随机选择 DNS 服务器
            resolver := s.resolvers[rand.Intn(len(s.resolvers))]
            ips, err := lookupWithResolver(ctx, fqdn, resolver)
            if err != nil || len(ips) == 0 {
                return
            }

            mu.Lock()
            results = append(results, SubdomainResult{
                Domain:  fqdn,
                IPs:     ips,
                Source:  "dns_enum",
            })
            mu.Unlock()
        })
    }
    wg.Wait()
    return results
}

// 证书透明度查询
func (s *SubdomainScanner) queryCTLogs(ctx context.Context, domain string) []SubdomainResult {
    url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
    req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return nil
    }
    defer resp.Body.Close()

    var entries []struct {
        CommonName string `json:"common_name"`
        NameValue  string `json:"name_value"`
    }
    json.NewDecoder(resp.Body).Decode(&entries)

    seen := make(map[string]bool)
    var results []SubdomainResult
    for _, e := range entries {
        names := strings.Split(e.NameValue, "\n")
        for _, name := range names {
            name = strings.TrimSpace(name)
            name = strings.TrimPrefix(name, "*.")
            if !strings.HasSuffix(name, "."+domain) && name != domain {
                continue
            }
            if seen[name] { continue }
            seen[name] = true
            results = append(results, SubdomainResult{
                Domain: name,
                Source: "ct_log",
            })
        }
    }
    return results
}
```

---

## 5. SQL 注入检测 (SQLi)

```go
type SQLiScanner struct {
    client  *http.Client
    timeout time.Duration
}

// 检测方法矩阵
// 1. 布尔盲注 — 比较正常/异常响应差异
// 2. 时间盲注 — 注入 SLEEP/WAITFOR 测量延迟
// 3. 报错注入 — 检测响应中的数据库错误信息
// 4. UNION 注入 — 探测列数，拼接 UNION SELECT

func (s *SQLiScanner) Scan(ctx context.Context, target *Target, params []CrawledParam) []VulnResult {
    var results []VulnResult

    for _, param := range params {
        // 报错注入检测（最快）
        if result := s.testErrorBased(ctx, target, param); result != nil {
            results = append(results, *result)
            continue
        }

        // 布尔盲注检测
        if result := s.testBooleanBased(ctx, target, param); result != nil {
            results = append(results, *result)
            continue
        }

        // 时间盲注检测
        if result := s.testTimeBased(ctx, target, param); result != nil {
            results = append(results, *result)
        }
    }
    return results
}

func (s *SQLiScanner) testErrorBased(ctx context.Context, target *Target, param CrawledParam) *VulnResult {
    payloads := []string{
        `'`,
        `"`,
        `' OR '1'='1`,
        `1 AND 1=CONVERT(int,(SELECT @@version))`,
        `' AND extractvalue(1,concat(0x7e,version()))--`,
    }

    dbErrors := []string{
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "PostgreSQL",
        "Microsoft SQL",
        "SQLSTATE",
        "syntax error",
        "unterminated",
        "XPATH syntax",
    }

    for _, payload := range payloads {
        resp, body, err := s.sendWithPayload(ctx, target, param, payload)
        if err != nil { continue }

        for _, errStr := range dbErrors {
            if strings.Contains(body, errStr) {
                return &VulnResult{
                    Type:     "sqli",
                    SubType:  "error_based",
                    Severity: "high",
                    Target:   target.URL(),
                    Param:    param.Name,
                    Payload:  payload,
                    Evidence: fmt.Sprintf("DB error found: %s (HTTP %d)", errStr, resp.StatusCode),
                }
            }
        }
    }
    return nil
}

func (s *SQLiScanner) testTimeBased(ctx context.Context, target *Target, param CrawledParam) *VulnResult {
    payloads := map[string]string{
        "mysql":  "' OR SLEEP(5)-- -",
        "mssql":  "'; WAITFOR DELAY '0:0:5'--",
        "pg":     "'; SELECT pg_sleep(5)--",
    }

    // 先测量基线响应时间
    baseline := s.measureBaseline(ctx, target, param)

    for dbType, payload := range payloads {
        start := time.Now()
        _, _, err := s.sendWithPayload(ctx, target, param, payload)
        elapsed := time.Since(start)

        if err != nil { continue }

        // 如果响应时间显著大于基线（超过 4 秒差值），判定为时间盲注
        if elapsed-baseline > 4*time.Second {
            return &VulnResult{
                Type:     "sqli",
                SubType:  "time_based",
                Severity: "high",
                Target:   target.URL(),
                Param:    param.Name,
                Payload:  payload,
                Evidence: fmt.Sprintf("Time-based SQLi (%s): baseline %v, injected %v", dbType, baseline, elapsed),
            }
        }
    }
    return nil
}
```

---

## 6. XSS 检测

```go
type XSSScanner struct {
    client *http.Client
}

func (s *XSSScanner) Scan(ctx context.Context, target *Target, params []CrawledParam) []VulnResult {
    var results []VulnResult

    for _, param := range params {
        // 反射型 XSS
        if r := s.testReflected(ctx, target, param); r != nil {
            results = append(results, *r)
        }
    }
    return results
}

func (s *XSSScanner) testReflected(ctx context.Context, target *Target, param CrawledParam) *VulnResult {
    // 分层探测策略：先探测反射点，再逐步升级 payload
    marker := fmt.Sprintf("xssprobe%d", rand.Intn(99999))

    // Step 1: 探测反射 — 发送无害标记检查是否原样反射
    _, body, _ := sendWithPayload(ctx, target, param, marker)
    if !strings.Contains(body, marker) {
        return nil // 不反射，跳过
    }

    // Step 2: 检查编码上下文
    context := analyzeReflectionContext(body, marker) // html_body, html_attr, js_string, url, ...

    // Step 3: 根据上下文选择 payload
    payloads := getPayloadsForContext(context)

    for _, payload := range payloads {
        _, respBody, err := sendWithPayload(ctx, target, param, payload)
        if err != nil { continue }

        if isXSSSuccessful(respBody, payload) {
            return &VulnResult{
                Type:     "xss",
                SubType:  "reflected",
                Severity: "medium",
                Target:   target.URL(),
                Param:    param.Name,
                Payload:  payload,
                Evidence: fmt.Sprintf("Reflected XSS in %s context", context),
            }
        }
    }
    return nil
}

var xssPayloads = map[string][]string{
    "html_body": {
        `<script>alert(1)</script>`,
        `<img src=x onerror=alert(1)>`,
        `<svg onload=alert(1)>`,
        `<details open ontoggle=alert(1)>`,
    },
    "html_attr": {
        `" onmouseover="alert(1)`,
        `' onfocus='alert(1)' autofocus='`,
        `"><script>alert(1)</script>`,
    },
    "js_string": {
        `';alert(1)//`,
        `";alert(1)//`,
        `\';alert(1)//`,
    },
}
```

---

## 7. 弱口令检测 (WeakPass)

```go
type WeakPassScanner struct {
    pool     *WorkerPool
    limiter  *RateLimiter
    dict     *PasswordDict
    // 各协议的认证实现
    checkers map[string]AuthChecker
}

// AuthChecker 协议认证接口
type AuthChecker interface {
    Protocol() string
    DefaultPort() int
    Check(ctx context.Context, host string, port int, user, pass string) (bool, error)
}

// SSH 认证检查
type SSHChecker struct{}

func (c *SSHChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, error) {
    config := &ssh.ClientConfig{
        User: user,
        Auth: []ssh.AuthMethod{ssh.Password(pass)},
        HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        Timeout: 10 * time.Second,
    }
    addr := fmt.Sprintf("%s:%d", host, port)
    client, err := ssh.Dial("tcp", addr, config)
    if err != nil {
        if strings.Contains(err.Error(), "unable to authenticate") {
            return false, nil // 认证失败，非错误
        }
        return false, err // 连接错误
    }
    client.Close()
    return true, nil
}

// MySQL 认证检查
type MySQLChecker struct{}

func (c *MySQLChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, error) {
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", user, pass, host, port)
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return false, nil
    }
    defer db.Close()

    ctx2, cancel := context.WithTimeout(ctx, 10*time.Second)
    defer cancel()
    if err := db.PingContext(ctx2); err != nil {
        return false, nil
    }
    return true, nil
}

// Redis 未授权 / 弱口令
type RedisChecker struct{}

func (c *RedisChecker) Check(ctx context.Context, host string, port int, user, pass string) (bool, error) {
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
    if err != nil {
        return false, err
    }
    defer conn.Close()

    if pass == "" {
        // 未授权检查
        fmt.Fprintf(conn, "INFO\r\n")
    } else {
        fmt.Fprintf(conn, "AUTH %s\r\n", pass)
    }

    buf := make([]byte, 1024)
    n, _ := conn.Read(buf)
    resp := string(buf[:n])
    return !strings.HasPrefix(resp, "-ERR") && !strings.HasPrefix(resp, "-NOAUTH"), nil
}

// 支持的协议列表
var defaultCheckers = map[string]AuthChecker{
    "ssh":        &SSHChecker{},
    "ftp":        &FTPChecker{},
    "mysql":      &MySQLChecker{},
    "postgresql": &PostgreSQLChecker{},
    "redis":      &RedisChecker{},
    "mongodb":    &MongoDBChecker{},
    "mssql":      &MSSQLChecker{},
    "telnet":     &TelnetChecker{},
    "smb":        &SMBChecker{},
    "rdp":        &RDPChecker{},
    "vnc":        &VNCChecker{},
    "memcached":  &MemcachedChecker{},
    "elasticsearch": &ESChecker{},
    "rabbitmq":   &RabbitMQChecker{},
    "http_basic": &HTTPBasicChecker{},
}
```

---

## 8. 信息泄露检测 (InfoLeak)

```go
type InfoLeakScanner struct {
    client *http.Client
    rules  []InfoLeakRule
}

type InfoLeakRule struct {
    Name     string
    Severity string
    Paths    []string           // 待探测路径
    Matchers []InfoLeakMatcher  // 匹配规则
}

var defaultLeakRules = []InfoLeakRule{
    {
        Name: "Git 源码泄露", Severity: "high",
        Paths: []string{"/.git/HEAD", "/.git/config"},
        Matchers: []InfoLeakMatcher{
            {Type: "body", Keywords: []string{"ref: refs/heads/", "[core]"}},
            {Type: "status", Codes: []int{200}},
        },
    },
    {
        Name: "SVN 泄露", Severity: "high",
        Paths: []string{"/.svn/entries", "/.svn/wc.db"},
        Matchers: []InfoLeakMatcher{
            {Type: "status", Codes: []int{200}},
        },
    },
    {
        Name: "环境变量泄露", Severity: "critical",
        Paths: []string{"/.env", "/.env.production", "/.env.local"},
        Matchers: []InfoLeakMatcher{
            {Type: "body", Keywords: []string{"DB_PASSWORD", "SECRET_KEY", "API_KEY", "DATABASE_URL"}},
        },
    },
    {
        Name: "PHPInfo", Severity: "medium",
        Paths: []string{"/phpinfo.php", "/info.php", "/php_info.php"},
        Matchers: []InfoLeakMatcher{
            {Type: "body", Keywords: []string{"phpinfo()"}},
        },
    },
    {
        Name: "备份文件", Severity: "high",
        Paths: []string{"/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql", "/website.zip",
                        "/www.zip", "/web.zip", "/data.zip"},
        Matchers: []InfoLeakMatcher{
            {Type: "status", Codes: []int{200}},
            {Type: "header", Field: "content-length", MinSize: 1024},
        },
    },
    {
        Name: "目录列表", Severity: "low",
        Paths: []string{"/", "/uploads/", "/static/", "/backup/"},
        Matchers: []InfoLeakMatcher{
            {Type: "body", Keywords: []string{"Index of /", "Directory listing", "Parent Directory"}},
        },
    },
    {
        Name: "Spring Actuator", Severity: "high",
        Paths: []string{"/actuator", "/actuator/env", "/actuator/heapdump", "/env", "/heapdump"},
        Matchers: []InfoLeakMatcher{
            {Type: "body", Keywords: []string{"_links", "self", "href"}},
            {Type: "status", Codes: []int{200}},
        },
    },
    {
        Name: "Swagger 文档暴露", Severity: "low",
        Paths: []string{"/swagger-ui.html", "/swagger-ui/index.html", "/api-docs", "/v2/api-docs", "/v3/api-docs"},
        Matchers: []InfoLeakMatcher{
            {Type: "status", Codes: []int{200}},
            {Type: "body", Keywords: []string{"swagger", "openapi"}},
        },
    },
}
```

---

## 9. TLS/证书检查 (CertCheck)

```go
type CertChecker struct{}

type CertCheckResult struct {
    Subject     string
    Issuer      string
    NotBefore   time.Time
    NotAfter    time.Time
    SANs        []string
    TLSVersion  uint16
    CipherSuite uint16
    Issues      []CertIssue
}

type CertIssue struct {
    Severity    string
    Description string
}

func (c *CertChecker) Check(ctx context.Context, host string, port int) (*CertCheckResult, error) {
    addr := fmt.Sprintf("%s:%d", host, port)
    conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr,
        &tls.Config{InsecureSkipVerify: true})
    if err != nil {
        return nil, err
    }
    defer conn.Close()

    state := conn.ConnectionState()
    if len(state.PeerCertificates) == 0 {
        return nil, fmt.Errorf("no certificates")
    }

    cert := state.PeerCertificates[0]
    result := &CertCheckResult{
        Subject:     cert.Subject.CommonName,
        Issuer:      cert.Issuer.CommonName,
        NotBefore:   cert.NotBefore,
        NotAfter:    cert.NotAfter,
        SANs:        cert.DNSNames,
        TLSVersion:  state.Version,
        CipherSuite: state.CipherSuite,
    }

    // 检查项
    now := time.Now()

    if cert.NotAfter.Before(now) {
        result.Issues = append(result.Issues, CertIssue{"critical", "证书已过期"})
    } else if cert.NotAfter.Before(now.AddDate(0, 1, 0)) {
        result.Issues = append(result.Issues, CertIssue{"medium", "证书即将过期(30天内)"})
    }

    if cert.Issuer.CommonName == cert.Subject.CommonName {
        result.Issues = append(result.Issues, CertIssue{"medium", "自签名证书"})
    }

    if state.Version < tls.VersionTLS12 {
        result.Issues = append(result.Issues, CertIssue{"high", fmt.Sprintf("TLS 版本过低: 0x%04x", state.Version)})
    }

    weakCiphers := map[uint16]bool{
        tls.TLS_RSA_WITH_RC4_128_SHA:        true,
        tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:   true,
    }
    if weakCiphers[state.CipherSuite] {
        result.Issues = append(result.Issues, CertIssue{"high", "使用了弱加密套件"})
    }

    return result, nil
}
```

---

## 10. 目录扫描 (DirScan)

```go
type DirScanner struct {
    client   *http.Client
    pool     *WorkerPool
    limiter  *RateLimiter
    dictPath string
}

func (s *DirScanner) Scan(ctx context.Context, baseURL string) []DirResult {
    words := loadDict(s.dictPath)
    extensions := []string{"", ".php", ".asp", ".aspx", ".jsp", ".html", ".json", ".xml", ".bak", ".sql", ".txt"}

    // 先探测 404 基线（识别自定义 404 页面）
    baseline404 := s.detect404Baseline(ctx, baseURL)

    var results []DirResult
    var mu sync.Mutex
    var wg sync.WaitGroup

    for _, word := range words {
        for _, ext := range extensions {
            wg.Add(1)
            path := "/" + word + ext
            s.pool.Submit(func() {
                defer wg.Done()

                url := baseURL + path
                resp, body, err := s.fetch(ctx, url)
                if err != nil { return }

                // 过滤假 200（自定义 404）
                if resp.StatusCode == 200 && s.isFake200(body, baseline404) {
                    return
                }

                if resp.StatusCode >= 200 && resp.StatusCode < 400 {
                    mu.Lock()
                    results = append(results, DirResult{
                        URL:    url,
                        Status: resp.StatusCode,
                        Size:   len(body),
                        Title:  extractTitle(body),
                    })
                    mu.Unlock()
                }
            })
        }
    }
    wg.Wait()
    return results
}
```

---

## 11. Web 爬虫 (WebCrawl)

```go
type Crawler struct {
    client     *http.Client
    maxDepth   int
    maxPages   int
    scope      *url.URL         // 限定域名范围
    visited    sync.Map
    results    chan CrawlResult
}

type CrawlResult struct {
    URL     string
    Method  string
    Params  []CrawledParam      // GET/POST 参数
    Forms   []HTMLForm
    Links   []string
}

type CrawledParam struct {
    Name     string
    Value    string
    Type     string   // query, body, path, header, cookie
    Location string   // URL/Form action
    Method   string
}

func (c *Crawler) Crawl(ctx context.Context, startURL string) []CrawlResult {
    var allResults []CrawlResult
    queue := []crawlItem{{url: startURL, depth: 0}}

    for len(queue) > 0 && len(allResults) < c.maxPages {
        item := queue[0]
        queue = queue[1:]

        if item.depth > c.maxDepth { continue }
        if _, loaded := c.visited.LoadOrStore(item.url, true); loaded { continue }

        result, links := c.fetchAndParse(ctx, item.url)
        if result != nil {
            allResults = append(allResults, *result)
        }

        for _, link := range links {
            if c.inScope(link) {
                queue = append(queue, crawlItem{url: link, depth: item.depth + 1})
            }
        }
    }
    return allResults
}
```

---

## 12. SSRF 检测

```go
type SSRFScanner struct {
    client       *http.Client
    callbackHost string     // OOB 回调地址 (如自建 DNSLog)
}

func (s *SSRFScanner) Scan(ctx context.Context, target *Target, params []CrawledParam) []VulnResult {
    var results []VulnResult

    for _, param := range params {
        // 仅测试可能接受 URL/IP 的参数
        if !isURLLikeParam(param.Name) { continue }

        payloads := []struct {
            payload  string
            evidence string
        }{
            // 内网探测
            {payload: "http://127.0.0.1:80", evidence: "localhost response"},
            {payload: "http://169.254.169.254/latest/meta-data/", evidence: "aws_metadata"},
            {payload: "http://[::1]:80", evidence: "ipv6_localhost"},
            // DNS OOB（如有回调服务器）
            {payload: fmt.Sprintf("http://%s.%s", param.Name, s.callbackHost), evidence: "oob_dns"},
        }

        for _, p := range payloads {
            _, body, err := sendWithPayload(ctx, target, param, p.payload)
            if err != nil { continue }

            if s.detectSSRF(body, p.evidence) {
                results = append(results, VulnResult{
                    Type:     "ssrf",
                    Severity: "high",
                    Target:   target.URL(),
                    Param:    param.Name,
                    Payload:  p.payload,
                    Evidence: p.evidence,
                })
                break
            }
        }
    }
    return results
}
```
