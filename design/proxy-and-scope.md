# 代理池与监测范围设计

## 第一部分：代理池技术

### 1. 概述

代理池是漏扫系统的核心基础设施之一，主要解决：

| 问题 | 说明 |
|------|------|
| **IP 封禁** | 高频扫描触发目标 WAF/IDS 的 IP 封禁 |
| **请求限流** | 同 IP 大量请求被目标限速/拒绝 |
| **溯源防护** | 隐藏扫描源真实 IP |
| **地域限制** | 目标仅允许特定地区访问 |
| **协议适配** | 部分目标仅接受特定出口协议 |

### 2. 代理池架构

```
┌──────────────────────────────────────────────────────────────┐
│                      Proxy Pool Manager                       │
│                                                              │
│  ┌─────────────────┐  ┌──────────────┐  ┌────────────────┐  │
│  │ 代理源采集器    │  │  健康检查    │  │ 智能调度器     │  │
│  │                 │  │              │  │                │  │
│  │ · 付费API      │  │ · TCP连通性  │  │ · 轮询策略     │  │
│  │ · 免费抓取      │  │ · HTTP验证   │  │ · 加权随机     │  │
│  │ · 自建隧道      │  │ · 延迟测量   │  │ · 地域就近     │  │
│  │ · 配置文件      │  │ · 匿名度检测 │  │ · 协议匹配     │  │
│  │ · Cloud函数     │  │ · 周期巡检   │  │ · 黑名单回避   │  │
│  └─────────────────┘  └──────────────┘  └────────────────┘  │
│                              │                               │
│  ┌───────────────────────────┴────────────────────────────┐  │
│  │                   Proxy Store (Redis)                   │  │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │  │
│  │  │ 高匿代理 │ │ 透明代理 │ │ SOCKS5   │ │ 直连出口 │  │  │
│  │  │ (elite)  │ │ (transp) │ │ (socks)  │ │ (direct) │  │  │
│  │  └──────────┘ └──────────┘ └──────────┘ └──────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                              │                               │
│  ┌───────────────────────────┴────────────────────────────┐  │
│  │              Transport Layer Integration                │  │
│  │  HTTP Client / TCP Dialer / DNS Resolver                │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 3. 代理数据模型

```go
type Proxy struct {
    ID          string    `json:"id"`
    Protocol    string    `json:"protocol"`      // http, https, socks4, socks5
    Host        string    `json:"host"`
    Port        int       `json:"port"`
    Username    string    `json:"username"`       // 认证代理
    Password    string    `json:"password"`
    
    // 质量指标
    Anonymity   string    `json:"anonymity"`      // elite (高匿), anonymous, transparent
    Country     string    `json:"country"`         // CN, US, JP...
    Region      string    `json:"region"`          // 细分地区
    ISP         string    `json:"isp"`
    Latency     int       `json:"latency_ms"`      // 最近一次延迟
    AvgLatency  int       `json:"avg_latency_ms"`  // 历史平均延迟
    SuccessRate float64   `json:"success_rate"`    // 成功率 0~1
    Speed       int       `json:"speed_kbps"`      // 带宽估算

    // 状态
    Status      string    `json:"status"`          // active, inactive, banned, checking
    Source      string    `json:"source"`          // paid_api, free_crawl, self_hosted, config
    LastCheck   time.Time `json:"last_check"`
    FailCount   int       `json:"fail_count"`      // 连续失败次数
    BanTargets  []string  `json:"ban_targets"`     // 已被哪些目标封禁
    
    CreatedAt   time.Time `json:"created_at"`
}
```

### 4. 代理源采集器

#### 4.1 采集接口

```go
type ProxyProvider interface {
    Name() string
    Type() string                     // paid, free, self_hosted
    Fetch(ctx context.Context) ([]*Proxy, error)
    Interval() time.Duration          // 采集间隔
}
```

#### 4.2 付费代理 API

```go
type PaidAPIProvider struct {
    apiURL  string
    apiKey  string
    options map[string]string  // country, protocol, anonymity 等筛选
}

func (p *PaidAPIProvider) Fetch(ctx context.Context) ([]*Proxy, error) {
    // 调用代理服务商 API 获取代理列表
    // 常见服务商: 快代理、芝麻代理、讯代理、Luminati、Smartproxy
    return nil, nil
}
```

#### 4.3 自建隧道代理

```go
type TunnelProvider struct {
    tunnels []TunnelConfig
}

type TunnelConfig struct {
    Name     string `json:"name"`
    Type     string `json:"type"`     // ssh_tunnel, wireguard, shadowsocks, v2ray
    Host     string `json:"host"`
    Port     int    `json:"port"`
    Config   string `json:"config"`   // 协议特定配置
    LocalPort int   `json:"local_port"`
}
```

#### 4.4 云函数代理

利用 Serverless 云函数作为代理出口，天然 IP 池：

```go
type CloudFunctionProvider struct {
    provider string // aws_lambda, azure_function, aliyun_fc, tencent_scf
    regions  []string
    config   map[string]string
}

func (p *CloudFunctionProvider) Fetch(ctx context.Context) ([]*Proxy, error) {
    // 部署转发函数到多个区域
    // 每个区域函数实例 = 一个代理出口
    return nil, nil
}
```

### 5. 健康检查

```go
type ProxyHealthChecker struct {
    checkInterval time.Duration
    timeout       time.Duration
    testURLs      []string
}

type HealthCheckResult struct {
    ProxyID     string
    IsAlive     bool
    Latency     time.Duration
    Anonymity   string
    ExternalIP  string         // 出口 IP (用于验证匿名度)
    CheckedAt   time.Time
}

func (c *ProxyHealthChecker) Check(ctx context.Context, proxy *Proxy) *HealthCheckResult {
    result := &HealthCheckResult{ProxyID: proxy.ID, CheckedAt: time.Now()}

    // 1. TCP 连通性
    conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxy.Host, proxy.Port), c.timeout)
    if err != nil {
        result.IsAlive = false
        return result
    }
    conn.Close()

    // 2. HTTP 验证 + 延迟测量
    start := time.Now()
    transport := &http.Transport{
        Proxy: http.ProxyURL(proxy.URL()),
        DialContext: (&net.Dialer{Timeout: c.timeout}).DialContext,
    }
    client := &http.Client{Transport: transport, Timeout: c.timeout}

    resp, err := client.Get(c.testURLs[0]) // httpbin.org/ip 或自建检测服务
    if err != nil {
        result.IsAlive = false
        return result
    }
    defer resp.Body.Close()
    result.Latency = time.Since(start)
    result.IsAlive = resp.StatusCode == 200

    // 3. 匿名度检测
    body, _ := io.ReadAll(resp.Body)
    result.ExternalIP = extractIP(body)
    result.Anonymity = detectAnonymity(resp.Header, result.ExternalIP, proxy.Host)

    return result
}

func detectAnonymity(headers http.Header, externalIP, proxyHost string) string {
    // 检查是否泄露真实 IP
    forwarded := headers.Get("X-Forwarded-For")
    via := headers.Get("Via")

    if forwarded == "" && via == "" && externalIP != "" {
        return "elite" // 高匿
    }
    if forwarded != "" && !strings.Contains(forwarded, proxyHost) {
        return "anonymous"
    }
    return "transparent"
}
```

### 6. 智能调度策略

```go
type ProxySelector interface {
    Select(ctx context.Context, req *ProxyRequest) (*Proxy, error)
}

type ProxyRequest struct {
    TargetHost  string   // 目标主机
    Protocol    string   // 需要的代理协议
    Country     string   // 指定国家
    Anonymity   string   // 最低匿名度要求
    MaxLatency  int      // 最大延迟要求 (ms)
    ExcludeIPs  []string // 排除的代理 IP
}
```

#### 6.1 调度策略

```go
// 加权随机 (默认): 按成功率和延迟加权
type WeightedRandomSelector struct {
    store ProxyStore
}

func (s *WeightedRandomSelector) Select(ctx context.Context, req *ProxyRequest) (*Proxy, error) {
    candidates := s.store.Filter(req)
    if len(candidates) == 0 {
        return nil, ErrNoProxyAvailable
    }

    // 计算权重: 成功率 * (1000 / (延迟+1))
    var totalWeight float64
    weights := make([]float64, len(candidates))
    for i, p := range candidates {
        w := p.SuccessRate * (1000.0 / float64(p.AvgLatency+1))
        weights[i] = w
        totalWeight += w
    }

    // 加权随机选择
    r := rand.Float64() * totalWeight
    for i, w := range weights {
        r -= w
        if r <= 0 {
            return candidates[i], nil
        }
    }
    return candidates[len(candidates)-1], nil
}

// 轮询: 均匀分配请求
type RoundRobinSelector struct {
    counter atomic.Uint64
}

// 目标感知: 同一目标尽量使用不同代理
type TargetAwareSelector struct {
    targetHistory map[string][]string  // target → 最近使用的代理ID列表
    mu           sync.RWMutex
}

func (s *TargetAwareSelector) Select(ctx context.Context, req *ProxyRequest) (*Proxy, error) {
    s.mu.RLock()
    recentIDs := s.targetHistory[req.TargetHost]
    s.mu.RUnlock()

    candidates := s.store.Filter(req)
    // 排除最近用过的代理
    filtered := excludeRecent(candidates, recentIDs, 10) // 保留最近10个不同代理
    if len(filtered) == 0 {
        filtered = candidates // 代理不够时回退
    }

    proxy := weightedRandom(filtered)

    s.mu.Lock()
    s.targetHistory[req.TargetHost] = append(s.targetHistory[req.TargetHost], proxy.ID)
    if len(s.targetHistory[req.TargetHost]) > 20 {
        s.targetHistory[req.TargetHost] = s.targetHistory[req.TargetHost][10:]
    }
    s.mu.Unlock()

    return proxy, nil
}
```

#### 6.2 自动降级

```go
type ProxyFallbackChain struct {
    strategies []ProxySelector
}

func (c *ProxyFallbackChain) Select(ctx context.Context, req *ProxyRequest) (*Proxy, error) {
    for _, strategy := range c.strategies {
        proxy, err := strategy.Select(ctx, req)
        if err == nil {
            return proxy, nil
        }
    }
    // 所有代理不可用时，返回直连标记
    return &Proxy{Protocol: "direct"}, nil
}
```

### 7. 传输层集成

#### 7.1 代理感知的 HTTP Client

```go
type ProxiedHTTPClient struct {
    selector    ProxySelector
    baseClient  *http.Client
    retryCount  int
    onBan       func(proxy *Proxy, target string) // 封禁回调
}

func (c *ProxiedHTTPClient) Do(req *http.Request) (*http.Response, error) {
    var lastErr error

    for attempt := 0; attempt <= c.retryCount; attempt++ {
        proxy, err := c.selector.Select(req.Context(), &ProxyRequest{
            TargetHost: req.URL.Host,
            Protocol:   req.URL.Scheme,
        })
        if err != nil {
            return nil, fmt.Errorf("no proxy available: %w", err)
        }

        var transport *http.Transport
        if proxy.Protocol == "direct" {
            transport = http.DefaultTransport.(*http.Transport).Clone()
        } else {
            transport = &http.Transport{
                Proxy: http.ProxyURL(proxy.URL()),
            }
        }

        client := &http.Client{Transport: transport, Timeout: c.baseClient.Timeout}
        resp, err := client.Do(req)
        if err != nil {
            lastErr = err
            c.reportFailure(proxy, req.URL.Host)
            continue
        }

        // 检测是否被封禁 (返回 403/429/连接重置 等)
        if isBanResponse(resp) {
            c.reportBan(proxy, req.URL.Host)
            lastErr = fmt.Errorf("proxy %s banned by %s", proxy.Host, req.URL.Host)
            continue
        }

        c.reportSuccess(proxy)
        return resp, nil
    }

    return nil, fmt.Errorf("all proxy attempts failed: %w", lastErr)
}

func isBanResponse(resp *http.Response) bool {
    if resp.StatusCode == 403 || resp.StatusCode == 429 {
        return true
    }
    // 检查常见 WAF 拦截页面特征
    // Cloudflare, AWS WAF, ModSecurity 等
    return false
}
```

#### 7.2 代理感知的 TCP Dialer

```go
type ProxiedDialer struct {
    selector ProxySelector
    timeout  time.Duration
}

func (d *ProxiedDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    host, _, _ := net.SplitHostPort(addr)

    proxy, err := d.selector.Select(ctx, &ProxyRequest{
        TargetHost: host,
        Protocol:   "socks5",
    })
    if err != nil || proxy.Protocol == "direct" {
        return (&net.Dialer{Timeout: d.timeout}).DialContext(ctx, network, addr)
    }

    // SOCKS5 代理连接
    dialer, err := socksProxy.SOCKS5("tcp",
        fmt.Sprintf("%s:%d", proxy.Host, proxy.Port),
        &socksProxy.Auth{User: proxy.Username, Password: proxy.Password},
        &net.Dialer{Timeout: d.timeout},
    )
    if err != nil {
        return nil, err
    }

    return dialer.Dial(network, addr)
}
```

### 8. 封禁检测与自适应

```go
type BanDetector struct {
    banPatterns []BanPattern
    banStore    map[string]map[string]time.Time // proxy_ip → target → ban_time
    mu          sync.RWMutex
}

type BanPattern struct {
    Name       string
    StatusCode int
    BodyRegex  string
    HeaderKey  string
    HeaderVal  string
}

var defaultBanPatterns = []BanPattern{
    {Name: "Cloudflare Block", StatusCode: 403, BodyRegex: `Attention Required!|Cloudflare`},
    {Name: "AWS WAF Block", StatusCode: 403, BodyRegex: `<html><head><title>ERROR`},
    {Name: "Rate Limited", StatusCode: 429},
    {Name: "CAPTCHA", BodyRegex: `(?i)(captcha|recaptcha|hcaptcha)`},
    {Name: "IP Blocked", BodyRegex: `(?i)(ip.*(block|ban|deny)|access.denied)`},
}

func (d *BanDetector) MarkBanned(proxyIP, target string) {
    d.mu.Lock()
    if d.banStore[proxyIP] == nil {
        d.banStore[proxyIP] = make(map[string]time.Time)
    }
    d.banStore[proxyIP][target] = time.Now()
    d.mu.Unlock()
}

func (d *BanDetector) IsBanned(proxyIP, target string) bool {
    d.mu.RLock()
    defer d.mu.RUnlock()
    if banTime, ok := d.banStore[proxyIP][target]; ok {
        return time.Since(banTime) < 30*time.Minute // 封禁冷却时间
    }
    return false
}
```

### 9. 代理池 API

```
Proxy Pool
├── /api/v1/proxies
│   ├── GET    /                     代理列表 (筛选: protocol/country/anonymity/status)
│   ├── POST   /                     手动添加代理
│   ├── POST   /import               批量导入代理
│   ├── DELETE /:id                  删除代理
│   └── POST   /:id/check            手动检查单个代理
├── /api/v1/proxies/providers
│   ├── GET    /                     代理源列表
│   ├── POST   /                     添加代理源
│   ├── PUT    /:id                  更新代理源配置
│   ├── DELETE /:id                  删除代理源
│   └── POST   /:id/fetch            手动触发采集
├── /api/v1/proxies/stats
│   ├── GET    /overview              代理池概览 (总数/可用数/各协议分布)
│   ├── GET    /quality               质量统计 (成功率/延迟分布)
│   └── GET    /usage                 使用统计 (各目标消耗的代理数)
└── /api/v1/proxies/config
    ├── GET    /                     代理策略配置
    └── PUT    /                     更新代理策略
```

### 10. 代理池配置

```yaml
proxy_pool:
  enabled: true

  providers:
    - name: "paid_provider"
      type: "paid_api"
      api_url: "https://api.proxy-provider.com/v1/proxies"
      api_key: "${PROXY_API_KEY}"
      fetch_interval: "5m"
      options:
        country: "CN"
        protocol: "http,socks5"
        anonymity: "elite"

    - name: "self_hosted"
      type: "static"
      proxies:
        - "socks5://user:pass@10.0.1.100:1080"
        - "socks5://user:pass@10.0.1.101:1080"

    - name: "ssh_tunnels"
      type: "tunnel"
      tunnels:
        - type: "ssh"
          host: "jump1.example.com"
          port: 22
          local_port: 10800

  health_check:
    interval: "2m"
    timeout: "10s"
    test_urls:
      - "https://httpbin.org/ip"
      - "https://api.ipify.org"
    max_fail_count: 3           # 连续失败 N 次标记为 inactive

  selection:
    strategy: "target_aware"    # weighted_random, round_robin, target_aware
    min_anonymity: "elite"
    max_latency_ms: 5000
    ban_cooldown: "30m"
    retry_count: 3

  limits:
    max_pool_size: 1000
    min_available: 10           # 可用代理低于此值告警
    per_target_rate: 10         # 同一目标每秒最大请求
```

---

## 第二部分：监测范围

### 11. 监测范围总览

漏扫系统的监测覆盖以下维度：

```
监测范围
├── 1. 网络层
│   ├── IP/CIDR 范围
│   ├── 端口 (TCP/UDP)
│   ├── 网络协议 (TCP, UDP, ICMP, TLS)
│   └── IPv4 + IPv6
│
├── 2. 主机层
│   ├── 操作系统 (Linux, Windows, macOS)
│   ├── 系统服务 (SSH, RDP, FTP, SMB...)
│   ├── 安全配置 (密码策略, 权限, 审计)
│   └── 补丁状态
│
├── 3. Web 应用层
│   ├── Web 服务器 (Nginx, Apache, IIS, Tomcat...)
│   ├── Web 框架 (Spring, Django, Laravel, Express...)
│   ├── CMS / 中间件 (WordPress, Drupal, WebLogic, JBoss...)
│   ├── 前端技术栈 (React, Vue, Angular, jQuery...)
│   ├── Web 漏洞 (SQLi, XSS, SSRF, RCE, LFI/RFI, CSRF...)
│   └── 敏感信息泄露 (源码, 配置, 备份, API密钥)
│
├── 4. API 层
│   ├── REST API (OpenAPI/Swagger)
│   ├── GraphQL
│   ├── gRPC (proto 解析)
│   ├── WebSocket
│   └── OWASP API Top 10
│
├── 5. 数据库层
│   ├── 关系型 (MySQL, PostgreSQL, Oracle, MSSQL)
│   ├── NoSQL (MongoDB, Redis, Elasticsearch, CouchDB)
│   ├── 弱口令检测
│   ├── 未授权访问
│   └── 数据库版本漏洞
│
├── 6. 域名/DNS 层
│   ├── 子域名枚举
│   ├── DNS 记录 (A, AAAA, CNAME, MX, NS, TXT, SRV)
│   ├── 域名劫持检测
│   ├── DNSSEC 验证
│   └── DNS Zone Transfer
│
├── 7. 加密/证书层
│   ├── TLS 版本检测 (SSLv3, TLS1.0~1.3)
│   ├── 弱密码套件
│   ├── 证书有效性 (过期, 自签名, 域名不匹配)
│   ├── HSTS 配置
│   └── OCSP Stapling
│
├── 8. 云资产层
│   ├── S3/OSS Bucket 公开检测
│   ├── 云元数据泄露 (169.254.169.254)
│   ├── 云安全组配置
│   └── 容器/K8s 暴露
│
├── 9. 合规层
│   ├── CIS Benchmark (OS/DB/Web/Cloud/Container)
│   ├── 等保 2.0 (通信网络/区域边界/计算环境/管理中心)
│   ├── PCI-DSS
│   ├── HIPAA
│   └── 自定义安全基线
│
├── 10. 漏洞情报层
│   ├── CVE / CNVD / CNNVD
│   ├── CPE 匹配
│   ├── Exploit-DB PoC
│   ├── CISA KEV (已知被利用漏洞)
│   ├── Nuclei 社区模板
│   └── 0day 预警
│
├── 11. 攻击面层 (ASM)
│   ├── 资产变化监控 (新端口/新子域名/服务变更)
│   ├── 影子 IT 发现
│   ├── CDN/WAF 变更检测
│   ├── 证书透明度 (CT) 日志监控
│   └── 攻击面趋势分析
│
└── 12. 供应链层
    ├── 开源组件漏洞 (SCA)
    ├── 依赖关系分析
    ├── License 合规检查
    └── 恶意包检测
```

### 12. 各层监测能力矩阵

| 层 | 主动扫描 | 被动检测 | 合规检查 | 持续监控 |
|----|---------|---------|---------|---------|
| 网络层 | ✅ 端口扫描/服务探测 | ✅ 流量分析 | ✅ ACL检查 | ✅ 端口变化 |
| 主机层 | ✅ 漏洞验证 | ✅ 版本匹配 | ✅ CIS/等保 | ✅ 配置漂移 |
| Web应用层 | ✅ SQLi/XSS/RCE | ✅ 指纹识别 | ✅ 安全头检查 | ✅ 技术栈变更 |
| API层 | ✅ BOLA/注入 | ✅ 影子API发现 | ✅ 认证检查 | ✅ 端点变更 |
| 数据库层 | ✅ 弱口令/未授权 | ✅ 版本匹配 | ✅ 配置审计 | ✅ 暴露监控 |
| DNS层 | ✅ 子域名枚举 | ✅ CT日志监控 | ✅ DNSSEC | ✅ 记录变更 |
| 加密层 | ✅ TLS扫描 | ✅ 证书检测 | ✅ PCI-DSS | ✅ 证书过期 |
| 云资产层 | ✅ Bucket探测 | ✅ 元数据检测 | ✅ 安全组审计 | ✅ 配置变更 |
| 合规层 | — | — | ✅ 全量基线 | ✅ 配置漂移 |
| 情报层 | — | ✅ CVE匹配 | — | ✅ 新漏洞预警 |
| 攻击面层 | ✅ 全量发现 | ✅ CT/DNS监控 | — | ✅ 变化检测 |
| 供应链层 | ✅ SCA扫描 | ✅ 依赖匹配 | ✅ License | ✅ 新漏洞 |

### 13. 监测范围配置

#### 13.1 全局范围策略

```go
type ScopePolicy struct {
    ID          string      `json:"id" gorm:"primaryKey"`
    Name        string      `json:"name"`
    Type        string      `json:"type"` // whitelist, blacklist

    // 网络范围
    IncludeCIDRs  []string  `json:"include_cidrs" gorm:"serializer:json"`
    ExcludeCIDRs  []string  `json:"exclude_cidrs" gorm:"serializer:json"`
    IncludeDomains []string `json:"include_domains" gorm:"serializer:json"`
    ExcludeDomains []string `json:"exclude_domains" gorm:"serializer:json"`

    // 端口范围
    IncludePorts  string    `json:"include_ports"`   // 1-65535, top1000
    ExcludePorts  string    `json:"exclude_ports"`   // 如排除 80,443

    // 时间窗口
    ScanWindow    *TimeWindow `json:"scan_window" gorm:"serializer:json"`

    // 扫描强度
    MaxRPS        int       `json:"max_rps"`          // 全局每秒最大请求
    MaxConcurrent int       `json:"max_concurrent"`   // 最大并发
    
    CreatedAt   time.Time   `json:"created_at"`
    UpdatedAt   time.Time   `json:"updated_at"`
}

type TimeWindow struct {
    Enabled    bool   `json:"enabled"`
    StartTime  string `json:"start_time"`  // "22:00"
    EndTime    string `json:"end_time"`    // "06:00"
    Timezone   string `json:"timezone"`    // "Asia/Shanghai"
    Weekdays   []int  `json:"weekdays"`   // [1,2,3,4,5] = 工作日
}
```

#### 13.2 范围验证器

```go
type ScopeValidator struct {
    policy *ScopePolicy
}

func (v *ScopeValidator) IsInScope(target string) (bool, string) {
    ip := net.ParseIP(target)
    if ip != nil {
        return v.validateIP(ip)
    }

    // 域名/URL
    if strings.Contains(target, ".") {
        return v.validateDomain(target)
    }

    return false, "unknown target format"
}

func (v *ScopeValidator) validateIP(ip net.IP) (bool, string) {
    // 检查排除名单
    for _, cidr := range v.policy.ExcludeCIDRs {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return false, fmt.Sprintf("IP %s is in excluded CIDR %s", ip, cidr)
        }
    }

    // 检查包含名单 (如果设置了白名单模式)
    if len(v.policy.IncludeCIDRs) > 0 {
        for _, cidr := range v.policy.IncludeCIDRs {
            _, network, _ := net.ParseCIDR(cidr)
            if network.Contains(ip) {
                return true, ""
            }
        }
        return false, fmt.Sprintf("IP %s not in any included CIDR", ip)
    }

    return true, ""
}

func (v *ScopeValidator) IsInTimeWindow() bool {
    if v.policy.ScanWindow == nil || !v.policy.ScanWindow.Enabled {
        return true
    }
    // 检查当前时间是否在允许的扫描时间窗口内
    loc, _ := time.LoadLocation(v.policy.ScanWindow.Timezone)
    now := time.Now().In(loc)

    weekday := int(now.Weekday())
    if !contains(v.policy.ScanWindow.Weekdays, weekday) {
        return false
    }

    currentMinutes := now.Hour()*60 + now.Minute()
    startMinutes := parseTimeMinutes(v.policy.ScanWindow.StartTime)
    endMinutes := parseTimeMinutes(v.policy.ScanWindow.EndTime)

    if startMinutes <= endMinutes {
        return currentMinutes >= startMinutes && currentMinutes <= endMinutes
    }
    // 跨天 (如 22:00 ~ 06:00)
    return currentMinutes >= startMinutes || currentMinutes <= endMinutes
}
```

### 14. 监测范围 API

```
Scope Management
├── /api/v1/scope/policies
│   ├── GET    /                     范围策略列表
│   ├── POST   /                     创建范围策略
│   ├── PUT    /:id                  更新范围策略
│   ├── DELETE /:id                  删除范围策略
│   └── POST   /validate             验证目标是否在范围内
├── /api/v1/scope/coverage
│   ├── GET    /overview              监测覆盖率总览
│   ├── GET    /by-layer              按层统计覆盖情况
│   ├── GET    /gaps                  覆盖盲区分析
│   └── GET    /assets                各类资产数量统计
└── /api/v1/scope/schedule
    ├── GET    /windows               扫描时间窗口列表
    └── PUT    /windows/:id           更新时间窗口
```

### 15. 与现有模块的集成

```
proxy-and-scope.md (本文档)
│
├── 代理池
│   ├── → scan-engine.md       Pipeline 的 HTTP/TCP 请求经过代理池
│   ├── → modules.md           各扫描模块使用 ProxiedHTTPClient
│   ├── → asm.md               ASM 发现引擎使用代理池
│   └── → plugin-sandbox.md    沙箱的 SandboxDialer 可选经过代理
│
└── 监测范围
    ├── → scheduler.md         调度器在分发任务前验证范围
    ├── → scan-engine.md       Pipeline 入口校验目标范围
    ├── → asm.md               ASM 发现限制在范围内
    └── → scan-template.md     模板参数可引用全局范围策略
```
