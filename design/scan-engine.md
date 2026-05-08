# 漏洞扫描系统 — 扫描引擎核心设计

## 1. 引擎架构

扫描引擎是 Worker 节点的核心，采用 **Stage Pipeline** 模型，每个扫描任务流经多个阶段，各阶段可独立并行。

```
                     ┌─────────────┐
                     │  Task Input  │
                     │ (targets +   │
                     │  config)     │
                     └──────┬──────┘
                            │
              ┌─────────────▼─────────────┐
              │    Stage 0: Host Discovery │
              │  ICMP Ping / TCP Ping      │
              │  过滤不可达主机            │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    Stage 1: Resolve        │
              │  DNS解析 / CDN检测 / IP归属│
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    Stage 2: Port Scan      │
              │  TCP Connect / SYN Scan    │
              │  + UDP Scan (协议探针)     │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    Stage 3: Fingerprint    │
              │  Banner/HTTP/Cert/Favicon  │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    Stage 4: Vuln Detect    │
              │  PoC匹配 / Fuzz / 弱口令  │
              └─────────────┬─────────────┘
                            │
              ┌─────────────▼─────────────┐
              │    Stage 5: Report         │
              │  去重 / 评分 / 存储 / 通知 │
              └───────────────────────────┘
```

## 2. Pipeline 核心接口

```go
// Stage 接口 - 每个扫描阶段实现此接口
type Stage interface {
    Name() string
    // Execute 处理输入目标，返回产出结果
    // 通过 context 控制超时和取消
    Execute(ctx context.Context, input *StageInput) (*StageOutput, error)
}

// StageInput 阶段输入
type StageInput struct {
    TaskID    string
    Targets   []*Target          // 待处理目标
    Config    *ScanConfig        // 扫描配置
    PrevResults map[string]any   // 上一阶段的结果
}

// StageOutput 阶段输出
type StageOutput struct {
    Targets     []*Target        // 传递给下一阶段的目标（可能增加/过滤）
    Results     []StageResult    // 本阶段产出
    Errors      []StageError     // 错误记录
    Metrics     StageMetrics     // 阶段指标
}

// Target 扫描目标
type Target struct {
    Host        string            // IP 或域名
    IP          net.IP
    Port        int
    Protocol    string            // tcp, udp, http, https
    Service     string            // 指纹识别后填充
    Product     string
    Version     string
    Fingerprints []Fingerprint
    Extra       map[string]any
}

// Pipeline 流水线编排器
type Pipeline struct {
    stages      []Stage
    pool        *WorkerPool
    rateLimiter *RateLimiter
    reporter    ResultReporter
    metrics     *MetricsCollector
}

func (p *Pipeline) Run(ctx context.Context, task *ScanTask) error {
    input := &StageInput{
        TaskID:  task.ID,
        Targets: task.Targets,
        Config:  task.Config,
    }

    for _, stage := range p.stages {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        output, err := stage.Execute(ctx, input)
        if err != nil {
            p.metrics.RecordStageError(stage.Name(), err)
            // 非致命错误：记录并继续
            if !isFatal(err) {
                continue
            }
            return fmt.Errorf("stage %s fatal: %w", stage.Name(), err)
        }

        // 上报阶段结果
        p.reporter.ReportStageResults(task.ID, stage.Name(), output.Results)
        p.metrics.RecordStageComplete(stage.Name(), output.Metrics)

        // 传递给下一阶段
        input = &StageInput{
            TaskID:      task.ID,
            Targets:     output.Targets,
            Config:      task.Config,
            PrevResults: mergeResults(input.PrevResults, output),
        }
    }
    return nil
}
```

## 3. Goroutine 池

```go
// WorkerPool 基于 channel 的 goroutine 池
type WorkerPool struct {
    maxWorkers  int
    taskCh      chan func()
    wg          sync.WaitGroup
    ctx         context.Context
    cancel      context.CancelFunc
    running     atomic.Int64
    completed   atomic.Int64
}

func NewWorkerPool(maxWorkers int) *WorkerPool {
    ctx, cancel := context.WithCancel(context.Background())
    p := &WorkerPool{
        maxWorkers: maxWorkers,
        taskCh:     make(chan func(), maxWorkers*2),
        ctx:        ctx,
        cancel:     cancel,
    }
    for i := 0; i < maxWorkers; i++ {
        p.wg.Add(1)
        go p.worker()
    }
    return p
}

func (p *WorkerPool) worker() {
    defer p.wg.Done()
    for {
        select {
        case <-p.ctx.Done():
            return
        case fn, ok := <-p.taskCh:
            if !ok { return }
            p.running.Add(1)
            fn()
            p.running.Add(-1)
            p.completed.Add(1)
        }
    }
}

func (p *WorkerPool) Submit(fn func()) error {
    select {
    case <-p.ctx.Done():
        return p.ctx.Err()
    case p.taskCh <- fn:
        return nil
    }
}

func (p *WorkerPool) Shutdown() {
    p.cancel()
    close(p.taskCh)
    p.wg.Wait()
}
```

## 4. 速率控制

```go
// RateLimiter 多维度速率控制
type RateLimiter struct {
    mu       sync.Mutex
    // 全局限速
    global   *rate.Limiter
    // 每目标限速 (key: "ip:port" or "domain")
    targets  map[string]*rate.Limiter
    // 默认每目标 QPS
    defaultTargetRPS int
    // 清理间隔
    cleanupInterval time.Duration
}

func NewRateLimiter(globalRPS, perTargetRPS int) *RateLimiter {
    rl := &RateLimiter{
        global:          rate.NewLimiter(rate.Limit(globalRPS), globalRPS),
        targets:         make(map[string]*rate.Limiter),
        defaultTargetRPS: perTargetRPS,
        cleanupInterval: 5 * time.Minute,
    }
    go rl.cleanupLoop()
    return rl
}

func (rl *RateLimiter) Wait(ctx context.Context, targetKey string) error {
    // 全局限速
    if err := rl.global.Wait(ctx); err != nil {
        return err
    }
    // 目标维度限速
    rl.mu.Lock()
    limiter, ok := rl.targets[targetKey]
    if !ok {
        limiter = rate.NewLimiter(rate.Limit(rl.defaultTargetRPS), rl.defaultTargetRPS)
        rl.targets[targetKey] = limiter
    }
    rl.mu.Unlock()
    return limiter.Wait(ctx)
}
```

## 5. 连接池

```go
// ConnPool HTTP 连接池，复用底层 TCP 连接
type ConnPool struct {
    httpClient  *http.Client
    tlsClient   *http.Client
    dialer      *net.Dialer
    tcpConns    sync.Pool     // 裸 TCP 连接池
}

func NewConnPool(maxConnsPerHost, maxIdleConns int, timeout time.Duration) *ConnPool {
    dialer := &net.Dialer{
        Timeout:   timeout,
        KeepAlive: 30 * time.Second,
    }

    transport := &http.Transport{
        DialContext:         dialer.DialContext,
        MaxIdleConns:        maxIdleConns,
        MaxConnsPerHost:     maxConnsPerHost,
        MaxIdleConnsPerHost: maxConnsPerHost / 2,
        IdleConnTimeout:     90 * time.Second,
        TLSHandshakeTimeout: 10 * time.Second,
        DisableCompression:  true,
    }

    tlsTransport := transport.Clone()
    tlsTransport.TLSClientConfig = &tls.Config{
        InsecureSkipVerify: true,
    }

    return &ConnPool{
        httpClient: &http.Client{Transport: transport, Timeout: timeout},
        tlsClient:  &http.Client{Transport: tlsTransport, Timeout: timeout},
        dialer:     dialer,
    }
}

// Do 发送 HTTP 请求（自动选择 HTTP/HTTPS 客户端）
func (cp *ConnPool) Do(req *http.Request) (*http.Response, error) {
    if req.URL.Scheme == "https" {
        return cp.tlsClient.Do(req)
    }
    return cp.httpClient.Do(req)
}

// DialTCP 获取裸 TCP 连接
func (cp *ConnPool) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
    return cp.dialer.DialContext(ctx, "tcp", addr)
}
```

## 6. 插件引擎

### 6.1 YAML PoC DSL

```go
// PoCTemplate YAML PoC 结构
type PoCTemplate struct {
    ID       string     `yaml:"id"`
    Info     PoCInfo    `yaml:"info"`
    Match    []PoCMatch `yaml:"match"`     // 前置指纹匹配
    Requests []PoCReq   `yaml:"requests"`  // HTTP 请求序列
    TCP      []PoCTCP   `yaml:"tcp"`       // TCP 探测（可选）
    Variables map[string]string `yaml:"variables"`
}

type PoCInfo struct {
    Name      string   `yaml:"name"`
    Severity  string   `yaml:"severity"`
    CVSSScore float64  `yaml:"cvss"`
    Tags      []string `yaml:"tags"`
    Reference []string `yaml:"reference"`
}

type PoCMatch struct {
    Type    string `yaml:"type"`     // fingerprint, port, service
    Service string `yaml:"service"`
    Product string `yaml:"product"`
    Version string `yaml:"version"` // 支持 semver range: ">=2.0, <2.5"
}

type PoCReq struct {
    Method   string            `yaml:"method"`
    Path     string            `yaml:"path"`
    Headers  map[string]string `yaml:"headers"`
    Body     string            `yaml:"body"`
    Raw      string            `yaml:"raw"`       // 原始请求（绕过框架处理）
    Matchers []Matcher         `yaml:"matchers"`
    Extractors []Extractor     `yaml:"extractors"`
    FollowRedirects bool       `yaml:"follow_redirects"`
    MaxRedirects    int        `yaml:"max_redirects"`
}

type Matcher struct {
    Type      string   `yaml:"type"`      // status, body, header, regex, binary, dsl
    Status    []int    `yaml:"status"`
    Words     []string `yaml:"words"`
    Regex     []string `yaml:"regex"`
    Binary    []string `yaml:"binary"`    // hex encoded
    DSL       []string `yaml:"dsl"`       // DSL 表达式
    Negative  bool     `yaml:"negative"`  // 反向匹配
    Condition string   `yaml:"condition"` // and / or
}

type Extractor struct {
    Type  string   `yaml:"type"`   // regex, json, xpath, kval
    Name  string   `yaml:"name"`
    Regex []string `yaml:"regex"`
    JSON  []string `yaml:"json"`
}
```

### 6.2 PoC 执行器

```go
type PoCExecutor struct {
    pool    *ConnPool
    limiter *RateLimiter
    timeout time.Duration
}

func (e *PoCExecutor) Execute(ctx context.Context, target *Target, poc *PoCTemplate) (*PoCResult, error) {
    // Step 1: 检查前置匹配条件
    if !e.matchFingerprint(target, poc.Match) {
        return nil, nil // skip
    }

    // Step 2: 变量替换
    vars := e.buildVars(target, poc.Variables)

    // Step 3: 逐步执行请求序列
    var lastResp *http.Response
    allMatched := true

    for i, req := range poc.Requests {
        httpReq, err := e.buildRequest(target, req, vars)
        if err != nil {
            return nil, fmt.Errorf("build request[%d]: %w", i, err)
        }

        // 限速
        targetKey := fmt.Sprintf("%s:%d", target.IP, target.Port)
        if err := e.limiter.Wait(ctx, targetKey); err != nil {
            return nil, err
        }

        resp, err := e.pool.Do(httpReq)
        if err != nil {
            return nil, fmt.Errorf("request[%d]: %w", i, err)
        }
        defer resp.Body.Close()
        lastResp = resp

        // 提取变量
        for _, ext := range req.Extractors {
            extracted := e.extract(resp, ext)
            if extracted != "" {
                vars[ext.Name] = extracted
            }
        }

        // 匹配检查
        if !e.matchResponse(resp, req.Matchers) {
            allMatched = false
            break
        }
    }

    if !allMatched {
        return nil, nil
    }

    return &PoCResult{
        PluginID:  poc.ID,
        Name:      poc.Info.Name,
        Severity:  poc.Info.Severity,
        Target:    target,
        Evidence:  e.buildEvidence(lastResp),
        Variables: vars,
    }, nil
}
```

## 7. 指纹匹配引擎

```go
// FingerprintDB 指纹数据库
type FingerprintDB struct {
    // HTTP 指纹
    httpFingerprints []HTTPFingerprint
    // 服务指纹（Banner + Probe）
    serviceProbes    []ServiceProbe
    // Favicon hash 映射
    faviconMap       map[string]string   // md5 -> product
    // 预编译正则
    compiledRegex    map[string]*regexp.Regexp
}

type HTTPFingerprint struct {
    Product    string
    Version    string   // 正则提取
    Category   string   // cms, framework, webserver, language, os, waf, cdn
    Matchers   []FPMatcher
    Confidence int      // 0-100
}

type FPMatcher struct {
    Type     string   // header, body, title, favicon_hash, url, cookie, meta, cert
    Field    string   // 具体字段名
    Keywords []string // 关键词列表
    Regex    string   // 正则匹配
}

// Match 对 HTTP 响应进行指纹匹配
func (db *FingerprintDB) MatchHTTP(resp *HTTPResponse) []Fingerprint {
    var results []Fingerprint

    for _, fp := range db.httpFingerprints {
        if matched, version := db.matchHTTPFP(resp, &fp); matched {
            results = append(results, Fingerprint{
                Category:   fp.Category,
                Product:    fp.Product,
                Version:    version,
                Confidence: fp.Confidence,
                Source:     "http",
            })
        }
    }

    // Favicon hash
    if resp.FaviconHash != "" {
        if product, ok := db.faviconMap[resp.FaviconHash]; ok {
            results = append(results, Fingerprint{
                Category:   "cms",
                Product:    product,
                Confidence: 90,
                Source:     "favicon",
            })
        }
    }

    return dedupFingerprints(results)
}
```

## 8. 错误处理与重试

```go
// RetryPolicy 重试策略
type RetryPolicy struct {
    MaxRetries     int
    InitialBackoff time.Duration
    MaxBackoff     time.Duration
    RetryableErrs  []error  // 可重试的错误类型
}

func (p *RetryPolicy) Execute(ctx context.Context, fn func() error) error {
    var lastErr error
    backoff := p.InitialBackoff

    for attempt := 0; attempt <= p.MaxRetries; attempt++ {
        if attempt > 0 {
            select {
            case <-ctx.Done():
                return ctx.Err()
            case <-time.After(backoff):
            }
            backoff = min(backoff*2, p.MaxBackoff)
        }

        lastErr = fn()
        if lastErr == nil {
            return nil
        }

        if !p.isRetryable(lastErr) {
            return lastErr
        }
    }
    return fmt.Errorf("max retries exceeded: %w", lastErr)
}

// 错误分类
func classifyError(err error) ErrorClass {
    if errors.Is(err, context.DeadlineExceeded) ||
       errors.Is(err, context.Canceled) {
        return ErrCancelled
    }
    var netErr net.Error
    if errors.As(err, &netErr) {
        if netErr.Timeout() {
            return ErrTimeout  // 可重试
        }
        return ErrNetwork      // 可重试
    }
    var dnsErr *net.DNSError
    if errors.As(err, &dnsErr) {
        return ErrDNS          // 不重试
    }
    return ErrUnknown
}
```

## 9. 指标收集

```go
type MetricsCollector struct {
    mu sync.Mutex

    // 计数器
    hostsScanned    atomic.Int64
    portsScanned    atomic.Int64
    requestsSent    atomic.Int64
    vulnsFound      atomic.Int64
    errorsCount     atomic.Int64

    // 延迟直方图
    latencies       []time.Duration

    // 每阶段计时
    stageDurations  map[string]time.Duration

    // 最后更新时间
    lastUpdate      time.Time
}

func (m *MetricsCollector) Snapshot() Metrics {
    m.mu.Lock()
    defer m.mu.Unlock()

    return Metrics{
        HostsScanned:  m.hostsScanned.Load(),
        PortsScanned:  m.portsScanned.Load(),
        RequestsSent:  m.requestsSent.Load(),
        VulnsFound:    m.vulnsFound.Load(),
        ErrorsCount:   m.errorsCount.Load(),
        StageDurations: m.stageDurations,
        AvgLatency:    calcAvgLatency(m.latencies),
    }
}
```

## 10. 引擎配置

```go
type EngineConfig struct {
    // 并发控制
    MaxConcurrentScans   int   `yaml:"max_concurrent_scans" default:"500"`
    MaxConcurrentPerHost int   `yaml:"max_concurrent_per_host" default:"10"`

    // 速率限制
    GlobalRPS           int    `yaml:"global_rps" default:"1000"`
    PerTargetRPS        int    `yaml:"per_target_rps" default:"50"`

    // 超时
    ConnectTimeout      time.Duration `yaml:"connect_timeout" default:"5s"`
    ReadTimeout         time.Duration `yaml:"read_timeout" default:"10s"`
    PoCTimeout          time.Duration `yaml:"poc_timeout" default:"30s"`
    StageTimeout        time.Duration `yaml:"stage_timeout" default:"10m"`

    // 连接池
    MaxIdleConns        int    `yaml:"max_idle_conns" default:"1000"`
    MaxConnsPerHost     int    `yaml:"max_conns_per_host" default:"20"`

    // 重试
    MaxRetries          int    `yaml:"max_retries" default:"2"`

    // 插件
    PluginDir           string `yaml:"plugin_dir" default:"./plugins"`
    PluginTimeout       time.Duration `yaml:"plugin_timeout" default:"30s"`

    // 端口扫描
    PortScanMode        string `yaml:"port_scan_mode" default:"connect"` // connect, syn
    DefaultPorts        string `yaml:"default_ports" default:"top1000"`
}
```
