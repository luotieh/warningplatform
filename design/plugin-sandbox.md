# 插件沙箱安全设计

## 1. 概述

PoC 插件来源多样（Nuclei 社区模板、用户自编写、自动生成），其中可能包含恶意逻辑或缺陷代码。插件沙箱的目标：**让 PoC 执行在受控环境中，即使插件代码有问题也不影响 Worker 稳定性和宿主安全**。

### 威胁模型

| 威胁 | 风险等级 | 场景 |
|------|---------|------|
| 恶意 PoC 读取宿主敏感文件 | 高 | `/etc/shadow`, 私钥, 数据库凭据 |
| PoC 反连宿主内网 | 高 | SSRF 回弹攻击 Worker 所在内网 |
| PoC 死循环/内存爆炸 | 中 | 导致 Worker OOM 或 CPU 打满 |
| PoC 修改宿主文件系统 | 高 | 植入后门/篡改配置 |
| PoC 开启监听端口 | 中 | Worker 节点变成跳板 |
| PoC 执行系统命令 | 高 | 通过 `os/exec` 执行任意命令 |

## 2. 沙箱架构

### 2.1 分层隔离

```
┌──────────────────────────────────────────────────────┐
│                    Worker 进程                        │
│  ┌────────────────────────────────────────────────┐  │
│  │              Plugin Manager                     │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │  │
│  │  │  YAML    │  │  CEL     │  │  Script      │ │  │
│  │  │  Engine  │  │  Engine  │  │  Sandbox     │ │  │
│  │  │(Nuclei)  │  │(google/  │  │  (Goja)      │ │  │
│  │  │          │  │ cel-go)  │  │              │ │  │
│  │  │ L1: 声明 │  │ L1: 表达 │  │ L2: 受限    │ │  │
│  │  │ 式沙箱   │  │ 式沙箱   │  │ 执行沙箱    │ │  │
│  │  └──────────┘  └──────────┘  └──────────────┘ │  │
│  │                                                │  │
│  │  ┌──────────────────────────────────────────┐  │  │
│  │  │         Resource Limiter                  │  │  │
│  │  │  CPU | Memory | Network | Goroutine | Time│  │  │
│  │  └──────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌────────────────────────────────────────────────┐  │
│  │    OS-Level Isolation (Linux only, optional)    │  │
│  │    seccomp │ namespaces │ cgroups               │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

### 2.2 安全级别

| 级别 | 适用 | 隔离手段 | 性能开销 |
|------|------|---------|---------|
| **L1 - 声明式** | YAML PoC, CEL 表达式 | 语法约束 + 受限函数集 | 极低 |
| **L2 - 受限脚本** | Goja (JS) 脚本 | 删除危险API + 资源限制 | 低 |
| **L3 - 进程隔离** | 不可信第三方插件 | 子进程 + seccomp + namespace | 中 |

## 3. L1: 声明式沙箱 (YAML / CEL)

### 3.1 YAML PoC 安全约束

YAML PoC 通过声明式 DSL 定义，天然受限：

```go
type YAMLSandbox struct {
    allowedProtocols  map[string]bool  // http, https, tcp, udp, dns, tls
    maxRequests       int              // 单个 PoC 最大请求数
    maxRedirects      int              // 最大重定向次数
    maxResponseSize   int64            // 最大响应体大小
    timeout           time.Duration    // 单请求超时
    totalTimeout      time.Duration    // PoC 总超时
    denyNetworks      []*net.IPNet     // 禁止访问的网段
}

func (s *YAMLSandbox) ValidateTemplate(tpl *NucleiTemplate) []ValidationError {
    var errs []ValidationError

    // 检查协议白名单
    for _, req := range tpl.AllRequests() {
        if !s.allowedProtocols[req.Protocol()] {
            errs = append(errs, ValidationError{
                Field: "protocol",
                Msg:   fmt.Sprintf("protocol %s not allowed", req.Protocol()),
            })
        }
    }

    // 检查请求数量
    if tpl.TotalRequestCount() > s.maxRequests {
        errs = append(errs, ValidationError{
            Field: "requests",
            Msg:   fmt.Sprintf("too many requests: %d > %d", tpl.TotalRequestCount(), s.maxRequests),
        })
    }

    // 检查 payload 是否包含危险模式
    for _, pattern := range dangerousPatterns {
        if pattern.Match(tpl.Raw()) {
            errs = append(errs, ValidationError{
                Field:    "payload",
                Msg:      fmt.Sprintf("dangerous pattern detected: %s", pattern.Name),
                Severity: "warning",
            })
        }
    }

    return errs
}
```

### 3.2 网络出口控制

所有 PoC 发起的网络请求经过受控的 HTTP Client / TCP Dialer：

```go
type SandboxDialer struct {
    denyNetworks []*net.IPNet
    denyPorts    map[int]bool
    resolver     *net.Resolver
}

func (d *SandboxDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
    host, portStr, _ := net.SplitHostPort(addr)
    port, _ := strconv.Atoi(portStr)

    // 端口黑名单
    if d.denyPorts[port] {
        return nil, fmt.Errorf("port %d is denied by sandbox policy", port)
    }

    // DNS 解析
    ips, err := d.resolver.LookupIPAddr(ctx, host)
    if err != nil {
        return nil, err
    }

    // IP 黑名单检查 (阻止 SSRF 回弹)
    for _, ip := range ips {
        for _, deny := range d.denyNetworks {
            if deny.Contains(ip.IP) {
                return nil, fmt.Errorf("target IP %s is in denied network %s", ip.IP, deny)
            }
        }
    }

    // 使用过滤后的 IP 直连 (绕过 DNS 二次解析 TOCTOU 漏洞)
    return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), portStr))
}
```

默认拒绝的网络段：

```go
var defaultDenyNetworks = []string{
    "127.0.0.0/8",      // loopback
    "10.0.0.0/8",       // RFC1918
    "172.16.0.0/12",    // RFC1918
    "192.168.0.0/16",   // RFC1918
    "169.254.0.0/16",   // link-local
    "::1/128",          // IPv6 loopback
    "fc00::/7",         // IPv6 ULA
    "fe80::/10",        // IPv6 link-local
}
```

### 3.3 CEL 表达式沙箱

CEL (Common Expression Language) 本身就是沙箱安全的表达式引擎，但仍需限制注入的函数：

```go
func NewCELSandboxEnv() (*cel.Env, error) {
    return cel.NewEnv(
        // 安全的内置类型
        cel.Types(&ScanContext{}, &HTTPResponse{}, &MatchResult{}),

        // 白名单函数
        cel.Function("contains", ...),
        cel.Function("matches",  ...),    // 正则匹配
        cel.Function("md5",      ...),
        cel.Function("sha256",   ...),
        cel.Function("base64",   ...),
        cel.Function("urlencode",...),
        cel.Function("len",      ...),
        cel.Function("toLower",  ...),
        cel.Function("toUpper",  ...),
        cel.Function("trim",     ...),

        // 禁止: 文件操作、系统命令、网络请求、反射
    )
}
```

## 4. L2: 脚本沙箱 (Goja)

### 4.1 Goja 运行时隔离

Goja 是纯 Go 的 JS 引擎，通过控制注入的全局对象实现沙箱：

```go
type ScriptSandbox struct {
    maxExecutionTime time.Duration
    maxMemoryBytes   int64
    maxStackDepth    int
}

func (s *ScriptSandbox) Execute(ctx context.Context, script string, vars map[string]interface{}) (*ScriptResult, error) {
    vm := goja.New()

    // 资源限制
    vm.SetMaxCallStackSize(s.maxStackDepth)

    // 注入安全的 API
    s.injectSafeAPIs(vm)

    // 注入变量
    for k, v := range vars {
        vm.Set(k, v)
    }

    // 超时控制
    timer := time.AfterFunc(s.maxExecutionTime, func() {
        vm.Interrupt("execution timeout")
    })
    defer timer.Stop()

    // 内存监控 (通过 goroutine 定期检查)
    memCtx, memCancel := context.WithCancel(ctx)
    defer memCancel()
    go s.monitorMemory(memCtx, vm)

    val, err := vm.RunString(script)
    if err != nil {
        return nil, fmt.Errorf("script execution failed: %w", err)
    }

    return &ScriptResult{Value: val.Export()}, nil
}
```

### 4.2 安全 API 白名单

```go
func (s *ScriptSandbox) injectSafeAPIs(vm *goja.Runtime) {
    // HTTP 客户端 (受 SandboxDialer 保护)
    vm.Set("http", map[string]interface{}{
        "get":  s.safeHTTPGet,
        "post": s.safeHTTPPost,
        "request": s.safeHTTPRequest,
    })

    // 编码工具
    vm.Set("encoding", map[string]interface{}{
        "base64Encode": base64Encode,
        "base64Decode": base64Decode,
        "urlEncode":    urlEncode,
        "urlDecode":    urlDecode,
        "hexEncode":    hexEncode,
        "hexDecode":    hexDecode,
    })

    // 哈希工具
    vm.Set("crypto", map[string]interface{}{
        "md5":    md5Hash,
        "sha1":   sha1Hash,
        "sha256": sha256Hash,
    })

    // 正则
    vm.Set("regex", map[string]interface{}{
        "match":   regexMatch,
        "findAll": regexFindAll,
    })

    // 日志 (输出到 PoC 执行日志，不写宿主文件系统)
    vm.Set("log", map[string]interface{}{
        "info":  s.logInfo,
        "debug": s.logDebug,
        "warn":  s.logWarn,
    })

    // 禁止注入的全局对象:
    // ❌ require, import, eval, Function
    // ❌ process, os, child_process, fs
    // ❌ setTimeout, setInterval (使用自定义的受控版本)
    // ❌ WebSocket, XMLHttpRequest (使用受控 http)
}
```

### 4.3 阻止逃逸的防护

```go
// 拦截危险的原型链操作
func (s *ScriptSandbox) installPrototypeGuards(vm *goja.Runtime) {
    // 阻止 constructor 逃逸: ({}).constructor.constructor("return this")()
    vm.RunString(`
        Object.defineProperty(Object.prototype, 'constructor', {
            get: function() { return Object; },
            set: function() {},
            configurable: false
        });
    `)
}
```

## 5. L3: 进程隔离 (Linux)

用于执行来源不可信的第三方插件，提供 OS 级隔离。

### 5.1 架构

```
Worker 进程 (主进程)
    │
    ├── [gRPC / Unix Socket]
    │
    └── Plugin Runner (子进程)
        ├── seccomp filter (禁止危险系统调用)
        ├── PID namespace (进程隔离)
        ├── Network namespace (网络隔离)
        ├── Mount namespace (文件系统隔离)
        ├── cgroups v2 (CPU/内存/IO限制)
        └── tmpfs 只读 rootfs + 可写 /tmp
```

### 5.2 实现

```go
type ProcessSandbox struct {
    maxCPUPercent  int
    maxMemoryBytes int64
    maxDiskBytes   int64
    maxNetBandwidth int64
    timeout        time.Duration
    allowedSyscalls []string
}

func (s *ProcessSandbox) Run(ctx context.Context, plugin *Plugin, target *ScanTarget) (*PluginResult, error) {
    // 创建临时工作目录
    workDir, err := os.MkdirTemp("", "plugin-sandbox-*")
    if err != nil {
        return nil, err
    }
    defer os.RemoveAll(workDir)

    // 序列化输入
    inputPath := filepath.Join(workDir, "input.json")
    if err := writeJSON(inputPath, &PluginInput{
        Plugin: plugin,
        Target: target,
    }); err != nil {
        return nil, err
    }

    // 构建沙箱子进程
    cmd := exec.CommandContext(ctx, os.Args[0], "--plugin-runner",
        "--input", inputPath,
        "--output", filepath.Join(workDir, "output.json"),
    )

    // Linux: 配置命名空间和 seccomp
    if runtime.GOOS == "linux" {
        cmd.SysProcAttr = &syscall.SysProcAttr{
            Cloneflags: syscall.CLONE_NEWPID |
                       syscall.CLONE_NEWNET |
                       syscall.CLONE_NEWNS,
        }
        s.applySeccomp(cmd)
        s.applyCgroups(cmd)
    }

    // 执行
    if err := cmd.Start(); err != nil {
        return nil, err
    }

    // 超时守护
    done := make(chan error, 1)
    go func() { done <- cmd.Wait() }()

    select {
    case err := <-done:
        if err != nil {
            return nil, fmt.Errorf("plugin exited with error: %w", err)
        }
    case <-time.After(s.timeout):
        cmd.Process.Kill()
        return nil, fmt.Errorf("plugin execution timed out after %v", s.timeout)
    }

    // 读取结果
    return readJSON[PluginResult](filepath.Join(workDir, "output.json"))
}
```

### 5.3 Seccomp 白名单

```go
var allowedSyscalls = []string{
    "read", "write", "close", "fstat",
    "mmap", "mprotect", "munmap", "brk",
    "clock_gettime", "nanosleep",
    "socket", "connect", "sendto", "recvfrom",  // 网络 (受 netns 限制)
    "epoll_create1", "epoll_ctl", "epoll_wait",
    "futex", "sigaltstack",
    "exit", "exit_group",
}

// 禁止: execve, fork, clone, open(O_CREAT), unlink, mount, ptrace, ...
```

## 6. 资源限制器

### 6.1 统一资源限制

无论哪个安全级别，所有 PoC 执行都受统一资源限制器约束：

```go
type ResourceLimiter struct {
    maxConcurrentPlugins int
    maxGoroutinesPerPoc  int
    maxMemoryPerPoc      int64
    maxNetBytesPerPoc    int64
    maxRequestsPerPoc    int
    maxExecutionTime     time.Duration
    semaphore            chan struct{}
}

func (rl *ResourceLimiter) Acquire(ctx context.Context) (ResourceToken, error) {
    select {
    case rl.semaphore <- struct{}{}:
        return &token{
            limiter:    rl,
            memTracker: newMemTracker(rl.maxMemoryPerPoc),
            netTracker: newNetTracker(rl.maxNetBytesPerPoc),
            reqCounter: newReqCounter(rl.maxRequestsPerPoc),
            startTime:  time.Now(),
        }, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    }
}

type ResourceToken interface {
    TrackMemory(bytes int64) error
    TrackNetwork(bytes int64) error
    TrackRequest() error
    CheckTimeout() error
    Release()
}
```

### 6.2 默认限制值

```go
var DefaultLimits = ResourceLimits{
    MaxConcurrentPlugins: 50,
    MaxGoroutinesPerPoc:  10,
    MaxMemoryPerPoc:      64 * 1024 * 1024,  // 64 MB
    MaxNetBytesPerPoc:    10 * 1024 * 1024,   // 10 MB
    MaxRequestsPerPoc:    100,
    MaxExecutionTime:     60 * time.Second,
}
```

## 7. 插件审计与信任链

### 7.1 信任级别

| 信任级别 | 来源 | 审计要求 | 执行级别 |
|---------|------|---------|---------|
| **Trusted** | 内置/团队审核 | 代码审查通过 | L1 (声明式) |
| **Community** | Nuclei 社区模板 | 自动静态检查 | L1 + 加强网络管控 |
| **User** | 用户上传 | 静态检查 + 人工可选 | L2 (脚本沙箱) |
| **Untrusted** | 外部/未审计 | 静态检查 + 动态监控 | L3 (进程隔离) |

### 7.2 静态检查器

```go
type PluginAuditor struct {
    rules []AuditRule
}

type AuditRule interface {
    Name() string
    Check(plugin *Plugin) []AuditFinding
}

// 内置审计规则
type DangerousPatternRule struct{}    // 检查危险字符串模式
type NetworkScopeRule struct{}        // 检查是否请求非目标地址
type ResourceUsageRule struct{}       // 估算资源消耗
type PayloadSafetyRule struct{}       // 检查 payload 安全性
type InformationLeakRule struct{}     // 检查是否泄露宿主信息

type AuditFinding struct {
    Rule     string  `json:"rule"`
    Severity string  `json:"severity"` // critical, high, medium, low, info
    Message  string  `json:"message"`
    Location string  `json:"location"` // 文件:行号 或 YAML路径
}
```

### 7.3 签名验证

可信插件通过 Ed25519 签名确保完整性：

```go
type PluginVerifier struct {
    trustedKeys map[string]ed25519.PublicKey
}

func (v *PluginVerifier) Verify(plugin *Plugin) error {
    if plugin.Signature == "" {
        return ErrUnsigned
    }

    sig, err := base64.StdEncoding.DecodeString(plugin.Signature)
    if err != nil {
        return fmt.Errorf("invalid signature format: %w", err)
    }

    content := plugin.ContentHash()

    for name, pubKey := range v.trustedKeys {
        if ed25519.Verify(pubKey, content, sig) {
            plugin.TrustLevel = "trusted"
            plugin.SignedBy = name
            return nil
        }
    }

    return ErrSignatureInvalid
}
```

## 8. 运行时监控

### 8.1 行为监控

```go
type RuntimeMonitor struct {
    metrics *PluginMetrics
    alerts  chan<- *SecurityAlert
}

type PluginMetrics struct {
    PluginID      string
    RequestCount  int64
    BytesSent     int64
    BytesReceived int64
    MemoryPeak    int64
    CPUTime       time.Duration
    ErrorCount    int64
    DeniedActions []DeniedAction
}

type DeniedAction struct {
    Time    time.Time
    Type    string  // network_denied, resource_exceeded, dangerous_pattern
    Detail  string
}
```

### 8.2 异常检测

当 PoC 执行出现以下行为时自动标记：

| 行为 | 响应 |
|------|------|
| 尝试访问内网IP | 阻断 + 记录 + 标记插件 |
| 请求量超限 | 阻断后续请求 |
| 内存使用超限 | 终止执行 |
| 执行超时 | 强制终止 |
| 大量相同请求 | 限流 + 告警 |
| 尝试DNS重绑定 | 阻断 + 标记插件 |

## 9. 配置

```yaml
sandbox:
  # 全局默认
  default_level: "L1"
  
  # 资源限制
  limits:
    max_concurrent_plugins: 50
    max_memory_per_poc: "64MB"
    max_net_bytes_per_poc: "10MB"
    max_requests_per_poc: 100
    max_execution_time: "60s"
  
  # 网络策略
  network:
    deny_private: true
    deny_loopback: true
    deny_link_local: true
    extra_deny_cidrs:
      - "100.64.0.0/10"    # CGNAT
    allow_dns_resolution: true
    max_redirects: 5

  # 信任策略
  trust:
    auto_trust_nuclei_official: true
    require_signature_for_trusted: true
    untrusted_use_process_isolation: true

  # 审计
  audit:
    auto_audit_on_upload: true
    block_critical_findings: true
    log_all_denied_actions: true
```

## 10. 安全级别选择流程

```
插件上传/导入
       │
       ↓
  ┌─────────────┐
  │  签名验证    │──── 签名有效 ──→ Trusted (L1)
  └─────────────┘
       │ 签名无效/无签名
       ↓
  ┌─────────────┐
  │  来源检查    │──── Nuclei官方 ──→ Community (L1+)
  └─────────────┘
       │ 其他来源
       ↓
  ┌─────────────┐
  │  静态审计    │──── 仅YAML/CEL ──→ User (L2)
  └─────────────┘
       │ 包含脚本/复杂逻辑
       ↓
  ┌─────────────┐
  │  危险检测    │──── 无危险发现 ──→ User (L2)
  └─────────────┘
       │ 检测到危险模式
       ↓
     Untrusted (L3)
```
