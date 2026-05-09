# 信息收集与漏洞扫描 - 迭代设计文档

## 1. 信息收集增强

### 1.1 端口扫描收集器

**文件**: `asm/collector_portscan.go`

**功能**: 对目标 IP/域名进行 TCP 端口扫描，发现开放端口和服务。

**核心设计**:
- 支持自定义端口列表，默认覆盖 23 个常见端口
- 支持 IP、域名、CIDR 三种种子类型
- 并发扫描，可配置最大连接数（默认 100）
- 超时控制（默认 2 秒/端口）
- 端口-服务映射（21=ftp, 22=ssh, 3306=mysql 等）

```go
type PortScanCollector struct {
    ports    []int       // 扫描端口列表
    timeout  time.Duration // 连接超时
    maxConns int         // 最大并发连接数
}
```

**CIDR 展开**: 自动将 CIDR 格式（如 `192.168.1.0/24`）展开为 IP 列表。

### 1.2 服务指纹探测收集器

**文件**: `asm/collector_fingerprint.go`

**功能**: 通过 HTTP 响应头、Cookie、页面内容识别目标技术栈。

**检测维度**:
| 维度 | 检测内容 | 置信度 |
|------|----------|--------|
| Server Header | nginx, apache, iis, openresty, caddy, lighttpd | high |
| X-Powered-By | PHP 版本识别 | high |
| X-Generator | wordpress, drupal, joomla, django, laravel 等 | high |
| Set-Cookie | phpsessid→PHP, jsessionid→Java, asp.net_sessionid→ASP.NET | medium |
| Content-Type | application/json → API 识别 | low |
| Body 内容 | vue.js, react, angular, jquery, bootstrap 等 | medium |

**Banner 抓取**: 对非 HTTP 服务（SSH、FTP、MySQL 等）进行 TCP Banner 抓取，通过特征匹配识别服务类型。

### 1.3 子域名爆破收集器

**文件**: `asm/collector_subdomain.go`

**功能**: 基于字典的子域名爆破，发现隐藏子域名。

**核心设计**:
- 内置 70+ 常见子域名（www, mail, admin, api, dev, staging 等）
- 支持自定义字典
- 使用 Google DNS (8.8.8.8) 进行解析，避免本地 DNS 污染
- 并发爆破，可配置最大连接数（默认 50）

### 1.4 被动 HTTP 收集器

**文件**: `asm/collector_subdomain.go` (PassiveHTTPCollector)

**功能**: 通过访问目标的公开 HTTP 资源文件，被动收集信息。

**收集内容**:
- `robots.txt` → 提取 Disallowed 路径，发现隐藏目录
- `sitemap.xml` → 提取所有 URL，发现页面数量
- `.well-known/security.txt` → 安全联系信息

### 1.5 收集器架构

```
┌─────────────────────────────────────────────────┐
│             ConcurrentDiscoveryEngine            │
├─────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │   DNS    │  │   RDNS   │  │      CT      │  │
│  │Collector │  │Collector │  │  Collector   │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │
│  │   Port   │  │  Fingerprint│ │  Subdomain   │  │
│  │  Scan    │  │ Collector │  │    Brute     │  │
│  └──────────┘  └──────────┘  └──────────────┘  │
│  ┌──────────┐  ┌──────────┐                    │
│  │  Banner  │  │ Passive  │                    │
│  │ Collector│  │  HTTP    │                    │
│  └──────────┘  └──────────┘                    │
└─────────────────────────────────────────────────┘
                      │
              streamDedupAndScore()
                      │
              ┌───────▼───────┐
              │ Risk Scorer   │
              └───────────────┘
```

## 2. 漏洞扫描增强

### 2.1 插件系统

**文件**: `scan/engine/plugin_system.go`

**架构设计**:

```go
type Plugin interface {
    Info() PluginInfo
    Run(ctx context.Context, target *Target) ([]*Finding, error)
}

type PluginRegistry struct {
    plugins map[string]Plugin
}
```

**插件类型**:
- `PluginWeb` - Web 应用漏洞
- `PluginNetwork` - 网络服务漏洞
- `PluginConfig` - 配置错误
- `PluginCVE` - CVE 已知漏洞

**扫描器**:
- `RunAll()` - 运行所有插件
- `RunByType()` - 按类型运行插件
- `RunSelected()` - 运行指定插件

**PluginModuleAdapter**: 将插件系统适配为 `ScanModule` 接口，可无缝集成到 Pipeline 中。

### 2.2 CVE 匹配引擎

**文件**: `scan/engine/cve_matcher.go`

**功能**: 根据目标的产品名和版本号，自动匹配已知 CVE 漏洞。

**核心设计**:
- 产品索引 + 版本索引双层加速
- 支持版本范围匹配（`<2.17.0`, `<=5.3.18`）
- 版本号规范化处理（去除 `v` 前缀等）
- 语义化版本比较

**内置 CVE 库** (8 个高危 CVE):
| CVE ID | 产品 | 影响版本 | CVSS |
|--------|------|----------|------|
| CVE-2021-44228 | Log4j | <2.17.0 | 10.0 |
| CVE-2021-41773 | Apache | 2.4.49 | 7.5 |
| CVE-2022-22965 | Spring | <5.3.18 | 9.8 |
| CVE-2023-44487 | Nginx | <1.25.3 | 7.5 |
| CVE-2021-3129 | Laravel | <8.4.3 | 9.8 |
| CVE-2022-0543 | Redis | <6.2.7 | 10.0 |
| CVE-2022-24999 | Express | <4.17.3 | 7.5 |
| CVE-2023-22515 | Confluence | <8.5.1 | 10.0 |

**匹配流程**:
```
Target (Product + Version + Fingerprints)
         │
    CVEDatabase.MatchTarget()
         │
    ├── Product Index Lookup
    ├── Version Range Check
    └── Fingerprint Match
         │
    [CVE Finding List]
```

### 2.3 Web 应用扫描模块

**文件**: `scan/engine/web_scanner.go`

**检测项**:

| 检测项 | 类型 | 严重性 |
|--------|------|--------|
| 安全头缺失 (HSTS, CSP, X-Frame-Options 等 6 项) | security_header | low~medium |
| 危险 HTTP 方法 (TRACE, DELETE, PUT, PATCH) | http_method | medium |
| 敏感文件暴露 (.env, .git, phpinfo, pprof 等 10 项) | info_disclosure | low~critical |
| 默认页面发现 (/admin, /login, /api) | discovery | info~medium |
| HTML 注释信息泄露 | info_disclosure | info |

### 2.4 配置检查模块

**文件**: `scan/engine/config_check.go`

**检测项**:

| 检测项 | 服务 | 严重性 |
|--------|------|--------|
| 默认/弱凭证 (MySQL, Redis, MongoDB, PostgreSQL) | 数据库 | critical |
| TLS 版本过低 (< TLS 1.2) | HTTPS | high |
| 弱加密套件 (RC4, 3DES) | HTTPS | medium |
| SSH v1 协议启用 | SSH | high |
| FTP 匿名访问 | FTP | medium |
| Redis 无认证 | Redis | critical |

## 3. 集成方式

### 3.1 ASM 信息收集集成

在 `discovery_concurrent.go` 中，通过 `extraCollectors` 参数注入新增收集器：

```go
engine := NewConcurrentDiscoveryEngine(10, 30*time.Second,
    NewPortScanCollector(nil, 2*time.Second, 100),
    NewServiceFingerprintCollector(10*time.Second),
    NewSubdomainBruteCollector(nil, 50, 3*time.Second),
    NewPassiveHTTPCollector(15*time.Second),
    NewBannerCollector(5*time.Second),
)
```

### 3.2 扫描 Pipeline 集成

新增模块注册到 `ModuleRegistry`：

```go
registry := NewModuleRegistry()
registry.Register(NewCVEMatcherModule(nil))
registry.Register(NewWebScannerModule(nil))
registry.Register(NewConfigCheckModule(10*time.Second))
registry.Register(NewPluginModuleAdapter(pluginRegistry, 10))
```

## 4. 预期效果

| 指标 | 优化前 | 优化后 | 提升 |
|------|--------|--------|------|
| 资产发现覆盖率 | DNS + CT | +端口扫描 + 子域名爆破 + 指纹 | +200% |
| 技术栈识别准确率 | 65% | 90%+ | +38% |
| CVE 自动匹配 | 无 | 8+ 高危 CVE | 新增 |
| 安全配置检查 | 无 | 6 类检测项 | 新增 |
| Web 安全检测 | 基础 | 4 类 20+ 检测项 | +300% |
| 插件扩展能力 | 无 | 完整插件系统 | 新增 |
