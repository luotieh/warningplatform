# 漏洞扫描系统 — 漏洞情报中心设计

## 1. 总体架构

```
┌─────────────────────────────────────────────────────────────────┐
│                   漏洞情报中心 (Vulnerability Intelligence)      │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                  情报数据源                                  │ │
│  │  NVD │ CNVD │ CNNVD │ GitHub Advisory │ Exploit-DB │ KEV  │ │
│  └────────────────────────┬───────────────────────────────────┘ │
│                           │                                     │
│                           ▼                                     │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                 漏洞知识库 (VulnDB)                         │ │
│  │  CVE + CPE + CVSS + CWE + 影响版本 + 修复信息 + PoC 关联   │ │
│  └────────────────────────┬───────────────────────────────────┘ │
│                           │                                     │
│  指纹识别结果              │                                     │
│  (Product + Version       │                                     │
│   + CPE)                  │                                     │
│       │                   │                                     │
│       ▼                   ▼                                     │
│  ┌──────────────────────────────────┐                           │
│  │         自动关联引擎               │                           │
│  │  指纹 → CPE → CVE → PoC           │                           │
│  │  版本范围匹配 + 风险评分           │                           │
│  └──────────────────┬───────────────┘                           │
│                     │                                           │
│                     ▼                                           │
│  ┌──────────────────────────────────┐                           │
│  │  自动触发匹配的 PoC 检测          │                           │
│  │  优先级: KEV > CVSS高分 > 有EXP  │                           │
│  └──────────────────────────────────┘                           │
└─────────────────────────────────────────────────────────────────┘
```

## 2. 情报数据源

| 数据源 | URL / 接口 | 更新频率 | 数据量 |
|--------|-----------|----------|--------|
| **NVD** (NIST) | `https://services.nvd.nist.gov/rest/json/cves/2.0` | 实时 API | 25万+ CVE |
| **CNVD** | 爬取 `https://www.cnvd.org.cn` | 每日 | 18万+ |
| **CNNVD** | 爬取 | 每日 | 20万+ |
| **GitHub Advisory** | `https://api.github.com/advisories` | 实时 | 6万+ |
| **Exploit-DB** | `https://gitlab.com/exploit-database/exploitdb` | 每日 | 5万+ |
| **KEV** (CISA) | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | 每周 | 1100+ |
| **Nuclei Templates** | `https://github.com/projectdiscovery/nuclei-templates` | 每日 | 8000+ |

## 3. 数据模型

```sql
-- 漏洞知识库主表
CREATE TABLE vuln_knowledge (
    cve_id          VARCHAR(20) PRIMARY KEY,
    cnvd_id         VARCHAR(30),
    cnnvd_id        VARCHAR(30),
    title           TEXT NOT NULL,
    title_cn        TEXT,                              -- 中文标题
    description     TEXT,
    description_cn  TEXT,
    published_at    TIMESTAMPTZ,
    modified_at     TIMESTAMPTZ,

    -- 风险评估
    cvss3_score     NUMERIC(3,1),
    cvss3_vector    VARCHAR(100),
    cvss2_score     NUMERIC(3,1),
    severity        VARCHAR(10) NOT NULL,              -- critical/high/medium/low
    cwe_ids         TEXT[] DEFAULT '{}',

    -- 威胁情报标签
    is_kev          BOOLEAN DEFAULT FALSE,             -- CISA KEV (已在野利用)
    in_the_wild     BOOLEAN DEFAULT FALSE,
    has_public_exploit BOOLEAN DEFAULT FALSE,
    exploit_maturity VARCHAR(30) DEFAULT 'unproven',   -- unproven, poc, functional, high

    -- 修复信息
    fix_available   BOOLEAN DEFAULT FALSE,
    fixed_versions  JSONB DEFAULT '[]',
    patches         JSONB DEFAULT '[]',                -- [{url, vendor, date}]
    workaround      TEXT,

    -- 引用链接
    references      JSONB DEFAULT '[]',

    -- 元数据
    source          VARCHAR(20) NOT NULL,              -- nvd, cnvd, github, custom
    tags            TEXT[] DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_vk_severity ON vuln_knowledge(severity);
CREATE INDEX idx_vk_cvss ON vuln_knowledge(cvss3_score DESC);
CREATE INDEX idx_vk_published ON vuln_knowledge(published_at DESC);
CREATE INDEX idx_vk_kev ON vuln_knowledge(is_kev) WHERE is_kev = TRUE;
CREATE INDEX idx_vk_exploit ON vuln_knowledge(has_public_exploit) WHERE has_public_exploit = TRUE;
CREATE INDEX idx_vk_cwe ON vuln_knowledge USING GIN(cwe_ids);
CREATE INDEX idx_vk_tags ON vuln_knowledge USING GIN(tags);

-- CPE 影响范围表
CREATE TABLE vuln_affected_cpe (
    id                  SERIAL PRIMARY KEY,
    cve_id              VARCHAR(20) NOT NULL REFERENCES vuln_knowledge(cve_id),
    cpe23               VARCHAR(500) NOT NULL,         -- cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*
    vendor              VARCHAR(200),
    product             VARCHAR(200),
    version_start       VARCHAR(50),
    version_start_type  VARCHAR(10),                   -- including / excluding
    version_end         VARCHAR(50),
    version_end_type    VARCHAR(10),
    UNIQUE(cve_id, cpe23, version_start, version_end)
);
CREATE INDEX idx_vac_cve ON vuln_affected_cpe(cve_id);
CREATE INDEX idx_vac_vendor ON vuln_affected_cpe(vendor);
CREATE INDEX idx_vac_product ON vuln_affected_cpe(product);
CREATE INDEX idx_vac_cpe ON vuln_affected_cpe(cpe23);

-- PoC 关联表
CREATE TABLE vuln_poc_link (
    id      SERIAL PRIMARY KEY,
    cve_id  VARCHAR(20) NOT NULL REFERENCES vuln_knowledge(cve_id),
    poc_id  VARCHAR(200) NOT NULL,                    -- 模板文件名或ID
    source  VARCHAR(30) NOT NULL,                     -- nuclei, exploitdb, custom
    url     TEXT,
    UNIQUE(cve_id, poc_id)
);
CREATE INDEX idx_vpl_cve ON vuln_poc_link(cve_id);
CREATE INDEX idx_vpl_poc ON vuln_poc_link(poc_id);

-- 同步状态表
CREATE TABLE intel_sync_status (
    source      VARCHAR(30) PRIMARY KEY,
    last_sync   TIMESTAMPTZ,
    total_items BIGINT DEFAULT 0,
    status      VARCHAR(20) DEFAULT 'idle',           -- idle, syncing, error
    error       TEXT,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
```

## 4. 自动关联引擎

### 4.1 指纹 → CVE 关联

```go
type VulnIntelEngine struct {
    db         VulnKnowledgeDB
    pocIndex   PoCIndex
}

type CVEMatchResult struct {
    CVEID         string
    Title         string
    Severity      string
    CVSSScore     float64
    IsKEV         bool
    HasExploit    bool
    ExploitMaturity string
    FixedVersion  string
    MatchedPoCs   []string    // 可直接执行的 PoC ID
    Confidence    int         // 0-100（版本精确度）
}

func (e *VulnIntelEngine) MatchByFingerprint(fp Fingerprint) ([]CVEMatchResult, error) {
    // Step 1: 构造 CPE 查询
    // Product: "Apache HTTP Server", Version: "2.4.49"
    // → 查找 vuln_affected_cpe WHERE product ILIKE '%http_server%' AND vendor ILIKE '%apache%'
    //   AND version 在影响范围内

    affectedCVEs, err := e.db.FindCVEsByProduct(fp.Product, fp.Version)
    if err != nil {
        return nil, err
    }

    var results []CVEMatchResult
    for _, cve := range affectedCVEs {
        result := CVEMatchResult{
            CVEID:         cve.CVEID,
            Title:         cve.Title,
            Severity:      cve.Severity,
            CVSSScore:     cve.CVSS3Score,
            IsKEV:         cve.IsKEV,
            HasExploit:    cve.HasPublicExploit,
            ExploitMaturity: cve.ExploitMaturity,
            FixedVersion:  cve.GetFixedVersion(),
        }

        // Step 2: 计算置信度
        if fp.Version != "" {
            result.Confidence = 90 // 精确版本匹配
        } else {
            result.Confidence = 50 // 仅产品匹配，无版本
        }

        // Step 3: 查找关联 PoC
        pocs := e.pocIndex.FindByCVE(cve.CVEID)
        for _, poc := range pocs {
            result.MatchedPoCs = append(result.MatchedPoCs, poc.ID)
        }

        results = append(results, result)
    }

    // Step 4: 排序（KEV > CVSS > HasExploit）
    sortByRisk(results)

    return results, nil
}
```

### 4.2 版本范围匹配算法

```go
type VersionMatcher struct{}

// IsAffected 检查给定版本是否在漏洞影响范围内
func (vm *VersionMatcher) IsAffected(version string, affected AffectedCPE) bool {
    v, err := semver.Parse(normalizeVersion(version))
    if err != nil {
        return false // 无法解析版本，保守跳过
    }

    // 检查起始版本
    if affected.VersionStart != "" {
        start, err := semver.Parse(normalizeVersion(affected.VersionStart))
        if err != nil {
            return false
        }
        if affected.VersionStartType == "including" {
            if v.LT(start) { return false }
        } else {
            if v.LTE(start) { return false }
        }
    }

    // 检查结束版本
    if affected.VersionEnd != "" {
        end, err := semver.Parse(normalizeVersion(affected.VersionEnd))
        if err != nil {
            return false
        }
        if affected.VersionEndType == "including" {
            if v.GT(end) { return false }
        } else {
            if v.GTE(end) { return false }
        }
    }

    return true
}

// normalizeVersion 处理非标准版本号
// "2.4.49" → "2.4.49"
// "8.0_342" → "8.0.342"
// "5.3.x" → "5.3.0"
func normalizeVersion(v string) string {
    v = strings.ReplaceAll(v, "_", ".")
    v = strings.ReplaceAll(v, "-", ".")
    v = strings.TrimSuffix(v, ".x")
    parts := strings.Split(v, ".")
    for len(parts) < 3 {
        parts = append(parts, "0")
    }
    return strings.Join(parts[:3], ".")
}
```

## 5. 数据同步服务

```go
type IntelSyncService struct {
    db     VulnKnowledgeDB
    syncer map[string]IntelSyncer
}

type IntelSyncer interface {
    Source() string
    SyncIncremental(ctx context.Context, since time.Time) (int, error)
    SyncFull(ctx context.Context) (int, error)
}

// NVD 同步器
type NVDSyncer struct {
    apiKey  string
    baseURL string
    db      VulnKnowledgeDB
}

func (s *NVDSyncer) SyncIncremental(ctx context.Context, since time.Time) (int, error) {
    total := 0
    for startIndex := 0; ; startIndex += 2000 {
        params := url.Values{
            "lastModStartDate": {since.Format(time.RFC3339)},
            "lastModEndDate":   {time.Now().Format(time.RFC3339)},
            "resultsPerPage":   {"2000"},
            "startIndex":       {strconv.Itoa(startIndex)},
        }

        resp, err := s.fetchWithRetry(ctx, params)
        if err != nil {
            return total, err
        }

        for _, vuln := range resp.Vulnerabilities {
            entry := s.convertToEntry(vuln.CVE)
            s.db.Upsert(entry)

            // 同步 CPE 影响范围
            for _, config := range vuln.CVE.Configurations {
                for _, node := range config.Nodes {
                    for _, match := range node.CPEMatch {
                        s.db.UpsertAffectedCPE(entry.CVEID, match)
                    }
                }
            }
            total++
        }

        if startIndex+2000 >= resp.TotalResults {
            break
        }
    }
    return total, nil
}

// CISA KEV 同步
type KEVSyncer struct {
    url string
    db  VulnKnowledgeDB
}

func (s *KEVSyncer) SyncFull(ctx context.Context) (int, error) {
    req, _ := http.NewRequestWithContext(ctx, "GET", s.url, nil)
    client := &http.Client{Timeout: 30 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return 0, err
    }
    defer resp.Body.Close()

    var kev struct {
        Vulnerabilities []struct {
            CVEID string `json:"cveID"`
        } `json:"vulnerabilities"`
    }
    json.NewDecoder(resp.Body).Decode(&kev)

    count := 0
    for _, v := range kev.Vulnerabilities {
        if err := s.db.MarkAsKEV(v.CVEID); err == nil {
            count++
        }
    }
    return count, nil
}
```

### 同步调度配置

```yaml
intel:
  sync:
    nvd:
      enabled: true
      interval: "4h"
      full_sync_day: "sunday"
      api_key: "${NVD_API_KEY}"
    cnvd:
      enabled: true
      interval: "24h"
    kev:
      enabled: true
      interval: "24h"
    github_advisory:
      enabled: true
      interval: "6h"
      token: "${GITHUB_TOKEN}"
    nuclei_templates:
      enabled: true
      interval: "24h"
      repo: "https://github.com/projectdiscovery/nuclei-templates"
```

## 6. 情报 API

```
GET    /api/v1/intel/cves                  CVE 列表（分页、搜索、筛选）
GET    /api/v1/intel/cves/:id              CVE 详情
GET    /api/v1/intel/cves/:id/pocs         CVE 关联的 PoC
GET    /api/v1/intel/cves/:id/affected     CVE 影响的产品/版本
POST   /api/v1/intel/match                 传入指纹/CPE，返回匹配的 CVE
GET    /api/v1/intel/kev                   在野利用漏洞清单
GET    /api/v1/intel/trending              近期热门/新增高危漏洞
GET    /api/v1/intel/stats                 情报库统计
POST   /api/v1/intel/sync                 手动触发同步
GET    /api/v1/intel/sync/status           各数据源同步状态
```

### POST /api/v1/intel/match

```json
// Request: 传入指纹列表
{
  "fingerprints": [
    { "product": "Apache HTTP Server", "version": "2.4.49", "cpe": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" },
    { "product": "PHP", "version": "8.1.2" },
    { "product": "WordPress", "version": "6.4.3" }
  ]
}

// Response
{
  "matches": [
    {
      "fingerprint": { "product": "Apache HTTP Server", "version": "2.4.49" },
      "cves": [
        {
          "cve_id": "CVE-2021-41773",
          "title": "Apache HTTP Server Path Traversal",
          "severity": "critical",
          "cvss_score": 7.5,
          "is_kev": true,
          "has_exploit": true,
          "matched_pocs": ["CVE-2021-41773.yaml"],
          "fixed_version": "2.4.50",
          "confidence": 95
        }
      ],
      "total_cves": 5,
      "risk_summary": { "critical": 2, "high": 2, "medium": 1 }
    }
  ]
}
```

## 7. 指纹校验功能

### 7.1 在线指纹测试

允许用户输入 URL 或 IP，实时返回指纹识别结果及关联的已知漏洞：

```
POST /api/v1/fingerprint/verify
```

```json
// Request
{
  "target": "https://example.com",
  "options": {
    "probe_paths": true,     // 是否探测常见路径
    "favicon_hash": true,    // 是否抓取 favicon
    "jarm": false,           // 是否做 JARM 指纹（耗时较长）
    "banner_grab": true,     // 是否抓取 Banner
    "match_cve": true        // 是否关联 CVE
  }
}

// Response
{
  "target": "https://example.com",
  "scan_time_ms": 2340,
  "tech_stack": {
    "web_server": "Nginx/1.25.3",
    "language": "PHP/8.2.15",
    "framework": "WordPress/6.5.2",
    "os": "Linux (Ubuntu)",
    "cdn": "Cloudflare",
    "waf": "Cloudflare WAF"
  },
  "technologies": [
    {
      "name": "Nginx",
      "category": "web_server",
      "version": "1.25.3",
      "confidence": 95,
      "cpe": "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
      "evidence": [
        { "type": "header", "field": "Server", "value": "nginx/1.25.3" }
      ],
      "known_cves": 3,
      "risk": "low"
    },
    {
      "name": "WordPress",
      "category": "cms",
      "version": "6.5.2",
      "confidence": 98,
      "cpe": "cpe:2.3:a:wordpress:wordpress:6.5.2:*:*:*:*:*:*:*",
      "evidence": [
        { "type": "body", "field": "meta_generator", "value": "WordPress 6.5.2" },
        { "type": "body", "field": "path", "value": "/wp-content/" }
      ],
      "known_cves": 12,
      "risk": "medium"
    }
  ],
  "cve_summary": {
    "total": 15,
    "by_severity": { "critical": 1, "high": 4, "medium": 8, "low": 2 },
    "kev_count": 1,
    "with_exploit": 6
  },
  "top_risks": [
    {
      "cve_id": "CVE-2024-XXXX",
      "title": "WordPress Plugin XSS",
      "severity": "high",
      "cvss_score": 8.1,
      "is_kev": false,
      "has_exploit": true,
      "product": "WordPress",
      "affected_version": "<6.5.3"
    }
  ]
}
```

### 7.2 批量资产指纹校验

```
POST /api/v1/fingerprint/batch-verify
```

```json
{
  "targets": ["192.168.1.1:80", "example.com", "https://app.example.com"],
  "options": { "match_cve": true }
}
```

### 7.3 指纹对比（两次扫描之间的变化）

```
GET /api/v1/fingerprint/diff?asset_id=xxx&scan1=task_id_a&scan2=task_id_b
```

```json
{
  "asset": "192.168.1.100",
  "added": [
    { "name": "Redis", "version": "7.2", "category": "database" }
  ],
  "removed": [
    { "name": "Memcached", "version": "1.6", "category": "cache" }
  ],
  "version_changed": [
    {
      "name": "Nginx",
      "old_version": "1.24.0",
      "new_version": "1.25.3",
      "new_cves_fixed": 2,
      "new_cves_introduced": 0
    }
  ]
}
```
