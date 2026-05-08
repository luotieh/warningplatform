# 漏洞扫描系统 — 高级检测与智能化设计

## 1. 原理扫描与实际扫描分离

### 1.1 概念定义

| 类型 | 名称 | 说明 | 风险 | 速度 | 准确度 |
|------|------|------|------|------|--------|
| **原理扫描** | Passive/Inference Scan | 基于版本号、指纹、配置信息**推断**漏洞是否存在，**不发送攻击载荷** | 零风险 | 极快 | 中（可能误报） |
| **实际扫描** | Active/Verification Scan | 发送 PoC 载荷**实际验证**漏洞是否可利用 | 低~中 | 较慢 | 高（几乎无误报） |

### 1.2 两阶段检测架构

```
                     ┌──────────────────────────────────────┐
                     │          Scan Task Config             │
                     │  mode: "inference" | "verify" | "full"│
                     └──────────────────┬───────────────────┘
                                        │
                     ┌──────────────────▼───────────────────┐
                     │     Stage 1: 原理扫描 (Inference)     │
                     │                                       │
                     │  输入: 指纹 + 版本 + 配置信息          │
                     │                                       │
                     │  检测方法:                             │
                     │  ① 版本比对 → CVE 影响范围匹配         │
                     │  ② 配置审计 → 安全头/TLS/CORS 检查    │
                     │  ③ 特征比对 → 已知脆弱特征匹配         │
                     │  ④ 被动分析 → 响应中的敏感信息          │
                     │                                       │
                     │  输出: 潜在漏洞列表 (待验证)            │
                     │  状态: status = "inferred"             │
                     └──────────────────┬───────────────────┘
                                        │
                             mode == "inference" ?
                            ┌──── yes ─────┐
                            ▼              │
                     ┌─────────────┐       │
                     │ 直接输出     │       │
                     │ 推断结果     │       │
                     └─────────────┘       │
                                    no ────┘
                                        │
                     ┌──────────────────▼───────────────────┐
                     │     Stage 2: 实际扫描 (Verify)        │
                     │                                       │
                     │  输入: 原理扫描的潜在漏洞列表           │
                     │                                       │
                     │  检测方法:                             │
                     │  ① PoC 验证 → Nuclei/自研模板执行      │
                     │  ② Fuzz 测试 → SQLi/XSS/SSRF 注入     │
                     │  ③ 认证测试 → 弱口令/默认凭据           │
                     │  ④ 利用验证 → 安全的 EXP 执行           │
                     │                                       │
                     │  输出: 确认漏洞 (已验证)                │
                     │  状态: status = "confirmed"            │
                     └──────────────────────────────────────┘
```

### 1.3 扫描模式配置

```go
type ScanMode string

const (
    ScanModeInference ScanMode = "inference" // 仅原理扫描
    ScanModeVerify    ScanMode = "verify"    // 仅实际验证（跳过推断）
    ScanModeFull      ScanMode = "full"      // 原理 + 验证（推荐）
    ScanModeSafe      ScanMode = "safe"      // 仅被动检测（零攻击载荷）
)

type ScanConfig struct {
    Mode           ScanMode `yaml:"mode" json:"mode"`
    // 原理扫描配置
    Inference      InferenceConfig `yaml:"inference" json:"inference"`
    // 实际扫描配置
    Verification   VerifyConfig    `yaml:"verification" json:"verification"`
}

type InferenceConfig struct {
    Enabled          bool `yaml:"enabled" json:"enabled"`
    VersionMatch     bool `yaml:"version_match" json:"version_match"`       // CVE 版本匹配
    ConfigAudit      bool `yaml:"config_audit" json:"config_audit"`         // 安全配置审计
    PassiveAnalysis  bool `yaml:"passive_analysis" json:"passive_analysis"` // 被动信息分析
    MinConfidence    int  `yaml:"min_confidence" json:"min_confidence"`     // 最低置信度阈值 (0-100)
}

type VerifyConfig struct {
    Enabled         bool     `yaml:"enabled" json:"enabled"`
    PoCVerify       bool     `yaml:"poc_verify" json:"poc_verify"`
    FuzzTest        bool     `yaml:"fuzz_test" json:"fuzz_test"`
    WeakPassTest    bool     `yaml:"weak_pass_test" json:"weak_pass_test"`
    MaxPayloadsPerParam int  `yaml:"max_payloads_per_param" json:"max_payloads_per_param"`
    SkipSeverity    []string `yaml:"skip_severity" json:"skip_severity"` // 跳过验证的等级，如 ["low","info"]
    SafePayloadsOnly bool   `yaml:"safe_payloads_only" json:"safe_payloads_only"` // 仅使用无害 payload
}
```

### 1.4 原理扫描检测器

```go
type InferenceDetector struct {
    intelEngine *VulnIntelEngine
}

type InferredVuln struct {
    CVEID        string
    Title        string
    Severity     string
    CVSSScore    float64
    Confidence   int     // 0-100
    Basis        string  // 推断依据
    //  "version_match": 版本在影响范围内
    //  "config_issue": 配置缺陷
    //  "passive_detect": 被动发现
    Product      string
    Version      string
    FixedVersion string
    HasPoC       bool    // 是否有可验证的 PoC
}

func (d *InferenceDetector) Detect(ctx context.Context, target *Target) ([]InferredVuln, error) {
    var results []InferredVuln

    // ① 版本匹配推断
    for _, fp := range target.Fingerprints {
        cveMatches, err := d.intelEngine.MatchByFingerprint(fp)
        if err != nil { continue }
        for _, cve := range cveMatches {
            results = append(results, InferredVuln{
                CVEID:        cve.CVEID,
                Title:        cve.Title,
                Severity:     cve.Severity,
                CVSSScore:    cve.CVSSScore,
                Confidence:   cve.Confidence,
                Basis:        "version_match",
                Product:      fp.Product,
                Version:      fp.Version,
                FixedVersion: cve.FixedVersion,
                HasPoC:       len(cve.MatchedPoCs) > 0,
            })
        }
    }

    // ② 安全配置审计（被动，不发送攻击载荷）
    configIssues := d.auditConfig(target)
    results = append(results, configIssues...)

    // ③ 被动信息分析（从已有响应中提取）
    passiveFindings := d.passiveAnalyze(target)
    results = append(results, passiveFindings...)

    return results, nil
}

func (d *InferenceDetector) auditConfig(target *Target) []InferredVuln {
    var results []InferredVuln

    if target.HTTPResponse != nil {
        headers := target.HTTPResponse.Header

        // HSTS 缺失
        if headers.Get("Strict-Transport-Security") == "" && target.Protocol == "https" {
            results = append(results, InferredVuln{
                Title: "缺少 HSTS 安全头", Severity: "low",
                Confidence: 100, Basis: "config_issue",
            })
        }
        // CSP 缺失
        if headers.Get("Content-Security-Policy") == "" {
            results = append(results, InferredVuln{
                Title: "缺少 Content-Security-Policy", Severity: "low",
                Confidence: 100, Basis: "config_issue",
            })
        }
        // CORS 宽松
        if headers.Get("Access-Control-Allow-Origin") == "*" {
            results = append(results, InferredVuln{
                Title: "CORS 配置过于宽松 (Allow-Origin: *)", Severity: "medium",
                Confidence: 95, Basis: "config_issue",
            })
        }
        // TLS 版本低
        if target.TLSVersion > 0 && target.TLSVersion < 0x0303 { // < TLS 1.2
            results = append(results, InferredVuln{
                Title: "TLS 版本过低", Severity: "high",
                Confidence: 100, Basis: "config_issue",
            })
        }
    }
    return results
}
```

### 1.5 漏洞状态流转

```
原理扫描发现 → status: "inferred" (推断)
                    │
                    ├─ 有 PoC → 自动进入实际验证
                    │                │
                    │                ├─ 验证成功 → status: "confirmed" (已确认)
                    │                └─ 验证失败 → status: "unverified" (无法验证)
                    │
                    └─ 无 PoC → 保持 "inferred"
                                     │
                                     └─ 人工确认/忽略
```

| 状态 | 说明 | 前端显示 |
|------|------|----------|
| `inferred` | 原理扫描推断存在，未验证 | 黄色标记 "待验证" |
| `confirmed` | PoC 实际验证确认存在 | 红色标记 "已确认" |
| `unverified` | 有 PoC 但验证未通过 | 灰色标记 "未验证通过" |
| `false_positive` | 确认为误报 | 删除线 |
| `fixed` | 已修复 | 绿色标记 |

---

## 2. 指纹自主迭代

### 2.1 指纹学习系统

```
┌──────────────────────────────────────────────────────────┐
│                 指纹自主迭代系统                            │
│                                                          │
│  ┌─────────────────────────────────────────────────────┐ │
│  │  数据采集层                                          │ │
│  │                                                     │ │
│  │  • 每次扫描的 HTTP 响应（headers, body, favicon）     │ │
│  │  • 已知指纹识别结果 (标注数据)                         │ │
│  │  • 用户手动标注/纠正的指纹                             │ │
│  │  • 公开指纹库更新 (Wappalyzer, etc.)                  │ │
│  └───────────────────────┬─────────────────────────────┘ │
│                          │                                │
│  ┌───────────────────────▼─────────────────────────────┐ │
│  │  特征提取层                                          │ │
│  │                                                     │ │
│  │  • HTTP Header 特征向量                               │ │
│  │  • HTML Body 关键词 / 结构特征                         │ │
│  │  • URL 路径模式                                       │ │
│  │  • Favicon hash / 资源 hash                           │ │
│  │  • 响应时间 / 大小分布特征                              │ │
│  │  • TLS 证书特征                                       │ │
│  └───────────────────────┬─────────────────────────────┘ │
│                          │                                │
│  ┌───────────────────────▼─────────────────────────────┐ │
│  │  规则生成层                                          │ │
│  │                                                     │ │
│  │  方案 A: 统计规则挖掘（轻量，无 ML 依赖）              │ │
│  │    - 高频特征提取 → 自动生成 YAML 规则                 │ │
│  │    - 置信度自动计算                                    │ │
│  │                                                     │ │
│  │  方案 B: ML 分类器（准确度更高）                       │ │
│  │    - 文本特征 + TF-IDF → 随机森林/XGBoost              │ │
│  │    - 响应体 embedding → KNN / 聚类                    │ │
│  └───────────────────────┬─────────────────────────────┘ │
│                          │                                │
│  ┌───────────────────────▼─────────────────────────────┐ │
│  │  验证与发布层                                         │ │
│  │                                                     │ │
│  │  • 自动生成的规则先进入 "候选" 状态                     │ │
│  │  • 用已知标注数据验证准确率                             │ │
│  │  • 准确率 > 90% 自动启用                               │ │
│  │  • 准确率 60-90% 标记为人工审核                         │ │
│  │  • 准确率 < 60% 丢弃                                  │ │
│  └─────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────┘
```

### 2.2 统计规则挖掘（方案 A，推荐首选）

```go
// FingerprintLearner 指纹自学习器
type FingerprintLearner struct {
    db         FingerprintSampleDB
    minSamples int // 至少需要多少样本才生成规则
    minConfidence float64
}

type FingerprintSample struct {
    Product     string
    Version     string
    URL         string
    Headers     map[string]string
    BodyHash    string
    BodyKeywords []string
    FaviconHash string
    Source      string // "known_rule", "user_label", "wappalyzer"
}

// LearnFromSamples 从样本中挖掘高频特征，生成指纹规则
func (l *FingerprintLearner) LearnFromSamples(product string) (*FingerprintRule, error) {
    samples := l.db.GetSamplesByProduct(product)
    if len(samples) < l.minSamples {
        return nil, fmt.Errorf("insufficient samples: %d < %d", len(samples), l.minSamples)
    }

    // 统计各特征出现频率
    headerFreq := make(map[string]map[string]int) // field → value → count
    keywordFreq := make(map[string]int)
    faviconFreq := make(map[string]int)

    for _, s := range samples {
        for k, v := range s.Headers {
            if headerFreq[k] == nil { headerFreq[k] = make(map[string]int) }
            headerFreq[k][v]++
        }
        for _, kw := range s.BodyKeywords {
            keywordFreq[kw]++
        }
        if s.FaviconHash != "" {
            faviconFreq[s.FaviconHash]++
        }
    }

    total := len(samples)
    var rules []FPMatcherRule

    // 高频 Header 特征（出现率 > 80%）
    for field, values := range headerFreq {
        for value, count := range values {
            if float64(count)/float64(total) > 0.8 {
                rules = append(rules, FPMatcherRule{
                    Type: "header", Field: field, Value: value,
                    Confidence: int(float64(count) / float64(total) * 100),
                })
            }
        }
    }

    // 高频 Body 关键词（出现率 > 70%）
    for kw, count := range keywordFreq {
        if float64(count)/float64(total) > 0.7 {
            rules = append(rules, FPMatcherRule{
                Type: "body", Value: kw,
                Confidence: int(float64(count) / float64(total) * 100),
            })
        }
    }

    // Favicon
    for hash, count := range faviconFreq {
        if float64(count)/float64(total) > 0.9 {
            rules = append(rules, FPMatcherRule{
                Type: "favicon", Value: hash, Confidence: 95,
            })
        }
    }

    if len(rules) == 0 {
        return nil, fmt.Errorf("no significant features found for %s", product)
    }

    return &FingerprintRule{
        Product:  product,
        Category: "auto_learned",
        Rules:    rules,
        Status:   "candidate", // 候选状态，待验证
        LearnedAt: time.Now(),
        SampleCount: total,
    }, nil
}
```

### 2.3 指纹样本采集

```go
// SampleCollector 扫描时自动采集指纹样本
type SampleCollector struct {
    db FingerprintSampleDB
}

// CollectFromScan 每次指纹识别成功后，自动记录为训练样本
func (c *SampleCollector) CollectFromScan(target *Target, matchResult []Fingerprint) {
    for _, fp := range matchResult {
        if fp.Confidence < 80 {
            continue // 只采集高置信度的结果作为训练数据
        }

        sample := FingerprintSample{
            Product:      fp.Product,
            Version:      fp.Version,
            URL:          target.URL(),
            Headers:      flattenHeaders(target.HTTPResponse.Header),
            BodyKeywords: extractKeywords(target.ResponseBody),
            FaviconHash:  target.FaviconHash,
            Source:       "auto_scan",
        }
        c.db.Save(sample)
    }
}
```

---

## 3. 机器学习赋能

### 3.1 ML 应用场景

| 场景 | ML 方法 | 输入 | 输出 | 价值 |
|------|---------|------|------|------|
| **指纹分类** | 文本分类 (TF-IDF + RF/XGBoost) | HTTP 响应特征 | 产品名称 | 识别未知/变种产品 |
| **误报过滤** | 二分类器 | 漏洞特征向量 | 真/假阳性 | 减少 50%+ 误报 |
| **异常检测** | Isolation Forest / Autoencoder | 响应特征分布 | 异常分数 | 发现 0day 特征 |
| **相似指纹发现** | 文本 Embedding + 聚类 | 响应体向量 | 相似度聚类 | 自动发现新指纹 |
| **扫描策略优化** | 强化学习 / Bandit | 历史扫描数据 | 最优模块组合 | 提高检出率/降低耗时 |

### 3.2 指纹分类模型

```
架构（Go + Python 微服务模式）：

┌──────────────┐       gRPC / HTTP       ┌──────────────────────┐
│  Go 扫描引擎  │ ─────────────────────→ │  Python ML 服务       │
│              │                         │                      │
│  1. 提取特征  │                         │  • Flask/FastAPI      │
│  2. 调用 ML  │                         │  • scikit-learn       │
│  3. 合并结果  │                         │  • 模型推理            │
│              │ ←───────────────────── │  • 返回预测结果        │
└──────────────┘                         └──────────────────────┘
```

**特征工程：**

```python
class FingerprintFeatureExtractor:
    """从 HTTP 响应提取 ML 特征"""

    def extract(self, response: dict) -> dict:
        features = {}

        # Header 特征
        headers = response.get("headers", {})
        features["has_server"] = "server" in headers
        features["has_x_powered_by"] = "x-powered-by" in headers
        features["server_value"] = headers.get("server", "")
        features["content_type"] = headers.get("content-type", "")
        features["header_count"] = len(headers)

        # Body 特征
        body = response.get("body", "")
        features["body_length"] = len(body)
        features["has_doctype"] = "<!DOCTYPE" in body.upper()
        features["script_count"] = body.count("<script")
        features["meta_count"] = body.count("<meta")
        features["has_wp_content"] = "wp-content" in body
        features["has_react"] = "__REACT" in body or "react" in body.lower()
        features["has_vue"] = "__VUE" in body or "v-app" in body

        # TF-IDF 文本特征（body 关键词向量）
        features["body_tfidf"] = self.tfidf.transform([body])

        # Favicon hash
        features["favicon_hash"] = response.get("favicon_hash", "")

        return features
```

**模型训练流程：**

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer

class FingerprintClassifier:
    def __init__(self):
        self.tfidf = TfidfVectorizer(max_features=5000, ngram_range=(1,2))
        self.model = RandomForestClassifier(n_estimators=200, max_depth=20)

    def train(self, samples: list[dict]):
        """从标注样本训练分类模型"""
        # 样本格式: {"headers": {...}, "body": "...", "label": "WordPress"}
        texts = [s["body"] for s in samples]
        labels = [s["label"] for s in samples]

        X = self.tfidf.fit_transform(texts)
        self.model.fit(X, labels)

    def predict(self, response: dict) -> list[tuple[str, float]]:
        """预测产品类型，返回 [(产品名, 概率), ...]"""
        X = self.tfidf.transform([response["body"]])
        proba = self.model.predict_proba(X)[0]
        classes = self.model.classes_

        results = sorted(zip(classes, proba), key=lambda x: -x[1])
        return [(cls, prob) for cls, prob in results if prob > 0.1]
```

### 3.3 误报过滤模型

```python
class FalsePositiveFilter:
    """基于历史数据训练误报过滤模型"""

    def __init__(self):
        self.model = XGBClassifier(n_estimators=100, max_depth=8)

    def extract_features(self, vuln: dict) -> dict:
        """从漏洞报告提取特征"""
        return {
            "severity_score": severity_to_score(vuln["severity"]),
            "confidence": vuln["confidence"],
            "has_evidence": len(vuln.get("evidence", "")) > 0,
            "response_status": vuln.get("response_status", 0),
            "response_length": vuln.get("response_length", 0),
            "matcher_count": vuln.get("matcher_count", 0),
            "payload_reflected": vuln.get("payload_reflected", False),
            "detection_method": encode_method(vuln["method"]),
            "target_has_waf": vuln.get("has_waf", False),
            "scanner_module": encode_module(vuln["module"]),
        }

    def train(self, labeled_vulns: list[dict]):
        """
        训练数据: 历史漏洞 + 人工标注 (true_positive / false_positive)
        """
        X = [self.extract_features(v) for v in labeled_vulns]
        y = [1 if v["label"] == "true_positive" else 0 for v in labeled_vulns]
        self.model.fit(X, y)

    def score(self, vuln: dict) -> float:
        """返回该漏洞为真阳性的概率 (0~1)"""
        features = self.extract_features(vuln)
        return self.model.predict_proba([features])[0][1]
```

### 3.4 相似指纹聚类发现

```python
from sklearn.cluster import DBSCAN
from sentence_transformers import SentenceTransformer

class SimilarFingerprintDiscovery:
    """发现未知产品的指纹聚类"""

    def __init__(self):
        self.encoder = SentenceTransformer("all-MiniLM-L6-v2")

    def discover(self, unidentified_responses: list[dict]) -> list[dict]:
        """
        对无法识别指纹的响应进行聚类，
        同一聚类可能属于同一个未知产品
        """
        texts = [r["body"][:2000] for r in unidentified_responses]
        embeddings = self.encoder.encode(texts)

        clustering = DBSCAN(eps=0.3, min_samples=5, metric="cosine")
        labels = clustering.fit_predict(embeddings)

        clusters = {}
        for i, label in enumerate(labels):
            if label == -1:
                continue  # 噪声
            if label not in clusters:
                clusters[label] = []
            clusters[label].append(unidentified_responses[i])

        # 每个聚类提取共同特征，生成候选指纹规则
        candidates = []
        for cluster_id, members in clusters.items():
            common_features = extract_common_features(members)
            candidates.append({
                "cluster_id": cluster_id,
                "sample_count": len(members),
                "common_features": common_features,
                "suggested_name": f"unknown_product_{cluster_id}",
            })
        return candidates
```

### 3.5 ML 服务集成方式

```go
// MLService Go 侧调用 ML 微服务
type MLService struct {
    endpoint string
    client   *http.Client
    enabled  bool
    timeout  time.Duration
}

type FingerprintPrediction struct {
    Product    string  `json:"product"`
    Confidence float64 `json:"confidence"`
}

type FPFilterResult struct {
    IsLikelyFP  bool    `json:"is_likely_fp"`
    TruePositiveProb float64 `json:"true_positive_prob"`
}

func (s *MLService) PredictFingerprint(resp HTTPResponse) ([]FingerprintPrediction, error) {
    if !s.enabled {
        return nil, nil
    }
    ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
    defer cancel()

    body, _ := json.Marshal(map[string]any{
        "headers": resp.Headers,
        "body":    resp.Body[:min(10000, len(resp.Body))],
    })

    req, _ := http.NewRequestWithContext(ctx, "POST", s.endpoint+"/predict/fingerprint", bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")

    httpResp, err := s.client.Do(req)
    if err != nil {
        return nil, nil // ML 服务不可用时降级为规则匹配
    }
    defer httpResp.Body.Close()

    var predictions []FingerprintPrediction
    json.NewDecoder(httpResp.Body).Decode(&predictions)
    return predictions, nil
}

func (s *MLService) FilterFalsePositive(vuln VulnResult) (*FPFilterResult, error) {
    if !s.enabled {
        return nil, nil
    }
    // 类似调用...
}
```

### 3.6 指纹引擎融合策略

```go
// HybridFingerprintEngine 混合指纹引擎
// 规则匹配 + ML 预测融合
type HybridFingerprintEngine struct {
    ruleEngine  *FingerprintMatcher  // 传统规则匹配
    mlService   *MLService           // ML 预测（可选）
    learner     *FingerprintLearner  // 自学习
    collector   *SampleCollector     // 样本采集
}

func (e *HybridFingerprintEngine) Identify(ctx context.Context, target *Target) []Fingerprint {
    // 1. 规则引擎匹配（主力）
    ruleResults := e.ruleEngine.Match(ctx, target)

    // 2. ML 预测（辅助，仅在规则引擎无结果时启用）
    var mlResults []Fingerprint
    if len(ruleResults) == 0 && e.mlService != nil && e.mlService.enabled {
        predictions, err := e.mlService.PredictFingerprint(target.HTTPResponse)
        if err == nil {
            for _, p := range predictions {
                if p.Confidence > 0.7 {
                    mlResults = append(mlResults, Fingerprint{
                        Product:    p.Product,
                        Confidence: int(p.Confidence * 100),
                        Source:     "ml_predict",
                    })
                }
            }
        }
    }

    // 3. 融合结果
    merged := mergeFingerprints(ruleResults, mlResults)

    // 4. 采集样本（用于自学习）
    if e.collector != nil {
        go e.collector.CollectFromScan(target, merged)
    }

    return merged
}
```

## 4. 配置

```yaml
# configs/config.yaml 中的高级检测配置
advanced_detection:
  scan_mode: "full"   # inference / verify / full / safe

  inference:
    enabled: true
    version_match: true
    config_audit: true
    passive_analysis: true
    min_confidence: 60

  verification:
    enabled: true
    poc_verify: true
    fuzz_test: true
    weak_pass_test: true
    safe_payloads_only: false

  fingerprint:
    hybrid_mode: true              # 启用混合引擎
    auto_learn: true               # 启用自学习
    min_samples_for_rule: 20       # 自动生成规则最低样本数
    auto_publish_threshold: 0.9    # 自动发布的准确率阈值

  ml:
    enabled: false                 # ML 服务是否启用（可选）
    endpoint: "http://ml-service:8000"
    timeout: "5s"
    fallback_to_rules: true        # ML 不可用时降级到规则
    fp_filter_threshold: 0.3       # 误报过滤阈值（低于此概率标记为疑似误报）
```

## 5. 数据流全景

```
┌─────────┐     ┌──────────┐     ┌──────────────┐
│ 目标输入  │ ──→ │ 指纹识别  │ ──→ │ 原理扫描      │
└─────────┘     │ (规则+ML) │     │ (版本匹配     │
                └─────┬────┘     │  配置审计     │
                      │          │  被动分析)    │
                      │          └──────┬───────┘
                      │                 │
                      │     ┌───────────▼──────────┐
                      │     │ 潜在漏洞列表           │
                      │     │ status: inferred      │
                      │     └───────────┬──────────┘
                      │                 │
                      │     ┌───────────▼──────────┐
                      │     │ 实际验证               │
                      │     │ (PoC/Fuzz/弱口令)     │
                      │     └───────────┬──────────┘
                      │                 │
                      │     ┌───────────▼──────────┐
                      │     │ 误报过滤 (ML)          │
                      │     │ score < threshold     │
                      │     │ → 标记为疑似误报       │
                      │     └───────────┬──────────┘
                      │                 │
                      ▼                 ▼
              ┌──────────────┐  ┌──────────────┐
              │ 样本采集      │  │ 确认漏洞      │
              │ → 自学习      │  │ → 入库/通知   │
              └──────────────┘  └──────────────┘
```
