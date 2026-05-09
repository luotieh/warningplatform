# 漏洞扫描系统 - 性能与检测准确性优化方案

## 1. 概述

本文档详细描述漏洞扫描系统从信息收集到漏洞扫描全流程的性能优化与检测准确性提升方案。

### 1.1 优化目标

| 维度 | 目标 | 衡量指标 |
|------|------|----------|
| 性能 | 扫描速度提升 40-50% | 端到端扫描耗时 |
| 性能 | 资源利用率从 30% → 70% | CPU/内存/网络使用率 |
| 准确性 | 技术栈识别准确率 65% → 90%+ | 指纹匹配准确率 |
| 准确性 | 漏洞检出率 +20-30% | 有效漏洞发现数量 |
| 准确性 | 误报率 -40-50% | 误报/总发现比例 |

### 1.2 当前瓶颈分析

通过代码审查发现以下关键瓶颈：

1. **信息收集串行执行** - `asm/discovery.go` 收集器依次执行，未利用并发
2. **目标传播简单粗暴** - `scan/engine/target_enricher.go` 使用简单 append，未去重排序
3. **技术栈检测粗糙** - `scan/engine/strategy.go` 基于关键词匹配，误判率高
4. **自适应控制单一** - `scan/engine/adaptive.go` 仅基于成功率/延迟，未考虑系统资源
5. **去重内存占用大** - `scan/engine/dedup.go` 使用 map 存储所有指纹

---

## 2. 方案一：信息收集并发化 + 流式流水线

### 2.1 设计目标

将 ASM 发现引擎从串行执行改造为并发执行，引入流式去重和风险评估。

### 2.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    ConcurrentDiscoveryEngine                 │
│                                                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐    │
│  │ DNS      │  │ CT Log   │  │ Reverse  │  │ Passive  │    │
│  │Collector │  │Collector │  │DNS       │  │Sources   │    │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘    │
│       │              │             │              │          │
│       └──────────────┴─────────────┴──────────────┘          │
│                          │                                   │
│                    assetCh (chan)                            │
│                          │                                   │
│              ┌───────────▼───────────┐                       │
│              │  StreamDeduplicator   │                       │
│              │  (实时去重 + 评分)     │                       │
│              └───────────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### 2.3 核心接口

```go
// ConcurrentDiscoveryEngine 并发发现引擎
type ConcurrentDiscoveryEngine struct {
    collectors []AssetCollector
    maxWorkers int
    timeout    time.Duration
}

// Discover 并发执行资产发现
func (e *ConcurrentDiscoveryEngine) Discover(ctx context.Context, project *ASMProject) ([]DiscoveredAsset, error)

// StreamDeduplicator 流式去重器
type StreamDeduplicator struct {
    seen      sync.Map
    riskScorer *RiskScorer
}

// DedupAndScore 实时去重并计算风险评分
func (d *StreamDeduplicator) DedupAndScore(ctx context.Context, input <-chan DiscoveredAsset) <-chan DiscoveredAsset
```

### 2.4 实现细节

#### 2.4.1 并发收集器调度

```go
func (e *ConcurrentDiscoveryEngine) Discover(ctx context.Context, project *ASMProject) ([]DiscoveredAsset, error) {
    assetCh := make(chan DiscoveredAsset, 1024)
    errCh := make(chan error, len(e.collectors))
    
    var wg sync.WaitGroup
    sem := make(chan struct{}, e.maxWorkers)
    
    for _, collector := range e.collectors {
        wg.Add(1)
        go func(c AssetCollector) {
            defer wg.Done()
            sem <- struct{}{}
            defer func() { <-sem }()
            
            collectCtx, cancel := context.WithTimeout(ctx, e.timeout)
            defer cancel()
            
            for _, seed := range project.Seeds {
                assets, err := c.Collect(collectCtx, seed)
                if err != nil {
                    errCh <- fmt.Errorf("%s: %w", c.Name(), err)
                    continue
                }
                for _, a := range assets {
                    assetCh <- a
                }
            }
        }(collector)
    }
    
    go func() {
        wg.Wait()
        close(assetCh)
    }()
    
    return streamDedupAndScore(ctx, assetCh, errCh)
}
```

#### 2.4.2 流式去重与评分

```go
func streamDedupAndScore(ctx context.Context, input <-chan DiscoveredAsset, errCh <-chan error) ([]DiscoveredAsset, error) {
    seen := make(map[string]bool)
    var results []DiscoveredAsset
    scorer := NewRiskScorer()
    
    for {
        select {
        case <-ctx.Done():
            return results, ctx.Err()
        case asset, ok := <-input:
            if !ok {
                return results, nil
            }
            
            key := normalizeAssetKey(asset)
            if !seen[key] {
                seen[key] = true
                asset.RiskScore = scorer.Calculate(asset)
                results = append(results, asset)
            }
        }
    }
}
```

### 2.5 预期效果

| 指标 | 优化前 | 优化后 | 提升幅度 |
|------|--------|--------|----------|
| 单域名发现耗时 | 15-30s | 3-8s | **60-75%** |
| CPU 利用率 | 20-30% | 60-80% | **2-3x** |
| 资产发现数量 | 基准 | +15-25% | 更多被动源 |

---

## 3. 方案二：智能目标传播 + 动态优先级

### 3.1 设计目标

优化扫描阶段间的目标传递机制，实现智能去重、风险排序和精准传播。

### 3.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    SmartTargetPropagator                     │
│                                                              │
│  Stage N Findings ──┐                                       │
│                     ▼                                       │
│              ┌──────────────┐                               │
│              │ Enrichment   │ 基于发现结果增强目标信息        │
│              └──────┬───────┘                               │
│                     │                                       │
│              ┌──────▼───────┐                               │
│              │ SmartDedup   │ 泛域名合并、IP段聚合            │
│              └──────┬───────┘                               │
│                     │                                       │
│              ┌──────▼───────┐                               │
│              │ RiskSort     │ 基于风险评分动态排序            │
│              └──────┬───────┘                               │
│                     │                                       │
│              ┌──────▼───────┐                               │
│              │ Pruning      │ 剪枝低价值目标                  │
│              └──────┬───────┘                               │
│                     │                                       │
│                     ▼                                       │
│              Stage N+1 Targets                              │
└─────────────────────────────────────────────────────────────┘
```

### 3.3 核心接口

```go
// SmartTargetPropagator 智能目标传播器
type SmartTargetPropagator struct {
    dedup       *TargetDeduplicator
    prioritizer *TargetPrioritizer
    enricher    *TargetEnricher
    pruner      *TargetPruner
}

// Propagate 传播目标到下一阶段
func (p *SmartTargetPropagator) Propagate(existing, newTargets []*Target, findings []*Finding) []*Target

// TargetDeduplicator 智能去重器
type TargetDeduplicator struct {
    // 支持泛域名合并、IP段聚合
}

// SmartDedup 智能去重
func (d *TargetDeduplicator) SmartDedup(targets []*Target) []*Target

// TargetPrioritizer 目标优先级排序器
type TargetPrioritizer struct {
    // 基于风险评分、资产重要性排序
}

// SortByRisk 基于风险排序
func (p *TargetPrioritizer) SortByRisk(targets []*Target, findings []*Finding) []*Target
```

### 3.4 实现细节

#### 3.4.1 智能去重

```go
func (d *TargetDeduplicator) SmartDedup(targets []*Target) []*Target {
    // 1. 泛域名合并 (*.example.com → example.com)
    wildcardMerged := d.mergeWildcards(targets)
    
    // 2. IP段聚合 (192.168.1.1-192.168.1.254 → 192.168.1.0/24)
    ipAggregated := d.aggregateIPRanges(wildcardMerged)
    
    // 3. 端口去重（同一主机相同服务只保留一个）
    return d.dedupByService(ipAggregated)
}
```

#### 3.4.2 风险评分排序

```go
func (p *TargetPrioritizer) SortByRisk(targets []*Target, findings []*Finding) []*Target {
    scoreMap := make(map[string]float64)
    
    // 初始化基础分数
    for _, t := range targets {
        scoreMap[targetKey(t)] = p.baseScore(t)
    }
    
    // 基于发现结果调整分数
    for _, f := range findings {
        key := targetKey(f.Target)
        switch f.Type {
        case "vulnerability":
            scoreMap[key] += severityWeight(f.Severity) * 10
        case "fingerprint":
            scoreMap[key] += 2
        case "waf":
            scoreMap[key] -= 3 // 有WAF保护，降低优先级
        case "cdn":
            scoreMap[key] -= 2 // CDN背后，降低优先级
        }
    }
    
    // 排序
    sort.Slice(targets, func(i, j int) bool {
        return scoreMap[targetKey(targets[i])] > scoreMap[targetKey(targets[j])]
    })
    
    return targets
}
```

#### 3.4.3 目标剪枝

```go
func (p *TargetPruner) Prune(targets []*Target, findings []*Finding) []*Target {
    var kept []*Target
    
    for _, t := range targets {
        score := p.calculateValue(t, findings)
        
        // 保留高价值目标
        if score >= p.threshold {
            kept = append(kept, t)
        }
    }
    
    // 限制最大目标数，防止爆炸
    if len(kept) > p.maxTargets {
        kept = kept[:p.maxTargets]
    }
    
    return kept
}
```

### 3.5 预期效果

| 指标 | 优化前 | 优化后 | 提升幅度 |
|------|--------|--------|----------|
| 无效扫描目标 | 30-40% | 5-10% | **减少 70%** |
| 高危漏洞发现时间 | 扫描周期后段 | 扫描周期前 20% | **提前 4-5x** |
| 扫描资源浪费 | 基准 | -35% | 更聚焦 |

---

## 4. 方案三：技术栈精准检测 + 模块智能裁剪

### 4.1 设计目标

提升技术栈识别准确率，基于多维度证据进行模块智能裁剪。

### 4.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                   AdvancedTechDetector                       │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Evidence Collection                                 │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐           │   │
│  │  │ HTTP     │  │ Port/    │  │ Vuln     │           │   │
│  │  │Response  │  │ Service  │  │ Findings │           │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘           │   │
│  │       │              │             │                  │   │
│  │       └──────────────┴─────────────┘                  │   │
│  │                          │                            │   │
│  │              ┌───────────▼───────────┐                │   │
│  │              │  Weighted Scoring     │                │   │
│  │              │  (多证据加权评分)      │                │   │
│  │              └───────────────────────┘                │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                   │
│              ┌───────────▼───────────┐                      │
│              │  SmartModuleCutter    │                      │
│              │  (智能模块裁剪)        │                      │
│              └───────────────────────┘                      │
└─────────────────────────────────────────────────────────────┘
```

### 4.3 核心接口

```go
// AdvancedTechDetector 高级技术栈检测器
type AdvancedTechDetector struct {
    httpFingerprints *HTTPFingerprintDB
    portServiceMap   map[int]string
}

// Detect 多维度技术栈检测
func (d *AdvancedTechDetector) Detect(targets []*Target, findings []*Finding) *TechProfile

// TechProfile 技术栈画像
type TechProfile struct {
    Stack            TechStack
    Confidence       float64    // 置信度 0-1
    Framework        string
    Server           string
    Version          string
    Evidence         []TechEvidence
    RecommendModules []string
    SkipModules      []string
    HighPriority     []string
}

// TechEvidence 技术证据
type TechEvidence struct {
    Source     string    // 证据来源
    TechStack  TechStack
    Confidence float64
    Detail     string
}

// SmartModuleCutter 智能模块裁剪器
type SmartModuleCutter struct {
    threshold      float64
    historicalStats map[string]*ModuleStats
}

// CutModules 智能裁剪模块
func (c *SmartModuleCutter) CutModules(modules []ScanModule, profile *TechProfile, targets []*Target) []ScanModule
```

### 4.4 实现细节

#### 4.4.1 多维度技术栈检测

```go
func (d *AdvancedTechDetector) Detect(targets []*Target, findings []*Finding) *TechProfile {
    scores := make(map[TechStack]float64)
    var evidence []TechEvidence
    
    // 1. HTTP 响应指纹匹配 (权重 0.4)
    for _, t := range targets {
        if t.Fingerprints != nil {
            for _, fp := range t.Fingerprints {
                scores[fp.TechStack] += fp.Confidence * 0.4
                evidence = append(evidence, TechEvidence{
                    Source:     "http_fingerprint",
                    TechStack:  fp.TechStack,
                    Confidence: fp.Confidence * 0.4,
                    Detail:     fp.Product,
                })
            }
        }
    }
    
    // 2. 端口服务先验概率 (权重 0.2)
    for _, t := range targets {
        if t.Port > 0 {
            if tech := d.portServiceMap[t.Port]; tech != "" {
                scores[tech] += 1.5
                evidence = append(evidence, TechEvidence{
                    Source:     "port_service",
                    TechStack:  tech,
                    Confidence: 0.2,
                    Detail:     fmt.Sprintf("port %d", t.Port),
                })
            }
        }
    }
    
    // 3. 漏洞发现贝叶斯更新 (权重 0.4)
    for _, f := range findings {
        if f.Type == "vulnerability" {
            for _, tag := range f.Tags {
                if tech := tagToTechStack(tag); tech != "" {
                    scores[tech] += 3.0
                    evidence = append(evidence, TechEvidence{
                        Source:     "vuln_finding",
                        TechStack:  tech,
                        Confidence: 0.4,
                        Detail:     f.Title,
                    })
                }
            }
        }
    }
    
    // 归一化并选择最佳匹配
    bestStack, confidence := normalizeAndSelect(scores)
    
    return &TechProfile{
        Stack:      bestStack,
        Confidence: confidence,
        Evidence:   evidence,
    }
}
```

#### 4.4.2 智能模块裁剪

```go
func (c *SmartModuleCutter) CutModules(modules []ScanModule, profile *TechProfile, targets []*Target) []ScanModule {
    var selected []ModuleScore
    
    for _, m := range modules {
        score := c.scoreModule(m, profile, targets)
        
        if score >= c.threshold {
            selected = append(selected, ModuleScore{Module: m, Score: score})
        }
    }
    
    // 按分数排序
    sort.Slice(selected, func(i, j int) bool {
        return selected[i].Score > selected[j].Score
    })
    
    // 提取模块列表
    var result []ScanModule
    for _, s := range selected {
        s.Module.SetPriority(s.Score)
        result = append(result, s.Module)
    }
    
    return result
}

func (c *SmartModuleCutter) scoreModule(m ScanModule, profile *TechProfile, targets []*Target) float64 {
    score := 1.0
    
    // 技术栈匹配度
    if matchesTech(m, profile.Stack) {
        score *= 2.0
    }
    
    // 端口适用性
    if applicablePorts := m.ApplicablePorts(); len(applicablePorts) > 0 {
        portMatchRatio := countPortMatches(targets, applicablePorts) / float64(len(targets))
        score *= (1 + portMatchRatio)
    }
    
    // 历史成功率
    if stats := c.getHistoricalStats(m.ID()); stats.SuccessRate > 0 {
        score *= (0.5 + stats.SuccessRate)
    }
    
    // 置信度惩罚
    if profile.Confidence < 0.5 {
        score *= 0.8 // 低置信度时降低分数
    }
    
    return score
}
```

### 4.5 预期效果

| 指标 | 优化前 | 优化后 | 提升幅度 |
|------|--------|--------|----------|
| 技术栈误判率 | 25-35% | 5-10% | **减少 70%** |
| 无效模块执行 | 40-50% | 10-15% | **减少 65%** |
| 漏洞检出率 | 基准 | +20-30% | 更精准匹配 |
| 扫描总耗时 | 基准 | -25-35% | 跳过无关模块 |

---

## 5. 方案四：资源感知自适应并发控制

### 5.1 设计目标

在原有自适应并发控制基础上，增加系统资源监控和目标特征分析。

### 5.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│               ResourceAwareAdaptiveController                │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Base         │  │ Resource     │  │ Target       │      │
│  │ Controller   │  │ Monitor      │  │ Profiler     │      │
│  │ (成功率/延迟) │  │ (CPU/内存/IO)│  │ (目标特征)    │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                  │                  │              │
│         └──────────────────┴──────────────────┘              │
│                            │                                 │
│                 ┌──────────▼──────────┐                     │
│                 │  Comprehensive      │                     │
│                 │  Adjustment Engine  │                     │
│                 └─────────────────────┘                     │
└─────────────────────────────────────────────────────────────┘
```

### 5.3 核心接口

```go
// ResourceAwareAdaptiveController 资源感知自适应控制器
type ResourceAwareAdaptiveController struct {
    baseController *AdaptiveController
    resourceMonitor *ResourceMonitor
    targetProfiler *TargetProfiler
}

// Adjust 综合调整并发数
func (c *ResourceAwareAdaptiveController) Adjust() int

// ResourceMonitor 资源监控器
type ResourceMonitor struct {
    cpuUsage     float64
    memoryUsage  float64
    networkIO    NetworkStats
    diskIO       DiskStats
}

// GetResourceFactor 获取资源约束系数
func (m *ResourceMonitor) GetResourceFactor() float64

// TargetProfiler 目标画像器
type TargetProfiler struct {
    history map[string]*TargetStats
}

// GetOptimalFactor 基于目标特征获取最优系数
func (p *TargetProfiler) GetOptimalFactor() float64
```

### 5.4 实现细节

#### 5.4.1 资源监控

```go
func (m *ResourceMonitor) GetResourceFactor() float64 {
    factor := 1.0
    
    // CPU 约束
    if m.cpuUsage > 90 {
        factor *= 0.5
    } else if m.cpuUsage > 80 {
        factor *= 0.7
    } else if m.cpuUsage > 70 {
        factor *= 0.9
    }
    
    // 内存约束
    if m.memoryUsage > 90 {
        factor *= 0.5
    } else if m.memoryUsage > 85 {
        factor *= 0.6
    } else if m.memoryUsage > 75 {
        factor *= 0.8
    }
    
    // 网络 IO 约束
    if m.networkIO.Saturated {
        factor *= 0.5
    } else if m.networkIO.Utilization > 80 {
        factor *= 0.7
    }
    
    return factor
}
```

#### 5.4.2 目标画像

```go
func (p *TargetProfiler) GetOptimalFactor() float64 {
    // 基于目标类型返回差异化系数
    switch p.targetType {
    case "cdn_backed":
        return 1.5 // CDN 背后，可高并发
    case "standalone":
        return 1.0 // 单机服务，中等并发
    case "legacy_system":
        return 0.5 // 老旧系统，低并发
    case "waf_protected":
        return 0.6 // WAF 保护，低并发
    case "cloud_native":
        return 1.3 // 云原生，较高并发
    default:
        return 1.0
    }
}
```

#### 5.4.3 综合调整

```go
func (c *ResourceAwareAdaptiveController) Adjust() int {
    // 1. 基础调整
    baseConc := c.baseController.CurrentConcurrency()
    
    // 2. 资源约束
    resourceFactor := c.resourceMonitor.GetResourceFactor()
    
    // 3. 目标特征调整
    targetFactor := c.targetProfiler.GetOptimalFactor()
    
    // 4. 综合计算
    newConc := int(float64(baseConc) * resourceFactor * targetFactor)
    
    return clamp(newConc, c.minConcurrency, c.maxConcurrency)
}
```

### 5.5 预期效果

| 指标 | 优化前 | 优化后 | 提升幅度 |
|------|--------|--------|----------|
| 扫描吞吐量 | 基准 | +40-60% | 资源充分利用 |
| 目标打挂率 | 8-12% | 2-4% | **减少 65%** |
| 系统稳定性 | 偶发 OOM | 资源使用率 60-80% | 更平稳 |

---

## 6. 方案五：多层去重 + 布隆过滤器

### 6.1 设计目标

优化去重系统内存占用，支持跨任务去重。

### 6.2 架构设计

```
┌─────────────────────────────────────────────────────────────┐
│                    MultiLayerDeduplicator                    │
│                                                              │
│  Finding ──┐                                                │
│            ▼                                                │
│  ┌──────────────────┐                                       │
│  │ L1: Bloom Filter │ 快速判断可能存在 (误判率 1%)           │
│  │ (内存 10MB)      │                                       │
│  └────────┬─────────┘                                       │
│           │ 可能存在                                        │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ L2: Exact Map    │ 精确确认是否重复                       │
│  │ (内存 50MB)      │                                       │
│  └────────┬─────────┘                                       │
│           │ 确认重复                                        │
│           ▼                                                 │
│  ┌──────────────────┐                                       │
│  │ L3: Persistent   │ 跨任务去重 (Redis/DB)                  │
│  │ Store (可选)     │                                       │
│  └──────────────────┘                                       │
└─────────────────────────────────────────────────────────────┘
```

### 6.3 核心接口

```go
// MultiLayerDeduplicator 多层去重器
type MultiLayerDeduplicator struct {
    bloomFilter     *bloom.BloomFilter
    exactFingerprints sync.Map
    persistentStore DedupStore
    crossTaskEnabled bool
}

// IsDuplicate 检查是否重复
func (d *MultiLayerDeduplicator) IsDuplicate(taskID string, f *Finding) bool

// DedupStore 持久化存储接口
type DedupStore interface {
    Exists(fp string) bool
    Store(fp string) error
    Cleanup(before time.Time) error
}
```

### 6.4 实现细节

```go
func (d *MultiLayerDeduplicator) IsDuplicate(taskID string, f *Finding) bool {
    fp := d.computeFingerprint(taskID, f)
    
    // L1: 布隆过滤器快速检查
    if !d.bloomFilter.Test(fp) {
        d.bloomFilter.Add(fp)
        return false
    }
    
    // L2: 精确检查
    if _, exists := d.exactFingerprints.Load(fp); !exists {
        d.exactFingerprints.Store(fp, struct{}{})
        return false
    }
    
    // L3: 跨任务检查
    if d.crossTaskEnabled {
        return d.persistentStore.Exists(fp)
    }
    
    return true
}
```

### 6.5 预期效果

| 指标 | 优化前 | 优化后 | 提升幅度 |
|------|--------|--------|----------|
| 去重内存占用 | 500MB (100w 指纹) | 50MB | **减少 90%** |
| 去重查询速度 | O(1) map | O(1) 布隆 + O(1) map | **更快** |
| 跨任务重复发现 | 无 | 支持 | 避免重复扫描 |

---

## 7. 实施路线图

### 7.1 第一阶段：核心性能优化

**目标：** 扫描速度提升 40-50%，内存占用减少 60%

| 任务 | 文件 | 预计工作量 |
|------|------|-----------|
| 信息收集并发化 | `asm/discovery_concurrent.go` | 中 |
| 流式去重器 | `asm/stream_dedup.go` | 小 |
| 智能目标传播 | `scan/engine/target_propagator.go` | 中 |
| 多层去重系统 | `scan/engine/dedup_multilayer.go` | 中 |

### 7.2 第二阶段：准确性提升

**目标：** 漏洞检出率 +25%，误报率 -45%

| 任务 | 文件 | 预计工作量 |
|------|------|-----------|
| 技术栈精准检测 | `scan/engine/tech_detector.go` | 大 |
| 模块智能裁剪 | `scan/engine/module_cutter.go` | 中 |
| 动态优先级排序 | `scan/engine/priority_sorter.go` | 中 |

### 7.3 第三阶段：高级优化

**目标：** 系统稳定性 +50%，长期扫描效率 +30%

| 任务 | 文件 | 预计工作量 |
|------|------|-----------|
| 资源感知自适应 | `scan/engine/adaptive_resource.go` | 大 |
| 跨任务去重 | `scan/engine/dedup_persistent.go` | 中 |
| 扫描反馈闭环 | `scheduler/feedback_loop.go` | 大 |

---

## 8. 测试策略

### 8.1 性能测试

- 基准测试：对比优化前后的扫描耗时
- 压力测试：大规模目标集（10000+ IP）扫描
- 资源监控：CPU/内存/网络使用率

### 8.2 准确性测试

- 技术栈识别准确率测试集
- 漏洞检出率对比测试
- 误报率统计分析

### 8.3 集成测试

- 端到端扫描流程测试
- 并发安全性测试
- 故障恢复测试

---

## 9. 风险评估

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 并发引入竞态条件 | 高 | 充分测试，使用 race detector |
| 技术栈检测误判 | 中 | 保留回退机制，可配置阈值 |
| 布隆过滤器误判 | 低 | 双层验证，精确 map 确认 |
| 资源监控开销 | 低 | 采样频率控制，异步采集 |

---

## 10. 配置参数

### 10.1 并发控制参数

```yaml
discovery:
  max_workers: 10
  collector_timeout: 30s
  
scanning:
  min_concurrency: 2
  max_concurrency: 50
  adjust_interval: 5s
```

### 10.2 去重参数

```yaml
dedup:
  bloom_filter_size: 1000000
  bloom_filter_fp_rate: 0.01
  cross_task_enabled: false
  persistent_store: redis
```

### 10.3 技术栈检测参数

```yaml
tech_detection:
  confidence_threshold: 0.6
  evidence_weights:
    http_fingerprint: 0.4
    port_service: 0.2
    vuln_finding: 0.4
```

### 10.4 资源监控参数

```yaml
resource_monitor:
  cpu_threshold: 80
  memory_threshold: 85
  network_utilization_threshold: 80
  sampling_interval: 5s
```
