package engine

import (
	"context"
	"log/slog"
	"runtime"
	"sync"
	"time"
)

type NetworkStats struct {
	Saturated   bool
	Utilization float64
	BytesSent   uint64
	BytesRecv   uint64
}

type DiskStats struct {
	ReadIOps  float64
	WriteIOps float64
}

type ResourceMonitor struct {
	mu               sync.RWMutex
	cpuUsage         float64
	memoryUsage      float64
	networkIO        NetworkStats
	diskIO           DiskStats
	samplingInterval time.Duration
	stopCh           chan struct{}
}

func NewResourceMonitor(samplingInterval time.Duration) *ResourceMonitor {
	if samplingInterval <= 0 {
		samplingInterval = 5 * time.Second
	}
	return &ResourceMonitor{
		samplingInterval: samplingInterval,
		stopCh:           make(chan struct{}),
	}
}

func (m *ResourceMonitor) Start(ctx context.Context) {
	go m.sampleLoop(ctx)
}

func (m *ResourceMonitor) Stop() {
	close(m.stopCh)
}

func (m *ResourceMonitor) sampleLoop(ctx context.Context) {
	ticker := time.NewTicker(m.samplingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sample()
		}
	}
}

func (m *ResourceMonitor) sample() {
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cpuUsage = float64(runtime.NumGoroutine()) / float64(runtime.GOMAXPROCS(0)) * 10
	if m.cpuUsage > 100 {
		m.cpuUsage = 100
	}

	totalAlloc := mem.TotalAlloc
	sys := mem.Sys
	if sys > 0 {
		m.memoryUsage = float64(totalAlloc) / float64(sys) * 100
	}
	if m.memoryUsage > 100 {
		m.memoryUsage = 100
	}
}

func (m *ResourceMonitor) GetResourceFactor() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	factor := 1.0

	if m.cpuUsage > 90 {
		factor *= 0.5
	} else if m.cpuUsage > 80 {
		factor *= 0.7
	} else if m.cpuUsage > 70 {
		factor *= 0.9
	}

	if m.memoryUsage > 90 {
		factor *= 0.5
	} else if m.memoryUsage > 85 {
		factor *= 0.6
	} else if m.memoryUsage > 75 {
		factor *= 0.8
	}

	if m.networkIO.Saturated {
		factor *= 0.5
	} else if m.networkIO.Utilization > 80 {
		factor *= 0.7
	}

	return factor
}

func (m *ResourceMonitor) GetCPUUsage() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cpuUsage
}

func (m *ResourceMonitor) GetMemoryUsage() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.memoryUsage
}

type TargetType string

const (
	TargetCDNBacked    TargetType = "cdn_backed"
	TargetStandalone   TargetType = "standalone"
	TargetLegacySystem TargetType = "legacy_system"
	TargetWAFProtected TargetType = "waf_protected"
	TargetCloudNative  TargetType = "cloud_native"
	TargetUnknown      TargetType = "unknown"
)

type TargetStats struct {
	Type          TargetType
	AvgResponseMs float64
	SuccessRate   float64
	RequestCount  int
}

type TargetProfiler struct {
	mu         sync.RWMutex
	targetType TargetType
	history    map[string]*TargetStats
}

func NewTargetProfiler() *TargetProfiler {
	return &TargetProfiler{
		targetType: TargetUnknown,
		history:    make(map[string]*TargetStats),
	}
}

func (p *TargetProfiler) SetTargetType(t TargetType) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.targetType = t
}

func (p *TargetProfiler) GetOptimalFactor() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()

	switch p.targetType {
	case TargetCDNBacked:
		return 1.5
	case TargetStandalone:
		return 1.0
	case TargetLegacySystem:
		return 0.5
	case TargetWAFProtected:
		return 0.6
	case TargetCloudNative:
		return 1.3
	default:
		return 1.0
	}
}

func (p *TargetProfiler) DetectTargetType(findings []*Finding) TargetType {
	var hasWAF, hasCDN, hasCloud bool

	for _, f := range findings {
		if f.Type == "waf" {
			hasWAF = true
		}
		if f.Type == "cdn" {
			hasCDN = true
		}
		if f.Data != nil {
			if _, ok := f.Data["cloud_provider"]; ok {
				hasCloud = true
			}
		}
	}

	if hasWAF && hasCDN {
		return TargetCDNBacked
	}
	if hasWAF {
		return TargetWAFProtected
	}
	if hasCDN {
		return TargetCDNBacked
	}
	if hasCloud {
		return TargetCloudNative
	}

	return TargetStandalone
}

type ResourceAwareAdaptiveController struct {
	baseController  *AdaptiveController
	resourceMonitor *ResourceMonitor
	targetProfiler  *TargetProfiler
	minConcurrency  int
	maxConcurrency  int
}

func NewResourceAwareAdaptiveController(minConc, maxConc int, samplingInterval time.Duration) *ResourceAwareAdaptiveController {
	base := NewAdaptiveController(minConc, maxConc)
	monitor := NewResourceMonitor(samplingInterval)
	profiler := NewTargetProfiler()

	return &ResourceAwareAdaptiveController{
		baseController:  base,
		resourceMonitor: monitor,
		targetProfiler:  profiler,
		minConcurrency:  minConc,
		maxConcurrency:  maxConc,
	}
}

func (c *ResourceAwareAdaptiveController) Start(ctx context.Context) {
	c.resourceMonitor.Start(ctx)
}

func (c *ResourceAwareAdaptiveController) Stop() {
	c.resourceMonitor.Stop()
}

func (c *ResourceAwareAdaptiveController) Adjust() int {
	baseConc := c.baseController.CurrentConcurrency()

	resourceFactor := c.resourceMonitor.GetResourceFactor()

	targetFactor := c.targetProfiler.GetOptimalFactor()

	newConc := int(float64(baseConc) * resourceFactor * targetFactor)

	newConc = clamp(newConc, c.minConcurrency, c.maxConcurrency)

	if newConc != baseConc {
		slog.Info("[ResourceAwareAdaptive] 并发调整",
			"base", baseConc,
			"resource_factor", resourceFactor,
			"target_factor", targetFactor,
			"new", newConc,
		)
	}

	return newConc
}

func (c *ResourceAwareAdaptiveController) CurrentConcurrency() int {
	return c.baseController.CurrentConcurrency()
}

func (c *ResourceAwareAdaptiveController) RecordSuccess(latencyMs float64) {
	c.baseController.RecordSuccess(latencyMs)
}

func (c *ResourceAwareAdaptiveController) RecordFailure(latencyMs float64) {
	c.baseController.RecordFailure(latencyMs)
}

func (c *ResourceAwareAdaptiveController) IsOpen() bool {
	return c.baseController.IsOpen()
}

func (c *ResourceAwareAdaptiveController) UpdateTargetType(findings []*Finding) {
	targetType := c.targetProfiler.DetectTargetType(findings)
	c.targetProfiler.SetTargetType(targetType)
}

func clamp(value, min, max int) int {
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func init() {
	slog.Debug("[ResourceAwareAdaptiveController] 资源感知自适应控制器就绪")
}
