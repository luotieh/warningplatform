package engine

import (
	"context"
	"testing"
	"time"
)

func TestResourceAwareAdaptiveController_BasicAdjust(t *testing.T) {
	controller := NewResourceAwareAdaptiveController(2, 10, 1*time.Second)

	newConc := controller.Adjust()

	if newConc < 2 || newConc > 10 {
		t.Errorf("并发数应在 2-10 范围内, got %d", newConc)
	}
}

func TestResourceAwareAdaptiveController_RecordSuccess(t *testing.T) {
	controller := NewResourceAwareAdaptiveController(2, 10, 1*time.Second)

	controller.RecordSuccess(100.0)
	controller.RecordSuccess(150.0)

	if controller.CurrentConcurrency() < 2 {
		t.Error("并发数不应低于最小值")
	}
}

func TestResourceAwareAdaptiveController_RecordFailure(t *testing.T) {
	controller := NewResourceAwareAdaptiveController(2, 10, 1*time.Second)

	for i := 0; i < 15; i++ {
		controller.RecordFailure(5000.0)
	}

	if controller.IsOpen() {
		t.Log("熔断已触发")
	}
}

func TestResourceMonitor_GetResourceFactor(t *testing.T) {
	monitor := NewResourceMonitor(1 * time.Second)

	factor := monitor.GetResourceFactor()

	if factor <= 0 || factor > 1.5 {
		t.Errorf("资源因子应在合理范围内, got %f", factor)
	}
}

func TestTargetProfiler_GetOptimalFactor(t *testing.T) {
	profiler := NewTargetProfiler()

	testCases := []struct {
		targetType TargetType
		expected   float64
	}{
		{TargetCDNBacked, 1.5},
		{TargetStandalone, 1.0},
		{TargetLegacySystem, 0.5},
		{TargetWAFProtected, 0.6},
		{TargetCloudNative, 1.3},
		{TargetUnknown, 1.0},
	}

	for _, tc := range testCases {
		profiler.SetTargetType(tc.targetType)
		factor := profiler.GetOptimalFactor()
		if factor != tc.expected {
			t.Errorf("目标类型 %s 的系数应为 %f, got %f", tc.targetType, tc.expected, factor)
		}
	}
}

func TestTargetProfiler_DetectTargetType(t *testing.T) {
	profiler := NewTargetProfiler()

	findings := []*Finding{
		{Type: "waf"},
		{Type: "cdn"},
	}

	targetType := profiler.DetectTargetType(findings)

	if targetType != TargetCDNBacked {
		t.Errorf("有 WAF 和 CDN 应识别为 CDNBacked, got %s", targetType)
	}
}

func TestResourceAwareAdaptiveController_UpdateTargetType(t *testing.T) {
	controller := NewResourceAwareAdaptiveController(2, 10, 1*time.Second)

	findings := []*Finding{
		{Type: "waf"},
	}

	controller.UpdateTargetType(findings)

	newConc := controller.Adjust()

	if newConc < 2 || newConc > 10 {
		t.Errorf("并发数应在 2-10 范围内, got %d", newConc)
	}
}

func TestResourceAwareAdaptiveController_StartStop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	controller := NewResourceAwareAdaptiveController(2, 10, 100*time.Millisecond)
	controller.Start(ctx)

	time.Sleep(200 * time.Millisecond)

	controller.Stop()

	t.Log("资源监控器启动和停止正常")
}
