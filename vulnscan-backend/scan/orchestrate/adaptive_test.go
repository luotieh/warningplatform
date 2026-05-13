package orchestrate

import (
	"testing"
	"time"
)

func TestAdaptiveController_InitialConcurrency(t *testing.T) {
	ac := NewAdaptiveController(5, 100)
	got := ac.CurrentConcurrency()
	if got != 52 {
		t.Errorf("初始并发应为 (5+100)/2=52, got %d", got)
	}
}

func TestAdaptiveController_MinMax(t *testing.T) {
	ac := NewAdaptiveController(10, 20)
	c := ac.CurrentConcurrency()
	if c < 10 || c > 20 {
		t.Errorf("并发 %d 应在 [10,20] 范围内", c)
	}
}

func TestAdaptiveController_SuccessIncrease(t *testing.T) {
	ac := NewAdaptiveController(2, 200)
	ac.adjustInterval = 0

	initial := ac.CurrentConcurrency()
	for i := 0; i < 200; i++ {
		ac.RecordSuccess(50)
	}

	after := ac.CurrentConcurrency()
	if after <= initial {
		t.Errorf("高成功率+低延迟后并发应增加, got before=%d after=%d", initial, after)
	}
}

func TestAdaptiveController_FailureDecrease(t *testing.T) {
	ac := NewAdaptiveController(2, 200)
	ac.adjustInterval = 0

	for i := 0; i < 50; i++ {
		ac.RecordSuccess(100)
	}
	initial := ac.CurrentConcurrency()

	for i := 0; i < 200; i++ {
		ac.RecordFailure(3000)
	}

	after := ac.CurrentConcurrency()
	if after >= initial {
		t.Errorf("大量失败后并发应降低, got before=%d after=%d", initial, after)
	}
}

func TestAdaptiveController_CircuitOpen(t *testing.T) {
	ac := NewAdaptiveController(2, 100)

	for i := 0; i < 15; i++ {
		ac.RecordFailure(1000)
	}

	if !ac.IsOpen() {
		t.Error("连续失败后熔断器应为 Open 状态")
	}
}

func TestAdaptiveController_CircuitRecovery(t *testing.T) {
	ac := NewAdaptiveController(2, 100)

	for i := 0; i < 15; i++ {
		ac.RecordFailure(1000)
	}
	if !ac.IsOpen() {
		t.Fatal("应为 Open 状态")
	}

	ac.mu.Lock()
	ac.openUntil = time.Now().Add(-1 * time.Second)
	ac.mu.Unlock()

	if ac.IsOpen() {
		t.Error("超时后应转为 HalfOpen")
	}

	for i := 0; i < 5; i++ {
		ac.RecordSuccess(50)
	}

	ac.mu.Lock()
	state := ac.state
	ac.mu.Unlock()
	if state != stateClosed {
		t.Errorf("足够成功后应回到 Closed, got %v", state)
	}
}

func TestAdaptiveController_Stats(t *testing.T) {
	ac := NewAdaptiveController(5, 50)
	ac.RecordSuccess(100)
	ac.RecordFailure(500)

	stats := ac.Stats()
	if stats["total_requests"].(int64) != 2 {
		t.Errorf("总请求应为 2, got %v", stats["total_requests"])
	}
	if stats["circuit_state"].(string) != "closed" {
		t.Errorf("初始状态应为 closed, got %v", stats["circuit_state"])
	}
}
