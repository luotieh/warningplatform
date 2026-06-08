package orchestrate

import (
	"code.yt-security.com/public/scanengine/core"

	"context"
	"errors"
	"testing"
	"time"
)

type mockModule struct {
	id       string
	runCount int
	failN    int
	findings []*core.Finding
}

func (m *mockModule) ID() string       { return m.id }
func (m *mockModule) Name() string     { return "Mock " + m.id }
func (m *mockModule) Category() string { return "test" }
func (m *mockModule) Run(ctx context.Context, targets []*core.Target, config map[string]interface{}) (*core.ModuleResult, error) {
	m.runCount++
	if m.runCount <= m.failN {
		return nil, errors.New("mock failure")
	}
	return &core.ModuleResult{
		ModuleID: m.id,
		Findings: m.findings,
	}, nil
}

func TestRunWithRetry_SuccessFirst(t *testing.T) {
	mod := &mockModule{id: "ok_mod", failN: 0, findings: []*core.Finding{{Title: "found"}}}
	rc := RetryConfig{MaxRetries: 2, InitialBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}

	result, err := RunWithRetry(context.Background(), mod, nil, nil, rc)
	if err != nil {
		t.Fatalf("不应失败: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("应有 1 条发现, got %d", len(result.Findings))
	}
	if mod.runCount != 1 {
		t.Errorf("应只运行 1 次, got %d", mod.runCount)
	}
}

func TestRunWithRetry_SuccessAfterRetry(t *testing.T) {
	mod := &mockModule{id: "retry_mod", failN: 2, findings: []*core.Finding{{Title: "found"}}}
	rc := RetryConfig{MaxRetries: 2, InitialBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}

	result, err := RunWithRetry(context.Background(), mod, nil, nil, rc)
	if err != nil {
		t.Fatalf("第3次应成功: %v", err)
	}
	if mod.runCount != 3 {
		t.Errorf("应运行 3 次, got %d", mod.runCount)
	}
	if len(result.Findings) != 1 {
		t.Errorf("应有 1 条发现, got %d", len(result.Findings))
	}
}

func TestRunWithRetry_AllFail(t *testing.T) {
	mod := &mockModule{id: "fail_mod", failN: 100}
	rc := RetryConfig{MaxRetries: 2, InitialBackoff: 10 * time.Millisecond, MaxBackoff: 50 * time.Millisecond}

	_, err := RunWithRetry(context.Background(), mod, nil, nil, rc)
	if err == nil {
		t.Fatal("全部失败应返回错误")
	}
	if mod.runCount != 3 {
		t.Errorf("应运行 3 次 (1+2重试), got %d", mod.runCount)
	}
}

func TestRunWithRetry_ContextCancel(t *testing.T) {
	mod := &mockModule{id: "cancel_mod", failN: 100}
	rc := RetryConfig{MaxRetries: 5, InitialBackoff: 100 * time.Millisecond, MaxBackoff: 1 * time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := RunWithRetry(ctx, mod, nil, nil, rc)
	if err == nil {
		t.Fatal("取消后应返回错误")
	}
}

func TestCircuitBreaker_ClosedByDefault(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)
	if !cb.CanExecute("mod1") {
		t.Error("初始状态应允许执行")
	}
}

func TestCircuitBreaker_OpenAfterFailures(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)

	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")

	if cb.CanExecute("mod1") {
		t.Error("3次失败后应熔断 mod1")
	}

	if !cb.CanExecute("mod2") {
		t.Error("mod2 未失败，应允许执行")
	}
}

func TestCircuitBreaker_RecoveryToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")

	if cb.CanExecute("mod1") {
		t.Error("刚熔断应不可执行")
	}

	time.Sleep(150 * time.Millisecond)

	if !cb.CanExecute("mod1") {
		t.Error("超时后应转为 HalfOpen 并允许尝试")
	}
}

func TestCircuitBreaker_HalfOpenSuccess(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")

	time.Sleep(150 * time.Millisecond)
	cb.CanExecute("mod1")

	cb.RecordSuccess("mod1")
	cb.RecordSuccess("mod1")

	if !cb.CanExecute("mod1") {
		t.Error("HalfOpen 成功后应恢复为 Closed")
	}
}

func TestCircuitBreaker_HalfOpenFailure(t *testing.T) {
	cb := NewCircuitBreaker(3, 100*time.Millisecond)

	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")

	time.Sleep(150 * time.Millisecond)
	cb.CanExecute("mod1")

	cb.RecordFailure("mod1")

	if cb.CanExecute("mod1") {
		t.Error("HalfOpen 再次失败后应回到 Open")
	}
}

func TestCircuitBreaker_SuccessResetsFail(t *testing.T) {
	cb := NewCircuitBreaker(3, 10*time.Second)

	cb.RecordFailure("mod1")
	cb.RecordFailure("mod1")
	cb.RecordSuccess("mod1")
	cb.RecordFailure("mod1")

	if !cb.CanExecute("mod1") {
		t.Error("成功应重置失败计数，不应触发熔断")
	}
}

func TestCircuitBreaker_Stats(t *testing.T) {
	cb := NewCircuitBreaker(5, 10*time.Second)
	cb.RecordSuccess("mod1")
	cb.RecordFailure("mod1")

	stats := cb.Stats()
	modStats := stats["mod1"].(map[string]interface{})
	if modStats["state"].(string) != "closed" {
		t.Error("应为 closed 状态")
	}
}
