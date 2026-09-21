package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func makeObservables(n int) []domain.IOC {
	obs := make([]domain.IOC, n)
	for i := range obs {
		obs[i] = domain.IOC{Type: "ip", Value: fmt.Sprintf("10.0.0.%d", i), Role: "attacker"}
	}
	return obs
}

// autoAnalysisPrompt 必须采用结论前置的强制模板 + 硬指令,并移除原始 context JSON。
func TestAutoAnalysisPromptStructure(t *testing.T) {
	ev := domain.Event{
		EventID:  "evt-1",
		EventName: "13.248.169.48",
		Severity: "high",
		Source:   "ta node",
		Message:  "malware-ip 命中",
		Context:  `{"direction":"outbound","recommended_action":"block_and_report"}`,
	}
	p := autoAnalysisPrompt(ev)

	for _, want := range []string{
		"【结论】", "## 事件概览", "## 关键证据", "## 攻击源与受影响资产分析", "## 攻击链与风险判断",
		"## 已执行处置/自动驾驶进展", "## 后续处置建议", "## 信息缺口", "## 可交付给安全团队的结论",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("missing template marker %q", want)
		}
	}
	if !strings.Contains(p, "禁止复述") {
		t.Fatalf("missing hard instruction against restating input")
	}
	// 原始 context JSON 不再注入(去掉"塞两遍"的那份)。
	if strings.Contains(p, "原始上下文") {
		t.Fatalf("raw context JSON section should be removed")
	}
	// 情报侧建议仍通过摘要出现,供模型研判。
	if !strings.Contains(p, "block_and_report") {
		t.Fatalf("recommended_action should surface via aux summary")
	}
}

// 可观察对象超过上限时,只渲染前 maxObservables 条并给出省略提示。
func TestAutoAnalysisPromptCapsObservables(t *testing.T) {
	ev := domain.Event{EventID: "e", Observables: makeObservables(100)}
	p := autoAnalysisPrompt(ev)

	if c := strings.Count(p, "role=attacker"); c != maxObservables {
		t.Fatalf("rendered observables = %d, want %d", c, maxObservables)
	}
	if !strings.Contains(p, "省略") {
		t.Fatalf("expected omission note for capped observables")
	}
}

// 即使事件携带超大 context/大量 observables,整段 prompt 也必须落在 token 预算内。
func TestAutoAnalysisPromptWithinBudget(t *testing.T) {
	headers := map[string]any{}
	for i := 0; i < 4000; i++ {
		headers[fmt.Sprintf("x-header-%d", i)] = "横向移动数据外传载荷下载"
	}
	ev := domain.Event{
		EventID:     "e",
		Observables: makeObservables(200),
		Context: fmt.Sprintf(`{"app":{"http_headers":%s}}`,
			mustJSONString(headers)),
	}
	p := autoAnalysisPrompt(ev)
	if est := estimateTokens(p); est > promptBudgetTokens {
		t.Fatalf("prompt exceeds budget: est=%d budget=%d", est, promptBudgetTokens)
	}
}

func mustJSONString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
