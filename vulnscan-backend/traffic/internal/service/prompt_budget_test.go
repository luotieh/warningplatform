package service

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// formatAuxContext 必须渲染新增的 recommended_action 与 ioc_evidence 情报富化证据。
func TestFormatAuxContextNewFields(t *testing.T) {
	raw := mustJSON(t, map[string]any{
		"direction":          "outbound",
		"recommended_action": "block_and_report",
		"ioc_evidence": map[string]any{
			"activity":      "FIN7 Campaign",
			"threat_labels": []any{"ransomware", "c2"},
			"source":        "otx",
			"cross_check":   "confirmed by misp",
			"confidence":    "high (2 sources)",
			"tlp":           "white",
			"misp_event_id": "12345",
			"narrative":     "该 IP 近期参与勒索软件 C2 通信",
		},
	})
	out := formatAuxContext(raw)

	for _, want := range []string{
		"建议处置", "block_and_report",
		"情报富化证据", "FIN7 Campaign", "ransomware, c2", "otx",
		"confirmed by misp", "high (2 sources)", "white", "12345",
		"该 IP 近期参与勒索软件 C2 通信",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("aux context missing %q\n---\n%s", want, out)
		}
	}
}

// 过长的 narrative / payload 样本必须被截断,避免撑爆 token 预算。
func TestFormatAuxContextTruncatesLongSamples(t *testing.T) {
	longNarrative := strings.Repeat("勒", 500)
	longPayload := strings.Repeat("A", 2000)
	raw := mustJSON(t, map[string]any{
		"ioc_evidence": map[string]any{"narrative": longNarrative},
		"app":          map[string]any{"payload_sample": longPayload},
	})
	out := formatAuxContext(raw)

	if strings.Contains(out, longNarrative) {
		t.Fatalf("long narrative was not truncated")
	}
	if strings.Contains(out, longPayload) {
		t.Fatalf("long payload_sample was not truncated")
	}
	if !strings.Contains(out, truncateMarker) {
		t.Fatalf("expected truncate marker in output")
	}
}

// truncateRunes 按 rune 数截断(CJK 安全),超长时追加中文截断标记。
func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("hello", 10); got != "hello" {
		t.Fatalf("short string should be unchanged, got %q", got)
	}
	// 6 个汉字截到 3 个 + 标记。
	got := truncateRunes("你好世界你好", 3)
	want := "你好世…(已截断)"
	if got != want {
		t.Fatalf("truncate cjk: want %q, got %q", want, got)
	}
	// 恰好等于上限时不截断。
	if got := truncateRunes("你好世", 3); got != "你好世" {
		t.Fatalf("equal-to-limit should be unchanged, got %q", got)
	}
}

// estimateTokens 是截断决策用的保守启发式:CJK 按 ~0.7 token/字,其余按 rune/3.5,
// 再乘 1.1 保守系数并向上取整。宁可高估(早截)不可低估(溢出 16K 窗口)。
func TestEstimateTokens(t *testing.T) {
	if got := estimateTokens(""); got != 0 {
		t.Fatalf("empty string: want 0, got %d", got)
	}

	// 35 个 ASCII 字符: 35/3.5=10, ×1.1=11。
	ascii := ""
	for i := 0; i < 35; i++ {
		ascii += "a"
	}
	if got := estimateTokens(ascii); got != 11 {
		t.Fatalf("35 ascii: want 11, got %d", got)
	}

	// 4 个汉字: 4×0.7=2.8, ×1.1=3.08, ceil=4。
	if got := estimateTokens("你好世界"); got != 4 {
		t.Fatalf("4 han: want 4, got %d", got)
	}

	// CJK 标点也算 CJK(全角逗号)。"你好，" = 3 个 CJK: 3×0.7=2.1,×1.1=2.31,ceil=3。
	if got := estimateTokens("你好，"); got != 3 {
		t.Fatalf("cjk with punct: want 3, got %d", got)
	}
}

// fitToTokenBudget 保证返回串的估算 token 数不超过预算(短则原样返回,长则截断)。
func TestFitToTokenBudget(t *testing.T) {
	short := "源IP 访问目标 80 端口"
	if got := fitToTokenBudget(short, 1000); got != short {
		t.Fatalf("under-budget string should be unchanged, got %q", got)
	}

	// 全 CJK 的大块内容 —— token/rune 成本最高,最容易溢出。
	huge := strings.Repeat("勒索软件横向移动数据外传", 400) // ~4800 runes
	budget := 500
	got := fitToTokenBudget(huge, budget)
	if est := estimateTokens(got); est > budget {
		t.Fatalf("result exceeds budget: est=%d budget=%d", est, budget)
	}
	if !strings.Contains(got, truncateMarker) {
		t.Fatalf("truncated result should carry the marker")
	}
}

// 追加内容后估算值不应变小(单调),截断循环依赖这个性质收敛。
func TestEstimateTokensMonotonic(t *testing.T) {
	base := "源IP 221.178.242.16 访问目标 80 端口"
	longer := base + "，命中威胁情报 malware-ip，通联方向 to_ioc"
	if estimateTokens(longer) < estimateTokens(base) {
		t.Fatalf("appending content decreased estimate: base=%d longer=%d",
			estimateTokens(base), estimateTokens(longer))
	}
}
