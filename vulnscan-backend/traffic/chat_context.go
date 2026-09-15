package traffic

import (
	"encoding/json"
	"strings"
)

const engineerContextMaxRunes = 6000

func limitEngineerText(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	const suffix = "…（模型输入已截断，完整记录仍保留）"
	return string(runes[:limit-len([]rune(suffix))]) + suffix
}

// compactEngineerContext builds a model-only projection. It never updates the
// event, its detail API, or the database. Preserve aggregate counts and bounds;
// sample first/middle/last occurrences rather than sending every packet twice
// (as both text and HEX). Synthetic-data provenance remains in the context.
func compactEngineerContext(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "无上下文"
	}
	var ctx map[string]any
	if err := json.Unmarshal([]byte(raw), &ctx); err != nil || ctx == nil {
		return limitEngineerText(raw, engineerContextMaxRunes)
	}
	if occurrences, ok := ctx["occurrences"].([]any); ok {
		ctx["occurrences_available"] = len(occurrences)
		if len(occurrences) > 3 {
			ctx["occurrences"] = []any{occurrences[0], occurrences[len(occurrences)/2], occurrences[len(occurrences)-1]}
			ctx["occurrences_sampled"] = true
			ctx["occurrences_note"] = "仅提供首条、中间、末条明细样本；全局命中次数以 occurrence_count 为准，不能用样本数代替。"
		}
	}
	trimEngineerValue(ctx)
	b, err := json.Marshal(ctx)
	if err != nil {
		return "上下文编码失败"
	}
	return limitEngineerText(string(b), engineerContextMaxRunes)
}

func trimEngineerValue(value any) {
	switch v := value.(type) {
	case map[string]any:
		if text, ok := v["payload_text"].(string); ok && text != "" {
			if _, exists := v["payload_hex"]; exists {
				delete(v, "payload_hex")
				v["payload_hex_omitted"] = true
			}
		}
		for key, child := range v {
			if text, ok := child.(string); ok {
				v[key] = limitEngineerText(text, 512)
			} else {
				trimEngineerValue(child)
			}
		}
	case []any:
		for i, child := range v {
			if text, ok := child.(string); ok {
				v[i] = limitEngineerText(text, 512)
			} else {
				trimEngineerValue(child)
			}
		}
	}
}
