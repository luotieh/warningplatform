package traffic

import (
	"encoding/json"
	"fmt"
	"regexp"
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
func compactEngineerContext(raw string) string { return buildEngineerEvidenceContext("event", raw) }

// buildEngineerEvidenceContext scans every occurrence and creates a stable,
// model-facing evidence index. Full packet/detail APIs remain untouched.
func buildEngineerEvidenceContext(eventID, raw string) string {
	if strings.TrimSpace(raw) == "" {
		return "无上下文"
	}
	var ctx map[string]any
	if err := json.Unmarshal([]byte(raw), &ctx); err != nil || ctx == nil {
		return limitEngineerText(raw, engineerContextMaxRunes)
	}
	if _, ok := ctx["snapshot_version"]; ok {
		return raw
	}
	available := 0
	if occurrences, ok := ctx["occurrences"].([]any); ok {
		available = len(occurrences)
		ctx["occurrences_available"] = len(occurrences)
		ctx["evidence_index"] = makeEvidenceIndex(eventID, occurrences)
		delete(ctx, "occurrences")
		ctx["evidence_note"] = "仅扫描当前已保存明细；历史频次未核验，不代表完整原始数据。旧数组索引引用需通过历史快照核验。"
	}
	trimEngineerValue(ctx)
	b, err := json.Marshal(ctx)
	if err != nil {
		return "上下文编码失败"
	}
	// Put deterministic totals before the bounded evidence index so they cannot
	// be lost when a very large event is clipped for the model window.
	count := 0
	if declared, ok := ctx["occurrence_count"].(float64); ok && declared > 0 {
		count = int(declared)
	}
	prefix := fmt.Sprintf("证据摘要：声明命中数=%d；旧格式可索引明细数=%d；全量扫描范围以 input_manifest 为准；统计量由系统计算，证据需回溯 evidence_id。\n", count, available)
	return limitEngineerText(prefix+string(b), engineerContextMaxRunes)
}

var hexOnlyRE = regexp.MustCompile(`^[0-9a-fA-F\s]+$`)

func makeEvidenceIndex(eventID string, occurrences []any) []map[string]any {
	out := make([]map[string]any, 0, len(occurrences))
	seen := map[string]int{}
	for i, item := range occurrences {
		m, _ := item.(map[string]any)
		e := map[string]any{"evidence_id": fmt.Sprintf("E-%s-O%d", eventID, i+1), "occurrence_index": i + 1}
		for _, k := range []string{"time", "occurrence_time", "src_ip", "dst_ip", "source", "target", "protocol", "direction", "session_id", "rule_id", "ioc_type", "ioc_value", "parse_status", "field_path"} {
			if v, ok := m[k]; ok && fmt.Sprint(v) != "" {
				e[k] = v
			}
		}
		text, _ := m["payload_text"].(string)
		hx, _ := m["payload_hex"].(string)
		if hx != "" && (strings.HasPrefix(strings.TrimSpace(hx), "16 03") || strings.HasPrefix(strings.TrimSpace(hx), "1603")) {
			e["protocol_hint"] = "TLS"
			e["parse_status"] = "encrypted_unparsed"
		}
		if text != "" {
			e["payload_preview"] = limitEngineerText(text, 240)
		} else if hx != "" && hexOnlyRE.MatchString(hx) {
			e["payload_preview"] = limitEngineerText(strings.TrimSpace(hx), 160)
			e["parse_status"] = firstNonEmpty(fmt.Sprint(e["parse_status"]), "hex_unparsed")
		}
		key := text + "|" + hx
		first, exists := seen[key]
		if !exists {
			seen[key] = i + 1
			e["selection_reason"] = "全量明细证据索引"
		} else {
			e["duplicate_of"] = fmt.Sprintf("E-%s-O%d", eventID, first)
			e["selection_reason"] = "重复载荷，保留索引与计数"
		}
		out = append(out, e)
	}
	return out
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
