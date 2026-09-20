package service

import (
	"encoding/json"
	"sort"
	"strings"
)

// Keep structured response/application evidence without allowing an unbounded
// packet body or local attachment path into the model's representative samples.
func boundedEvidenceValue(v any, depth int) any {
	remaining := 1000
	return boundedEvidencePart(v, depth, &remaining)
}

// Statistical distributions remain complete in the snapshot. The model gets
// the most frequent entries and explicit omitted totals, leaving room for raw
// evidence instead of spending its entire context on a long IOC dictionary.
func modelStatistics(full any) (map[string]any, map[string]any) {
	raw, _ := json.Marshal(full)
	q := map[string]any{}
	_ = json.Unmarshal(raw, &q)
	omitted := map[string]any{}
	for _, field := range []string{"by_rule", "by_direction", "source_ips", "dest_ips"} {
		m, ok := q[field].(map[string]any)
		if !ok {
			continue
		}
		keys := []string{}
		for k := range m {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if toInt(m[keys[i]]) == toInt(m[keys[j]]) {
				return keys[i] < keys[j]
			}
			return toInt(m[keys[i]]) > toInt(m[keys[j]])
		})
		top := map[string]any{}
		var omittedHits int64
		for _, k := range keys {
			if len(top) < 8 && len([]rune(k)) <= 128 {
				top[k] = m[k]
			} else {
				omittedHits += int64(toInt(m[k]))
			}
		}
		q[field] = top
		if len(top) != len(keys) {
			omitted[field] = map[string]any{"omitted_entries": len(keys) - len(top), "omitted_hits": omittedHits}
		}
	}
	if items, ok := q["by_ioc"].([]any); ok {
		top := []any{}
		var omittedHits int64
		for _, item := range items {
			m, _ := item.(map[string]any)
			if len(top) < 4 && len([]rune(asString(m["ioc_value"]))) <= 256 {
				top = append(top, m)
			} else {
				omittedHits += int64(toInt(m["count"]))
			}
		}
		q["by_ioc"] = top
		if len(top) != len(items) {
			omitted["by_ioc"] = map[string]any{"omitted_entries": len(items) - len(top), "omitted_hits": omittedHits}
		}
	}
	return q, omitted
}

func boundedEvidencePart(v any, depth int, remaining *int) any {
	if depth >= 4 || *remaining <= 0 {
		return "[摘要深度受限；完整内容见明细]"
	}
	switch x := v.(type) {
	case string:
		r := []rune(x)
		limit := min(256, *remaining)
		*remaining -= min(len(r), limit)
		if len(r) > limit {
			return string(r[:limit]) + "[摘要截断]"
		}
		return x
	case map[string]any:
		keys := []string{}
		for k := range x {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "path") || strings.Contains(lower, "file") {
				continue
			}
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := map[string]any{}
		if len(keys) > 12 {
			out["summary_truncated"] = true
			keys = keys[:12]
		}
		for _, k := range keys {
			if *remaining <= 0 {
				out["summary_truncated"] = true
				break
			}
			*remaining -= len([]rune(k))
			out[k] = boundedEvidencePart(x[k], depth+1, remaining)
		}
		return out
	case []any:
		out := []any{}
		for i, item := range x {
			if i == 4 {
				out = append(out, "[其余项目见明细]")
				break
			}
			out = append(out, boundedEvidencePart(item, depth+1, remaining))
		}
		return out
	default:
		return v
	}
}

// Ranking only selects model samples; it never determines event severity or
// removes a raw record. Unknown payloads remain candidates for model analysis.
func evidenceScore(m, o map[string]any) int {
	score := 10
	if asString(m["rule_id"]) != "" {
		score += 40
	}
	if asString(m["ioc_value"]) != "" {
		score += 25
	}
	switch strings.ToLower(asString(m["severity"])) {
	case "critical":
		score += 30
	case "high":
		score += 20
	}
	if asString(o["payload_text"]) != "" {
		score += 10
	} else if asString(o["payload_hex"]) != "" {
		score += 15
	}
	if exchange, ok := m["exchange"].(map[string]any); ok && exchange["response"] != nil {
		score += 25
	}
	return score
}
