package sitemonitor

import (
	"strings"

	"vulnscan-backend/sitemonitor/contract"
)

func formatRunTaskSkips(skips []contract.RunTaskSkip) string {
	parts := make([]string, 0, len(skips))
	for _, s := range skips {
		parts = append(parts, s.Dimension+": "+s.Reason)
	}
	return strings.Join(parts, "; ")
}

func extractStringSlice(m map[string]any, key string) []string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch arr := v.(type) {
	case []any:
		result := make([]string, 0, len(arr))
		for _, item := range arr {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case []string:
		return arr
	}
	return nil
}

func toInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	}
	return 0
}
