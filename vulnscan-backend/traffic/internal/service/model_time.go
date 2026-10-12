package service

import (
	"encoding/json"
	"strings"
	"time"
)

var modelBeijingLocation = time.FixedZone("Asia/Shanghai", 8*60*60)

// ModelTimeContext converts structured timestamps only in a model-facing copy.
// Stored snapshots, source text, numeric timestamps and evidence identities are unchanged.
func ModelTimeContext(raw string) string {
	var value any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		return raw
	}
	var walk func(any)
	walk = func(value any) {
		switch x := value.(type) {
		case map[string]any:
			for key, child := range x {
				if text, ok := child.(string); ok && modelTimeKey(key) {
					if stamp, err := time.Parse(time.RFC3339Nano, text); err == nil && !stamp.IsZero() {
						x[key] = stamp.In(modelBeijingLocation).Format(time.RFC3339Nano)
					}
				} else {
					walk(child)
				}
			}
		case []any:
			for _, child := range x {
				walk(child)
			}
		}
	}
	walk(value)
	data, err := json.Marshal(value)
	if err != nil {
		return raw
	}
	return string(data)
}

func modelTimeKey(key string) bool {
	switch key {
	case "time", "timestamp", "start", "end", "first", "last", "as_of", "lookback_start":
		return true
	}
	return strings.HasSuffix(key, "_time") || strings.HasSuffix(key, "_at")
}
