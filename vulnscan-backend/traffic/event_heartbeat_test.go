package traffic

import (
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/domain"
)

// 快照持久化的心跳结论优先于 occurrences 本地判定：预览窗口只有最近 10 条，
// 本地判定只是无快照字段的旧数据回退路径。
func TestLyCompatibleEventHeartbeatPersistedPrecedence(t *testing.T) {
	t.Run("快照命中但无明细仍提升", func(t *testing.T) {
		ctx := map[string]any{
			"src_ip": "1.2.3.4", "dst_ip": "10.0.0.8",
			"src_port": 4444, "dst_port": 443, "event_type": "c2",
			"heartbeat_detected": true, "heartbeat_period_sec": 30,
		}
		row := lyCompatibleEvent(domain.Event{Severity: "low", Context: ctxJSON(t, ctx)})
		if row["level"] != "middle" || row["heartbeat_level_boost"] != true {
			t.Fatalf("persisted heartbeat ignored: level=%v boost=%v", row["level"], row["heartbeat_level_boost"])
		}
		if row["heartbeat_period_sec"] != int64(30) {
			t.Fatalf("heartbeat_period_sec = %v, want 30", row["heartbeat_period_sec"])
		}
	})
	t.Run("快照否定时不被预览明细翻盘", func(t *testing.T) {
		ctx := map[string]any{
			"src_ip": "1.2.3.4", "dst_ip": "10.0.0.8",
			"src_port": 4444, "dst_port": 443, "event_type": "c2",
			"heartbeat_detected": false, "heartbeat_period_sec": 0,
			"occurrences":        regularOccurrences(10, 30, 2),
		}
		row := lyCompatibleEvent(domain.Event{Severity: "low", Context: ctxJSON(t, ctx)})
		if row["level"] != "low" || row["heartbeat_detected"] != false {
			t.Fatalf("persisted negative heartbeat overridden: level=%v detected=%v", row["level"], row["heartbeat_detected"])
		}
	})
}

// regularOccurrences 构造 count 条固定间隔 periodSec 秒的命中记录。
func regularOccurrences(count, periodSec, packets int) []any {
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	items := make([]any, 0, count)
	for i := 0; i < count; i++ {
		items = append(items, map[string]any{
			"time":    base.Add(time.Duration(i*periodSec) * time.Second).Format(time.RFC3339Nano),
			"packets": packets,
		})
	}
	return items
}

func TestDetectHeartbeat(t *testing.T) {
	cases := []struct {
		name       string
		occs       []any
		want       bool
		wantPeriod int64
	}{
		{name: "固定30秒周期小包", occs: regularOccurrences(10, 30, 2), want: true, wantPeriod: 30},
		{name: "单次超过5包不判心跳", occs: regularOccurrences(10, 30, 6), want: false},
		{name: "不足8次命中", occs: regularOccurrences(7, 30, 2), want: false},
		{name: "周期小于5秒", occs: regularOccurrences(10, 2, 2), want: false},
		{
			name: "间隔抖动过大",
			occs: func() []any {
				base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
				gaps := []int{10, 200, 15, 180, 12, 220, 10, 190, 14}
				items := make([]any, 0, len(gaps)+1)
				cur := base
				items = append(items, map[string]any{"time": cur.Format(time.RFC3339Nano), "packets": 1})
				for _, gap := range gaps {
					cur = cur.Add(time.Duration(gap) * time.Second)
					items = append(items, map[string]any{"time": cur.Format(time.RFC3339Nano), "packets": 1})
				}
				return items
			}(),
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, period := detectHeartbeat(tc.occs)
			if got != tc.want {
				t.Fatalf("detected=%v want %v (period=%d)", got, tc.want, period)
			}
			if tc.want && period != tc.wantPeriod {
				t.Fatalf("period=%d want %d", period, tc.wantPeriod)
			}
		})
	}
}

func TestLyCompatibleEventHeartbeatLevelBoost(t *testing.T) {
	cases := []struct {
		name         string
		severity     string
		occs         []any
		wantLevel    string
		wantLevelRaw string
		wantBoost    bool
	}{
		{name: "低危+心跳提升为中危", severity: "low", occs: regularOccurrences(10, 30, 2),
			wantLevel: "middle", wantLevelRaw: "low", wantBoost: true},
		{name: "中危+心跳提升为高危", severity: "medium", occs: regularOccurrences(10, 30, 2),
			wantLevel: "high", wantLevelRaw: "middle", wantBoost: true},
		{name: "高危+心跳不再上调", severity: "high", occs: regularOccurrences(10, 30, 2),
			wantLevel: "high", wantLevelRaw: "high", wantBoost: false},
		{name: "低危无心跳不提升", severity: "low", occs: nil,
			wantLevel: "low", wantLevelRaw: "low", wantBoost: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := map[string]any{
				"src_ip": "1.2.3.4", "dst_ip": "10.0.0.8",
				"src_port": 4444, "dst_port": 443,
				"event_type": "c2",
			}
			if tc.occs != nil {
				ctx["occurrences"] = tc.occs
			}
			row := lyCompatibleEvent(domain.Event{Severity: tc.severity, Context: ctxJSON(t, ctx)})
			if got := row["level"]; got != tc.wantLevel {
				t.Errorf("level = %v, want %q", got, tc.wantLevel)
			}
			if got := row["level_raw"]; got != tc.wantLevelRaw {
				t.Errorf("level_raw = %v, want %q", got, tc.wantLevelRaw)
			}
			if got := row["heartbeat_level_boost"]; got != tc.wantBoost {
				t.Errorf("heartbeat_level_boost = %v, want %v", got, tc.wantBoost)
			}
			if tc.wantBoost {
				if got := row["heartbeat_detected"]; got != true {
					t.Errorf("heartbeat_detected = %v, want true", got)
				}
				if got := row["heartbeat_period_sec"]; got != int64(30) {
					t.Errorf("heartbeat_period_sec = %v, want 30", got)
				}
			}
		})
	}
}
