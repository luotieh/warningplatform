package service

import "testing"

func TestParseThreatProbability(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   float64
		ok     bool
	}{
		{"conclusion wins over hypothetical", "【结论】C2通信，威胁事件概率60%，建议隔离\n如果进一步确认外联成功，概率提升至90%", 60, true},
		{"conclusion generic wording", "【结论】疑为误报，概率为60%\n若补充证据，概率提升至90%", 60, true},
		{"fallback when conclusion lacks value", "【结论】C2通信，被攻击资产未登记\n威胁事件概率70%", 70, true},
		{"event wording", "【结论】C2通信，威胁事件概率85%，被攻击资产…", 85, true},
		{"event wording bold", "**威胁事件概率**：72%", 72, true},
		{"event wording range echo", "威胁事件概率0–100%及依据：综合判定为60%", 60, true},
		{"event wording zero range", "威胁事件概率0–100%", 0, false},
		{"colon percent", "## 攻击链与风险判断\n威胁概率：75%，依据：……", 75, true},
		{"approx", "威胁概率约 80%", 80, true},
		{"bold label", "**威胁概率**：65%", 65, true},
		{"danger wording", "危险攻击概率为 45%", 45, true},
		{"decimal", "威胁概率：87.5%", 87.5, true},
		{"zero", "威胁概率：0%", 0, true},
		{"hundred", "威胁概率 100%", 100, true},
		{"clamp over", "威胁概率：150%", 100, true},
		{"none", "本报告未给出概率", 0, false},
		{"empty", "", 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseThreatProbability(tc.report)
			if ok != tc.ok {
				t.Fatalf("ok=%v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("value=%v, want %v", got, tc.want)
			}
		})
	}
}
