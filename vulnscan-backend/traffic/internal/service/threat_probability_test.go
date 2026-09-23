package service

import "testing"

func TestParseThreatProbability(t *testing.T) {
	cases := []struct {
		name   string
		report string
		want   float64
		ok     bool
	}{
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
