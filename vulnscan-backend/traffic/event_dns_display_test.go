package traffic

import (
	"encoding/json"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func ctxJSON(t *testing.T, m map[string]any) string {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal context: %v", err)
	}
	return string(b)
}

func TestLyCompatibleEventDNSDisplay(t *testing.T) {
	cases := []struct {
		name       string
		ctx        map[string]any
		wantAttack string
		wantVictim string
		wantDomain string
	}{
		{
			name: "应答方向+域名IOC：受害列是内网主机而非DNS服务器",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": 53, "dst_port": 51234,
				"app":        map[string]any{"dns_query": "lsax.org"},
				"ioc":        map[string]any{"ioc_type": "domain", "ioc_value": "lsax.org"},
				"event_type": "network_activity",
			},
			wantAttack: "lsax.org", wantVictim: "10.0.0.8", wantDomain: "lsax.org",
		},
		{
			name: "查询方向+域名IOC",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "218.2.2.2",
				"src_port": 51234, "dst_port": 53,
				"app":        map[string]any{"dns_query": "lsax.org"},
				"ioc":        map[string]any{"ioc_type": "domain", "ioc_value": "lsax.org"},
				"event_type": "network_activity",
			},
			wantAttack: "lsax.org", wantVictim: "10.0.0.8", wantDomain: "lsax.org",
		},
		{
			name: "应答方向无IOC仅dns_query：域名归攻击源列",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": 53, "dst_port": 51234,
				"app":        map[string]any{"dns_query": "xzasket.com"},
				"event_type": "c2",
			},
			wantAttack: "xzasket.com", wantVictim: "10.0.0.8", wantDomain: "xzasket.com",
		},
		{
			name: "非DNS事件保持原逻辑",
			ctx: map[string]any{
				"src_ip": "1.2.3.4", "dst_ip": "10.0.0.8",
				"src_port": 4444, "dst_port": 443,
				"event_type": "c2",
			},
			wantAttack: "1.2.3.4", wantVictim: "10.0.0.8", wantDomain: "",
		},
		{
			name: "应答方向无域名信息：攻击列置空而非公共DNS",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": 53, "dst_port": 51234,
				"event_type": "network_activity",
			},
			wantAttack: "", wantVictim: "10.0.0.8", wantDomain: "",
		},
		{
			name: "查询方向无域名信息：攻击列置空而非内网主机自身",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "218.2.2.2",
				"src_port": 51234, "dst_port": 53,
				"event_type": "network_activity",
			},
			wantAttack: "", wantVictim: "10.0.0.8", wantDomain: "",
		},
		{
			name: "字符串端口兼容",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": "53", "dst_port": "51234",
				"app":        map[string]any{"dns_query": "lsax.org"},
				"event_type": "network_activity",
			},
			wantAttack: "lsax.org", wantVictim: "10.0.0.8", wantDomain: "lsax.org",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := domain.Event{Severity: "high", Context: ctxJSON(t, tc.ctx)}
			row := lyCompatibleEvent(ev)
			if got := row["attackDevice"]; got != tc.wantAttack {
				t.Errorf("attackDevice = %v, want %q", got, tc.wantAttack)
			}
			if got := row["victimDevice"]; got != tc.wantVictim {
				t.Errorf("victimDevice = %v, want %q", got, tc.wantVictim)
			}
			if got := row["domain"]; got != tc.wantDomain {
				t.Errorf("domain = %v, want %q", got, tc.wantDomain)
			}
			// 原始方向字段必须保留
			if got := row["src_ip"]; got != tc.ctx["src_ip"] {
				t.Errorf("src_ip = %v, want %v", got, tc.ctx["src_ip"])
			}
			if got := row["dst_ip"]; got != tc.ctx["dst_ip"] {
				t.Errorf("dst_ip = %v, want %v", got, tc.ctx["dst_ip"])
			}
		})
	}
}

func TestLyCompatibleEventDNSDomainSet(t *testing.T) {
	cases := []struct {
		name      string
		ctx       map[string]any
		wantCount int
		wantFirst string
	}{
		{
			name: "v1平铺occurrences多域名去重",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "180.104.100.118",
				"src_port": 53, "dst_port": 51234,
				"app": map[string]any{"dns_query": "yinxing8.com"},
				"occurrences": []any{
					map[string]any{"time": "2026-09-20T08:24:37Z", "dns_query": "yinxing8.com"},
					map[string]any{"time": "2026-09-20T08:34:06Z", "dns_query": "atcumt.com"},
					map[string]any{"time": "2026-09-20T08:40:00Z", "dns_query": "atcumt.com"},
				},
			},
			wantCount: 2, wantFirst: "yinxing8.com",
		},
		{
			name: "v2嵌套preview多域名去重",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "180.104.100.118",
				"src_port": 53, "dst_port": 51234,
				"occurrences_preview": []any{
					map[string]any{"time": "2026-09-20T08:24:37Z", "app": map[string]any{"dns_query": "yinxing8.com"}},
					map[string]any{"time": "2026-09-20T08:34:06Z", "app": map[string]any{"dns_query": "atcumt.com"}},
				},
			},
			wantCount: 2, wantFirst: "yinxing8.com",
		},
		{
			name: "无命中明细计数为零",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "180.104.100.118",
				"src_port": 53, "dst_port": 51234,
			},
			wantCount: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			row := lyCompatibleEvent(domain.Event{Severity: "high", Context: ctxJSON(t, tc.ctx)})
			if got := row["dns_domain_count"]; got != tc.wantCount {
				t.Errorf("dns_domain_count = %v, want %d", got, tc.wantCount)
			}
			if tc.wantFirst != "" {
				queries, _ := row["dns_queries"].([]string)
				if len(queries) == 0 || queries[0] != tc.wantFirst {
					t.Errorf("dns_queries = %v, want first %q", row["dns_queries"], tc.wantFirst)
				}
			}
		})
	}
}
