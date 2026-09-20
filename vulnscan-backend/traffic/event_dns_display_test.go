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

func TestDNSResolutionPeers(t *testing.T) {
	cases := []struct {
		name       string
		ctx        map[string]any
		wantServer string
		wantClient string
	}{
		{
			name: "查询方向 dst_port=53",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "218.2.2.2",
				"src_port": 51234, "dst_port": 53,
			},
			wantServer: "218.2.2.2", wantClient: "10.0.0.8",
		},
		{
			name: "应答方向 src_port=53",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": 53, "dst_port": 51234,
			},
			wantServer: "218.2.2.2", wantClient: "10.0.0.8",
		},
		{
			name: "无端口、dns_query+内网兜底",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "218.2.2.2",
				"app": map[string]any{"dns_query": "xzasket.com"},
			},
			wantServer: "218.2.2.2", wantClient: "10.0.0.8",
		},
		{
			name: "无端口且无 dns_query 不干预",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "218.2.2.2",
			},
			wantServer: "", wantClient: "",
		},
		{
			name: "双内网不干预",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "10.0.0.9",
				"app": map[string]any{"dns_query": "x.com"},
			},
			wantServer: "", wantClient: "",
		},
		{
			name: "非 DNS 不干预",
			ctx: map[string]any{
				"src_ip": "1.2.3.4", "dst_ip": "10.0.0.8",
				"src_port": 12345, "dst_port": 443,
			},
			wantServer: "", wantClient: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, client := dnsResolutionPeers(tc.ctx)
			if server != tc.wantServer || client != tc.wantClient {
				t.Fatalf("got (%q, %q), want (%q, %q)", server, client, tc.wantServer, tc.wantClient)
			}
		})
	}
}

func TestLyCompatibleEventDNSDisplay(t *testing.T) {
	cases := []struct {
		name         string
		ctx          map[string]any
		wantAttack   string
		wantVictim   string
		wantDomain   string
	}{
		{
			name: "应答方向+域名IOC：受害列是内网主机而非DNS服务器",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": 53, "dst_port": 51234,
				"app": map[string]any{"dns_query": "lsax.org"},
				"ioc": map[string]any{"ioc_type": "domain", "ioc_value": "lsax.org"},
				"event_type": "network_activity",
			},
			wantAttack: "lsax.org", wantVictim: "10.0.0.8", wantDomain: "lsax.org",
		},
		{
			name: "查询方向+域名IOC",
			ctx: map[string]any{
				"src_ip": "10.0.0.8", "dst_ip": "218.2.2.2",
				"src_port": 51234, "dst_port": 53,
				"app": map[string]any{"dns_query": "lsax.org"},
				"ioc": map[string]any{"ioc_type": "domain", "ioc_value": "lsax.org"},
				"event_type": "network_activity",
			},
			wantAttack: "lsax.org", wantVictim: "10.0.0.8", wantDomain: "lsax.org",
		},
		{
			name: "应答方向无IOC仅dns_query：域名归攻击源列",
			ctx: map[string]any{
				"src_ip": "218.2.2.2", "dst_ip": "10.0.0.8",
				"src_port": 53, "dst_port": 51234,
				"app": map[string]any{"dns_query": "xzasket.com"},
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
				"app": map[string]any{"dns_query": "lsax.org"},
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
