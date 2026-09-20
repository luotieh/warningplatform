package service

import "testing"

func TestBuildOccurrenceDNSTags(t *testing.T) {
	cases := []struct {
		name        string
		ly          map[string]any
		wantRole    string
		wantQuery   string
		wantRoleSet bool
	}{
		{
			name: "查询方向 dst_port=53",
			ly: map[string]any{
				"occurrence_time": "2026-09-20T10:00:00Z",
				"src_port":        51234, "dst_port": 53,
				"app": map[string]any{"dns_query": "lsax.org"},
			},
			wantRole: "query", wantQuery: "lsax.org", wantRoleSet: true,
		},
		{
			name: "应答方向 src_port=53",
			ly: map[string]any{
				"occurrence_time": "2026-09-20T10:00:01Z",
				"src_port":        53, "dst_port": 51234,
				"app": map[string]any{"dns_query": "lsax.org"},
			},
			wantRole: "response", wantQuery: "lsax.org", wantRoleSet: true,
		},
		{
			name: "非 DNS 无标签",
			ly: map[string]any{
				"occurrence_time": "2026-09-20T10:00:02Z",
				"src_port":        4444, "dst_port": 443,
			},
			wantRoleSet: false,
		},
		{
			name: "字符串端口兼容",
			ly: map[string]any{
				"occurrence_time": "2026-09-20T10:00:03Z",
				"src_port":        "51234", "dst_port": "53",
				"app": map[string]any{"dns_query": "lsax.org"},
			},
			wantRole: "query", wantQuery: "lsax.org", wantRoleSet: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			occ := buildOccurrence(tc.ly)
			role, ok := occ["dns_role"]
			if ok != tc.wantRoleSet {
				t.Fatalf("dns_role present = %v, want %v (occ=%v)", ok, tc.wantRoleSet, occ)
			}
			if tc.wantRoleSet && role != tc.wantRole {
				t.Errorf("dns_role = %v, want %q", role, tc.wantRole)
			}
			if tc.wantQuery != "" {
				if q := occ["dns_query"]; q != tc.wantQuery {
					t.Errorf("dns_query = %v, want %q", q, tc.wantQuery)
				}
			}
		})
	}
}
