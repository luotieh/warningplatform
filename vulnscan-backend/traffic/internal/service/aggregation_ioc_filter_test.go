package service

import (
	"context"
	"testing"
	"time"

	"vulnscan-backend/traffic/internal/store"
)

// 聚合前过滤：IP 型 IOC 为特殊用途地址的命中（如 DNS 应答 A 记录 127.0.0.1）
// 不产生事件；公网/内网 IOC 与域名型 IOC 不受影响。
func TestIngestFiltersSpecialUseIOC(t *testing.T) {
	cases := []struct {
		name     string
		iocType  string
		iocValue string
		wantDrop bool
	}{
		{"回环地址127.0.0.1过滤", "ip", "127.0.0.1", true},
		{"IPv6回环过滤", "ip", "::1", true},
		{"IPv4映射IPv6回环过滤", "ip", "::ffff:127.0.0.1", true},
		{"未指定地址过滤", "ip", "0.0.0.0", true},
		{"链路本地过滤", "ip", "169.254.1.1", true},
		{"组播地址过滤", "ip", "224.0.0.251", true},
		{"公网IOC正常入库", "ip", "185.230.12.34", false},
		{"内网IOC不排除（内网C2是真实场景）", "ip", "10.20.30.40", false},
		{"域名型IOC不受影响", "domain", "127.0.0.1", false},
		{"IOC值非法不过滤（按普通命中处理）", "ip", "not-an-ip", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := Services{Store: store.NewMemoryStore()}
			m := testHit("ioc-filter-"+tc.name, time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond))
			m["ioc_type"] = tc.iocType
			m["ioc_value"] = tc.iocValue
			r, err := svc.ProcessLyEvent(context.Background(), m)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantDrop {
				if r["ingest_status"] != "filtered" {
					t.Fatalf("ingest_status = %v, want filtered", r["ingest_status"])
				}
				if id := asString(r["deepsoc_event_id"]); id != "" {
					t.Fatalf("filtered hit should not produce event, got %q", id)
				}
			} else {
				if asString(r["deepsoc_event_id"]) == "" {
					t.Fatalf("hit should be ingested: %v", r)
				}
			}
		})
	}
}
