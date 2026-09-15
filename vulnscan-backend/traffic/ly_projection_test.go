package traffic

import (
	"encoding/json"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func TestLyCompatibleEventIncludesReviewFields(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{
		EventID:      "evt-1",
		EventStatus:  "round_finished",
		ReviewStatus: "approved",
		CircularCode: "XF-1",
	})
	if row["review_status"] != "approved" {
		t.Fatalf("review_status=%v", row["review_status"])
	}
	if row["circular_code"] != "XF-1" {
		t.Fatalf("circular_code=%v", row["circular_code"])
	}
}

func TestLyCompatibleEventDefaultReviewStatus(t *testing.T) {
	row := lyCompatibleEvent(domain.Event{EventID: "evt-2", EventStatus: "processing"})
	if row["review_status"] != "" {
		t.Fatalf("expected empty review_status, got %v", row["review_status"])
	}
}
func TestLyCompatibleEventIOCDestinationSwap(t *testing.T) {
	// 内网主机外连 C2：dst_ip == ioc_value（IP 型 IOC）→ 展示交换，受害目标=内网主机
	ctx := map[string]any{
		"src_ip": "172.16.100.16",
		"dst_ip": "192.185.86.177",
		"ioc": map[string]any{
			"ioc_type":  "ip",
			"ioc_value": "192.185.86.177",
		},
		"quant_stats": map[string]any{"total_payload_bytes": float64(4096)},
	}
	b, _ := json.Marshal(ctx)
	row := lyCompatibleEvent(domain.Event{
		EventID: "evt-ioc1",
		Context: string(b),
		Observables: []domain.IOC{
			{Type: "ip", Value: "172.16.100.16", Role: "source"},
			{Type: "ip", Value: "192.185.86.177", Role: "destination"},
			{Type: "indicator", Value: "192.185.86.177", Role: "threat_intel"},
		},
	})
	if row["attackDevice"] != "192.185.86.177" {
		t.Fatalf("attackDevice=%v, want IOC addr", row["attackDevice"])
	}
	if row["victimDevice"] != "172.16.100.16" {
		t.Fatalf("victimDevice=%v, want real victim", row["victimDevice"])
	}
	if row["obj"] != "192.185.86.177>172.16.100.16" {
		t.Fatalf("obj=%v", row["obj"])
	}
	// 原始流向保持真实方向（研判回传用）
	if row["src_ip"] != "172.16.100.16" || row["dst_ip"] != "192.185.86.177" {
		t.Fatalf("src_ip/dst_ip=%v/%v, want original direction", row["src_ip"], row["dst_ip"])
	}
	if row["total_payload_bytes"] != int64(4096) {
		t.Fatalf("total_payload_bytes=%v", row["total_payload_bytes"])
	}
}

func TestLyCompatibleEventIOCSourceNoSwap(t *testing.T) {
	// 恶意 IP（IOC）主动攻击内网：src == ioc_value，受害目标本就是 dst，不交换
	ctx := map[string]any{
		"src_ip": "203.0.113.9",
		"dst_ip": "172.16.100.20",
		"ioc": map[string]any{
			"ioc_type":  "ip",
			"ioc_value": "203.0.113.9",
		},
	}
	b, _ := json.Marshal(ctx)
	row := lyCompatibleEvent(domain.Event{EventID: "evt-ioc2", Context: string(b)})
	if row["attackDevice"] != "203.0.113.9" {
		t.Fatalf("attackDevice=%v", row["attackDevice"])
	}
	if row["victimDevice"] != "172.16.100.20" {
		t.Fatalf("victimDevice=%v", row["victimDevice"])
	}
}

func TestLyCompatibleEventDomainIOCNoSwap(t *testing.T) {
	// 域名型 IOC 作为威胁源展示，受害主机保留为目标
	ctx := map[string]any{
		"src_ip": "172.16.100.16",
		"dst_ip": "192.185.86.177",
		"ioc": map[string]any{
			"ioc_type":  "domain",
			"ioc_value": "evil.example.com",
		},
	}
	b, _ := json.Marshal(ctx)
	row := lyCompatibleEvent(domain.Event{EventID: "evt-ioc3", Context: string(b)})
	if row["attackDevice"] != "evil.example.com" || row["victimDevice"] != "172.16.100.16" {
		t.Fatalf("unexpected swap: %v > %v", row["attackDevice"], row["victimDevice"])
	}
}

func TestLyCompatibleEventCIDRIOCSwap(t *testing.T) {
	// CIDR 型 IOC：dst 落在网段内 → 交换
	ctx := map[string]any{
		"src_ip": "10.0.0.5",
		"dst_ip": "192.168.1.77",
		"ioc": map[string]any{
			"ioc_type":  "cidr",
			"ioc_value": "192.168.1.0/24",
		},
	}
	b, _ := json.Marshal(ctx)
	row := lyCompatibleEvent(domain.Event{EventID: "evt-ioc4", Context: string(b)})
	if row["attackDevice"] != "192.168.1.77" || row["victimDevice"] != "10.0.0.5" {
		t.Fatalf("cidr swap failed: %v > %v", row["attackDevice"], row["victimDevice"])
	}
}

func TestLyCompatibleEventMissingQuantStats(t *testing.T) {
	// 旧事件无 quant_stats → total_payload_bytes=0，不 panic
	ctx := "{\"src_ip\":\"1.1.1.1\",\"dst_ip\":\"2.2.2.2\"}"
	row := lyCompatibleEvent(domain.Event{EventID: "evt-old", Context: ctx})
	if row["total_payload_bytes"] != int64(0) {
		t.Fatalf("total_payload_bytes=%v", row["total_payload_bytes"])
	}
}
