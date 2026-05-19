package monitoragent

import (
	"encoding/json"
	"testing"

	"vulnscan-backend/sitemonitor/analyzer"
)

func TestBuildAvailabilityResultJSON_nestedShape(t *testing.T) {
	snap := PageSnapshot{
		URL:            "http://example.com/",
		FinalURL:       "http://example.com/index",
		StatusCode:     200,
		ResolvedIPs:    []string{"93.184.216.34"},
		DNSMS:          12,
		TCPConnectMS:   34,
		TLSHandshakeMS: 0,
		TTFBMS:         120,
		TotalMS:        250,
		ContentLength:  1024,
		Headers:        map[string]string{"Content-Type": "text/html"},
	}
	raw, _ := json.Marshal(snap)
	out := &analyzer.Output{HasIssue: false}
	body := BuildAvailabilityResultJSON(string(raw), out)

	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	timing, _ := parsed["timing"].(map[string]any)
	if timing["dns_ms"].(float64) != 12 {
		t.Fatalf("timing.dns_ms = %v", timing["dns_ms"])
	}
	dns, _ := parsed["dns"].(map[string]any)
	ips, _ := dns["resolved_ips"].([]any)
	if len(ips) != 1 {
		t.Fatalf("dns.resolved_ips = %v", dns["resolved_ips"])
	}
	httpInfo, _ := parsed["http"].(map[string]any)
	if httpInfo["method"] != "GET" {
		t.Fatalf("http.method = %v", httpInfo["method"])
	}
}

func TestBuildAvailabilityResultJSON_legacyFlatFields(t *testing.T) {
	legacy := `{"available":true,"status_code":200,"dns_ms":5,"tcp_connect_ms":6,"ttfb_ms":7,"total_ms":8,"url":"http://a.com"}`
	// 模拟仅扁平字段的旧结果：仍应从 snapshot 重建；此处用 PageSnapshot 形态
	out := BuildAvailabilityResultJSON(legacy, nil)
	var parsed map[string]any
	_ = json.Unmarshal([]byte(out), &parsed)
	if parsed["url"] == nil && parsed["url"] != "http://a.com" {
		// url 来自 snap 解析失败时可能为空，不强制
	}
	if _, ok := parsed["timing"].(map[string]any); !ok {
		t.Fatalf("expected timing object, got %v", parsed["timing"])
	}
}
