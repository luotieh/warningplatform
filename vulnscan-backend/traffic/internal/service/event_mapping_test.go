package service

import (
	"encoding/json"
	"strings"
	"testing"

	"vulnscan-backend/traffic/internal/domain"
)

func observableByRole(items []domain.IOC, role string) string {
	for _, item := range items {
		if item.Role == role {
			return item.Value
		}
	}
	return ""
}

// 内网主机外连 C2：dst==IOC，威胁侧必须是 IOC，资产侧是内网主机。
func TestSemanticPeersIOCatDestination(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":   "e1",
		"src_ip":     "172.16.100.16",
		"dst_ip":     "192.185.86.177",
		"ioc_type":   "ip",
		"ioc_value":  "192.185.86.177",
		"event_type": "c2",
		"rule_desc":  "C2 通讯",
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "192.185.86.177" {
		t.Fatalf("threat_source=%q, want IOC addr", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "172.16.100.16" {
		t.Fatalf("affected_asset=%q, want internal host", got)
	}
	if !strings.Contains(ev.Message, "受影响资产 172.16.100.16 与威胁地址 192.185.86.177") {
		t.Fatalf("message=%q", ev.Message)
	}
	var ctx map[string]any
	if err := json.Unmarshal([]byte(ev.Context), &ctx); err != nil {
		t.Fatal(err)
	}
	if ctx["threat_source"] != "192.185.86.177" || ctx["victim_target"] != "172.16.100.16" {
		t.Fatalf("ctx threat/victim=%v/%v", ctx["threat_source"], ctx["victim_target"])
	}
	// 原始报文方向保留在 source/destination 角色，供研判回传。
	if observableByRole(ev.Observables, "source") != "172.16.100.16" ||
		observableByRole(ev.Observables, "destination") != "192.185.86.177" {
		t.Fatalf("raw direction roles lost: %+v", ev.Observables)
	}
}

// 恶意 IP 主动攻击内网：src==IOC，威胁侧是 src，不交换。
func TestSemanticPeersIOCatSource(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":  "e2",
		"src_ip":    "203.0.113.9",
		"dst_ip":    "172.16.100.20",
		"ioc_type":  "ip",
		"ioc_value": "203.0.113.9",
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "203.0.113.9" {
		t.Fatalf("threat_source=%q", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "172.16.100.20" {
		t.Fatalf("affected_asset=%q", got)
	}
}

// DNS 解析流量：威胁侧是 IOC 域名，受害侧是发起查询的主机，公共 DNS 服务器不参与归属。
func TestSemanticPeersDNSDomainIOC(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":  "e3",
		"src_ip":    "10.0.0.5",
		"dst_ip":    "218.2.2.2",
		"dst_port":  53,
		"ioc_type":  "domain",
		"ioc_value": "evil.example.com",
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "evil.example.com" {
		t.Fatalf("threat_source=%q, want IOC domain", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "10.0.0.5" {
		t.Fatalf("affected_asset=%q, want query client", got)
	}
	for _, item := range ev.Observables {
		if item.Role == "threat_source" && item.Type != "domain" {
			t.Fatalf("domain threat observable type=%q", item.Type)
		}
	}
}

// 无 IOC 时按 ta_node 方向字段判定：outbound → 目标侧为威胁侧。
func TestSemanticPeersDirectionFallback(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":  "e4",
		"src_ip":    "10.0.0.5",
		"dst_ip":    "93.184.216.34",
		"direction": "outbound",
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "93.184.216.34" {
		t.Fatalf("threat_source=%q", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "10.0.0.5" {
		t.Fatalf("affected_asset=%q", got)
	}
}

// 无 IOC 且无方向信息：不断言发起方，message 标注方向待研判。
func TestSemanticPeersUnknown(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id": "e5",
		"src_ip":   "10.0.0.5",
		"dst_ip":   "10.0.0.6",
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "" {
		t.Fatalf("threat_source=%q, want empty", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "" {
		t.Fatalf("affected_asset=%q, want empty", got)
	}
	if !strings.Contains(ev.Message, "通讯方向待研判") {
		t.Fatalf("message=%q", ev.Message)
	}
}

// DNS 流量 + IP 型 IOC 命中解析器一侧（恶意/被劫持 DNS 服务器）：
// 威胁侧是解析器 IP 而非查询域名，受害侧是发起查询的内网主机。
func TestSemanticPeersDNSMaliciousResolver(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":  "e6",
		"src_ip":    "10.0.0.5",
		"dst_ip":    "198.51.100.53",
		"dst_port":  53,
		"ioc_type":  "ip",
		"ioc_value": "198.51.100.53",
		"app":       map[string]any{"dns_query": "www.benign.example.com"},
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "198.51.100.53" {
		t.Fatalf("threat_source=%q, want malicious resolver", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "10.0.0.5" {
		t.Fatalf("affected_asset=%q, want query client", got)
	}
}

// DNS 流量 + CIDR 型 IOC 命中、dns_query 缺失：威胁侧仍按命中侧归属，不留空。
func TestSemanticPeersDNSCIDROnResolverNoQuery(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":  "e7",
		"src_ip":    "198.51.100.53",
		"dst_ip":    "10.0.0.5",
		"src_port":  53,
		"ioc_type":  "cidr",
		"ioc_value": "198.51.100.0/24",
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "198.51.100.53" {
		t.Fatalf("threat_source=%q, want IOC-hit resolver", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "10.0.0.5" {
		t.Fatalf("affected_asset=%q, want internal host", got)
	}
}

// DNS 应答中的解析结果 IP 型 IOC 不在报文 src/dst 中：不命中，仍回落查询域名。
func TestSemanticPeersDNSAnswerIPNotInPeers(t *testing.T) {
	ev := LyEventToDeepSOC(map[string]any{
		"event_id":  "e8",
		"src_ip":    "10.0.0.5",
		"dst_ip":    "218.2.2.2",
		"dst_port":  53,
		"ioc_type":  "ip",
		"ioc_value": "203.0.113.99",
		"app":       map[string]any{"dns_query": "evil.example.com"},
	})
	if got := observableByRole(ev.Observables, "threat_source"); got != "evil.example.com" {
		t.Fatalf("threat_source=%q, want fallback to query domain", got)
	}
	if got := observableByRole(ev.Observables, "affected_asset"); got != "10.0.0.5" {
		t.Fatalf("affected_asset=%q", got)
	}
}
