package domain

import "testing"

// DNS 流量识别与查询客户端判定（原展示层 dnsResolutionPeers 用例，随实现迁入 domain）。
func TestAttributePeersDNSClientDetection(t *testing.T) {
	cases := []struct {
		name       string
		in         PeerAttributionInput
		wantThreat string
		wantAsset  string
	}{
		{
			name: "查询方向 dst_port=53",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.8", DstIP: "218.2.2.2",
				SrcPort: 51234, DstPort: 53,
				DNSQuery: "x.com",
			},
			wantThreat: "x.com", wantAsset: "10.0.0.8",
		},
		{
			name: "应答方向 src_port=53",
			in: PeerAttributionInput{
				SrcIP: "218.2.2.2", DstIP: "10.0.0.8",
				SrcPort: 53, DstPort: 51234,
				DNSQuery: "x.com",
			},
			wantThreat: "x.com", wantAsset: "10.0.0.8",
		},
		{
			name: "无端口、dns_query+内网兜底",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.8", DstIP: "218.2.2.2",
				DNSQuery: "xzasket.com",
			},
			wantThreat: "xzasket.com", wantAsset: "10.0.0.8",
		},
		{
			name: "双内网客户端留空、威胁侧仍按查询域名",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.8", DstIP: "10.0.0.9",
				DNSQuery: "x.com",
			},
			wantThreat: "x.com", wantAsset: "",
		},
		{
			name: "无端口且无 dns_query 不干预",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.8", DstIP: "218.2.2.2",
			},
			wantThreat: "", wantAsset: "",
		},
		{
			name: "非 DNS 不干预",
			in: PeerAttributionInput{
				SrcIP: "1.2.3.4", DstIP: "10.0.0.8",
				SrcPort: 12345, DstPort: 443,
			},
			wantThreat: "", wantAsset: "",
		},
		{
			name: "DoT 应答方向 src_port=853",
			in: PeerAttributionInput{
				SrcIP: "218.2.2.2", DstIP: "10.0.0.8",
				SrcPort: 853, DstPort: 51234,
				DNSQuery: "x.com",
			},
			wantThreat: "x.com", wantAsset: "10.0.0.8",
		}, {
			name: "恶意解析器：IP IOC 命中侧优先于查询域名",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.5", DstIP: "198.51.100.53",
				DstPort: 53, DNSQuery: "www.benign.example.com",
				IOCType: "ip", IOCValue: "198.51.100.53",
			},
			wantThreat: "198.51.100.53", wantAsset: "10.0.0.5",
		},
		{
			name: "失陷主机清单：客户端自身命中 IP IOC",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.5", DstIP: "218.2.2.2",
				DstPort: 53, DNSQuery: "x.com",
				IOCType: "ip", IOCValue: "10.0.0.5",
			},
			wantThreat: "10.0.0.5", wantAsset: "218.2.2.2",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			threat, asset := AttributePeers(tc.in)
			if threat != tc.wantThreat || asset != tc.wantAsset {
				t.Fatalf("got (%q, %q), want (%q, %q)", threat, asset, tc.wantThreat, tc.wantAsset)
			}
		})
	}
}

// 非 DNS 场景的归属优先级：IP IOC 命中侧 > 域名 IOC > 方向字段 > 留空。
func TestAttributePeersPriority(t *testing.T) {
	cases := []struct {
		name       string
		in         PeerAttributionInput
		wantThreat string
		wantAsset  string
	}{
		{
			name: "IP IOC 命中目的侧（外连 C2）",
			in: PeerAttributionInput{
				SrcIP: "172.16.100.16", DstIP: "192.185.86.177",
				SrcPort: 51000, DstPort: 443,
				IOCType: "ip", IOCValue: "192.185.86.177",
			},
			wantThreat: "192.185.86.177", wantAsset: "172.16.100.16",
		},
		{
			name: "域名 IOC：域名是威胁侧，访问发起方是资产侧",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.5", DstIP: "93.184.216.34",
				SrcPort: 51000, DstPort: 443,
				IOCType: "domain", IOCValue: "evil.example.com",
			},
			wantThreat: "evil.example.com", wantAsset: "10.0.0.5",
		},
		{
			name: "域名 IOC 应答方向：资产是发起方 dst 而非 DNS 服务器",
			in: PeerAttributionInput{
				SrcIP: "223.5.5.5", DstIP: "10.0.0.8",
				Direction: "inbound",
				IOCType:   "domain", IOCValue: "evil.example.com",
			},
			wantThreat: "evil.example.com", wantAsset: "10.0.0.8",
		},
		{
			name: "ioc_type=dns 不穿透到方向兜底误标 DNS 服务器",
			in: PeerAttributionInput{
				SrcIP: "223.5.5.5", DstIP: "10.0.0.8",
				Direction: "inbound",
				IOCType:   "dns", IOCValue: "evil.example.com",
			},
			wantThreat: "evil.example.com", wantAsset: "10.0.0.8",
		},
		{
			name: "域名 IOC 无方向标注：按内外网判定发起方",
			in: PeerAttributionInput{
				SrcIP: "93.184.216.34", DstIP: "10.0.0.8",
				SrcPort: 443, DstPort: 51000,
				IOCType: "domain", IOCValue: "evil.example.com",
			},
			wantThreat: "evil.example.com", wantAsset: "10.0.0.8",
		}, {
			name: "无 IOC 方向兜底 outbound",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.5", DstIP: "93.184.216.34",
				SrcPort: 51000, DstPort: 443,
				Direction: "outbound",
			},
			wantThreat: "93.184.216.34", wantAsset: "10.0.0.5",
		},
		{
			name: "判据不足留空",
			in: PeerAttributionInput{
				SrcIP: "10.0.0.5", DstIP: "10.0.0.6",
				SrcPort: 51000, DstPort: 443,
			},
			wantThreat: "", wantAsset: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			threat, asset := AttributePeers(tc.in)
			if threat != tc.wantThreat || asset != tc.wantAsset {
				t.Fatalf("got (%q, %q), want (%q, %q)", threat, asset, tc.wantThreat, tc.wantAsset)
			}
		})
	}
}
