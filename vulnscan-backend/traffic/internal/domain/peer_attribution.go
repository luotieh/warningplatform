package domain

import (
	"net/netip"
	"strings"
)

// PeerAttributionInput 是威胁侧/受影响资产归属判定的输入视图。
// ingest（原始 ly 事件）与展示层（已存事件 context）各自适配到该结构，
// 共用 AttributePeers 一份实现，保证 AI 研判输入与列表展示语义一致。
type PeerAttributionInput struct {
	SrcIP    string
	DstIP    string
	SrcPort  int
	DstPort  int
	DNSQuery string
	IOCType  string
	IOCValue string
	// Direction 是 ta_node 的方向标注：inbound/outbound/lateral。
	Direction string
}

// AttributePeers 判定事件的威胁侧与受影响资产侧。
// 判据优先级：DNS 解析流量 > IP/CIDR 型 IOC 命中侧 > 域名/URL 型 IOC > ta_node 方向字段。
// 报文原始方向（src→dst）不代表攻击方向：命中情报 IOC 的一侧永远是威胁侧。
// 返回空字符串表示无法可靠判定，调用方不得据此断言攻击发起方。
func AttributePeers(in PeerAttributionInput) (threat, asset string) {
	src := strings.TrimSpace(in.SrcIP)
	dst := strings.TrimSpace(in.DstIP)
	iocValue := strings.TrimSpace(in.IOCValue)
	iocType := strings.ToLower(strings.TrimSpace(in.IOCType))
	dnsQuery := strings.TrimSpace(in.DNSQuery)

	// DNS 解析流量：威胁侧是域名（IOC 或查询名），受害侧是发起查询的主机；
	// 公共 DNS 服务器（应答方向）既不是威胁侧也不是受害资产。
	if client, isDNS := dnsQueryClient(in.SrcPort, in.DstPort, src, dst, dnsQuery); isDNS {
		if iocValue != "" && isDomainIOCType(iocType) {
			return iocValue, client
		}
		// IP/CIDR 型 IOC 命中报文一侧时按命中侧归属：此时威胁在解析链路本身
		// （恶意/被劫持解析器、失陷主机），而非查询域名——命中侧永远是威胁侧。
		// DNS 应答里的解析结果 IP 不在报文 src/dst 中，不会命中，仍回落查询域名。
		if threat, asset, ok := ipIOCPeers(iocValue, iocType, src, dst); ok {
			if client != "" && client != threat {
				asset = client
			}
			return threat, asset
		}
		return dnsQuery, client
	}

	// IP/CIDR 型 IOC：命中哪一侧，哪一侧就是威胁地址，另一侧为受影响资产。
	if threat, asset, ok := ipIOCPeers(iocValue, iocType, src, dst); ok {
		return threat, asset
	}

	// 域名/URL 型 IOC（HTTP/TLS 等访问恶意域名）：域名是威胁侧，受影响资产是
	// 访问发起方。响应方向的报文 src 是服务端（DNS 应答中的 DNS 服务器、HTTP
	// 应答中的远端服务器），不能按报文 src 取资产，需按方向/内外网判定发起方。
	if iocValue != "" && isDomainIOCType(iocType) {
		return iocValue, accessInitiator(in.Direction, src, dst)
	}

	// 无 IOC（载荷/行为规则命中）：借 ta_node 方向字段辅助判定，仍不足则留空。
	switch strings.ToLower(strings.TrimSpace(in.Direction)) {
	case "inbound", "lateral":
		return src, dst
	case "outbound":
		return dst, src
	}
	return "", ""
}

// isDomainIOCType 判定域名型 IOC 类别：domain/url/dns/hostname/fqdn 均按
// “域名是威胁侧”处理，避免 dns/hostname 等类别穿透到方向兜底误标报文 src。
func isDomainIOCType(iocType string) bool {
	switch iocType {
	case "domain", "url", "dns", "hostname", "fqdn":
		return true
	}
	return false
}

// accessInitiator 判定域名访问的发起方（受影响资产侧）：
// outbound 由 src 发起，inbound 应答流量的发起方是 dst；无方向标注时按内外网
// 位置兜底（内网侧通常是访问发起方），仍无法区分时退回报文 src。
func accessInitiator(direction, src, dst string) string {
	switch strings.ToLower(strings.TrimSpace(direction)) {
	case "outbound":
		return src
	case "inbound":
		return dst
	}
	srcPrivate, dstPrivate := isPrivateIP(src), isPrivateIP(dst)
	switch {
	case srcPrivate && !dstPrivate:
		return src
	case dstPrivate && !srcPrivate:
		return dst
	}
	return src
}

// dnsQueryClient 识别 DNS 解析流量并返回发起查询的主机（客户端）。
// 端口优先：dst_port=53 为查询方向、src_port=53 为应答方向（853 为 DoT，同语义）；
// 端口缺失时要求存在查询域名，并用内网地址兜底判定；双内网/双外网无法判定时客户端留空。
func dnsQueryClient(srcPort, dstPort int, src, dst, dnsQuery string) (client string, isDNS bool) {
	if dstPort == 53 || dstPort == 853 {
		return src, true
	}
	if srcPort == 53 || srcPort == 853 {
		return dst, true
	}
	if dnsQuery == "" {
		return "", false
	}
	srcPrivate, dstPrivate := isPrivateIP(src), isPrivateIP(dst)
	switch {
	case srcPrivate && !dstPrivate:
		return src, true
	case dstPrivate && !srcPrivate:
		return dst, true
	}
	return "", true
}

func isPrivateIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil && addr.Unmap().IsPrivate()
}

// ipIOCPeers 返回 IP/CIDR 型 IOC 的命中侧归属：命中侧为威胁侧，另一侧为受影响资产。
// 域名型 IOC 与空值不参与，交由调用方按各自语义处理。
func ipIOCPeers(iocValue, iocType, src, dst string) (threat, asset string, ok bool) {
	if iocValue == "" || isDomainIOCType(iocType) {
		return "", "", false
	}
	if ipIOCMatch(iocValue, dst) {
		return dst, src, true
	}
	if ipIOCMatch(iocValue, src) {
		return src, dst, true
	}
	return "", "", false
}

// ipIOCMatch 判定 ip 是否命中 IP/CIDR 型 IOC 值（精确匹配或网段包含）。
func ipIOCMatch(iocValue, ip string) bool {
	iocValue = strings.TrimSpace(iocValue)
	ip = strings.TrimSpace(ip)
	if iocValue == "" || ip == "" {
		return false
	}
	if strings.EqualFold(iocValue, ip) {
		return true
	}
	if network, err := netip.ParsePrefix(strings.ToLower(iocValue)); err == nil {
		if addr, err := netip.ParseAddr(strings.ToLower(ip)); err == nil {
			return network.Contains(addr.Unmap())
		}
	}
	return false
}
