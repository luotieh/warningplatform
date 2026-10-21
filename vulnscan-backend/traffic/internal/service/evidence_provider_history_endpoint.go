package service

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"vulnscan-backend/traffic/internal/domain"
)

// Preserve a saved outbound alert endpoint, not an endpoint guessed from its
// IOC or application port. Ambiguous direction/asset/protocol stays absent.
func providerSavedHistoryEndpoint(m map[string]any, assets []domain.Asset, ids []string) string {
	if len(ids) != 1 {
		return ""
	}
	asset, ok := registeredSnapshotAsset(assets, asString(m["src_ip"]))
	if !ok || asset != ids[0] {
		return ""
	}
	ip, err := netip.ParseAddr(asString(m["dst_ip"]))
	if err != nil {
		return ""
	}
	port, valid := strictUint(m["dst_port"])
	if !valid || port == 0 || port > 65535 {
		return ""
	}
	transport := ""
	for _, key := range []string{"protocol", "proto", "detection_method"} {
		value := strings.ToLower(asString(m[key]))
		if value == "" {
			continue
		}
		if value != "tcp" && value != "udp" {
			return ""
		}
		if transport != "" && transport != value {
			return ""
		}
		transport = value
	}
	if transport == "" {
		return ""
	}
	return transport + "://" + net.JoinHostPort(ip.Unmap().String(), strconv.FormatUint(port, 10))
}
