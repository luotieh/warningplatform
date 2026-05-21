package bundle

import (
	"log/slog"

	"vulnscan-backend/scan/core"
)

// filterHostDiscoverChildren 避免 port_scan 与 syn_scan 对同一端口范围重复全量 TCP 探测。
func filterHostDiscoverChildren(bundleID string, children []core.ScanModule, bundleCfg map[string]interface{}) []core.ScanModule {
	if bundleID != "host_discover" || len(children) < 2 {
		return children
	}

	var portScan, synScan core.ScanModule
	rest := make([]core.ScanModule, 0, len(children))
	for _, c := range children {
		switch c.ID() {
		case "port_scan":
			portScan = c
		case "syn_scan":
			synScan = c
		default:
			rest = append(rest, c)
		}
	}
	if portScan == nil || synScan == nil {
		return children
	}

	out := append([]core.ScanModule{}, rest...)
	if core.CanRawSYNScan() {
		out = append(out, synScan)
		slog.Info("[host_discover] 使用 SYN 扫描，跳过重复的 TCP Connect 端口扫描")
	} else {
		out = append(out, portScan)
		slog.Info("[host_discover] 无 raw SYN 权限，使用 TCP Connect 端口扫描，跳过 syn_scan 回退重复扫描")
	}
	return out
}
