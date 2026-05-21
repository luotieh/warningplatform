package bundle

import "vulnscan-backend/scan/core"

// PortRangeParam 主机发现组合模块内 port_scan / syn_scan 共用的端口范围配置。
func PortRangeParam() core.ModuleParam {
	return core.ModuleParam{
		Key:          "ports",
		Name:         "端口范围",
		Type:         "string",
		DefaultValue: "top100",
		Description:  "top100 / top1000 / full，或自定义：22,80,443,8000-8100",
	}
}

var portScanChildIDs = map[string]struct{}{
	"port_scan": {},
	"syn_scan":  {},
}

var vulnVerifyChildIDs = map[string]struct{}{
	"sqli": {}, "xss": {}, "ssrf": {}, "cmdi": {}, "lfi": {}, "ssti": {}, "xxe": {}, "nosqli": {},
}

func applyBundleInheritance(bundleID string, bundleCfg, childCfg map[string]interface{}, childID string) {
	applyBundleCommonConfig(bundleID, bundleCfg, childCfg)
	applyBundleToPortChildren(bundleID, bundleCfg, childCfg, childID)
	if bundleID != "web_vuln_scan" {
		return
	}
	if _, ok := vulnVerifyChildIDs[childID]; !ok {
		return
	}
	if v, ok := bundleCfg["verification_level"]; ok && v != nil && v != "" {
		if _, set := childCfg["verification_level"]; !set {
			childCfg["verification_level"] = v
		}
	}
}

func applyBundleCommonConfig(bundleID string, bundleCfg, childCfg map[string]interface{}) {
	if bundleID != "host_discover" {
		return
	}
	if v, ok := bundleCfg["timeout"]; ok && v != nil && v != "" {
		if _, set := childCfg["timeout"]; !set {
			childCfg["timeout"] = v
		}
	}
}

func applyBundleToPortChildren(bundleID string, bundleCfg, childCfg map[string]interface{}, childID string) {
	if bundleID != "host_discover" {
		return
	}
	if _, ok := portScanChildIDs[childID]; !ok {
		return
	}
	if v, ok := bundleCfg["ports"]; ok && v != nil && v != "" {
		if _, set := childCfg["ports"]; !set {
			childCfg["ports"] = v
		}
	}
}
