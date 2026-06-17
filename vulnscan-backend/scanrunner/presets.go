package scanrunner

import (
	"fmt"
	"sort"
	"strings"

	"vulnscan-backend/model"
)

// EnginePresetInfo 供 GET /scan/engine-presets 与前端展示。
type EnginePresetInfo struct {
	Name        string                 `json:"name"`
	Label       string                 `json:"label"`
	Description string                 `json:"description"`
	Category    string                 `json:"category"`
	Parameters  map[string]interface{} `json:"parameters"`
}

var enginePresetDefs = map[string]EnginePresetInfo{
	"auto": {
		Name:        "auto",
		Label:       "自动模式",
		Description: "按目标数量自动推导并发与速率（任务 parameters 可覆盖单项）。",
		Category:    "通用",
		Parameters:  map[string]interface{}{},
	},
	"quick": {
		Name:        "quick",
		Label:       "快速扫描",
		Description: "仅执行端口扫描、服务探测和高危 PoC 匹配，跳过爬虫和深度检测，适合快速排查。",
		Category:    "通用",
		Parameters: map[string]interface{}{
			"rate_limit":                       200,
			"host_rate_limit":                  80,
			"max_concurrency":                  1000,
			"nuclei_interactsh_disable":        true,
			"poc_unmatched_fallback":           "skip",
			"engine.module_timeout_seconds":    60,
			"auto_skip_web_vulns_without_http": true,
			"skip_modules":                     "web_crawl,js_analyze,dir_scan,subdomain_brute,email_collect,company_recon,screenshot,nettopo",
		},
	},
	"full": {
		Name:        "full",
		Label:       "全量扫描",
		Description: "启用所有模块进行全面深度扫描，包括爬虫、目录扫描、JS分析、所有漏洞检测。耗时较长。",
		Category:    "通用",
		Parameters: map[string]interface{}{
			"rate_limit":                    80,
			"host_rate_limit":               40,
			"nuclei_interactsh_disable":     false,
			"poc_unmatched_fallback":        "run",
			"engine.module_timeout_seconds": 300,
			"engine.max_findings":           50000,
		},
	},
	"weak_password": {
		Name:        "weak_password",
		Label:       "弱口令专项",
		Description: "专注弱口令和默认凭据检测，适用于内网资产合规排查。",
		Category:    "专项",
		Parameters: map[string]interface{}{
			"rate_limit":                    60,
			"host_rate_limit":               30,
			"nuclei_interactsh_disable":     true,
			"poc_unmatched_fallback":        "skip",
			"focus_modules":                 "weak_pass,brute_force,credential,unauth",
			"engine.module_timeout_seconds": 180,
		},
	},
	"compliance": {
		Name:        "compliance",
		Label:       "合规检查",
		Description: "检查安全头、TLS配置、敏感信息泄露、弱加密等合规项，适用于等保/合规评估。",
		Category:    "专项",
		Parameters: map[string]interface{}{
			"rate_limit":                    100,
			"host_rate_limit":               50,
			"nuclei_interactsh_disable":     true,
			"poc_unmatched_fallback":        "skip",
			"focus_modules":                 "sec_headers,cert_check,info_leak,cors,web_fingerprint,tech_detect",
			"engine.module_timeout_seconds": 120,
		},
	},
	"web_vuln": {
		Name:        "web_vuln",
		Label:       "Web漏洞扫描",
		Description: "专注 Web 应用漏洞检测，包括注入、XSS、SSRF、文件包含等 OWASP Top 10。",
		Category:    "专项",
		Parameters: map[string]interface{}{
			"rate_limit":                    100,
			"host_rate_limit":               40,
			"nuclei_interactsh_disable":     false,
			"poc_unmatched_fallback":        "run",
			"focus_modules":                 "web_crawl,sqli,xss,ssrf,cmdi,lfi,ssti,xxe,nosqli,cors,open_redirect,hpp,jwt_sec,idor,injection",
			"engine.module_timeout_seconds": 240,
		},
	},
	"recon_only": {
		Name:        "recon_only",
		Label:       "信息收集",
		Description: "仅进行资产发现和信息收集，不发送任何攻击性 payload。适用于资产测绘。",
		Category:    "通用",
		Parameters: map[string]interface{}{
			"rate_limit":                    150,
			"host_rate_limit":               60,
			"nuclei_interactsh_disable":     true,
			"poc_unmatched_fallback":        "skip",
			"focus_modules":                 "icmp_ping,port_scan,service_probe,web_fingerprint,tech_detect,waf_detect,dns_all,cert_check,favicon,ip_attr,real_ip,subdomain_brute,screenshot",
			"engine.module_timeout_seconds": 120,
		},
	},
	"conservative": {
		Name:        "conservative",
		Label:       "保守模式",
		Description: "降低全局请求速率并关闭 Interactsh OOB，适合脆弱环境或低带宽。",
		Category:    "性能",
		Parameters: map[string]interface{}{
			"rate_limit":                40,
			"host_rate_limit":           20,
			"nuclei_interactsh_disable": true,
			"poc_unmatched_fallback":    "skip",
		},
	},
	"distributed_safe": {
		Name:        "distributed_safe",
		Label:       "分布式安全",
		Description: "多 Worker 分片时减轻 OOB 与总出站压力；仍允许任务参数覆盖。",
		Category:    "性能",
		Parameters: map[string]interface{}{
			"rate_limit":                60,
			"host_rate_limit":           30,
			"nuclei_interactsh_disable": true,
			"poc_unmatched_fallback":    "skip",
		},
	},
	"nuclei_oast_ready": {
		Name:        "nuclei_oast_ready",
		Label:       "OOB检测增强",
		Description: "显式允许 Interactsh（需自建服务或环境变量 URL）；并略放宽轮询。",
		Category:    "性能",
		Parameters: map[string]interface{}{
			"nuclei_interactsh_disable":      false,
			"nuclei_interactsh_poll_seconds": 8,
		},
	},
}

// ScanEnginePreset 按名称返回预设参数字典（拷贝），未知名称返回 nil。
func ScanEnginePreset(name string) map[string]interface{} {
	key := strings.ToLower(strings.TrimSpace(name))
	def, ok := enginePresetDefs[key]
	if !ok || len(def.Parameters) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(def.Parameters))
	for k, v := range def.Parameters {
		out[k] = v
	}
	return out
}

// ListScanEnginePresets 返回全部内置预设（稳定排序）。
func ListScanEnginePresets() []EnginePresetInfo {
	names := make([]string, 0, len(enginePresetDefs))
	for n := range enginePresetDefs {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]EnginePresetInfo, 0, len(names))
	for _, n := range names {
		def := enginePresetDefs[n]
		cp := make(map[string]interface{}, len(def.Parameters))
		for k, v := range def.Parameters {
			cp[k] = v
		}
		def.Parameters = cp
		out = append(out, def)
	}
	return out
}

func enginePresetName(params model.JSONMap) string {
	if params == nil {
		return ""
	}
	v, ok := params["engine_preset"]
	if !ok || v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return strings.TrimSpace(fmt.Sprint(t))
	}
}

// MergePresetWithParameters 先合并 engine_preset 对应键，再用任务 parameters 覆盖（并去掉 engine_preset 元键）。
func MergePresetWithParameters(params model.JSONMap) map[string]interface{} {
	out := make(map[string]interface{})
	if name := enginePresetName(params); name != "" {
		if preset := ScanEnginePreset(name); len(preset) > 0 {
			for k, v := range preset {
				out[k] = v
			}
		}
	}
	if params != nil {
		for k, v := range params {
			if k == "engine_preset" {
				continue
			}
			out[k] = v
		}
	}
	return out
}
