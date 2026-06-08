package engine

func BuiltinTemplates() []*ScanTemplate {
	return []*ScanTemplate{
		quickTemplate(),
		assetEnrichTemplate(),
		assetDiscoveryTemplate(),
		vulnRetestTemplate(),
		reconTemplate(),
		vulnTemplate(),
		vulnFullTemplate(),
		fullTemplate(),
		webFullScanTemplate(),
		hostSecurityTemplate(),
		emergencyTemplate(),
	}
}

func quickTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "quick",
		Name:        "快速扫描",
		Description: "ICMP存活检测+端口扫描+服务识别+Web爬虫",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"quick", "fast"},
		Stages: []TemplateStage{
			{Name: "discover", Modules: []string{"icmp_ping", "port_scan"}, Parallel: true},
			{Name: "probe", Modules: []string{"service_probe", "web_crawl"}, Parallel: true, DependsOn: []string{"discover"}},
		},
	}
}

// assetEnrichTemplate 的 ID 须与 scanrunner.AssetEnrichTemplateID 一致（asset-enrich）。
func assetEnrichTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "asset-enrich",
		Name:        "资产信息富化",
		Description: "DNS 枚举、存活与常用端口探测、服务识别、证书检测、IP 属性（走扫描引擎，结果写入扫描发现）",
		Version:     "2.0.0",
		Author:      "system",
		Tags:        []string{"asset", "enrich", "recon"},
		Stages: []TemplateStage{
			{Name: "discover", Modules: []string{"icmp_ping", "port_scan"}, Parallel: true},
			{Name: "enrich", Modules: []string{"service_probe", "asset_enrich"}, Parallel: true, DependsOn: []string{"discover"}},
		},
	}
}

// assetDiscoveryTemplate 的 ID 须与 scanrunner.AssetDiscoveryTemplateID 一致。
func assetDiscoveryTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "asset-discovery",
		Name:        "资产探测",
		Description: "仅信息收集：主机发现（ICMP/端口）、服务识别，不含漏洞扫描",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"asset", "discovery", "recon"},
		Stages: []TemplateStage{
			{Name: "discover", Modules: []string{"host_discover"}, Parallel: false},
			{Name: "probe", Modules: []string{"service_probe"}, Parallel: false, DependsOn: []string{"discover"}},
		},
	}
}

func vulnRetestTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "vuln-retest",
		Name:        "漏洞回测",
		Description: "针对指定目标复测 Nuclei/PoC 模板，验证漏洞是否仍可被触发",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"vuln", "retest", "poc"},
		Stages: []TemplateStage{
			{Name: "retest", Modules: []string{"nuclei-poc"}, Parallel: false},
		},
	}
}

func reconTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "recon",
		Name:        "信息收集",
		Description: "全面信息收集：子域名、DNS、指纹、WAF、JS分析、证书、API发现",
		Version:     "2.0.0",
		Author:      "system",
		Tags:        []string{"recon", "discovery"},
		Stages: []TemplateStage{
			{Name: "discover", Modules: []string{"host_discover", "service_probe", "web_crawl"}, Parallel: true},
			{Name: "recon", Modules: []string{"web_recon"}, Parallel: true, DependsOn: []string{"discover"}},
		},
	}
}

func vulnTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "vuln",
		Name:        "漏洞扫描",
		Description: "Web 漏洞与凭据安全组合检测",
		Version:     "2.0.0",
		Author:      "system",
		Tags:        []string{"vuln", "attack"},
		Stages: []TemplateStage{
			{Name: "vuln", Modules: []string{"web_vuln_scan", "credential_audit"}, Parallel: true},
		},
	}
}

// PLACEHOLDER_REMAINING_TEMPLATES

func vulnFullTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "vuln-full",
		Name:        "完整漏洞扫描",
		Description: "Web 漏洞与凭据安全组合检测（含 API 安全）",
		Version:     "2.0.0",
		Author:      "system",
		Tags:        []string{"vuln", "full"},
		Stages: []TemplateStage{
			{Name: "vuln", Modules: []string{"web_vuln_scan", "credential_audit"}, Parallel: true},
		},
	}
}

func fullTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "full",
		Name:        "全量扫描",
		Description: "信息收集+目录扫描+漏洞扫描+nuclei模板完整流程",
		Version:     "2.0.0",
		Author:      "system",
		Tags:        []string{"full", "recommended"},
		Stages: []TemplateStage{
			{Name: "discover", Modules: []string{"host_discover", "service_probe"}, Parallel: true},
			{Name: "recon", Modules: []string{"web_recon"}, Parallel: true, DependsOn: []string{"discover"}},
			{Name: "attack", Modules: []string{
				"web_vuln_scan", "credential_audit", "nuclei-poc", "dir_scan", "infra_extra",
			}, Parallel: true, DependsOn: []string{"recon"}, Condition: &StageCondition{PrevStageMinTargets: 1}},
		},
	}
}

func webFullScanTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "web-full",
		Name:        "Web 全量扫描",
		Description: "对Web应用进行全面安全检测，包含端口、指纹、漏洞、信息泄露等",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"web", "full"},
		Params: []TemplateParam{
			{Name: "ports", Type: "string", Default: "top100", Description: "扫描端口范围"},
			{Name: "concurrency", Type: "int", Default: 500, Description: "端口扫描并发数"},
			{Name: "scan_sqli", Type: "bool", Default: true, Description: "是否检测SQL注入"},
			{Name: "scan_xss", Type: "bool", Default: true, Description: "是否检测XSS"},
		},
		Stages: []TemplateStage{
			{Name: "端口发现", Module: "port_scan", Config: map[string]interface{}{
				"ports": "{{.ports}}", "concurrency": "{{.concurrency}}",
			}},
			{Name: "服务识别", Modules: []string{"service_probe", "web_fingerprint"}, Parallel: true, DependsOn: []string{"端口发现"}},
			{Name: "信息收集", Modules: []string{"dir_scan", "info_leak"}, Parallel: true, DependsOn: []string{"服务识别"}},
			{Name: "SQL注入", Module: "sqli", Condition: &StageCondition{Expression: "{{.scan_sqli}}"}, DependsOn: []string{"信息收集"}},
			{Name: "XSS检测", Module: "xss", Condition: &StageCondition{Expression: "{{.scan_xss}}"}, DependsOn: []string{"信息收集"}},
			{Name: "证书检测", Module: "cert_check", DependsOn: []string{"端口发现"}},
		},
	}
}

func hostSecurityTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "host-security",
		Name:        "主机安全扫描",
		Description: "针对主机进行端口、服务、弱口令检测",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"host", "infra"},
		Params: []TemplateParam{
			{Name: "ports", Type: "string", Default: "top1000", Description: "扫描端口范围"},
		},
		Stages: []TemplateStage{
			{Name: "端口发现", Module: "port_scan", Config: map[string]interface{}{"ports": "{{.ports}}"}},
			{Name: "服务识别", Module: "service_probe", DependsOn: []string{"端口发现"}},
			{Name: "弱口令", Module: "weak_pass", DependsOn: []string{"服务识别"}},
			{Name: "证书检测", Module: "cert_check", DependsOn: []string{"端口发现"}},
		},
	}
}

func emergencyTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "emergency",
		Name:        "应急响应扫描",
		Description: "快速扫描关键端口和已知漏洞，用于应急响应场景",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"emergency", "fast"},
		Params: []TemplateParam{
			{Name: "ports", Type: "string", Default: "21,22,80,443,3306,3389,6379,8080,8443,9200", Description: "快速端口列表"},
		},
		Stages: []TemplateStage{
			{Name: "端口发现", Module: "port_scan", Config: map[string]interface{}{"ports": "{{.ports}}", "concurrency": 1000}},
			{Name: "服务识别", Modules: []string{"service_probe", "info_leak"}, Parallel: true, DependsOn: []string{"端口发现"}},
			{Name: "弱口令", Module: "weak_pass", DependsOn: []string{"服务识别"}},
		},
	}
}
