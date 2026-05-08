package engine

func BuiltinTemplates() []*ScanTemplate {
	return []*ScanTemplate{
		webFullScanTemplate(),
		hostSecurityTemplate(),
		emergencyTemplate(),
	}
}

func webFullScanTemplate() *ScanTemplate {
	return &ScanTemplate{
		ID:          "web-full",
		Name:        "Web 全量扫描",
		Description: "对Web应用进行全面安全检测，包含端口、指纹、漏洞、信息泄露等",
		Version:     "1.0.0",
		Author:      "system",
		Tags:        []string{"web", "full", "recommended"},
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
			{Name: "服务识别", Module: "service_probe", Parallel: true, Config: nil},
			{Name: "Web指纹", Module: "web_fingerprint", Parallel: true, Config: nil},
			{Name: "目录扫描", Module: "dir_scan", Config: nil},
			{Name: "信息泄露", Module: "info_leak", Parallel: true, Config: nil},
			{Name: "SQL注入", Module: "sqli", Condition: &StageCondition{
				Expression: "{{.scan_sqli}}",
			}, Config: nil},
			{Name: "XSS检测", Module: "xss", Condition: &StageCondition{
				Expression: "{{.scan_xss}}",
			}, Config: nil},
			{Name: "证书检测", Module: "cert_check", Config: nil},
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
			{Name: "端口发现", Module: "port_scan", Config: map[string]interface{}{
				"ports": "{{.ports}}",
			}},
			{Name: "服务识别", Module: "service_probe", Config: nil},
			{Name: "弱口令", Module: "weak_pass", Config: nil},
			{Name: "证书检测", Module: "cert_check", Config: nil},
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
			{Name: "端口发现", Module: "port_scan", Config: map[string]interface{}{
				"ports":       "{{.ports}}",
				"concurrency": 1000,
			}},
			{Name: "服务+指纹", Module: "service_probe", Parallel: true, Config: nil},
			{Name: "弱口令", Module: "weak_pass", Parallel: true, Config: nil},
			{Name: "信息泄露", Module: "info_leak", Parallel: true, Config: nil},
		},
	}
}
