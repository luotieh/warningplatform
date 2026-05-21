package scanrunner

// EngineRuleInfo 描述一条影响扫描行为的规则及其来源，供前端展示与审计。
type EngineRuleInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Source       string `json:"source"`
	Default      string `json:"default"`
	ConfigKey    string `json:"config_key,omitempty"`
	Configurable bool   `json:"configurable"`
	Description  string `json:"description"`
}

// TaskLevelParam 任务级可配置项（写入 parameters，非 module_configs）。
type TaskLevelParam struct {
	Key          string        `json:"key"`
	Name         string        `json:"name"`
	Type         string        `json:"type"`
	DefaultValue interface{}   `json:"default_value"`
	Description  string        `json:"description"`
	Source       string        `json:"source"`
	Options      []ParamOption `json:"options,omitempty"`
}

type ParamOption struct {
	Value interface{} `json:"value"`
	Label string      `json:"label"`
}

// EngineRulesCatalog 内置/硬编码规则的清单（可配置项标明 config_key）。
func EngineRulesCatalog() []EngineRuleInfo {
	return []EngineRuleInfo{
		{
			ID: "derive_performance", Name: "按目标数推导性能参数", Source: "scanrunner/derive.go",
			Default: "engine_preset=auto 时启用", ConfigKey: "engine_preset", Configurable: true,
			Description: "推导 rate_limit、max_concurrency、nuclei_concurrency 等；parameters 中同名键可覆盖。",
		},
		{
			ID: "engine_presets", Name: "引擎预设", Source: "scanrunner/presets.go",
			Default: "无", ConfigKey: "engine_preset", Configurable: true,
			Description: "conservative / distributed_safe / nuclei_oast_ready / auto。",
		},
		{
			ID: "auto_skip_web_vuln", Name: "无 HTTP 服务时跳过 Web 漏洞模块", Source: "scanrunner/engine_gating.go",
			Default: "关闭", ConfigKey: "engine.auto_skip_web_vulns_without_http", Configurable: true,
			Description: "未发现 80/443/8080 等或 service_probe 的 http 服务时，跳过 web_vuln_scan、dir_scan 等。",
		},
		{
			ID: "web_vuln_module_set", Name: "Web 漏洞模块集合", Source: "scanrunner/engine_gating.go",
			Default: "内置 map（含组合模块 web_vuln_scan）", Configurable: false,
			Description: "门控判断使用的模块 ID 列表；通过上一项开关整体启用/关闭，不可逐项编辑。",
		},
		{
			ID: "finding_min_confidence", Name: "发现项最低置信度", Source: "scanrunner/engine_policy.go",
			Default: "不限制", ConfigKey: "engine.min_confidence", Configurable: true,
			Description: "低于阈值的发现可能不入库；可配合 engine.min_confidence_vuln_only。",
		},
		{
			ID: "finding_max_count", Name: "单任务最大入库发现数", Source: "scanrunner/engine_policy.go",
			Default: "不限制", ConfigKey: "engine.max_findings", Configurable: true,
			Description: "达到上限后停止持久化新发现。",
		},
		{
			ID: "nuclei_interactsh_derive", Name: "大目标量默认关闭 Interactsh", Source: "scanrunner/derive.go",
			Default: "目标>50 时 nuclei_interactsh_disable=true", ConfigKey: "nuclei_interactsh_disable", Configurable: true,
			Description: "OOB 检测；也可在引擎预设 nuclei_oast_ready 中显式开启。",
		},
		{
			ID: "nuclei_templates", Name: "Nuclei 模板路径", Source: "knowledge/nuclei/fs_sources.go",
			Default: "环境变量 VULNSCAN_NUCLEI_EXTRA_TEMPLATE_DIRS + DB PoC", ConfigKey: "nuclei_template_dir", Configurable: true,
			Description: "任务 parameters 可指定 nuclei_template_dir / nuclei_template_paths。",
		},
		{
			ID: "scan_global_config", Name: "全局扫描默认值", Source: "scan/scanconfig/config.go",
			Default: "DB 表 vs_scan_config 或代码 defaultConfig", Configurable: true,
			Description: "HTTP 超时、默认端口范围、爬虫深度等；系统设置中维护，非任务弹窗。",
		},
		{
			ID: "exclusion_rules", Name: "扫描排除规则", Source: "scanrunner/filter.go + 排除规则 API",
			Default: "任务创建时加载 DB 规则", Configurable: true,
			Description: "按目标/端口/模块过滤；在「扫描排除规则」页面配置。",
		},
		{
			ID: "fp_rules", Name: "误报规则", Source: "漏洞/误报规则模块",
			Default: "DB", Configurable: true,
			Description: "过滤已知误报；在「误报规则」页面配置。",
		},
		{
			ID: "builtin_templates", Name: "内置扫描模板", Source: "template/engine/builtins.go",
			Default: "代码内置，启动/同步写入 DB", Configurable: true,
			Description: "模板阶段与模块列表；「同步内置」更新 DB，非隐藏逻辑。",
		},
	}
}

// TaskLevelParamsCatalog 建议在「创建任务」高级区配置的任务级参数。
func TaskLevelParamsCatalog() []TaskLevelParam {
	return []TaskLevelParam{
		{
			Key: "engine_preset", Name: "引擎预设", Type: "select", DefaultValue: "auto",
			Source:      "scanrunner/presets.go",
			Description: "auto=按目标数推导；也可选 conservative 等",
			Options: []ParamOption{
				{Value: "auto", Label: "自动推导"},
				{Value: "conservative", Label: "保守"},
				{Value: "distributed_safe", Label: "分布式安全"},
				{Value: "nuclei_oast_ready", Label: "Nuclei OAST"},
				{Value: "", Label: "不使用预设"},
			},
		},
		{
			Key: "rate_limit", Name: "全局请求速率", Type: "number", DefaultValue: nil,
			Source:      "scanrunner/derive.go 或 presets",
			Description: "覆盖自动推导值；影响 Nuclei 等模块",
		},
		{
			Key: "max_concurrency", Name: "全局最大并发", Type: "number", DefaultValue: nil,
			Source:      "scanrunner/derive.go",
			Description: "覆盖自动推导值",
		},
		{
			Key: "engine.auto_skip_web_vulns_without_http", Name: "无 HTTP 时跳过 Web 漏洞", Type: "boolean", DefaultValue: false,
			Source:      "scanrunner/engine_gating.go",
			Description: "true=启用门控；false=始终执行 Web 漏洞阶段",
		},
		{
			Key: "nuclei_interactsh_disable", Name: "禁用 Nuclei Interactsh", Type: "boolean", DefaultValue: nil,
			Source:      "knowledge/nuclei/interactsh_config.go",
			Description: "OOB/盲注协作平台；大扫描建议开启禁用",
		},
		{
			Key: "verification_level", Name: "验证级别（任务级默认）", Type: "select", DefaultValue: "both",
			Source:      "scan/core/module_config.go",
			Description: "可被 module_configs.web_vuln_scan 覆盖",
			Options: []ParamOption{
				{Value: "both", Label: "原理+利用"},
				{Value: "principle", Label: "仅原理"},
				{Value: "exploit", Label: "仅利用"},
			},
		},
	}
}

// ModuleCreateParamsCatalog 创建任务弹窗应直接展示的主模块参数（写入 module_configs）。
func ModuleCreateParamsCatalog() []TaskLevelParam {
	return []TaskLevelParam{
		{
			Key: "host_discover.ports", Name: "端口范围", Type: "select", DefaultValue: "top100",
			Source:      "scan/module/bundle/params.go",
			Description: "作用于主机发现组合模块内的端口/SYN 扫描",
			Options: []ParamOption{
				{Value: "top100", Label: "常用100端口"},
				{Value: "top1000", Label: "常用1000端口"},
				{Value: "full", Label: "全端口 (1-65535)"},
			},
		},
	}
}

// PrimaryModuleExposureDoc 主模块应在 UI 暴露的配置项说明。
func PrimaryModuleExposureDoc() map[string][]string {
	return map[string][]string{
		"host_discover":    {"ports（端口范围）", "parallel（可选，子模块并行度）"},
		"service_probe":    {"（无单独参数，使用任务级并发/超时）"},
		"web_recon":        {"（子模块参数合并隐藏；需细调时用 legacy 模式）"},
		"web_vuln_scan":    {"verification_level（验证级别）"},
		"credential_audit": {"（弱口令/爆破在子模块；字典来自系统字典库）"},
		"nuclei-poc":       {"rate_limit、nuclei_template_dir、nuclei_interactsh_disable（任务级 parameters）"},
		"dir_scan":         {"concurrency、timeout（legacy 或任务级）"},
		"web_crawl":        {"（爬虫深度等见 scan/scanconfig 全局配置）"},
	}
}
