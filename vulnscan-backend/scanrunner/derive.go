package scanrunner

// DeriveScanParameters 根据目标数量推导扫描性能相关参数（可被任务 parameters 覆盖）。
func DeriveScanParameters(targetCount int) map[string]interface{} {
	if targetCount <= 0 {
		targetCount = 1
	}

	rateLimit := 80
	maxConcurrency := 500
	moduleConcurrency := 10
	nucleiConcurrency := 15

	switch {
	case targetCount <= 3:
		rateLimit = 150
		maxConcurrency = 800
		moduleConcurrency = 16
		nucleiConcurrency = 25
	case targetCount <= 20:
		rateLimit = 100
		maxConcurrency = 600
		moduleConcurrency = 12
		nucleiConcurrency = 20
	case targetCount <= 100:
		rateLimit = 80
		maxConcurrency = 400
		moduleConcurrency = 10
		nucleiConcurrency = 15
	case targetCount <= 500:
		rateLimit = 50
		maxConcurrency = 250
		moduleConcurrency = 8
		nucleiConcurrency = 10
	default:
		rateLimit = 30
		maxConcurrency = 150
		moduleConcurrency = 6
		nucleiConcurrency = 8
	}

	return map[string]interface{}{
		"rate_limit":                rateLimit,
		"max_concurrency":           maxConcurrency,
		"module_concurrency":        moduleConcurrency,
		"nuclei_concurrency":        nucleiConcurrency,
		"nuclei_interactsh_disable": targetCount > 50,
		"poc_unmatched_fallback":    "skip",
		"derived":                   true,
		"derived_target_count":      targetCount,
	}
}

// SuggestParametersResponse 供创建任务前展示推荐参数。
type SuggestParametersResponse struct {
	TargetCount      int                    `json:"target_count"`
	ModuleCount      int                    `json:"module_count"`
	TemplateVersion  string                 `json:"template_version,omitempty"`
	TemplateOutdated bool                   `json:"template_outdated"`
	Derived          map[string]interface{} `json:"derived"`
	ModuleIDs        []string               `json:"module_ids,omitempty"`
}
