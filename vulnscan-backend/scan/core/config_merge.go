package core

// ModuleConfigFor 合并任务级参数与 module_configs[moduleID] 覆盖项。
func ModuleConfigFor(moduleID string, global map[string]interface{}) map[string]interface{} {
	cfg := shallowCopyMap(global)
	delete(cfg, "module_configs")
	delete(cfg, "engine_preset")
	delete(cfg, "derived")
	delete(cfg, "derived_target_count")

	if per := moduleConfigOverrides(global); per != nil {
		if modCfg, ok := per[moduleID]; ok {
			for k, v := range modCfg {
				cfg[k] = v
			}
		}
	}
	return cfg
}

func moduleConfigOverrides(global map[string]interface{}) map[string]map[string]interface{} {
	if global == nil {
		return nil
	}
	raw, ok := global["module_configs"]
	if !ok || raw == nil {
		return nil
	}
	switch m := raw.(type) {
	case map[string]map[string]interface{}:
		return m
	case map[string]interface{}:
		out := make(map[string]map[string]interface{}, len(m))
		for id, v := range m {
			if inner, ok := v.(map[string]interface{}); ok {
				out[id] = inner
			}
		}
		return out
	default:
		return nil
	}
}

func shallowCopyMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return make(map[string]interface{})
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
