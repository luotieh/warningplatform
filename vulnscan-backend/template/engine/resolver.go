package engine

import (
	"fmt"
	"regexp"
	"strings"
)

var varPattern = regexp.MustCompile(`\{\{\.(\w+)\}\}`)

func Instantiate(tmpl *ScanTemplate, params map[string]interface{}) (*TemplateInstance, error) {
	merged, err := mergeParams(tmpl.Params, params)
	if err != nil {
		return nil, err
	}

	var stages []ResolvedStage
	for _, s := range tmpl.Stages {
		resolved := ResolvedStage{
			Name:      s.Name,
			ModuleID:  s.Module,
			Parallel:  s.Parallel,
			Condition: s.Condition,
			Config:    resolveConfig(s.Config, merged),
			DependsOn: s.DependsOn,
		}
		stages = append(stages, resolved)
	}

	return &TemplateInstance{
		TemplateID: tmpl.ID,
		Params:     merged,
		Stages:     stages,
	}, nil
}

func mergeParams(defs []TemplateParam, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for _, def := range defs {
		if val, ok := input[def.Name]; ok {
			result[def.Name] = val
		} else if def.Default != nil {
			result[def.Name] = def.Default
		} else if def.Required {
			return nil, fmt.Errorf("缺少必需参数: %s", def.Name)
		}
	}

	for k, v := range input {
		if _, exists := result[k]; !exists {
			result[k] = v
		}
	}

	return result, nil
}

func resolveConfig(config map[string]interface{}, params map[string]interface{}) map[string]interface{} {
	if config == nil {
		return nil
	}

	resolved := make(map[string]interface{}, len(config))
	for k, v := range config {
		resolved[k] = resolveValue(v, params)
	}
	return resolved
}

func resolveValue(v interface{}, params map[string]interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return resolveString(val, params)
	case map[string]interface{}:
		return resolveConfig(val, params)
	case []interface{}:
		resolved := make([]interface{}, len(val))
		for i, item := range val {
			resolved[i] = resolveValue(item, params)
		}
		return resolved
	default:
		return v
	}
}

func resolveString(s string, params map[string]interface{}) string {
	return varPattern.ReplaceAllStringFunc(s, func(match string) string {
		key := strings.TrimPrefix(strings.TrimSuffix(match, "}}"), "{{.")
		if val, ok := params[key]; ok {
			return fmt.Sprintf("%v", val)
		}
		return match
	})
}
