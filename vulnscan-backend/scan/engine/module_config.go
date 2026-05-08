package engine

type ModuleParam struct {
	Key          string        `json:"key"`
	Name         string        `json:"name"`
	Type         string        `json:"type"`
	DefaultValue interface{}   `json:"default_value"`
	Description  string        `json:"description"`
	Required     bool          `json:"required"`
	Options      []ParamOption `json:"options,omitempty"`
	Min          *float64      `json:"min,omitempty"`
	Max          *float64      `json:"max,omitempty"`
}

type ParamOption struct {
	Value interface{} `json:"value"`
	Label string      `json:"label"`
}

type ConfigurableModule interface {
	ScanModule
	Params() []ModuleParam
}

type ModuleConfigInfo struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Category string        `json:"category"`
	Params   []ModuleParam `json:"params"`
}

var defaultParams = []ModuleParam{
	{
		Key:          "concurrency",
		Name:         "并发数",
		Type:         "number",
		DefaultValue: 10,
		Description:  "模块内部并发工作线程数",
		Min:          ptrFloat(1),
		Max:          ptrFloat(100),
	},
	{
		Key:          "timeout",
		Name:         "超时时间(秒)",
		Type:         "number",
		DefaultValue: 30,
		Description:  "单个目标的超时时间",
		Min:          ptrFloat(5),
		Max:          ptrFloat(300),
	},
	{
		Key:          "enabled",
		Name:         "启用",
		Type:         "boolean",
		DefaultValue: true,
		Description:  "是否启用该模块",
	},
}

func GetModuleConfigInfo(m ScanModule) ModuleConfigInfo {
	info := ModuleConfigInfo{
		ID:       m.ID(),
		Name:     m.Name(),
		Category: m.Category(),
	}

	info.Params = append(info.Params, defaultParams...)

	if cm, ok := m.(ConfigurableModule); ok {
		info.Params = append(info.Params, cm.Params()...)
	}

	return info
}

func GetConfigValue[T any](config map[string]interface{}, key string, defaultVal T) T {
	if config == nil {
		return defaultVal
	}
	v, ok := config[key]
	if !ok {
		return defaultVal
	}
	if typed, ok := v.(T); ok {
		return typed
	}
	return defaultVal
}

func GetConfigInt(config map[string]interface{}, key string, defaultVal int) int {
	if config == nil {
		return defaultVal
	}
	v, ok := config[key]
	if !ok {
		return defaultVal
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	case int64:
		return int(n)
	}
	return defaultVal
}

func GetConfigBool(config map[string]interface{}, key string, defaultVal bool) bool {
	if config == nil {
		return defaultVal
	}
	v, ok := config[key]
	if !ok {
		return defaultVal
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return defaultVal
}

func VulnVerificationParam() ModuleParam {
	return ModuleParam{
		Key:          "verification_level",
		Name:         "验证级别",
		Type:         "select",
		DefaultValue: "both",
		Description:  "principle=仅原理验证, exploit=仅实际利用, both=全部执行",
		Options: []ParamOption{
			{Value: "both", Label: "全部"},
			{Value: "principle", Label: "原理验证"},
			{Value: "exploit", Label: "实际利用"},
		},
	}
}

func ShouldRunPrinciple(level string) bool {
	return level == "both" || level == "principle"
}

func ShouldRunExploit(level string) bool {
	return level == "both" || level == "exploit"
}

func GetConfigStringSlice(config map[string]interface{}, key string) []string {
	if config == nil {
		return nil
	}
	v, ok := config[key]
	if !ok {
		return nil
	}
	switch s := v.(type) {
	case []string:
		return s
	case []interface{}:
		var result []string
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}
	return nil
}

func ptrFloat(v float64) *float64 {
	return &v
}

func PtrFloat(v float64) *float64 {
	return &v
}
