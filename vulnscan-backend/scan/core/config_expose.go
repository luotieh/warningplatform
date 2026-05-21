package core

// GetExposedModuleConfigInfo 仅返回模块显式声明的参数（不含通用 concurrency/timeout/enabled），避免 UI 噪音。
func GetExposedModuleConfigInfo(m ScanModule) ModuleConfigInfo {
	info := ModuleConfigInfo{
		ID:       m.ID(),
		Name:     m.Name(),
		Category: m.Category(),
	}
	if cm, ok := m.(ConfigurableModule); ok {
		info.Params = append(info.Params, cm.Params()...)
	}
	return info
}
