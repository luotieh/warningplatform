package systemdict

type defaultDict struct {
	ID          string
	Name        string
	Category    string
	Description string
	Items       []defaultDictItem
}

type defaultDictItem struct {
	Label string
	Value string
}

func defaultDicts() []defaultDict {
	return []defaultDict{
		{
			ID:          "asset_system_type",
			Name:        "资产系统类型",
			Category:    "资产台账",
			Description: "资产登记中的系统类型字段",
			Items: []defaultDictItem{
				{Label: "网站", Value: "url"},
				{Label: "应用系统", Value: "application"},
				{Label: "数据库", Value: "database"},
				{Label: "服务器", Value: "server"},
				{Label: "网络设备", Value: "network"},
				{Label: "安全设备", Value: "security"},
			},
		},
		{
			ID:          "asset_type",
			Name:        "资产类型",
			Category:    "资产台账",
			Description: "资产登记中的资产类型字段",
			Items: []defaultDictItem{
				{Label: "网站", Value: "url"},
				{Label: "应用系统", Value: "application"},
				{Label: "数据库", Value: "database"},
				{Label: "服务器", Value: "server"},
				{Label: "网络设备", Value: "network"},
				{Label: "安全设备", Value: "security"},
			},
		},
		{
			ID:          "asset_security_level",
			Name:        "安全保护等级",
			Category:    "资产台账",
			Description: "资产登记中的安全保护等级字段",
			Items: []defaultDictItem{
				{Label: "一级", Value: "level1"},
				{Label: "二级", Value: "level2"},
				{Label: "三级", Value: "level3"},
				{Label: "四级", Value: "level4"},
				{Label: "五级", Value: "level5"},
			},
		},
		{
			ID:          "asset_data_source",
			Name:        "资产数据来源",
			Category:    "资产台账",
			Description: "资产登记中的数据来源字段",
			Items: []defaultDictItem{
				{Label: "手动导入", Value: "manual_import"},
				{Label: "自动探测", Value: "auto_detect"},
				{Label: "外部集成", Value: "external"},
			},
		},
	}
}
