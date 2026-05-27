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
			ID:          "asset_family",
			Name:        "资产分类",
			Category:    "资产台账",
			Description: "资产登记中的资产分类字段",
			Items: []defaultDictItem{
				{Label: "IP资产", Value: "ip"},
				{Label: "域名网站", Value: "domain_site"},
				{Label: "业务系统", Value: "business_system"},
				{Label: "硬件设备", Value: "hardware"},
				{Label: "软件资产", Value: "software"},
				{Label: "APP", Value: "app"},
				{Label: "小程序", Value: "mini_program"},
				{Label: "公众号", Value: "official_account"},
				{Label: "公共邮箱", Value: "public_mailbox"},
				{Label: "其他", Value: "other"},
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
				{Label: "手工录入", Value: "manual"},
				{Label: "扫描发现", Value: "scan"},
				{Label: "批量导入", Value: "import"},
				{Label: "自动探测", Value: "discovery"},
			},
		},
		{
			ID:          "organize_unit_type",
			Name:        "单位类型",
			Category:    "单位管理",
			Description: "单位信息中的单位类型字段",
			Items: []defaultDictItem{
				{Label: "政府机关", Value: "政府机关"},
				{Label: "事业单位", Value: "事业单位"},
				{Label: "国有企业", Value: "国有企业"},
				{Label: "企业", Value: "企业"},
				{Label: "私营企业", Value: "私营企业"},
				{Label: "其他", Value: "其他"},
			},
		},
		{
			ID:          "organize_industry_category",
			Name:        "行业分类",
			Category:    "单位管理",
			Description: "单位信息中的行业分类字段",
			Items: []defaultDictItem{
				{Label: "政务", Value: "政务"},
				{Label: "金融", Value: "金融"},
				{Label: "教育", Value: "教育"},
				{Label: "医疗", Value: "医疗"},
				{Label: "能源", Value: "能源"},
				{Label: "通信", Value: "通信"},
				{Label: "交通", Value: "交通"},
				{Label: "其他", Value: "其他"},
			},
		},
	}
}

// DefaultDictLabels 返回内置字典项展示名（数据库无配置时用于导入模板等）。
func DefaultDictLabels(dictID string) []string {
	for _, d := range defaultDicts() {
		if d.ID != dictID {
			continue
		}
		labels := make([]string, 0, len(d.Items))
		for _, item := range d.Items {
			labels = append(labels, item.Label)
		}
		return labels
	}
	return nil
}
