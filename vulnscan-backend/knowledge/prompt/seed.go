package prompt

import (
	"log/slog"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

var builtinTemplates = []model.PromptTemplate{
	{
		Name:         "安全事件AI预审",
		Scene:        "ai_preaudit",
		Description:  "对安全事件进行AI预审分析，生成漏洞描述、漏洞危害、修复建议和综合意见",
		SystemPrompt: "你是一名专业的网络安全分析师，擅长安全事件预审、漏洞分析和修复建议。请严格按照 JSON 格式输出，不要输出其他内容。",
		UserPrompt: `请对以下安全事件进行专业预审分析，返回 JSON 格式（字段均为字符串）：
{"vuln_desc":"漏洞描述(详细描述该漏洞/事件的技术原理和表现)","vuln_harm":"漏洞危害(分析该漏洞可能造成的安全影响和业务损失)","fix_advice":"修复建议(给出具体可操作的修复步骤和加固措施)","opinion":"综合预审意见(综合分析结论和处置优先级建议)"}

---
事件信息：
事件名称：{{.Name}}
事件等级：{{.Level}}
风险评分：{{.RiskScore}}
{{if .IncidentType}}事件类型：{{.IncidentType}}
{{end}}{{if .CveId}}CVE编号：{{.CveId}}
{{end}}{{if .CvssScore}}CVSS评分：{{.CvssScore}}
{{end}}{{if .OwaspCategory}}OWASP分类：{{.OwaspCategory}}
{{end}}{{if .ExploitDifficulty}}利用难度：{{.ExploitDifficulty}}
{{end}}{{if .AffectScope}}影响范围：{{.AffectScope}}
{{end}}{{if .Description}}事件描述：{{.Description}}
{{end}}{{if .AssetName}}关联资产：{{.AssetName}}
{{end}}{{if .AssetIP}}资产IP：{{.AssetIP}}
{{end}}`,
		OutputFormat: `{"vuln_desc":"string","vuln_harm":"string","fix_advice":"string","opinion":"string"}`,
		Variables:    `["Name","Level","RiskScore","IncidentType","CveId","CvssScore","OwaspCategory","ExploitDifficulty","AffectScope","Description","AssetName","AssetIP"]`,
		Temperature:  0.3,
		MaxTokens:    2000,
		Enabled:      true,
		IsBuiltin:    true,
		Version:      1,
	},
	{
		Name:         "安全事件AI分类",
		Scene:        "ai_classify",
		Description:  "对安全事件进行AI智能分类和标签标注",
		SystemPrompt: "你是一名网络安全事件分类专家。根据提供的安全事件信息，判断其所属分类并打上合适的标签。请严格按照 JSON 格式输出。",
		UserPrompt: `请对以下安全事件进行分类和标签标注，返回 JSON：
{"category":"事件分类(如:Web应用漏洞/网络攻击/恶意软件/数据泄露/配置缺陷/其他)","tags":"标签(逗号分隔,最多5个)","confidence":"置信度(0-1之间的小数)"}

事件名称：{{.Name}}
事件等级：{{.Level}}
{{if .IncidentType}}事件类型：{{.IncidentType}}
{{end}}{{if .Description}}事件描述：{{.Description}}
{{end}}{{if .CveId}}CVE编号：{{.CveId}}
{{end}}`,
		OutputFormat: `{"category":"string","tags":"string","confidence":"number"}`,
		Variables:    `["Name","Level","IncidentType","Description","CveId"]`,
		Temperature:  0.2,
		MaxTokens:    500,
		Enabled:      true,
		IsBuiltin:    true,
		Version:      1,
	},
}

func SeedBuiltinTemplates(db *gorm.DB) {
	for _, tpl := range builtinTemplates {
		var count int64
		db.Model(&model.PromptTemplate{}).
			Where("scene = ? AND is_builtin = ?", tpl.Scene, true).
			Count(&count)
		if count == 0 {
			if err := db.Create(&tpl).Error; err != nil {
				slog.Warn("种子提示词模板创建失败", "name", tpl.Name, "error", err)
			} else {
				slog.Info("[+] 内置提示词模板已创建", "name", tpl.Name, "scene", tpl.Scene)
			}
		}
	}
}
