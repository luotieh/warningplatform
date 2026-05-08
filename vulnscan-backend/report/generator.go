package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
)

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) Generate(data *ReportData, format string) ([]byte, error) {
	switch format {
	case FormatMarkdown:
		return g.generateMarkdown(data)
	case FormatJSON:
		return g.generateJSON(data)
	case FormatCSV:
		return g.generateCSV(data)
	case FormatSARIF:
		return g.generateSARIF(data)
	default:
		return nil, fmt.Errorf("不支持的格式: %s", format)
	}
}

func (g *Generator) generateMarkdown(data *ReportData) ([]byte, error) {
	tmpl, err := template.New("report").Funcs(template.FuncMap{
		"upper":  strings.ToUpper,
		"repeat": strings.Repeat,
		"join":   strings.Join,
		"intJoin": func(arr []int, sep string) string {
			strs := make([]string, len(arr))
			for i, v := range arr {
				strs[i] = fmt.Sprintf("%d", v)
			}
			return strings.Join(strs, sep)
		},
	}).Parse(markdownTemplate())
	if err != nil {
		return nil, fmt.Errorf("解析模板失败: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("渲染模板失败: %w", err)
	}

	return buf.Bytes(), nil
}

func (g *Generator) generateJSON(data *ReportData) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

func (g *Generator) generateCSV(data *ReportData) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{"ID", "Title", "Severity", "CVE", "Asset", "Status", "Description"}
	if err := w.Write(header); err != nil {
		return nil, err
	}

	for _, v := range data.Vulnerabilities {
		row := []string{
			v.ID, v.Title, v.Severity, v.CVEID,
			v.Asset, v.Status, v.Description,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}

	w.Flush()
	return buf.Bytes(), w.Error()
}

func (g *Generator) generateSARIF(data *ReportData) ([]byte, error) {
	sarif := map[string]interface{}{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "VulnScan",
						"version": "1.0.0",
					},
				},
				"results": g.buildSARIFResults(data.Vulnerabilities),
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

func (g *Generator) buildSARIFResults(vulns []VulnItem) []map[string]interface{} {
	var results []map[string]interface{}

	severityMap := map[string]string{
		"critical": "error",
		"high":     "error",
		"medium":   "warning",
		"low":      "note",
		"info":     "note",
	}

	for _, v := range vulns {
		level := severityMap[strings.ToLower(v.Severity)]
		if level == "" {
			level = "note"
		}

		result := map[string]interface{}{
			"ruleId":  v.ID,
			"level":   level,
			"message": map[string]string{"text": v.Title},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": v.Asset,
						},
					},
				},
			},
		}
		results = append(results, result)
	}

	return results
}

func markdownTemplate() string {
	return `# {{.Title}}

> 生成时间: {{.GeneratedAt.Format "2006-01-02 15:04:05"}}
> 生成人: {{.GeneratedBy}}

## 概览

| 指标 | 数值 |
|------|------|
| 总资产数 | {{.Summary.TotalAssets}} |
| 总漏洞数 | {{.Summary.TotalVulns}} |
| 严重 | {{.Summary.CriticalCount}} |
| 高危 | {{.Summary.HighCount}} |
| 中危 | {{.Summary.MediumCount}} |
| 低危 | {{.Summary.LowCount}} |
| 信息 | {{.Summary.InfoCount}} |
| 风险评分 | {{printf "%.1f" .Summary.RiskScore}} |
| 扫描耗时 | {{.Summary.ScanDuration}} |

## 漏洞列表

| # | 标题 | 严重性 | CVE | 资产 | 状态 |
|---|------|--------|-----|------|------|
{{- range $i, $v := .Vulnerabilities}}
| {{$i}} | {{$v.Title}} | {{$v.Severity}} | {{$v.CVEID}} | {{$v.Asset}} | {{$v.Status}} |
{{- end}}

{{range .Vulnerabilities}}
### {{.Title}}

- **严重性**: {{.Severity}}
- **CVE**: {{.CVEID}}
- **资产**: {{.Asset}}
- **状态**: {{.Status}}

**描述**: {{.Description}}

{{if .Evidence}}**证据**: ` + "```" + `
{{.Evidence}}
` + "```" + `{{end}}

{{if .Remediation}}**修复建议**: {{.Remediation}}{{end}}

---
{{end}}

## 资产清单

| 主机 | IP | 开放端口 | 服务 | 指纹 | 漏洞数 |
|------|-----|---------|------|------|--------|
{{- range .Assets}}
| {{.Host}} | {{.IP}} | {{intJoin .OpenPorts ", "}} | {{join .Services ", "}} | {{join .Fingerprints ", "}} | {{.VulnCount}} |
{{- end}}

{{if .Compliance}}
## 合规检查

- **标准**: {{.Compliance.Framework}}
- **得分**: {{printf "%.1f%%" .Compliance.Score}}
- **通过**: {{.Compliance.Passed}} | **失败**: {{.Compliance.Failed}} | **跳过**: {{.Compliance.Skipped}}
{{end}}
`
}
