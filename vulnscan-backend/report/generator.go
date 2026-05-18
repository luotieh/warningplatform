package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	htmltemplate "html/template"
	"os"
	"path/filepath"
	"strings"
	texttemplate "text/template"

	"github.com/go-pdf/fpdf"
)

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) Generate(data *ReportData, format string) ([]byte, error) {
	switch format {
	case FormatWord:
		return g.generateWord(data)
	case FormatPDF:
		return g.generatePDF(data)
	case FormatMarkdown:
		return g.generateMarkdown(data)
	case FormatJSON:
		return g.generateJSON(data)
	case FormatCSV:
		return g.generateCSV(data)
	case FormatSARIF:
		return g.generateSARIF(data)
	default:
		return nil, fmt.Errorf("unsupported report format: %s", format)
	}
}

func (g *Generator) generateMarkdown(data *ReportData) ([]byte, error) {
	tmpl, err := texttemplate.New("report").Funcs(texttemplate.FuncMap{
		"join": strings.Join,
		"intJoin": func(arr []int, sep string) string {
			parts := make([]string, 0, len(arr))
			for _, value := range arr {
				parts = append(parts, fmt.Sprintf("%d", value))
			}
			return strings.Join(parts, sep)
		},
		"formatTarget": func(item DiscoveryItem) string {
			if item.Port > 0 {
				return fmt.Sprintf("%s:%d", item.Target, item.Port)
			}
			return item.Target
		},
	}).Parse(markdownTemplate())
	if err != nil {
		return nil, fmt.Errorf("parse markdown template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render markdown template: %w", err)
	}

	return buf.Bytes(), nil
}

func (g *Generator) generateWord(data *ReportData) ([]byte, error) {
	tmpl, err := htmltemplate.New("report-word").Funcs(htmltemplate.FuncMap{
		"formatTime": func(value interface{}) string {
			switch typed := value.(type) {
			case string:
				return typed
			default:
				return fmt.Sprint(value)
			}
		},
		"join": strings.Join,
		"intJoin": func(arr []int, sep string) string {
			parts := make([]string, 0, len(arr))
			for _, value := range arr {
				parts = append(parts, fmt.Sprintf("%d", value))
			}
			return strings.Join(parts, sep)
		},
		"severityLabel": severityLabel,
		"formatTarget": func(item DiscoveryItem) string {
			if item.Port > 0 {
				return fmt.Sprintf("%s:%d", item.Target, item.Port)
			}
			return item.Target
		},
	}).Parse(wordTemplate())
	if err != nil {
		return nil, fmt.Errorf("parse word template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("render word template: %w", err)
	}

	return buf.Bytes(), nil
}

func (g *Generator) generateJSON(data *ReportData) ([]byte, error) {
	return json.MarshalIndent(data, "", "  ")
}

func (g *Generator) generateCSV(data *ReportData) ([]byte, error) {
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	header := []string{
		"Kind", "ID", "Title", "Type", "Severity", "Target", "Status",
		"CVE", "Summary", "Description", "Evidence", "Remediation",
	}
	if err := w.Write(header); err != nil {
		return nil, err
	}

	for _, vuln := range data.Vulnerabilities {
		row := []string{
			"vulnerability",
			vuln.ID,
			vuln.Title,
			"漏洞",
			vuln.Severity,
			vuln.Asset,
			vuln.Status,
			vuln.CVEID,
			"",
			vuln.Description,
			vuln.Evidence,
			vuln.Remediation,
		}
		if err := w.Write(row); err != nil {
			return nil, err
		}
	}

	for _, finding := range data.DiscoveryFindings {
		target := finding.Target
		if finding.Port > 0 {
			target = fmt.Sprintf("%s:%d", finding.Target, finding.Port)
		}
		row := []string{
			"discovery",
			finding.ID,
			finding.Title,
			finding.TypeLabel,
			finding.Severity,
			target,
			"",
			"",
			finding.Summary,
			finding.Description,
			finding.Evidence,
			"",
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

func (g *Generator) generatePDF(data *ReportData) ([]byte, error) {
	fontBytes, err := loadReportPDFFont()
	if err != nil {
		return nil, err
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(14, 14, 14)
	pdf.SetAutoPageBreak(true, 14)
	pdf.AddUTF8FontFromBytes("report-font", "", fontBytes)
	pdf.SetFont("report-font", "", 11)
	pdf.SetTitle(data.Title, false)
	pdf.AddPage()

	pdf.SetFillColor(240, 246, 255)
	pdf.SetDrawColor(218, 228, 240)
	pdf.SetTextColor(34, 52, 76)
	pdf.SetFont("report-font", "", 18)
	pdf.CellFormat(0, 12, data.Title, "", 1, "L", false, 0, "")
	pdf.SetFont("report-font", "", 10)
	pdf.SetTextColor(92, 110, 133)
	pdf.CellFormat(0, 7, fmt.Sprintf("生成时间：%s", data.GeneratedAt.Format("2006-01-02 15:04:05")), "", 1, "L", false, 0, "")
	if data.Task != nil {
		pdf.CellFormat(0, 7, fmt.Sprintf("任务：%s", data.Task.Name), "", 1, "L", false, 0, "")
	}
	pdf.Ln(3)

	g.renderPDFSectionTitle(pdf, "摘要")
	summaryLines := []string{
		fmt.Sprintf("资产数：%d", data.Summary.TotalAssets),
		fmt.Sprintf("总发现：%d", data.Summary.TotalFindings),
		fmt.Sprintf("漏洞数：%d", data.Summary.TotalVulns),
		fmt.Sprintf("发现信息：%d", data.Summary.DiscoveryCount),
		fmt.Sprintf("严重 / 高危：%d / %d", data.Summary.CriticalCount, data.Summary.HighCount),
		fmt.Sprintf("风险评分：%.2f", data.Summary.RiskScore),
	}
	if data.Summary.ScanDuration != "" {
		summaryLines = append(summaryLines, fmt.Sprintf("扫描耗时：%s", data.Summary.ScanDuration))
	}
	for _, line := range summaryLines {
		g.renderPDFParagraph(pdf, line)
	}

	g.renderPDFSectionTitle(pdf, "漏洞列表")
	if len(data.Vulnerabilities) == 0 {
		g.renderPDFParagraph(pdf, "当前任务未发现漏洞。")
	} else {
		for index, item := range data.Vulnerabilities {
			content := fmt.Sprintf(
				"%d. [%s] %s\n资产：%s    CVE：%s    状态：%s\n说明：%s",
				index+1,
				severityLabel(item.Severity),
				item.Title,
				emptyAsDash(item.Asset),
				emptyAsDash(item.CVEID),
				emptyAsDash(item.Status),
				emptyAsDash(truncateReportText(item.Description, 220)),
			)
			g.renderPDFBlock(pdf, content)
		}
	}

	g.renderPDFSectionTitle(pdf, "发现信息")
	if len(data.DiscoveryFindings) == 0 {
		g.renderPDFParagraph(pdf, "当前任务未产生额外发现信息。")
	} else {
		for index, item := range data.DiscoveryFindings {
			target := item.Target
			if item.Port > 0 {
				target = fmt.Sprintf("%s:%d", item.Target, item.Port)
			}
			content := fmt.Sprintf(
				"%d. [%s] %s\n目标：%s    模块：%s    置信度：%d%%\n摘要：%s",
				index+1,
				emptyAsDash(item.TypeLabel),
				item.Title,
				emptyAsDash(target),
				emptyAsDash(item.ModuleID),
				item.Confidence,
				emptyAsDash(truncateReportText(item.Summary, 220)),
			)
			g.renderPDFBlock(pdf, content)
		}
	}

	g.renderPDFSectionTitle(pdf, "资产概览")
	if len(data.Assets) == 0 {
		g.renderPDFParagraph(pdf, "当前任务未形成资产概览。")
	} else {
		for index, item := range data.Assets {
			content := fmt.Sprintf(
				"%d. %s\nIP：%s    端口：%s\n服务：%s\n漏洞数：%d    总发现：%d",
				index+1,
				emptyAsDash(item.Host),
				emptyAsDash(item.IP),
				emptyAsDash(joinInts(item.OpenPorts, ", ")),
				emptyAsDash(strings.Join(item.Services, ", ")),
				item.VulnCount,
				item.FindingCount,
			)
			g.renderPDFBlock(pdf, content)
		}
	}

	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("render pdf: %w", err)
	}
	if pdf.Err() {
		return nil, fmt.Errorf("render pdf: %w", pdf.Error())
	}
	return buf.Bytes(), nil
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

	for _, vuln := range vulns {
		level := severityMap[strings.ToLower(vuln.Severity)]
		if level == "" {
			level = "note"
		}

		result := map[string]interface{}{
			"ruleId":  vuln.ID,
			"level":   level,
			"message": map[string]string{"text": vuln.Title},
			"locations": []map[string]interface{}{
				{
					"physicalLocation": map[string]interface{}{
						"artifactLocation": map[string]string{
							"uri": vuln.Asset,
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

{{if .Task}}
## 任务信息

| 字段 | 值 |
|------|------|
| 任务 ID | {{.Task.ID}} |
| 任务名称 | {{.Task.Name}} |
| 任务状态 | {{.Task.Status}} |
| 扫描目标 | {{join .Task.Targets ", "}} |
{{if .Summary.ScanDuration}}| 扫描耗时 | {{.Summary.ScanDuration}} |{{end}}
{{end}}

## 摘要

| 指标 | 值 |
|------|------|
| 资产数 | {{.Summary.TotalAssets}} |
| 总发现数 | {{.Summary.TotalFindings}} |
| 漏洞数 | {{.Summary.TotalVulns}} |
| 发现信息数 | {{.Summary.DiscoveryCount}} |
| 发现类型数 | {{.Summary.TotalDiscoveryType}} |
| 严重 | {{.Summary.CriticalCount}} |
| 高危 | {{.Summary.HighCount}} |
| 中危 | {{.Summary.MediumCount}} |
| 低危 | {{.Summary.LowCount}} |
| 提示 | {{.Summary.InfoCount}} |
| 风险分 | {{printf "%.2f" .Summary.RiskScore}} |

## 漏洞清单

| # | 标题 | 严重性 | CVE | 资产 | 状态 |
|---|------|--------|-----|------|------|
{{- range $index, $item := .Vulnerabilities}}
| {{$index}} | {{$item.Title}} | {{$item.Severity}} | {{$item.CVEID}} | {{$item.Asset}} | {{$item.Status}} |
{{- end}}

{{if .DiscoveryGroups}}
## 发现分布

| 类型 | 数量 |
|------|------|
{{- range .DiscoveryGroups}}
| {{.Label}} | {{.Count}} |
{{- end}}
{{end}}

{{if .DiscoveryFindings}}
## 发现信息

| # | 类型 | 标题 | 目标 | 摘要 |
|---|------|------|------|------|
{{- range $index, $item := .DiscoveryFindings}}
| {{$index}} | {{$item.TypeLabel}} | {{$item.Title}} | {{formatTarget $item}} | {{$item.Summary}} |
{{- end}}
{{end}}

{{if .Assets}}
## 资产概览

| 主机 | IP | 端口 | 服务 | 指纹 | 漏洞数 | 总发现 |
|------|----|------|------|------|--------|--------|
{{- range .Assets}}
| {{.Host}} | {{.IP}} | {{intJoin .OpenPorts ", "}} | {{join .Services ", "}} | {{join .Fingerprints ", "}} | {{.VulnCount}} | {{.FindingCount}} |
{{- end}}
{{end}}
`
}

func wordTemplate() string {
	return `<!DOCTYPE html>
<html lang="zh-CN" xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word">
<head>
  <meta charset="UTF-8" />
  <title>{{.Title}}</title>
  <style>
    body { font-family: "Microsoft YaHei", "SimHei", sans-serif; color: #24324c; font-size: 12pt; line-height: 1.7; margin: 24px; }
    h1 { font-size: 22pt; margin: 0 0 8px; color: #1d4ed8; }
    h2 { font-size: 15pt; margin: 22px 0 10px; padding: 8px 12px; background: #eff6ff; border-left: 4px solid #2563eb; }
    p { margin: 6px 0; }
    .meta { color: #5c6e85; margin-bottom: 14px; }
    .summary { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .summary td { width: 33%; padding: 8px 10px; border: 1px solid #dbe4f0; background: #fafcff; }
    .summary .label { display: block; font-size: 10.5pt; color: #6b7d93; }
    .summary .value { display: block; font-size: 15pt; font-weight: 700; color: #22344c; margin-top: 4px; }
    table.data { width: 100%; border-collapse: collapse; margin-top: 10px; }
    table.data th, table.data td { border: 1px solid #dbe4f0; padding: 8px 10px; vertical-align: top; }
    table.data th { background: #f5f8fc; text-align: left; color: #22344c; }
    .muted { color: #70839c; }
  </style>
</head>
<body>
  <h1>{{.Title}}</h1>
  <div class="meta">
    <div>生成时间：{{.GeneratedAt.Format "2006-01-02 15:04:05"}}</div>
    {{if .Task}}<div>任务名称：{{.Task.Name}}　任务状态：{{.Task.Status}}</div>{{end}}
    {{if .Summary.ScanDuration}}<div>扫描耗时：{{.Summary.ScanDuration}}</div>{{end}}
  </div>

  <h2>摘要</h2>
  <table class="summary">
    <tr>
      <td><span class="label">资产数</span><span class="value">{{.Summary.TotalAssets}}</span></td>
      <td><span class="label">总发现</span><span class="value">{{.Summary.TotalFindings}}</span></td>
      <td><span class="label">漏洞数</span><span class="value">{{.Summary.TotalVulns}}</span></td>
    </tr>
    <tr>
      <td><span class="label">发现信息</span><span class="value">{{.Summary.DiscoveryCount}}</span></td>
      <td><span class="label">严重 / 高危</span><span class="value">{{.Summary.CriticalCount}} / {{.Summary.HighCount}}</span></td>
      <td><span class="label">风险评分</span><span class="value">{{printf "%.2f" .Summary.RiskScore}}</span></td>
    </tr>
  </table>

  <h2>漏洞列表</h2>
  {{if .Vulnerabilities}}
  <table class="data">
    <thead>
      <tr><th>标题</th><th>严重度</th><th>CVE</th><th>资产</th><th>状态</th><th>说明</th></tr>
    </thead>
    <tbody>
      {{range .Vulnerabilities}}
      <tr>
        <td>{{.Title}}</td>
        <td>{{severityLabel .Severity}}</td>
        <td>{{.CVEID}}</td>
        <td>{{.Asset}}</td>
        <td>{{.Status}}</td>
        <td>{{.Description}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="muted">当前任务未发现漏洞。</p>
  {{end}}

  <h2>发现信息</h2>
  {{if .DiscoveryFindings}}
  <table class="data">
    <thead>
      <tr><th>类型</th><th>标题</th><th>目标</th><th>模块</th><th>置信度</th><th>摘要</th></tr>
    </thead>
    <tbody>
      {{range .DiscoveryFindings}}
      <tr>
        <td>{{.TypeLabel}}</td>
        <td>{{.Title}}</td>
        <td>{{formatTarget .}}</td>
        <td>{{.ModuleID}}</td>
        <td>{{.Confidence}}%</td>
        <td>{{.Summary}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="muted">当前任务未产生额外发现信息。</p>
  {{end}}

  <h2>资产概览</h2>
  {{if .Assets}}
  <table class="data">
    <thead>
      <tr><th>主机</th><th>IP</th><th>端口</th><th>服务</th><th>指纹</th><th>漏洞数</th><th>总发现</th></tr>
    </thead>
    <tbody>
      {{range .Assets}}
      <tr>
        <td>{{.Host}}</td>
        <td>{{.IP}}</td>
        <td>{{intJoin .OpenPorts ", "}}</td>
        <td>{{join .Services ", "}}</td>
        <td>{{join .Fingerprints ", "}}</td>
        <td>{{.VulnCount}}</td>
        <td>{{.FindingCount}}</td>
      </tr>
      {{end}}
    </tbody>
  </table>
  {{else}}
  <p class="muted">当前任务未形成资产概览。</p>
  {{end}}
</body>
</html>`
}

func severityLabel(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "严重"
	case "high":
		return "高危"
	case "medium":
		return "中危"
	case "low":
		return "低危"
	default:
		return "提示"
	}
}

func joinInts(values []int, sep string) string {
	if len(values) == 0 {
		return ""
	}
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, sep)
}

func emptyAsDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func truncateReportText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if value == "" || limit <= 0 {
		return value
	}
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "..."
}

func loadReportPDFFont() ([]byte, error) {
	candidates := []string{
		filepath.Join(os.Getenv("WINDIR"), "Fonts", "simhei.ttf"),
		filepath.Join(os.Getenv("WINDIR"), "Fonts", "Deng.ttf"),
		filepath.Join(os.Getenv("WINDIR"), "Fonts", "simsunb.ttf"),
		"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
		"/usr/share/fonts/opentype/noto/NotoSansCJKSC-Regular.otf",
		"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
	}

	for _, path := range candidates {
		if strings.TrimSpace(path) == "" {
			continue
		}
		content, err := os.ReadFile(path)
		if err == nil {
			return content, nil
		}
	}

	return nil, fmt.Errorf("生成 PDF 失败：未找到可用的中文字体")
}

func (g *Generator) renderPDFSectionTitle(pdf *fpdf.Fpdf, title string) {
	pdf.Ln(2)
	pdf.SetFont("report-font", "", 13)
	pdf.SetTextColor(29, 78, 216)
	pdf.CellFormat(0, 9, title, "", 1, "L", false, 0, "")
	pdf.SetFont("report-font", "", 11)
	pdf.SetTextColor(36, 50, 76)
}

func (g *Generator) renderPDFParagraph(pdf *fpdf.Fpdf, text string) {
	pdf.MultiCell(0, 6.5, text, "", "L", false)
}

func (g *Generator) renderPDFBlock(pdf *fpdf.Fpdf, text string) {
	pdf.SetFillColor(248, 251, 255)
	pdf.SetDrawColor(223, 232, 243)
	pdf.MultiCell(0, 6.5, text, "1", "L", true)
	pdf.Ln(1.5)
}
