package sitemonitor

import (
	"bytes"
	"context"
	"fmt"
	"html/template"
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type ReportGenerator struct {
	db *db.DB
}

func NewReportGenerator(database *db.DB) *ReportGenerator {
	return &ReportGenerator{db: database}
}

func (g *ReportGenerator) session() *gorm.DB {
	s, _ := g.db.GetDBSession()
	return s
}

type ReportData struct {
	Title       string
	GeneratedAt string
	Period      string
	StartDate   string
	EndDate     string
	Summary     ReportSummary
	TaskReports []TaskReportItem
	SLAStats    SLAStats
	Compliance  ComplianceResult
}

type ReportSummary struct {
	TotalTasks      int
	EnabledTasks    int
	TotalExecutions int
	IssueCount      int
	IssueRate       float64
	OnlineAgents    int
	DimStats        map[string]DimReportStat
}

type DimReportStat struct {
	Total     int
	Issues    int
	IssueRate float64
}

type TaskReportItem struct {
	TaskName   string
	URL        string
	Executions int
	Issues     int
	IssueRate  float64
	LastRun    string
	DimResults map[string]string
}

type SLAStats struct {
	AvailabilityRate float64
	AvgResponseMS    float64
	P95ResponseMS    float64
	UptimeHours      float64
	DowntimeMinutes  float64
	MeetsSLA         bool
	SLATarget        float64
}

type ComplianceResult struct {
	Level     string
	Score     float64
	Items     []ComplianceItem
	PassCount int
	WarnCount int
	FailCount int
}

type ComplianceItem struct {
	Category    string
	Name        string
	Status      string
	Description string
	Suggestion  string
}

func (g *ReportGenerator) GenerateReport(ctx context.Context, startDate, endDate time.Time, taskIDs []string) (*ReportData, error) {
	report := &ReportData{
		Title:       "站点监控报告",
		GeneratedAt: time.Now().Format("2006-01-02 15:04:05"),
		StartDate:   startDate.Format("2006-01-02"),
		EndDate:     endDate.Format("2006-01-02"),
		Period:      fmt.Sprintf("%s 至 %s", startDate.Format("2006-01-02"), endDate.Format("2006-01-02")),
	}

	session := g.session().WithContext(ctx)

	taskQuery := session.Model(&model.MonitorPathTask{})
	if len(taskIDs) > 0 {
		taskQuery = taskQuery.Where("id IN ?", taskIDs)
	}

	var tasks []model.MonitorPathTask
	taskQuery.Find(&tasks)

	report.Summary.TotalTasks = len(tasks)
	enabledCount := 0
	for _, t := range tasks {
		if t.Enabled {
			enabledCount++
		}
	}
	report.Summary.EnabledTasks = enabledCount

	execQuery := session.Model(&model.MonitorExecution{}).
		Where("created_at BETWEEN ? AND ?", startDate, endDate)
	if len(taskIDs) > 0 {
		execQuery = execQuery.Where("path_task_id IN ?", taskIDs)
	}

	var totalExecs int64
	execQuery.Count(&totalExecs)
	report.Summary.TotalExecutions = int(totalExecs)

	var issueExecs int64
	issueQuery := session.Model(&model.MonitorExecution{}).
		Where("created_at BETWEEN ? AND ? AND has_issue = ?", startDate, endDate, true)
	if len(taskIDs) > 0 {
		issueQuery = issueQuery.Where("path_task_id IN ?", taskIDs)
	}
	issueQuery.Count(&issueExecs)
	report.Summary.IssueCount = int(issueExecs)

	if totalExecs > 0 {
		report.Summary.IssueRate = float64(issueExecs) / float64(totalExecs) * 100
	}

	dimStats := make(map[string]DimReportStat)
	for _, dim := range model.MonitorAllDimensions {
		var dimTotal, dimIssue int64
		dq := session.Model(&model.MonitorExecution{}).
			Where("dimension = ? AND created_at BETWEEN ? AND ?", dim, startDate, endDate)
		if len(taskIDs) > 0 {
			dq = dq.Where("path_task_id IN ?", taskIDs)
		}
		dq.Count(&dimTotal)

		diq := session.Model(&model.MonitorExecution{}).
			Where("dimension = ? AND created_at BETWEEN ? AND ? AND has_issue = ?", dim, startDate, endDate, true)
		if len(taskIDs) > 0 {
			diq = diq.Where("path_task_id IN ?", taskIDs)
		}
		diq.Count(&dimIssue)

		rate := 0.0
		if dimTotal > 0 {
			rate = float64(dimIssue) / float64(dimTotal) * 100
		}
		dimStats[dim] = DimReportStat{
			Total: int(dimTotal), Issues: int(dimIssue), IssueRate: rate,
		}
	}
	report.Summary.DimStats = dimStats

	for _, task := range tasks {
		var taskExecs int64
		var taskIssues int64
		session.Model(&model.MonitorExecution{}).
			Where("path_task_id = ? AND created_at BETWEEN ? AND ?", task.ID, startDate, endDate).
			Count(&taskExecs)
		session.Model(&model.MonitorExecution{}).
			Where("path_task_id = ? AND created_at BETWEEN ? AND ? AND has_issue = ?", task.ID, startDate, endDate, true).
			Count(&taskIssues)

		issueRate := 0.0
		if taskExecs > 0 {
			issueRate = float64(taskIssues) / float64(taskExecs) * 100
		}
		displayURL := task.URLOverride
		if displayURL == "" {
			displayURL = task.Path
		}

		report.TaskReports = append(report.TaskReports, TaskReportItem{
			TaskName:   task.Name,
			URL:        displayURL,
			Executions: int(taskExecs),
			Issues:     int(taskIssues),
			IssueRate:  issueRate,
		})
	}

	report.SLAStats = g.computeSLA(ctx, startDate, endDate, taskIDs)
	report.Compliance = g.evaluateCompliance(report)

	return report, nil
}

func (g *ReportGenerator) computeSLA(ctx context.Context, startDate, endDate time.Time, taskIDs []string) SLAStats {
	session := g.session().WithContext(ctx)

	q := session.Model(&model.MonitorExecution{}).
		Where("dimension = ? AND created_at BETWEEN ? AND ?", "availability", startDate, endDate)
	if len(taskIDs) > 0 {
		q = q.Where("path_task_id IN ?", taskIDs)
	}

	var totalAvail, availOK int64
	q.Count(&totalAvail)

	okQ := session.Model(&model.MonitorExecution{}).
		Where("dimension = ? AND created_at BETWEEN ? AND ? AND has_issue = ?", "availability", startDate, endDate, false)
	if len(taskIDs) > 0 {
		okQ = okQ.Where("path_task_id IN ?", taskIDs)
	}
	okQ.Count(&availOK)

	sla := SLAStats{SLATarget: 99.9}
	if totalAvail > 0 {
		sla.AvailabilityRate = float64(availOK) / float64(totalAvail) * 100
	}

	totalHours := endDate.Sub(startDate).Hours()
	sla.UptimeHours = totalHours * sla.AvailabilityRate / 100
	sla.DowntimeMinutes = (totalHours - sla.UptimeHours) * 60
	sla.MeetsSLA = sla.AvailabilityRate >= sla.SLATarget

	return sla
}

func (g *ReportGenerator) evaluateCompliance(report *ReportData) ComplianceResult {
	result := ComplianceResult{Score: 100}
	var items []ComplianceItem

	checks := []struct {
		Category string
		Name     string
		Check    func() (string, string, string)
	}{
		{"可用性", "站点可用率≥99.9%", func() (string, string, string) {
			if report.SLAStats.AvailabilityRate >= 99.9 {
				return "pass", "可用率达标", ""
			}
			if report.SLAStats.AvailabilityRate >= 99.0 {
				return "warn", fmt.Sprintf("可用率%.2f%%，接近阈值", report.SLAStats.AvailabilityRate), "建议增加监控频率"
			}
			return "fail", fmt.Sprintf("可用率%.2f%%，未达标", report.SLAStats.AvailabilityRate), "需检查站点稳定性"
		}},
		{"安全", "无篡改事件", func() (string, string, string) {
			if ds, ok := report.Summary.DimStats["tamper"]; ok && ds.Issues > 0 {
				return "fail", fmt.Sprintf("发现%d次篡改事件", ds.Issues), "立即排查篡改原因"
			}
			return "pass", "未发现篡改", ""
		}},
		{"安全", "无暗链注入", func() (string, string, string) {
			if ds, ok := report.Summary.DimStats["blacklink"]; ok && ds.Issues > 0 {
				return "fail", fmt.Sprintf("发现%d次暗链", ds.Issues), "清除暗链并加固"
			}
			return "pass", "未发现暗链", ""
		}},
		{"安全", "无域名劫持", func() (string, string, string) {
			if ds, ok := report.Summary.DimStats["domain_hijack"]; ok && ds.Issues > 0 {
				return "fail", fmt.Sprintf("发现%d次域名劫持嫌疑", ds.Issues), "检查DNS配置"
			}
			return "pass", "未发现域名劫持", ""
		}},
		{"合规", "敏感词检测", func() (string, string, string) {
			if ds, ok := report.Summary.DimStats["sensitive_word"]; ok && ds.Issues > 0 {
				return "warn", fmt.Sprintf("发现%d次敏感词命中", ds.Issues), "审查敏感内容"
			}
			return "pass", "未发现违规敏感词", ""
		}},
		{"合规", "敏感文件检测", func() (string, string, string) {
			if ds, ok := report.Summary.DimStats["sensitive_file"]; ok && ds.Issues > 0 {
				return "warn", fmt.Sprintf("发现%d次敏感文件暴露", ds.Issues), "移除敏感文件"
			}
			return "pass", "未发现敏感文件暴露", ""
		}},
		{"运营", "监测覆盖率", func() (string, string, string) {
			if report.Summary.TotalTasks == 0 {
				return "warn", "无监测任务", "添加监测任务"
			}
			rate := float64(report.Summary.EnabledTasks) / float64(report.Summary.TotalTasks) * 100
			if rate >= 80 {
				return "pass", fmt.Sprintf("%.0f%%任务已启用", rate), ""
			}
			return "warn", fmt.Sprintf("仅%.0f%%任务已启用", rate), "建议启用更多任务"
		}},
	}

	for _, c := range checks {
		status, desc, sugg := c.Check()
		items = append(items, ComplianceItem{
			Category:    c.Category,
			Name:        c.Name,
			Status:      status,
			Description: desc,
			Suggestion:  sugg,
		})

		switch status {
		case "fail":
			result.FailCount++
			result.Score -= 15
		case "warn":
			result.WarnCount++
			result.Score -= 5
		case "pass":
			result.PassCount++
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	switch {
	case result.Score >= 90:
		result.Level = "优秀"
	case result.Score >= 70:
		result.Level = "良好"
	case result.Score >= 50:
		result.Level = "一般"
	default:
		result.Level = "需改进"
	}

	result.Items = items
	return result
}

func (g *ReportGenerator) RenderHTML(data *ReportData) ([]byte, error) {
	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

const reportTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>{{.Title}}</title>
<style>
body{font-family:'Microsoft YaHei',sans-serif;margin:0;padding:20px;background:#f5f5f5;color:#333}
.container{max-width:1000px;margin:0 auto;background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1)}
h1{color:#1890ff;border-bottom:2px solid #1890ff;padding-bottom:10px}
h2{color:#333;margin-top:30px;padding:8px 0;border-bottom:1px solid #e8e8e8}
table{width:100%;border-collapse:collapse;margin:15px 0}
th,td{padding:8px 12px;text-align:left;border:1px solid #e8e8e8}
th{background:#fafafa;font-weight:600}
.tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px}
.tag-pass{background:#f6ffed;color:#52c41a;border:1px solid #b7eb8f}
.tag-warn{background:#fffbe6;color:#faad14;border:1px solid #ffe58f}
.tag-fail{background:#fff1f0;color:#f5222d;border:1px solid #ffa39e}
.stat-card{display:inline-block;padding:15px 25px;margin:5px;border-radius:6px;background:#fafafa;text-align:center;min-width:120px}
.stat-card .value{font-size:28px;font-weight:700;color:#1890ff}
.stat-card .label{font-size:12px;color:#999;margin-top:4px}
.footer{margin-top:30px;padding-top:15px;border-top:1px solid #e8e8e8;font-size:12px;color:#999;text-align:center}
</style>
</head>
<body>
<div class="container">
<h1>{{.Title}}</h1>
<p>报告周期：{{.Period}} &nbsp;|&nbsp; 生成时间：{{.GeneratedAt}}</p>

<h2>概览</h2>
<div>
<div class="stat-card"><div class="value">{{.Summary.TotalTasks}}</div><div class="label">监测任务</div></div>
<div class="stat-card"><div class="value">{{.Summary.TotalExecutions}}</div><div class="label">总执行次数</div></div>
<div class="stat-card"><div class="value">{{.Summary.IssueCount}}</div><div class="label">问题数</div></div>
<div class="stat-card"><div class="value">{{printf "%.1f" .Summary.IssueRate}}%</div><div class="label">问题率</div></div>
</div>

<h2>SLA 达标情况</h2>
<table>
<tr><th>指标</th><th>数值</th><th>状态</th></tr>
<tr><td>可用率</td><td>{{printf "%.3f" .SLAStats.AvailabilityRate}}%</td><td>{{if .SLAStats.MeetsSLA}}<span class="tag tag-pass">达标</span>{{else}}<span class="tag tag-fail">未达标</span>{{end}}</td></tr>
<tr><td>SLA目标</td><td>{{printf "%.1f" .SLAStats.SLATarget}}%</td><td>-</td></tr>
<tr><td>正常运行时长</td><td>{{printf "%.1f" .SLAStats.UptimeHours}} 小时</td><td>-</td></tr>
<tr><td>故障时长</td><td>{{printf "%.1f" .SLAStats.DowntimeMinutes}} 分钟</td><td>-</td></tr>
</table>

<h2>合规评估</h2>
<p>综合评分：<strong>{{printf "%.0f" .Compliance.Score}}</strong> / 100 &nbsp; 等级：<strong>{{.Compliance.Level}}</strong></p>
<table>
<tr><th>类别</th><th>检查项</th><th>结果</th><th>说明</th><th>建议</th></tr>
{{range .Compliance.Items}}
<tr>
<td>{{.Category}}</td>
<td>{{.Name}}</td>
<td>{{if eq .Status "pass"}}<span class="tag tag-pass">通过</span>{{else if eq .Status "warn"}}<span class="tag tag-warn">警告</span>{{else}}<span class="tag tag-fail">不通过</span>{{end}}</td>
<td>{{.Description}}</td>
<td>{{.Suggestion}}</td>
</tr>
{{end}}
</table>

<h2>任务明细</h2>
<table>
<tr><th>任务名称</th><th>目标URL</th><th>执行次数</th><th>问题数</th><th>问题率</th></tr>
{{range .TaskReports}}
<tr>
<td>{{.TaskName}}</td>
<td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">{{.URL}}</td>
<td>{{.Executions}}</td>
<td>{{.Issues}}</td>
<td>{{printf "%.1f" .IssueRate}}%</td>
</tr>
{{end}}
</table>

<div class="footer">
由站点监控系统自动生成 | {{.GeneratedAt}}
</div>
</div>
</body>
</html>`
