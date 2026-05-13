package scanrunner

import (
	"code.yt-security.com/public/core/v2/web"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/definition"
	"vulnscan-backend/scan/core"
	"vulnscan-backend/scan/orchestrate"
)

type ReportAPI struct {
	db *gorm.DB
}

func NewReportAPI(db *gorm.DB) *ReportAPI {
	return &ReportAPI{db: db}
}

func (a *ReportAPI) RegisterRoutes(g *gin.RouterGroup) {
	rg := g.Group("/report")
	{
		rg.GET("/attack-path/:id", a.AttackPath)
		rg.GET("/delta/:current/:base", a.DeltaScan)
		rg.GET("/timeline", a.Timeline)
	}
}

func (a *ReportAPI) AttackPath(c *gin.Context) {
	taskID := c.Param("id")

	var task model.ScanTask
	if err := a.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		web.Err(c, definition.ScanTaskNotFound).Send()
		return
	}

	var findings []model.ScanFinding
	a.db.Where("task_id = ?", taskID).Find(&findings)

	engineTargets := make([]*core.Target, 0, len(task.Targets))
	for _, raw := range task.Targets {
		engineTargets = append(engineTargets, &core.Target{Host: raw})
	}

	engineFindings := make([]*core.Finding, 0, len(findings))
	for _, f := range findings {
		engineFindings = append(engineFindings, &core.Finding{
			ModuleID: f.ModuleID,
			Target: &core.Target{
				Host: f.Target,
				Port: f.Port,
			},
			Type:       f.Type,
			Title:      f.Title,
			Severity:   f.Severity,
			Confidence: f.Confidence,
		})
	}

	analyzer := orchestrate.NewAttackPathAnalyzer()
	paths := analyzer.Analyze(engineTargets, engineFindings)

	web.OK(c).Data(gin.H{
		"task_id":      taskID,
		"attack_paths": paths,
		"total_hosts":  len(paths),
	}).Send()
}

func (a *ReportAPI) DeltaScan(c *gin.Context) {
	currentID := c.Param("current")
	baseID := c.Param("base")

	delta := NewDeltaScanEngine(a.db)
	result, err := delta.Compare(currentID, baseID)
	if err != nil {
		web.Fail(c).Msg(err.Error()).Send()
		return
	}

	web.OK(c).Data(result).Send()
}

func (a *ReportAPI) Timeline(c *gin.Context) {
	target := c.Query("target")
	if target == "" {
		web.Fail(c).Msg("target required").Send()
		return
	}

	delta := NewDeltaScanEngine(a.db)
	entries, err := delta.Timeline(target, 50)
	if err != nil {
		web.Fail(c).Msg("获取时间线失败").Err(err).Send()
		return
	}

	web.OK(c).Data(entries).Send()
}
