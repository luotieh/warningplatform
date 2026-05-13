package report

import (
	"time"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type ServiceReport struct {
	db *db.DB
}

func NewServiceReport(database *db.DB) *ServiceReport {
	return &ServiceReport{db: database}
}

func (s *ServiceReport) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

// AvailableTasks returns completed scan tasks for report generation.
func (s *ServiceReport) AvailableTasks() []model.ScanTask {
	var tasks []model.ScanTask
	s.session().Where("status = ?", "completed").
		Order("finished_at DESC").
		Limit(50).
		Select("id, name, target, status, finished_at").
		Find(&tasks)
	return tasks
}

// GetTask retrieves a single scan task by ID.
func (s *ServiceReport) GetTask(taskID string) (*model.ScanTask, error) {
	var task model.ScanTask
	if err := s.session().First(&task, "id = ?", taskID).Error; err != nil {
		return nil, err
	}
	return &task, nil
}

// BuildReportData assembles report data from vulnerabilities and assets.
func (s *ServiceReport) BuildReportData(title, reportType, taskID string) *ReportData {
	data := &ReportData{
		Title:       title,
		GeneratedAt: time.Now(),
		GeneratedBy: "system",
	}

	vulnQuery := s.session().Model(&model.Vulnerability{})
	if taskID != "" {
		vulnQuery = vulnQuery.Where("task_id = ?", taskID)
	}

	var vulns []model.Vulnerability
	vulnQuery.Order("severity DESC").Limit(500).Find(&vulns)

	for _, v := range vulns {
		cveID := ""
		if len(v.CVEIDs) > 0 {
			cveID = v.CVEIDs[0]
		}
		data.Vulnerabilities = append(data.Vulnerabilities, VulnItem{
			ID:          v.ID,
			Title:       v.Title,
			Severity:    v.Severity,
			CVEID:       cveID,
			Asset:       v.Target,
			Status:      v.Status,
			Description: v.Description,
			Evidence:    v.Evidence,
			Remediation: v.Solution,
		})
	}

	var critCount, highCount, medCount, lowCount, infoCount int
	for _, v := range data.Vulnerabilities {
		switch v.Severity {
		case "critical":
			critCount++
		case "high":
			highCount++
		case "medium":
			medCount++
		case "low":
			lowCount++
		default:
			infoCount++
		}
	}

	var assetCount int64
	s.session().Model(&model.Asset{}).Count(&assetCount)

	data.Summary = ReportSummary{
		TotalAssets:   int(assetCount),
		TotalVulns:    len(data.Vulnerabilities),
		CriticalCount: critCount,
		HighCount:     highCount,
		MediumCount:   medCount,
		LowCount:      lowCount,
		InfoCount:     infoCount,
	}

	if reportType == TypeASM {
		data.Title = title + " (攻击面)"
	}

	return data
}

// CompareTasks compares vulnerabilities between two scan tasks.
func (s *ServiceReport) CompareTasks(baseTaskID, compareTaskID string) (*CompareResult, error) {
	return CompareTasks(s.session(), baseTaskID, compareTaskID)
}
