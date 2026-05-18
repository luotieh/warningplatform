package task

import (
	"fmt"
	"strconv"
	"strings"

	"vulnscan-backend/model"
	taskContract "vulnscan-backend/task/task-contract"

	"code.yt-security.com/public/core/v2/db"
	"gorm.io/gorm"
)

type serviceTask struct {
	db *db.DB
}

func NewServiceTask(database *db.DB) *serviceTask {
	return &serviceTask{db: database}
}

func (s *serviceTask) session() *gorm.DB {
	session, _ := s.db.GetDBSession()
	return session
}

func (s *serviceTask) List(query taskContract.TaskQuery, scopes ...func(*gorm.DB) *gorm.DB) ([]model.ScanTask, int64, error) {
	var items []model.ScanTask
	var count int64

	tx := s.session().Model(&model.ScanTask{}).Scopes(scopes...)

	if query.Keyword != "" {
		tx = tx.Where("name LIKE ?", "%"+query.Keyword+"%")
	}
	if query.Status != "" {
		tx = tx.Where("status = ?", query.Status)
	}
	if query.Type != "" {
		tx = tx.Where("type = ?", query.Type)
	}
	if query.TemplateID != "" {
		tx = tx.Where("template_id = ?", query.TemplateID)
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 100 {
		query.PageSize = 20
	}

	offset := (query.Page - 1) * query.PageSize
	if err := tx.Offset(offset).Limit(query.PageSize).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, count, nil
}

func (s *serviceTask) GetByID(id string) (*model.ScanTask, error) {
	var item model.ScanTask
	if err := s.session().First(&item, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &item, nil
}

func (s *serviceTask) Create(item *model.ScanTask) error {
	item.Status = model.TaskStatusPending
	item.TotalTargets = len(item.Targets)
	return s.session().Create(item).Error
}

func (s *serviceTask) Update(id string, updates map[string]any) error {
	return s.session().Model(&model.ScanTask{}).Where("id = ?", id).Updates(updates).Error
}

func (s *serviceTask) Delete(id string) error {
	var task model.ScanTask
	if err := s.session().First(&task, "id = ?", id).Error; err != nil {
		return err
	}
	if task.Status == model.TaskStatusRunning {
		return fmt.Errorf("cannot delete running task")
	}
	return s.session().Where("id = ?", id).Delete(&model.ScanTask{}).Error
}

func (s *serviceTask) Cancel(id string) error {
	return s.session().Model(&model.ScanTask{}).
		Where("id = ? AND status IN ?", id, []string{model.TaskStatusPending, model.TaskStatusQueued, model.TaskStatusRunning, model.TaskStatusPaused}).
		Update("status", model.TaskStatusCancelled).Error
}

func (s *serviceTask) Pause(id string) error {
	return s.session().Model(&model.ScanTask{}).
		Where("id = ? AND status = ?", id, model.TaskStatusRunning).
		Update("status", model.TaskStatusPaused).Error
}

func (s *serviceTask) Resume(id string) error {
	return s.session().Model(&model.ScanTask{}).
		Where("id = ? AND status = ?", id, model.TaskStatusPaused).
		Update("status", model.TaskStatusRunning).Error
}

func (s *serviceTask) ListFindings(query taskContract.FindingQuery) ([]model.ScanFinding, int64, error) {
	var items []model.ScanFinding
	var count int64

	tx := s.session().Model(&model.ScanFinding{}).Where("task_id = ?", query.TaskID)

	if query.Category != "" {
		tx = tx.Where("category = ?", query.Category)
	}
	if query.Type != "" {
		types := strings.Split(query.Type, ",")
		if len(types) == 1 {
			tx = tx.Where("type = ?", types[0])
		} else {
			tx = tx.Where("type IN ?", types)
		}
	}
	if query.Severity != "" {
		tx = tx.Where("severity = ?", query.Severity)
	}
	if query.ModuleID != "" {
		tx = tx.Where("module_id = ?", query.ModuleID)
	}
	if query.Keyword != "" {
		tx = tx.Where("title LIKE ? OR target LIKE ?", "%"+query.Keyword+"%", "%"+query.Keyword+"%")
	}
	if query.Target != "" {
		t := query.Target
		if !strings.Contains(t, "://") {
			host := t
			if idx := strings.LastIndex(t, ":"); idx > 0 {
				if _, err := strconv.Atoi(t[idx+1:]); err == nil {
					host = t[:idx]
				}
			}
			tx = tx.Where("(target = ? OR target = ? OR target = ? OR target LIKE ? OR target LIKE ?)",
				host, "http://"+t, "https://"+t, "http://"+host+"/%", "https://"+host+"/%")
		} else {
			tx = tx.Where("target = ?", t)
		}
	}

	if err := tx.Count(&count).Error; err != nil {
		return nil, 0, err
	}

	if query.Page <= 0 {
		query.Page = 1
	}
	if query.PageSize <= 0 || query.PageSize > 200 {
		query.PageSize = 50
	}

	offset := (query.Page - 1) * query.PageSize
	if err := tx.Offset(offset).Limit(query.PageSize).Order("created_at DESC").Find(&items).Error; err != nil {
		return nil, 0, err
	}

	return items, count, nil
}

func (s *serviceTask) FindingSummary(taskID string) (*taskContract.FindingSummary, error) {
	type countResult struct {
		Key   string `gorm:"column:key"`
		Count int    `gorm:"column:count"`
	}

	summary := &taskContract.FindingSummary{
		ByCategory: make(map[string]int),
		ByType:     make(map[string]int),
		BySeverity: make(map[string]int),
		ByModule:   make(map[string]int),
	}

	session := s.session()

	var total int64
	session.Model(&model.ScanFinding{}).Where("task_id = ?", taskID).Count(&total)
	summary.TotalFindings = int(total)

	var catResults []countResult
	session.Model(&model.ScanFinding{}).
		Select("category as key, count(*) as count").
		Where("task_id = ?", taskID).
		Group("category").Find(&catResults)
	for _, r := range catResults {
		summary.ByCategory[r.Key] = r.Count
	}

	var typeResults []countResult
	session.Model(&model.ScanFinding{}).
		Select("type as key, count(*) as count").
		Where("task_id = ?", taskID).
		Group("type").Find(&typeResults)
	for _, r := range typeResults {
		summary.ByType[r.Key] = r.Count
	}

	var sevResults []countResult
	session.Model(&model.ScanFinding{}).
		Select("severity as key, count(*) as count").
		Where("task_id = ?", taskID).
		Group("severity").Find(&sevResults)
	for _, r := range sevResults {
		summary.BySeverity[r.Key] = r.Count
	}

	var modResults []countResult
	session.Model(&model.ScanFinding{}).
		Select("module_id as key, count(*) as count").
		Where("task_id = ?", taskID).
		Group("module_id").Find(&modResults)
	for _, r := range modResults {
		summary.ByModule[r.Key] = r.Count
	}

	return summary, nil
}

func (s *serviceTask) ListAssets(taskID string) ([]taskContract.AssetSummary, error) {
	var findings []model.ScanFinding
	if err := s.session().Where("task_id = ?", taskID).
		Order("created_at ASC").Find(&findings).Error; err != nil {
		return nil, err
	}

	assetMap := make(map[string]*taskContract.AssetSummary)
	var assetOrder []string

	for _, f := range findings {
		host := f.Target
		if host == "" {
			continue
		}
		baseHost := extractBaseHost(host)

		asset, exists := assetMap[baseHost]
		if !exists {
			asset = &taskContract.AssetSummary{
				Target:    baseHost,
				IP:        baseHost,
				VulnCount: make(map[string]int),
				FirstSeen: f.CreatedAt.Format("2006-01-02 15:04:05"),
			}
			assetMap[baseHost] = asset
			assetOrder = append(assetOrder, baseHost)
		}

		asset.FindingIDs = append(asset.FindingIDs, f.ID)

		switch f.Type {
		case "host_alive":
			if ip := dataStr(f.Data, "ip"); ip != "" {
				asset.IP = ip
			}
		case "port_open", "udp_port":
			port := f.Port
			if port == 0 {
				port, _ = strconv.Atoi(dataStr(f.Data, "port"))
			}
			if port > 0 {
				proto := dataStr(f.Data, "protocol")
				if proto == "" {
					proto = f.Protocol
				}
				found := false
				for _, p := range asset.Ports {
					if p.Port == port && p.Protocol == proto {
						found = true
						break
					}
				}
				if !found {
					asset.Ports = append(asset.Ports, taskContract.AssetPort{
						Port: port, Protocol: proto,
					})
				}
			}
		case "service":
			svc := dataStr(f.Data, "service")
			ver := dataStr(f.Data, "version")
			banner := dataStr(f.Data, "banner")
			port := f.Port
			if port == 0 {
				port, _ = strconv.Atoi(dataStr(f.Data, "port"))
			}
			for i := range asset.Ports {
				if asset.Ports[i].Port == port {
					asset.Ports[i].Service = svc
					asset.Ports[i].Version = ver
					asset.Ports[i].Banner = banner
				}
			}
			if svc != "" {
				svcKey := svc
				if ver != "" {
					svcKey = svc + " " + ver
				}
				if !containsStr(asset.Services, svcKey) {
					asset.Services = append(asset.Services, svcKey)
				}
			}
		case "web_page":
			if t := dataStr(f.Data, "title"); t != "" {
				asset.Title = t
			}
			if b := dataStr(f.Data, "banner"); b != "" {
				asset.Banner = b
			}
			if sc := dataStr(f.Data, "status_code"); sc != "" {
				asset.StatusCode, _ = strconv.Atoi(sc)
			}
		case "tech":
			name := dataStr(f.Data, "name")
			ver := dataStr(f.Data, "version")
			tech := name
			if ver != "" {
				tech = name + " " + ver
			}
			if tech != "" && !containsStr(asset.Techs, tech) {
				asset.Techs = append(asset.Techs, tech)
			}
		case "waf":
			if w := dataStr(f.Data, "waf"); w != "" {
				asset.WAF = w
			}
		case "fingerprint":
			name := dataStr(f.Data, "product")
			ver := dataStr(f.Data, "version")
			tech := name
			if ver != "" {
				tech = name + " " + ver
			}
			if tech != "" && !containsStr(asset.Techs, tech) {
				asset.Techs = append(asset.Techs, tech)
			}
		}

		if f.Category == "vuln" {
			asset.VulnCount[f.Severity]++
		}
	}

	result := make([]taskContract.AssetSummary, 0, len(assetOrder))
	for _, key := range assetOrder {
		result = append(result, *assetMap[key])
	}
	return result, nil
}

func (s *serviceTask) ListLogs(taskID string, limit int) ([]model.ScanLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	var logs []model.ScanLog
	err := s.session().Where("task_id = ?", taskID).
		Order("id DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}

func containsStr(arr []string, s string) bool {
	for _, v := range arr {
		if v == s {
			return true
		}
	}
	return false
}

func extractBaseHost(target string) string {
	t := target
	if strings.HasPrefix(t, "http://") {
		t = t[7:]
	} else if strings.HasPrefix(t, "https://") {
		t = t[8:]
	}
	t = strings.TrimRight(t, "/")
	if idx := strings.LastIndex(t, ":"); idx > 0 {
		maybePort := t[idx+1:]
		if _, err := strconv.Atoi(maybePort); err == nil {
			t = t[:idx]
		}
	}
	return t
}

func dataStr(data model.JSONMap, key string) string {
	if data == nil {
		return ""
	}
	if v, ok := data[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
		return fmt.Sprintf("%v", v)
	}
	return ""
}
