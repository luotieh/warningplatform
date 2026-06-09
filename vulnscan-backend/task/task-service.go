package task

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"vulnscan-backend/model"
	taskContract "vulnscan-backend/task/task-contract"

	"code.yt-security.com/public/access/ai"
	"code.yt-security.com/public/core/db"
	"code.yt-security.com/public/core/generate/ulid"
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

func (s *serviceTask) DB() *gorm.DB {
	return s.session()
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
	if query.ExcludeTypes != "" {
		excluded := splitCSV(query.ExcludeTypes)
		if len(excluded) == 1 {
			tx = tx.Where("type <> ?", excluded[0])
		} else if len(excluded) > 1 {
			tx = tx.Where("type NOT IN ?", excluded)
		}
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
	if isActiveScanTaskStatus(task.Status) {
		return fmt.Errorf("任务正在运行或排队中，请先取消后再删除")
	}
	if err := s.session().Where("parent_id = ?", id).Delete(&model.ScanTask{}).Error; err != nil {
		return err
	}
	return s.session().Where("id = ?", id).Delete(&model.ScanTask{}).Error
}

func isActiveScanTaskStatus(status string) bool {
	switch status {
	case model.TaskStatusRunning, model.TaskStatusQueued, model.TaskStatusPending,
		model.TaskStatusPaused, model.TaskStatusSplitting:
		return true
	default:
		return false
	}
}

func (s *serviceTask) Cancel(id string) error {
	now := time.Now()
	active := []string{
		model.TaskStatusPending, model.TaskStatusQueued, model.TaskStatusRunning,
		model.TaskStatusPaused, model.TaskStatusSplitting,
	}
	return s.session().Model(&model.ScanTask{}).
		Where("(id = ? OR parent_id = ?) AND status IN ?", id, id, active).
		Updates(map[string]interface{}{
			"status":      model.TaskStatusCancelled,
			"finished_at": &now,
			"error_msg":   "用户取消",
		}).Error
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

// relatedTaskIDs 返回当前任务及全部分片子任务 ID，便于在父任务详情页聚合 findings。
func (s *serviceTask) relatedTaskIDs(taskID string) []string {
	ids := []string{taskID}
	var childIDs []string
	if err := s.session().Model(&model.ScanTask{}).Where("parent_id = ?", taskID).Pluck("id", &childIDs).Error; err == nil {
		ids = append(ids, childIDs...)
	}
	return ids
}

func scanFindingsScope(tx *gorm.DB, taskIDs []string) *gorm.DB {
	if len(taskIDs) == 1 {
		return tx.Where("task_id = ?", taskIDs[0])
	}
	return tx.Where("task_id IN ?", taskIDs)
}

func (s *serviceTask) ListFindings(query taskContract.FindingQuery) ([]model.ScanFinding, int64, error) {
	var items []model.ScanFinding
	var count int64

	taskIDs := s.relatedTaskIDs(query.TaskID)
	tx := scanFindingsScope(s.session().Model(&model.ScanFinding{}), taskIDs)

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
	if query.ExcludeType != "" {
		excluded := strings.Split(query.ExcludeType, ",")
		for i := range excluded {
			excluded[i] = strings.TrimSpace(excluded[i])
		}
		if len(excluded) == 1 && excluded[0] != "" {
			tx = tx.Where("type <> ?", excluded[0])
		} else if len(excluded) > 1 {
			tx = tx.Where("type NOT IN ?", excluded)
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
	taskIDs := s.relatedTaskIDs(taskID)
	base := func() *gorm.DB {
		return scanFindingsScope(session.Model(&model.ScanFinding{}), taskIDs)
	}

	var total int64
	base().Count(&total)
	summary.TotalFindings = int(total)

	var catResults []countResult
	base().
		Select("category as key, count(*) as count").
		Group("category").Find(&catResults)
	for _, r := range catResults {
		summary.ByCategory[r.Key] = r.Count
	}

	var typeResults []countResult
	base().
		Select("type as key, count(*) as count").
		Group("type").Find(&typeResults)
	for _, r := range typeResults {
		summary.ByType[r.Key] = r.Count
	}

	var sevResults []countResult
	base().
		Select("severity as key, count(*) as count").
		Group("severity").Find(&sevResults)
	for _, r := range sevResults {
		summary.BySeverity[r.Key] = r.Count
	}

	var modResults []countResult
	base().
		Select("module_id as key, count(*) as count").
		Group("module_id").Find(&modResults)
	for _, r := range modResults {
		summary.ByModule[r.Key] = r.Count
	}

	return summary, nil
}

func (s *serviceTask) ListAssets(taskID string) ([]taskContract.AssetSummary, error) {
	var findings []model.ScanFinding
	tx := scanFindingsScope(s.session().Model(&model.ScanFinding{}), s.relatedTaskIDs(taskID))
	if err := tx.Order("created_at ASC").Find(&findings).Error; err != nil {
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

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
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

func (s *serviceTask) AIEnrichFinding(ctx context.Context, findingID string, chatSvc ai.Service) (*taskContract.AIEnrichResult, error) {
	if chatSvc == nil {
		return nil, fmt.Errorf("AI 服务未配置")
	}
	var finding model.ScanFinding
	if err := s.session().WithContext(ctx).Where("id = ?", findingID).First(&finding).Error; err != nil {
		return nil, fmt.Errorf("漏洞发现不存在")
	}

	models, err := chatSvc.ListModels(ctx, "")
	if err != nil || len(models.Data) == 0 {
		return nil, fmt.Errorf("无可用 AI 模型")
	}
	modelName := models.Data[0].ID

	cacheKey := vulnKnowledgeCacheKey(finding)
	var cached model.VulnKnowledgeCache
	if err := s.session().WithContext(ctx).Where("vuln_key = ?", cacheKey).First(&cached).Error; err == nil {
		s.session().WithContext(ctx).Model(&cached).UpdateColumn("hit_count", cached.HitCount+1)
		result := &taskContract.AIEnrichResult{
			Description: cached.Description,
			Cause:       cached.Cause,
			Remediation: cached.Remediation,
		}
		s.applyEnrichToFinding(ctx, findingID, finding, result)
		return result, nil
	}

	systemPrompt := `你是一位资深网络安全专家。根据提供的漏洞扫描发现信息，生成以下三项内容：
1. 漏洞描述：简洁描述该漏洞是什么、存在于哪里
2. 漏洞成因：分析该漏洞产生的技术原因
3. 修复建议：给出具体可操作的修复方案

请以 JSON 格式返回，字段为 description、cause、remediation，每个字段使用中文。`

	findingInfo := fmt.Sprintf("漏洞标题: %s\n类型: %s\n严重程度: %s\n目标: %s\n端口: %d\n协议: %s",
		finding.Title, finding.Type, finding.Severity, finding.Target, finding.Port, finding.Protocol)
	if finding.Description != "" {
		findingInfo += "\n原始描述: " + finding.Description
	}
	if finding.Evidence != "" {
		findingInfo += "\n证据: " + finding.Evidence
	}
	if finding.Data != nil {
		if cve, ok := finding.Data["cve_id"].(string); ok && cve != "" {
			findingInfo += "\nCVE编号: " + cve
		}
		if rem, ok := finding.Data["remediation"].(string); ok && rem != "" {
			findingInfo += "\n原始修复建议: " + rem
		}
	}

	resp, err := chatSvc.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: modelName,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: findingInfo},
		},
		Temperature: 0.3,
		MaxTokens:   2000,
	})
	if err != nil {
		return nil, fmt.Errorf("AI 调用失败: %w", err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("AI 未返回内容")
	}

	content := strings.TrimSpace(resp.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result taskContract.AIEnrichResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		result = taskContract.AIEnrichResult{Description: content}
	}

	cve := ""
	if finding.Data != nil {
		if v, ok := finding.Data["cve_id"].(string); ok {
			cve = v
		}
	}
	entry := model.VulnKnowledgeCache{
		ID:          ulid.GenerateID(),
		VulnKey:     cacheKey,
		VulnType:    finding.Type,
		Title:       finding.Title,
		CveID:       cve,
		Description: result.Description,
		Cause:       result.Cause,
		Remediation: result.Remediation,
	}
	_ = s.session().WithContext(ctx).Create(&entry).Error

	s.applyEnrichToFinding(ctx, findingID, finding, &result)
	return &result, nil
}

func vulnKnowledgeCacheKey(f model.ScanFinding) string {
	if f.Data != nil {
		if cve, ok := f.Data["cve_id"].(string); ok && cve != "" {
			return "cve:" + strings.ToUpper(cve)
		}
	}
	return fmt.Sprintf("%s:%s", f.Type, f.Title)
}

func (s *serviceTask) applyEnrichToFinding(ctx context.Context, findingID string, finding model.ScanFinding, result *taskContract.AIEnrichResult) {
	updates := map[string]any{}
	if result.Description != "" && finding.Description == "" {
		updates["description"] = result.Description
	}
	if finding.Data == nil {
		finding.Data = model.JSONMap{}
	}
	if result.Cause != "" {
		finding.Data["vuln_cause"] = result.Cause
		updates["data"] = finding.Data
	}
	if result.Remediation != "" {
		if _, ok := finding.Data["remediation"]; !ok {
			finding.Data["remediation"] = result.Remediation
			updates["data"] = finding.Data
		}
	}
	if len(updates) > 0 {
		s.session().WithContext(ctx).Model(&model.ScanFinding{}).Where("id = ?", findingID).Updates(updates)
	}
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
