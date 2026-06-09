package scanrunner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"

	"code.yt-security.com/public/access/ai"
	"code.yt-security.com/public/core/generate/ulid"
	circularscope "vulnscan-backend/circular/scope"
	transferContract "vulnscan-backend/circular/transfer/transfer-contract"
	coreContract "vulnscan-backend/incident/core/core-contract"
	"vulnscan-backend/model"
)

// EventBridge connects scan findings to incident creation and incident to circular transfer.
type EventBridge struct {
	db             *gorm.DB
	incidentSvc    coreContract.ServiceCore
	transferSvc    transferContract.ServiceTransfer
	chatSvc        ai.Service
	config         EventBridgeConfig
	mu             sync.Mutex
	processedTasks map[string]time.Time
}

type EventBridgeConfig struct {
	Enabled                  bool
	AutoCreateIncident       bool
	AutoTransferToCircular   bool
	MinSeverityForIncident   string // "critical", "high", "medium"
	MinConfidenceForIncident int    // minimum confidence to auto-create (0-100)
	DeduplicateWindow        time.Duration
}

func DefaultEventBridgeConfig() EventBridgeConfig {
	return EventBridgeConfig{
		Enabled:                  true,
		AutoCreateIncident:       true,
		AutoTransferToCircular:   true,
		MinSeverityForIncident:   "high",
		MinConfidenceForIncident: 70,
		DeduplicateWindow:        24 * time.Hour,
	}
}

func NewEventBridge(db *gorm.DB, incidentSvc coreContract.ServiceCore, transferSvc transferContract.ServiceTransfer, chatSvc ai.Service, config EventBridgeConfig) *EventBridge {
	return &EventBridge{
		db:             db,
		incidentSvc:    incidentSvc,
		transferSvc:    transferSvc,
		chatSvc:        chatSvc,
		config:         config,
		processedTasks: make(map[string]time.Time),
	}
}

// OnScanComplete is called after a scan task finishes. It reviews vuln findings
// and creates incidents for high-severity ones.
func (eb *EventBridge) OnScanComplete(ctx context.Context, taskID string) {
	if !eb.config.Enabled || !eb.config.AutoCreateIncident {
		return
	}
	if eb.incidentSvc == nil {
		return
	}

	eb.mu.Lock()
	if t, ok := eb.processedTasks[taskID]; ok && time.Since(t) < eb.config.DeduplicateWindow {
		eb.mu.Unlock()
		return
	}
	eb.processedTasks[taskID] = time.Now()
	eb.mu.Unlock()

	eb.cleanupProcessedTasks()

	var findings []model.ScanFinding
	query := eb.db.WithContext(ctx).
		Where("task_id = ? AND category = ?", taskID, model.FindingCategoryVuln).
		Where("severity IN ?", eb.eligibleSeverities())

	if eb.config.MinConfidenceForIncident > 0 {
		query = query.Where("confidence >= ?", eb.config.MinConfidenceForIncident)
	}

	if err := query.Find(&findings).Error; err != nil {
		slog.Warn("[EventBridge] 查询扫描发现失败", "task_id", taskID, "error", err)
		return
	}

	if len(findings) == 0 {
		return
	}

	created := 0
	for _, f := range findings {
		if eb.incidentAlreadyExists(ctx, taskID, f) {
			continue
		}

		if err := eb.createIncidentFromFinding(ctx, f); err != nil {
			slog.Warn("[EventBridge] 自动创建事件失败", "finding_id", f.ID, "error", err)
			continue
		}
		created++
	}

	if created > 0 {
		slog.Info("[EventBridge] 扫描发现自动创建安全事件",
			"task_id", taskID, "findings", len(findings), "incidents_created", created)
	}

	go eb.autoEnrichFindings(ctx, taskID)
}

// OnIncidentReviewPassed is called when an incident passes review.
// It automatically transfers the incident to the circular system.
func (eb *EventBridge) OnIncidentReviewPassed(ctx context.Context, incident model.SecurityIncident) {
	if !eb.config.Enabled || !eb.config.AutoTransferToCircular {
		return
	}
	if eb.transferSvc == nil {
		return
	}

	if incident.Level < model.IncidentLevelHigh {
		return
	}

	var asset model.IncidentAsset
	eb.db.WithContext(ctx).Where("id = ?", incident.AssetDetailID).First(&asset)

	var metadata model.IncidentMetadata
	eb.db.WithContext(ctx).Where("id = ?", incident.EventMetadataID).First(&metadata)

	req := transferContract.TransferIncidentReq{
		IncidentNo:   incident.IncidentNo,
		Name:         incident.Name,
		Level:        incident.Level,
		AiOpinion:    incident.AiOpinion,
		AiConfidence: incident.AiConfidence,
		SourceSystem: model.IncidentSourceSystemLocal,
		AssetInfo: &transferContract.TransferAssetInfo{
			AssetName:    asset.AssetName,
			SystemName:   asset.SystemName,
			DomainIP:     asset.DomainIP,
			SiteIP:       asset.SiteIP,
			Unit:         asset.Unit,
			UnitType:     asset.UnitType,
			Industry:     asset.Industry,
			MLPSRecordNo: asset.MLPSRecordNo,
			MLPSLevel:    asset.MLPSLevel,
			Region:       asset.Region,
		},
		MetadataInfo: &transferContract.TransferMetadataInfo{
			DataNo:              metadata.DataNo,
			IncidentType:        metadata.IncidentType,
			IncidentURL:         metadata.IncidentURL,
			IncidentDescription: metadata.IncidentDescription,
			CvssScore:           metadata.CvssScore,
			CveId:               metadata.CveId,
		},
	}

	circularCode, err := eb.transferSvc.ReceiveIncident(ctx, req, circularscope.SystemActor(), incident.OrganizeID)
	if err != nil {
		slog.Warn("[EventBridge] 事件流转通报失败",
			"incident_no", incident.IncidentNo, "error", err)
		return
	}

	oplog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo, model.IncidentOpTransfer,
		"system", "系统自动", "流转到通报系统成功",
		map[string]interface{}{"circular_code": circularCode},
		model.IncidentSourceSystemLocal,
	)
	model.CreateIncidentOperationLog(eb.db.WithContext(ctx), oplog)

	slog.Info("[EventBridge] 事件自动流转到通报系统",
		"incident_no", incident.IncidentNo, "circular_code", circularCode)
}

func (eb *EventBridge) autoEnrichFindings(ctx context.Context, taskID string) {
	if eb.chatSvc == nil {
		return
	}

	var findings []model.ScanFinding
	if err := eb.db.WithContext(ctx).
		Where("task_id = ? AND category = ?", taskID, model.FindingCategoryVuln).
		Where("description = '' OR description IS NULL").
		Limit(50).
		Find(&findings).Error; err != nil {
		slog.Warn("[EventBridge] AI补充-查询发现失败", "task_id", taskID, "error", err)
		return
	}
	if len(findings) == 0 {
		return
	}

	models, err := eb.chatSvc.ListModels(ctx, "")
	if err != nil || len(models.Data) == 0 {
		slog.Warn("[EventBridge] AI补充-无可用模型", "task_id", taskID)
		return
	}
	modelName := models.Data[0].ID

	enriched := 0
	for _, f := range findings {
		if err := eb.enrichOneFinding(ctx, f, modelName); err != nil {
			slog.Warn("[EventBridge] AI补充失败", "finding_id", f.ID, "error", err)
			continue
		}
		enriched++
	}
	if enriched > 0 {
		slog.Info("[EventBridge] AI自动补充漏洞信息", "task_id", taskID, "enriched", enriched, "total", len(findings))
	}
}

func vulnCacheKey(f model.ScanFinding) string {
	cve := extractStr(f.Data, "cve_id", "cve")
	if cve != "" {
		return "cve:" + strings.ToUpper(cve)
	}
	return fmt.Sprintf("%s:%s", f.Type, f.Title)
}

func (eb *EventBridge) enrichOneFinding(ctx context.Context, f model.ScanFinding, modelName string) error {
	key := vulnCacheKey(f)

	var cached model.VulnKnowledgeCache
	if err := eb.db.WithContext(ctx).Where("vuln_key = ?", key).First(&cached).Error; err == nil {
		eb.db.WithContext(ctx).Model(&cached).UpdateColumn("hit_count", cached.HitCount+1)
		return eb.applyEnrichResult(ctx, f, cached.Description, cached.Cause, cached.Remediation)
	}

	systemPrompt := `你是一位资深网络安全专家。根据提供的漏洞扫描发现信息，生成以下三项内容：
1. 漏洞描述：简洁描述该漏洞是什么、存在于哪里
2. 漏洞成因：分析该漏洞产生的技术原因
3. 修复建议：给出具体可操作的修复方案

请以 JSON 格式返回，字段为 description、cause、remediation，每个字段使用中文。`

	info := fmt.Sprintf("漏洞标题: %s\n类型: %s\n严重程度: %s\n目标: %s\n端口: %d",
		f.Title, f.Type, f.Severity, f.Target, f.Port)
	if f.Evidence != "" {
		info += "\n证据: " + f.Evidence
	}
	if cve := extractStr(f.Data, "cve_id", "cve"); cve != "" {
		info += "\nCVE: " + cve
	}

	resp, err := eb.chatSvc.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: modelName,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: info},
		},
		Temperature: 0.3,
		MaxTokens:   1500,
	})
	if err != nil {
		return err
	}
	if len(resp.Choices) == 0 {
		return fmt.Errorf("AI未返回内容")
	}

	content := strings.TrimSpace(resp.Choices[0].Message.Content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result struct {
		Description string `json:"description"`
		Cause       string `json:"cause"`
		Remediation string `json:"remediation"`
	}
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		result.Description = content
	}

	cve := extractStr(f.Data, "cve_id", "cve")
	cacheEntry := model.VulnKnowledgeCache{
		ID:          ulid.GenerateID(),
		VulnKey:     key,
		VulnType:    f.Type,
		Title:       f.Title,
		CveID:       cve,
		Description: result.Description,
		Cause:       result.Cause,
		Remediation: result.Remediation,
	}
	if err := eb.db.WithContext(ctx).Create(&cacheEntry).Error; err != nil {
		slog.Debug("[EventBridge] 写入知识缓存失败", "key", key, "error", err)
	}

	return eb.applyEnrichResult(ctx, f, result.Description, result.Cause, result.Remediation)
}

func (eb *EventBridge) applyEnrichResult(ctx context.Context, f model.ScanFinding, description, cause, remediation string) error {
	updates := map[string]any{}
	if description != "" {
		updates["description"] = description
	}
	data := f.Data
	if data == nil {
		data = model.JSONMap{}
	}
	if cause != "" {
		data["vuln_cause"] = cause
		updates["data"] = data
	}
	if remediation != "" {
		if _, exists := data["remediation"]; !exists {
			data["remediation"] = remediation
			updates["data"] = data
		}
	}
	if len(updates) > 0 {
		return eb.db.WithContext(ctx).Model(&model.ScanFinding{}).Where("id = ?", f.ID).Updates(updates).Error
	}
	return nil
}

func (eb *EventBridge) createIncidentFromFinding(ctx context.Context, f model.ScanFinding) error {
	var scanTask model.ScanTask
	organizeID := ""
	if err := eb.db.WithContext(ctx).Select("organize_id").Where("id = ?", f.TaskID).First(&scanTask).Error; err == nil {
		organizeID = scanTask.OrganizeID
	}

	level := severityToIncidentLevel(f.Severity)

	name := f.Title
	if len(name) > 100 {
		name = name[:100]
	}

	var discoveryTime time.Time
	if !f.CreatedAt.IsZero() {
		discoveryTime = f.CreatedAt
	} else {
		discoveryTime = time.Now()
	}

	cveId := ""
	cvssScore := 0.0
	owaspCategory := ""
	incidentURL := ""
	affectScope := f.Target

	if f.Port > 0 {
		affectScope = fmt.Sprintf("%s:%d", f.Target, f.Port)
	}

	if f.Data != nil {
		cveId = extractStr(f.Data, "cve_id", "cve")
		cvssScore = extractCvss(f.Data)
		owaspCategory = extractStr(f.Data, "owasp_category", "owasp")

		if v := extractStr(f.Data, "matched_at", "url"); v != "" {
			incidentURL = v
		}

		if v := extractStr(f.Data, "affect_scope"); v != "" {
			affectScope = v
		}
	}

	incidentType := classifyIncidentType(f.ModuleID)
	description := buildScanIncidentDescription(f, incidentType)

	exploitDifficulty := "未知"
	switch f.VerificationLevel {
	case "exploit":
		exploitDifficulty = "低"
	case "principle":
		exploitDifficulty = "中"
	}

	req := coreContract.IncidentCreateReq{
		Name:       name,
		Level:      level,
		Source:     model.IncidentSourceVulnScan,
		ReportTime: discoveryTime,
		Asset: coreContract.IncidentAssetReq{
			DomainIP: f.Target,
		},
		Metadata: coreContract.IncidentMetaReq{
			IncidentType:        incidentType,
			IncidentURL:         incidentURL,
			DiscoveryTime:       discoveryTime,
			IncidentDescription: description,
			CvssScore:           cvssScore,
			CveId:               cveId,
			OwaspCategory:       owaspCategory,
			ExploitDifficulty:   exploitDifficulty,
			AffectScope:         affectScope,
		},
	}

	if f.AssetID != "" {
		var asset model.Asset
		if err := eb.db.WithContext(ctx).Where("id = ?", f.AssetID).First(&asset).Error; err == nil {
			req.Asset.AssetName = asset.Name
			req.Asset.SystemName = asset.Name
			if asset.Domain != "" {
				req.Asset.DomainIP = asset.Domain
			}
			if asset.IPv4 != "" {
				req.Asset.SiteIP = asset.IPv4
			}
			if organizeID == "" && asset.OrganizeID != "" {
				organizeID = asset.OrganizeID
			}
			if asset.OrganizeID != "" {
				var org model.Organize
				if err := eb.db.WithContext(ctx).Select("name").Where("id = ?", asset.OrganizeID).First(&org).Error; err == nil {
					req.Asset.Unit = org.Name
				}
			}
		}
	}

	return eb.incidentSvc.CreateIncident(ctx, req, "system", organizeID)
}

func extractStr(data model.JSONMap, keys ...string) string {
	for _, k := range keys {
		if v, ok := data[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

func extractCvss(data model.JSONMap) float64 {
	if v, ok := data["cvss_score"].(float64); ok {
		return v
	}
	if v, ok := data["cvss_score"].(string); ok {
		var score float64
		fmt.Sscanf(v, "%f", &score)
		return score
	}
	return 0
}

func classifyIncidentType(moduleID string) string {
	switch {
	case strings.Contains(moduleID, "sqli") || strings.Contains(moduleID, "sql"):
		return "SQL注入"
	case strings.Contains(moduleID, "xss"):
		return "XSS漏洞"
	case strings.Contains(moduleID, "cmdi") || strings.Contains(moduleID, "rce") || strings.Contains(moduleID, "command"):
		return "远程代码执行"
	case strings.Contains(moduleID, "lfi") || strings.Contains(moduleID, "xxe") || strings.Contains(moduleID, "ssti"):
		return "服务端注入"
	case strings.Contains(moduleID, "ssrf"):
		return "SSRF服务端请求伪造"
	case strings.Contains(moduleID, "nosqli"):
		return "NoSQL注入"
	case strings.Contains(moduleID, "jwt"):
		return "JWT安全缺陷"
	case strings.Contains(moduleID, "weak_pass") || strings.Contains(moduleID, "brute"):
		return "弱口令/爆破"
	case strings.Contains(moduleID, "cert"):
		return "证书安全"
	case strings.Contains(moduleID, "info_leak") || strings.Contains(moduleID, "dir_scan"):
		return "信息泄露"
	case strings.Contains(moduleID, "poc"):
		return "已知漏洞利用"
	default:
		return "漏洞"
	}
}

func (eb *EventBridge) incidentAlreadyExists(ctx context.Context, taskID string, f model.ScanFinding) bool {
	dedupName := f.Title
	if len(dedupName) > 100 {
		dedupName = dedupName[:100]
	}

	var count int64
	eb.db.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("name = ? AND source = ?", dedupName, model.IncidentSourceVulnScan).
		Where("created_at > ?", time.Now().Add(-eb.config.DeduplicateWindow)).
		Count(&count)
	return count > 0
}

func (eb *EventBridge) eligibleSeverities() []string {
	switch eb.config.MinSeverityForIncident {
	case "critical":
		return []string{"critical"}
	case "high":
		return []string{"critical", "high"}
	case "medium":
		return []string{"critical", "high", "medium"}
	default:
		return []string{"critical", "high"}
	}
}

func (eb *EventBridge) cleanupProcessedTasks() {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	for k, t := range eb.processedTasks {
		if time.Since(t) > eb.config.DeduplicateWindow {
			delete(eb.processedTasks, k)
		}
	}
}

func severityToIncidentLevel(severity string) int {
	switch strings.ToLower(severity) {
	case "critical":
		return model.IncidentLevelUrgent
	case "high":
		return model.IncidentLevelHigh
	case "medium":
		return model.IncidentLevelMedium
	default:
		return model.IncidentLevelLow
	}
}
