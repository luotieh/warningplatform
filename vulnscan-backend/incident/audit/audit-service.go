package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"vulnscan-backend/circular/scope"
	"vulnscan-backend/model"

	transferContract "vulnscan-backend/circular/transfer/transfer-contract"
	auditContract "vulnscan-backend/incident/audit/audit-contract"

	"code.yt-security.com/public/access/ai"
	"code.yt-security.com/public/core/db"
	"gorm.io/gorm"
)

type serviceAudit struct {
	db          *db.DB
	transferSvc transferContract.ServiceTransfer
	chatSvc     ai.Service
	aiModel     string
}

func NewServiceAudit(database *db.DB, transferSvc transferContract.ServiceTransfer, chatSvc ai.Service) *serviceAudit {
	return &serviceAudit{db: database, transferSvc: transferSvc, chatSvc: chatSvc, aiModel: ""}
}

func (s *serviceAudit) session() *gorm.DB {
	sess, _ := s.db.GetDBSession()
	return sess
}

func (s *serviceAudit) AIPreAudit(ctx context.Context, id string) (*auditContract.AIPreAuditResp, error) {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("事件不存在: %w", err)
	}

	if !model.IncidentSM.Can(incident.Status, model.IncidentEvtReviewPass) &&
		!model.IncidentSM.Can(incident.Status, model.IncidentEvtReviewFail) {
		return nil, fmt.Errorf("当前状态不允许AI预审")
	}

	result := CalculateRiskScore(&incident)
	aiOpinion := GenerateStructuredOpinion(&incident, result)

	confidence := result.TotalScore / 100.0
	if confidence < 0.3 {
		confidence = 0.3
	}
	if confidence > 0.95 {
		confidence = 0.95
	}

	tagsStr := strings.Join(result.Tags, ",")
	category := result.Category

	var vulnDesc, vulnHarm, fixAdvice string
	if llmResult, err := s.callLLMAnalysis(ctx, &incident, result); err != nil {
		slog.Warn("AI LLM 分析失败，使用规则引擎结果", "error", err)
	} else {
		vulnDesc = llmResult.VulnDesc
		vulnHarm = llmResult.VulnHarm
		fixAdvice = llmResult.FixAdvice
		if llmResult.Opinion != "" {
			aiOpinion = llmResult.Opinion
		}
	}

	updates := map[string]interface{}{
		"ai_pre_status": model.IncidentAiPreStatusDone,
		"ai_opinion":    aiOpinion,
		"ai_confidence": confidence,
		"risk_score":    result.TotalScore,
		"ai_tags":       tagsStr,
		"ai_category":   category,
		"ai_vuln_desc":  vulnDesc,
		"ai_vuln_harm":  vulnHarm,
		"ai_fix_advice": fixAdvice,
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新事件AI预审结果失败: %w", err)
	}

	opLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		model.IncidentOpAIPreAudit, "system", "AI引擎",
		"完成",
		map[string]interface{}{
			"risk_score":  result.TotalScore,
			"confidence":  confidence,
			"ai_category": category,
			"llm_used":    vulnDesc != "",
		},
		model.IncidentSourceSystemLocal,
	)
	if err := model.CreateIncidentOperationLog(sess.WithContext(ctx), opLog); err != nil {
		return nil, fmt.Errorf("创建操作日志失败: %w", err)
	}

	resp := &auditContract.AIPreAuditResp{
		AiOpinion:    aiOpinion,
		AiConfidence: confidence,
		RiskScore:    result.TotalScore,
		AiTags:       tagsStr,
		AiCategory:   category,
		AiVulnDesc:   vulnDesc,
		AiVulnHarm:   vulnHarm,
		AiFixAdvice:  fixAdvice,
		RiskDetail:   result,
	}
	return resp, nil
}

func (s *serviceAudit) ManualAudit(ctx context.Context, req auditContract.ManualAuditReq) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", req.ID).Error; err != nil {
		return fmt.Errorf("事件不存在: %w", err)
	}

	var event string
	switch req.AuditResult {
	case "success":
		event = model.IncidentEvtReviewPass
	case "fail":
		event = model.IncidentEvtReviewFail
	default:
		return fmt.Errorf("无效的审核结果: %s", req.AuditResult)
	}

	newStatus, err := model.IncidentSM.Apply(incident.Status, event)
	if err != nil {
		return err
	}

	updates := map[string]interface{}{"status": newStatus}
	var resultText string
	if req.AuditResult == "success" {
		resultText = "审核通过"
	} else {
		resultText = "审核不通过"
	}

	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", req.ID).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新事件状态失败: %w", err)
	}

	opLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		model.IncidentOpManualReview, "", "",
		resultText,
		map[string]interface{}{
			"audit_result": req.AuditResult,
			"opinion":      req.Opinion,
		},
		model.IncidentSourceSystemLocal,
	)
	if err := model.CreateIncidentOperationLog(sess.WithContext(ctx), opLog); err != nil {
		return fmt.Errorf("创建操作日志失败: %w", err)
	}

	if req.AuditResult == "success" {
		if err := s.transferToCircular(ctx, sess, &incident); err != nil {
			return fmt.Errorf("复核已通过，但流转通报失败: %w", err)
		}
	}

	return nil
}

func (s *serviceAudit) ResubmitForReview(ctx context.Context, id string, reason string) error {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).First(&incident, "id = ?", id).Error; err != nil {
		return fmt.Errorf("事件不存在: %w", err)
	}

	newStatus, err := model.IncidentSM.Apply(incident.Status, model.IncidentEvtResubmit)
	if err != nil {
		return fmt.Errorf("当前状态不允许重新提交复核: %w", err)
	}

	updates := map[string]interface{}{"status": newStatus}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", id).Updates(updates).Error; err != nil {
		return fmt.Errorf("更新事件状态失败: %w", err)
	}

	opLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		"resubmit", "", "",
		"重新提交复核",
		map[string]interface{}{"reason": reason},
		model.IncidentSourceSystemLocal,
	)
	if err := model.CreateIncidentOperationLog(sess.WithContext(ctx), opLog); err != nil {
		return fmt.Errorf("创建操作日志失败: %w", err)
	}

	return nil
}

func (s *serviceAudit) transferToCircular(ctx context.Context, sess *gorm.DB, incident *model.SecurityIncident) error {
	req := transferContract.TransferIncidentReq{
		IncidentID:   incident.Id,
		IncidentNo:   incident.IncidentNo,
		Name:         incident.Name,
		AiOpinion:    incident.AiOpinion,
		AiConfidence: incident.AiConfidence,
		SourceSystem: "security-incident",
	}
	if incident.AssetDetail != nil {
		a := incident.AssetDetail
		req.AssetInfo = &transferContract.TransferAssetInfo{
			AssetName: a.AssetName, SystemName: a.SystemName, DomainIP: a.DomainIP,
			SiteIP: a.SiteIP, Unit: a.Unit, UnitType: a.UnitType, Industry: a.Industry,
			MLPSRecordNo: a.MLPSRecordNo, MLPSLevel: a.MLPSLevel, Region: a.Region,
		}
	}
	if incident.EventMetadata != nil {
		m := incident.EventMetadata
		req.MetadataInfo = &transferContract.TransferMetadataInfo{
			IncidentType: m.IncidentType, IncidentURL: m.IncidentURL,
			IncidentDescription: m.IncidentDescription, CvssScore: m.CvssScore, CveId: m.CveId,
		}
	}

	circularCode, err := s.transferSvc.ReceiveIncident(ctx, req, scope.SystemActor(), incident.OrganizeID)
	if err != nil {
		slog.Error("流转到通报模块失败", "incident_no", incident.IncidentNo, "error", err)
		return err
	}

	transferLog := model.BuildIncidentOperationLog(
		incident.Id, incident.IncidentNo,
		model.IncidentOpTransfer, "system", "系统",
		"流转成功",
		map[string]interface{}{
			"circular_code": circularCode,
			"target_system": "circular",
		},
		model.IncidentSourceSystemLocal,
	)
	if err := model.CreateIncidentOperationLog(sess.WithContext(ctx), transferLog); err != nil {
		slog.Warn("创建流转操作日志失败", "incident_no", incident.IncidentNo, "error", err)
	}
	slog.Info("事件已流转到通报模块", "incident_no", incident.IncidentNo, "circular_code", circularCode)
	return nil
}

type llmAnalysisResult struct {
	VulnDesc  string `json:"vuln_desc"`
	VulnHarm  string `json:"vuln_harm"`
	FixAdvice string `json:"fix_advice"`
	Opinion   string `json:"opinion"`
}

func (s *serviceAudit) callLLMAnalysis(ctx context.Context, incident *model.SecurityIncident, riskResult auditContract.RiskScoreResult) (*llmAnalysisResult, error) {
	if s.chatSvc == nil {
		return nil, fmt.Errorf("AI Chat 服务未配置")
	}

	tpl, err := s.loadPromptTemplate(ctx, "ai_preaudit")
	if err != nil {
		slog.Warn("加载提示词模板失败，使用默认模板", "error", err)
	}

	modelName := s.aiModel
	if tpl != nil && tpl.ModelName != "" {
		modelName = tpl.ModelName
	}
	if modelName == "" {
		models, listErr := s.chatSvc.ListModels(ctx, "")
		if listErr != nil {
			return nil, fmt.Errorf("获取可用模型列表失败: %w", listErr)
		}
		if len(models.Data) == 0 {
			return nil, fmt.Errorf("无可用 AI 模型")
		}
		modelName = models.Data[0].ID
		s.aiModel = modelName
	}

	systemPrompt, userPrompt := s.buildPrompts(incident, riskResult, tpl)

	temperature := 0.3
	maxTokens := 2000
	if tpl != nil {
		if tpl.Temperature > 0 {
			temperature = tpl.Temperature
		}
		if tpl.MaxTokens > 0 {
			maxTokens = tpl.MaxTokens
		}
	}

	resp, err := s.chatSvc.ChatCompletions(ctx, "", &ai.CompletionsRequest{
		Model: modelName,
		Messages: []ai.ChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature: temperature,
		MaxTokens:   maxTokens,
	})
	if err != nil {
		return nil, fmt.Errorf("LLM 调用失败: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("LLM 未返回内容")
	}

	content := resp.Choices[0].Message.Content
	content = strings.TrimSpace(content)
	content = strings.TrimPrefix(content, "```json")
	content = strings.TrimPrefix(content, "```")
	content = strings.TrimSuffix(content, "```")
	content = strings.TrimSpace(content)

	var result llmAnalysisResult
	if err := json.Unmarshal([]byte(content), &result); err != nil {
		slog.Warn("LLM 输出解析失败，尝试提取文本", "content", content[:min(len(content), 200)])
		result.Opinion = content
	}
	return &result, nil
}

func (s *serviceAudit) loadPromptTemplate(ctx context.Context, scene string) (*model.PromptTemplate, error) {
	sess := s.session()
	var tpl model.PromptTemplate
	if err := sess.WithContext(ctx).
		Where("scene = ? AND enabled = ?", scene, true).
		Order("is_builtin DESC, version DESC").
		First(&tpl).Error; err != nil {
		return nil, err
	}
	return &tpl, nil
}

func (s *serviceAudit) buildPrompts(incident *model.SecurityIncident, riskResult auditContract.RiskScoreResult, tpl *model.PromptTemplate) (string, string) {
	vars := s.collectTemplateVars(incident, riskResult)

	if tpl != nil && tpl.SystemPrompt != "" && tpl.UserPrompt != "" {
		systemPrompt := tpl.SystemPrompt
		userPrompt := renderTemplate(tpl.UserPrompt, vars)
		return systemPrompt, userPrompt
	}

	return defaultSystemPrompt, buildFallbackPrompt(incident, riskResult)
}

func (s *serviceAudit) collectTemplateVars(incident *model.SecurityIncident, riskResult auditContract.RiskScoreResult) map[string]string {
	vars := map[string]string{
		"Name":      incident.Name,
		"Level":     model.IncidentLevelText[incident.Level],
		"RiskScore": fmt.Sprintf("%.1f/100（%s）", riskResult.TotalScore, riskResult.Level),
	}
	if incident.EventMetadata != nil {
		m := incident.EventMetadata
		vars["IncidentType"] = m.IncidentType
		vars["CveId"] = m.CveId
		if m.CvssScore > 0 {
			vars["CvssScore"] = fmt.Sprintf("%.1f", m.CvssScore)
		}
		vars["OwaspCategory"] = m.OwaspCategory
		vars["ExploitDifficulty"] = m.ExploitDifficulty
		vars["AffectScope"] = m.AffectScope
		desc := m.IncidentDescription
		if len(desc) > 1000 {
			desc = desc[:1000] + "..."
		}
		vars["Description"] = desc
	}
	if incident.AssetDetail != nil {
		a := incident.AssetDetail
		vars["AssetName"] = a.AssetName
		vars["AssetIP"] = a.DomainIP
	}
	return vars
}

func renderTemplate(tmpl string, vars map[string]string) string {
	result := tmpl
	for k, v := range vars {
		result = strings.ReplaceAll(result, "{{."+k+"}}", v)
	}
	// 清理未被替换且有 {{if .X}} 块的内容：简单起见仅替换空变量
	for k := range vars {
		if vars[k] == "" {
			placeholder := "{{if ." + k + "}}"
			end := "{{end}}"
			for {
				start := strings.Index(result, placeholder)
				if start < 0 {
					break
				}
				endIdx := strings.Index(result[start:], end)
				if endIdx < 0 {
					break
				}
				result = result[:start] + result[start+endIdx+len(end):]
			}
		}
	}
	// 移除非空变量的 if/end 包裹
	for k := range vars {
		if vars[k] != "" {
			result = strings.ReplaceAll(result, "{{if ."+k+"}}", "")
			result = strings.ReplaceAll(result, "{{end}}", "")
		}
	}
	return result
}

const defaultSystemPrompt = "你是一名专业的网络安全分析师，擅长安全事件预审、漏洞分析和修复建议。请严格按照 JSON 格式输出，不要输出其他内容。"

func buildFallbackPrompt(incident *model.SecurityIncident, riskResult auditContract.RiskScoreResult) string {
	var sb strings.Builder
	sb.WriteString("请对以下安全事件进行专业预审分析，返回 JSON 格式（字段均为字符串）：\n")
	sb.WriteString(`{"vuln_desc":"漏洞描述","vuln_harm":"漏洞危害","fix_advice":"修复建议","opinion":"综合预审意见"}`)
	sb.WriteString("\n\n---\n事件信息：\n")
	sb.WriteString(fmt.Sprintf("事件名称：%s\n", incident.Name))
	sb.WriteString(fmt.Sprintf("事件等级：%s\n", model.IncidentLevelText[incident.Level]))
	sb.WriteString(fmt.Sprintf("风险评分：%.1f/100（%s）\n", riskResult.TotalScore, riskResult.Level))

	if incident.EventMetadata != nil {
		m := incident.EventMetadata
		if m.IncidentType != "" {
			sb.WriteString(fmt.Sprintf("事件类型：%s\n", m.IncidentType))
		}
		if m.CveId != "" {
			sb.WriteString(fmt.Sprintf("CVE编号：%s\n", m.CveId))
		}
		if m.CvssScore > 0 {
			sb.WriteString(fmt.Sprintf("CVSS评分：%.1f\n", m.CvssScore))
		}
		if m.IncidentDescription != "" {
			desc := m.IncidentDescription
			if len(desc) > 1000 {
				desc = desc[:1000] + "..."
			}
			sb.WriteString(fmt.Sprintf("事件描述：%s\n", desc))
		}
	}

	if incident.AssetDetail != nil {
		a := incident.AssetDetail
		if a.AssetName != "" {
			sb.WriteString(fmt.Sprintf("资产名称：%s\n", a.AssetName))
		}
		if a.DomainIP != "" {
			sb.WriteString(fmt.Sprintf("域名/IP：%s\n", a.DomainIP))
		}
	}

	return sb.String()
}

func (s *serviceAudit) AIClassify(ctx context.Context, id string) (*auditContract.ClassifyResult, error) {
	sess := s.session()

	var incident model.SecurityIncident
	if err := sess.WithContext(ctx).
		Preload("AssetDetail").
		Preload("EventMetadata").
		First(&incident, "id = ?", id).Error; err != nil {
		return nil, fmt.Errorf("事件不存在: %w", err)
	}

	result := ClassifyIncident(&incident)

	tagsStr := strings.Join(result.Tags, ",")
	updates := map[string]interface{}{
		"ai_tags":     tagsStr,
		"ai_category": result.Category,
	}
	if err := sess.WithContext(ctx).Model(&model.SecurityIncident{}).
		Where("id = ?", id).Updates(updates).Error; err != nil {
		return nil, fmt.Errorf("更新事件分类结果失败: %w", err)
	}

	return &result, nil
}
