package scanrunner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"code.yt-security.com/public/access/ai"
	"code.yt-security.com/public/scanengine/core"
	"code.yt-security.com/public/scanengine/module/screenshot"

	"vulnscan-backend/knowledge/aiverify"
	"vulnscan-backend/model"
)

// evidenceEnrichVulnFindings asynchronously captures screenshots and triggers
// AI verification for vulnerability-category findings that were just persisted.
func (r *Runner) evidenceEnrichVulnFindings(records []model.ScanFinding) {
	var vulnRecords []model.ScanFinding
	for _, rec := range records {
		if rec.Category == model.FindingCategoryVuln {
			vulnRecords = append(vulnRecords, rec)
		}
	}
	if len(vulnRecords) == 0 {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		r.captureVulnScreenshots(ctx, vulnRecords)
	}()

	if r.eventBridge != nil && r.eventBridge.chatSvc != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			r.aiVerifyVulnFindings(ctx, vulnRecords, r.eventBridge.chatSvc)
		}()
	}
}

// captureVulnScreenshots captures a page screenshot for each web-based
// vulnerability finding and writes the base64 data into its Data field.
func (r *Runner) captureVulnScreenshots(ctx context.Context, records []model.ScanFinding) {
	mod := screenshot.New()
	captured := 0

	for _, rec := range records {
		if ctx.Err() != nil {
			break
		}
		if rec.Data != nil {
			if _, ok := rec.Data["screenshot"]; ok {
				continue
			}
		}

		targetURL := buildEvidenceURL(rec)
		if targetURL == "" {
			continue
		}

		capCtx, capCancel := context.WithTimeout(ctx, 20*time.Second)
		target := &core.Target{URL: targetURL}
		result, err := mod.Run(capCtx, []*core.Target{target}, nil)
		capCancel()

		if err != nil || result == nil || len(result.Findings) == 0 {
			continue
		}

		for _, f := range result.Findings {
			b64, ok := f.Data["screenshot"]
			if !ok || b64 == "" {
				continue
			}
			if len(b64) > 2*1024*1024 {
				continue
			}
			data := rec.Data
			if data == nil {
				data = model.JSONMap{}
			}
			data["screenshot"] = b64

			if err := r.db.Model(&model.ScanFinding{}).
				Where("id = ?", rec.ID).
				Update("data", data).Error; err != nil {
				slog.Warn("[EvidenceEnrich] 截图回写失败",
					"finding_id", rec.ID, "error", err)
			} else {
				captured++
			}
			break
		}
	}

	if captured > 0 {
		slog.Info("[EvidenceEnrich] 漏洞证据截图已采集",
			"task_id", r.task.ID, "captured", captured, "total", len(records))
	}
}

// aiVerifyVulnFindings runs AI verification on vulnerability findings, writing
// the verification result (confidence, reasoning, verification_detail) back.
func (r *Runner) aiVerifyVulnFindings(ctx context.Context, records []model.ScanFinding, chatSvc ai.Service) {
	svc := aiverify.NewService(chatSvc, "")
	verified := 0

	for _, rec := range records {
		if ctx.Err() != nil {
			break
		}
		if rec.Data != nil {
			if _, ok := rec.Data["ai_verified"]; ok {
				continue
			}
		}

		req := buildVerifyReqFromFinding(rec)
		if req == nil {
			continue
		}

		result, err := svc.Verify(ctx, req)
		if err != nil {
			slog.Debug("[EvidenceEnrich] AI验证调用失败",
				"finding_id", rec.ID, "error", err)
			continue
		}

		updates := map[string]any{}
		data := rec.Data
		if data == nil {
			data = model.JSONMap{}
		}

		data["ai_verified"] = "true"
		data["ai_verify_confidence"] = result.Confidence
		data["ai_verify_reasoning"] = result.Reasoning
		data["ai_verify_is_vulnerable"] = result.IsVulnerable
		if result.FalseReason != "" {
			data["ai_verify_false_reason"] = result.FalseReason
		}
		if result.Suggestion != "" {
			data["ai_verify_suggestion"] = result.Suggestion
		}
		updates["data"] = data

		if rec.VerificationDetail == "" && result.Reasoning != "" {
			detail := truncateStr(result.Reasoning, 200)
			updates["verification_detail"] = detail
		}

		if result.IsVulnerable && result.Confidence >= 80 {
			updates["verification_level"] = "exploit"
		}

		if result.Confidence > 0 && rec.Confidence < result.Confidence {
			updates["confidence"] = result.Confidence
			reason := rec.ConfidenceReason
			if reason == "" {
				reason = "AI验证置信度"
			} else {
				reason += "; AI验证置信度: " + fmt.Sprintf("%d%%", result.Confidence)
			}
			updates["confidence_reason"] = reason
		}

		if err := r.db.Model(&model.ScanFinding{}).
			Where("id = ?", rec.ID).
			Updates(updates).Error; err != nil {
			slog.Warn("[EvidenceEnrich] AI验证结果回写失败",
				"finding_id", rec.ID, "error", err)
		} else {
			verified++
		}
	}

	if verified > 0 {
		slog.Info("[EvidenceEnrich] AI漏洞验证已完成",
			"task_id", r.task.ID, "verified", verified, "total", len(records))
	}
}

func buildEvidenceURL(rec model.ScanFinding) string {
	if rec.Data != nil {
		if u, ok := rec.Data["url"].(string); ok && strings.Contains(u, "://") {
			return u
		}
		if u, ok := rec.Data["matched_at"].(string); ok && strings.Contains(u, "://") {
			return u
		}
	}
	target := strings.TrimSpace(rec.Target)
	if target == "" {
		return ""
	}
	if strings.Contains(target, "://") {
		return target
	}
	port := rec.Port
	if port == 443 {
		return "https://" + target
	}
	if port > 0 {
		return fmt.Sprintf("http://%s:%d", target, port)
	}
	return "http://" + target
}

func buildVerifyReqFromFinding(rec model.ScanFinding) *aiverify.VerifyRequest {
	vulnType := rec.Type
	if vulnType == "" {
		return nil
	}
	target := ""
	if rec.Data != nil {
		if u, ok := rec.Data["url"].(string); ok {
			target = u
		}
	}
	if target == "" {
		target = rec.Target
	}

	payload := dataStrFromMap(rec.Data, "payload")
	request := dataStrFromMap(rec.Data, "request")
	response := dataStrFromMap(rec.Data, "response")

	if request == "" && payload == "" && rec.Evidence == "" {
		return nil
	}

	baseReq := ""
	baseResp := ""
	attackReq := request
	attackResp := response

	waf := dataStrFromMap(rec.Data, "waf")
	extra := ""
	if rec.Evidence != "" {
		extra = "Evidence: " + truncateStr(rec.Evidence, 500)
	}

	return &aiverify.VerifyRequest{
		VulnType:   vulnType,
		Target:     target,
		Payload:    payload,
		BaseReq:    baseReq,
		BaseResp:   baseResp,
		AttackReq:  attackReq,
		AttackResp: attackResp,
		WAFName:    waf,
		Extra:      extra,
	}
}

func dataStrFromMap(m model.JSONMap, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	switch s := v.(type) {
	case string:
		return s
	default:
		b, _ := json.Marshal(s)
		return string(b)
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ExportEvidenceReport generates a structured evidence report for a finding.
type EvidenceReport struct {
	FindingID     string `json:"finding_id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	Target        string `json:"target"`
	Port          int    `json:"port"`
	VulnType      string `json:"vuln_type"`
	Description   string `json:"description"`
	Confidence    int    `json:"confidence"`
	ConfReason    string `json:"confidence_reason"`
	VerifyLevel   string `json:"verification_level"`
	VerifyDetail  string `json:"verification_detail"`
	Evidence      string `json:"evidence"`
	Payload       string `json:"payload,omitempty"`
	MatchedAt     string `json:"matched_at,omitempty"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
	CurlCommand   string `json:"curl_command,omitempty"`
	Screenshot    string `json:"screenshot,omitempty"`
	CveID         string `json:"cve_id,omitempty"`
	CvssScore     string `json:"cvss_score,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	CreatedAt     string `json:"created_at"`
	AIVerified    bool   `json:"ai_verified"`
	AIReasoning   string `json:"ai_reasoning,omitempty"`
	AISuggestion  string `json:"ai_suggestion,omitempty"`
	AIFalseReason string `json:"ai_false_reason,omitempty"`
}

func BuildEvidenceReport(f *model.ScanFinding) *EvidenceReport {
	r := &EvidenceReport{
		FindingID:    f.ID,
		Title:        f.Title,
		Severity:     f.Severity,
		Target:       f.Target,
		Port:         f.Port,
		VulnType:     f.Type,
		Description:  f.Description,
		Confidence:   f.Confidence,
		ConfReason:   f.ConfidenceReason,
		VerifyLevel:  f.VerificationLevel,
		VerifyDetail: f.VerificationDetail,
		Evidence:     f.Evidence,
		CreatedAt:    f.CreatedAt.Format("2006-01-02 15:04:05"),
	}

	if f.Data != nil {
		r.Payload = dataStrFromMap(f.Data, "payload")
		r.MatchedAt = dataStrFromMap(f.Data, "matched_at")
		r.Request = dataStrFromMap(f.Data, "request")
		r.Response = dataStrFromMap(f.Data, "response")
		r.CurlCommand = dataStrFromMap(f.Data, "curl_command")
		r.CveID = dataStrFromMap(f.Data, "cve_id")
		if r.CveID == "" {
			r.CveID = dataStrFromMap(f.Data, "cve")
		}
		r.CvssScore = dataStrFromMap(f.Data, "cvss_score")
		r.Remediation = dataStrFromMap(f.Data, "remediation")
		if r.Remediation == "" {
			r.Remediation = dataStrFromMap(f.Data, "solution")
		}

		if dataStrFromMap(f.Data, "ai_verified") == "true" {
			r.AIVerified = true
			r.AIReasoning = dataStrFromMap(f.Data, "ai_verify_reasoning")
			r.AISuggestion = dataStrFromMap(f.Data, "ai_verify_suggestion")
			r.AIFalseReason = dataStrFromMap(f.Data, "ai_verify_false_reason")
		}

		if ss := dataStrFromMap(f.Data, "screenshot"); ss != "" {
			if _, err := base64.StdEncoding.DecodeString(ss[:min(100, len(ss))]); err == nil {
				r.Screenshot = ss
			}
		}
	}

	return r
}
