package sitemonitor

import (
	"context"
	"encoding/json"
	"fmt"
	"vulnscan-backend/model"

	"gorm.io/gorm"
)

func (s *NatsServiceImpl) saveSensitiveWordResult(tx *gorm.DB, execID, taskID string, r *model.MonitorSensitiveWordResult) error {
	summaryJSON, _ := json.Marshal(r.MatchSummary)
	prepJSON, _ := json.Marshal(r.Preprocessing)

	result := model.MonitorResultSensitiveWord{
		ExecutionID:        execID,
		TaskID:             taskID,
		URL:                r.URL,
		HasHit:             r.HasHit,
		TotalMatches:       r.TotalMatches,
		ScanTimeMs:         int(r.ScanTimeMs),
		SkippedIncremental: r.SkippedIncremental,
		MatchSummaryJSON:   string(summaryJSON),
		PreprocessingJSON:  string(prepJSON),
	}
	if err := tx.Create(&result).Error; err != nil {
		return fmt.Errorf("save word result: %w", err)
	}

	if len(r.Matches) == 0 {
		return nil
	}
	matches := make([]model.MonitorResultSensitiveWordMatch, 0, len(r.Matches))
	for _, m := range r.Matches {
		ctxStr := ""
		if len(m.Contexts) > 0 {
			ctxJSON, _ := json.Marshal(m.Contexts)
			ctxStr = string(ctxJSON)
		}
		layer := ""
		if len(m.MatchLayers) > 0 {
			layer = m.MatchLayers[0]
		}
		severity := m.Severity
		if severity == "" {
			severity = "medium"
		}
		matches = append(matches, model.MonitorResultSensitiveWordMatch{
			ResultID: result.ID,
			Word:     m.Word,
			Category: m.Category,
			Severity: severity,
			Count:    m.Count,
			Context:  ctxStr,
			Layer:    layer,
		})
	}
	if err := tx.CreateInBatches(matches, 100).Error; err != nil {
		return fmt.Errorf("save word matches: %w", err)
	}
	return nil
}

func (s *NatsServiceImpl) saveBaselineFromResult(tx *gorm.DB, executionID, url, agentID string, bu *model.MonitorBaselineUpdate) error {
	ctx := context.Background()
	return s.SaveBaselineFromAgent(ctx, tx, executionID, url, agentID, bu)
}

func (s *NatsServiceImpl) saveSensitiveFileResult(tx *gorm.DB, execID, taskID string, r *model.MonitorSensitiveFileResult) error {
	cmsJSON, _ := json.Marshal(r.CmsDetected)
	riskJSON, _ := json.Marshal(r.Stats.RiskSummary)

	dirJSON := "false"
	if r.DirectoryListing {
		dirJSON = "true"
	}

	result := model.MonitorResultSensitiveFile{
		ExecutionID:          execID,
		TaskID:               taskID,
		URL:                  r.URL,
		HasHit:               r.HasHit,
		TotalChecked:         r.Stats.TotalChecked,
		TotalFindings:        r.Stats.TotalFindings,
		TotalProbeMs:         r.Stats.TotalProbeMs,
		CmsDetectedJSON:      string(cmsJSON),
		DirectoryListingJSON: dirJSON,
		RiskSummaryJSON:      string(riskJSON),
	}
	if err := tx.Create(&result).Error; err != nil {
		return fmt.Errorf("save file result: %w", err)
	}

	if len(r.Findings) == 0 {
		return nil
	}
	findings := make([]model.MonitorResultSensitiveFileFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		evidence := f.Detail
		findings = append(findings, model.MonitorResultSensitiveFileFinding{
			ResultID:      result.ID,
			Path:          f.Path,
			StatusCode:    f.StatusCode,
			Mark:          f.Mark,
			Risk:          f.Risk,
			ContentLength: int64(f.ContentLength),
			ProbeMs:       int(f.ElapsedMs),
			Evidence:      evidence,
		})
	}
	if err := tx.CreateInBatches(findings, 100).Error; err != nil {
		return fmt.Errorf("save file findings: %w", err)
	}
	return nil
}
