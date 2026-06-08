package sitemonitor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	"vulnscan-backend/model"

	"code.yt-security.com/public/core/generate/ulid"
	"gorm.io/gorm"
)

func GetActiveBaseline(ctx context.Context, db *gorm.DB, rawURL string) (*model.MonitorBaseline, error) {
	uh := urlHash(rawURL)
	var baseline model.MonitorBaseline
	err := db.WithContext(ctx).
		Where("url_hash = ? AND is_active = ?", uh, true).
		Order("version DESC").
		First(&baseline).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	return &baseline, nil
}

func SaveBaselineFromUpdate(ctx context.Context, tx *gorm.DB, executionID, url, agentID string, bu *model.MonitorBaselineUpdate) error {
	if bu == nil {
		return nil
	}
	if strings.TrimSpace(bu.ContentHash) == "" {
		return fmt.Errorf("baseline content_hash is empty, skip save")
	}
	uh := urlHash(url)

	var exists int64
	if err := tx.Model(&model.MonitorBaseline{}).Where("execution_id = ?", executionID).Count(&exists).Error; err != nil {
		return fmt.Errorf("baseline idempotency check: %w", err)
	}
	if exists > 0 {
		return nil
	}

	var maxVersion int
	if err := tx.Raw("SELECT COALESCE(MAX(version), 0) FROM monitor_baselines WHERE url_hash = ?", uh).
		Scan(&maxVersion).Error; err != nil {
		return fmt.Errorf("baseline version query: %w", err)
	}

	if err := tx.Model(&model.MonitorBaseline{}).
		Where("url_hash = ? AND is_active = ?", uh, true).
		Update("is_active", false).Error; err != nil {
		return fmt.Errorf("deactivate old baseline: %w", err)
	}

	exemptJSON, _ := json.Marshal(bu.ExemptSelectors)
	extResJSON, _ := json.Marshal(bu.ExternalResources)

	confidence := model.BaselineConfidenceLow
	if bu.SuspicionScore == 0 {
		confidence = model.BaselineConfidenceMedium
	}

	baseline := model.MonitorBaseline{
		URL:                   url,
		URLHash:               uh,
		Version:               maxVersion + 1,
		IsActive:              true,
		ExecutionID:           executionID,
		ContentHash:           bu.ContentHash,
		Simhash:               bu.Simhash,
		DomStructureHash:      bu.DomStructureHash,
		VisualHash:            bu.VisualHash,
		Title:                 bu.Title,
		StatusCode:            bu.StatusCode,
		VisibleTextLength:     bu.VisibleTextLength,
		BodyText:              bu.BodyText,
		ExemptSelectorsJSON:   string(exemptJSON),
		ExternalResourcesJSON: string(extResJSON),
		ObjKeyHTML:            bu.ObjKeyHTML,
		ObjKeyText:            bu.ObjKeyText,
		ObjKeyScreenshot:      bu.ObjKeyScreenshot,
		AgentID:               agentID,
		ConfirmedBy:           bu.ConfirmedBy,
		Confidence:            confidence,
		SuspicionScore:        bu.SuspicionScore,
		SuspicionDetail:       bu.SuspicionDetail,
	}
	baseline.ID = ulid.GenerateID()
	return tx.Create(&baseline).Error
}

func urlHash(rawURL string) string {
	h := sha256.Sum256([]byte(rawURL))
	return fmt.Sprintf("%x", h[:8])
}

func baselineToMetadata(bl *model.MonitorBaseline) *model.MonitorBaselineMetadata {
	if bl == nil {
		return nil
	}
	return &model.MonitorBaselineMetadata{
		Version:           bl.Version,
		Simhash:           bl.Simhash,
		ContentHash:       bl.ContentHash,
		DomStructureHash:  bl.DomStructureHash,
		VisualHash:        bl.VisualHash,
		Title:             bl.Title,
		StatusCode:        bl.StatusCode,
		VisibleTextLength: bl.VisibleTextLength,
		ObjKeyHTML:        bl.ObjKeyHTML,
		ObjKeyText:        bl.ObjKeyText,
		ObjKeyScreenshot:  bl.ObjKeyScreenshot,
		Confidence:        bl.Confidence,
		SuspicionScore:    bl.SuspicionScore,
	}
}
