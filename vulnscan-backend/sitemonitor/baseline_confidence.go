package sitemonitor

import (
	"context"
	"fmt"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

const (
	stableRunsForMedium = 3
	stableRunsForHigh   = 7
)

func TryUpgradeBaselineConfidence(ctx context.Context, db *gorm.DB, baseline *model.MonitorBaseline, contentUnchanged bool) error {
	if baseline == nil || baseline.Confidence == model.BaselineConfidenceHigh {
		return nil
	}

	updates := map[string]any{}

	if contentUnchanged {
		newRuns := baseline.ConsecutiveStableRuns + 1
		updates["consecutive_stable_runs"] = newRuns

		switch {
		case baseline.Confidence == model.BaselineConfidenceLow && newRuns >= stableRunsForMedium:
			updates["confidence"] = model.BaselineConfidenceMedium
		case baseline.Confidence == model.BaselineConfidenceMedium && newRuns >= stableRunsForHigh:
			updates["confidence"] = model.BaselineConfidenceHigh
		}
	} else {
		updates["consecutive_stable_runs"] = 0
	}

	if baseline.WaybackVerified && !baseline.CrossValidated {
		if c, ok := updates["confidence"].(string); ok && c == model.BaselineConfidenceMedium {
			// already medium, keep it
		} else if baseline.Confidence == model.BaselineConfidenceLow {
			updates["confidence"] = model.BaselineConfidenceMedium
		}
	}

	if baseline.WaybackVerified && baseline.CrossValidated && baseline.SuspicionScore < 20 {
		updates["confidence"] = model.BaselineConfidenceHigh
	}

	if len(updates) == 0 {
		return nil
	}
	return db.WithContext(ctx).Model(&model.MonitorBaseline{}).
		Where("id = ?", baseline.ID).Updates(updates).Error
}

func MarkWaybackVerified(ctx context.Context, db *gorm.DB, baselineID string, verified bool) error {
	return db.WithContext(ctx).Model(&model.MonitorBaseline{}).
		Where("id = ?", baselineID).
		Update("wayback_verified", verified).Error
}

func MarkCrossValidated(ctx context.Context, db *gorm.DB, baselineID string, validated bool) error {
	return db.WithContext(ctx).Model(&model.MonitorBaseline{}).
		Where("id = ?", baselineID).
		Update("cross_validated", validated).Error
}

func ManualConfirmBaseline(ctx context.Context, db *gorm.DB, baselineID, confirmedBy string) error {
	return db.WithContext(ctx).Model(&model.MonitorBaseline{}).
		Where("id = ?", baselineID).
		Updates(map[string]any{
			"confidence":   model.BaselineConfidenceHigh,
			"confirmed_by": confirmedBy,
		}).Error
}

func ShouldAlertOnTamper(baseline *model.MonitorBaseline) bool {
	if baseline == nil {
		return false
	}
	return baseline.Confidence == model.BaselineConfidenceMedium ||
		baseline.Confidence == model.BaselineConfidenceHigh
}

func DescribeConfidence(baseline *model.MonitorBaseline) string {
	if baseline == nil {
		return "无基线"
	}
	switch baseline.Confidence {
	case model.BaselineConfidenceLow:
		return fmt.Sprintf("低置信度（连续稳定 %d 次，需 %d 次升至中）",
			baseline.ConsecutiveStableRuns, stableRunsForMedium)
	case model.BaselineConfidenceMedium:
		return fmt.Sprintf("中置信度（连续稳定 %d 次，需 %d 次升至高）",
			baseline.ConsecutiveStableRuns, stableRunsForHigh)
	case model.BaselineConfidenceHigh:
		return "高置信度"
	default:
		return "未知"
	}
}
