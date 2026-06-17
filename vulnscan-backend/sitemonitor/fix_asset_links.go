package sitemonitor

import (
	"log/slog"
	"net/url"
	"strings"

	"vulnscan-backend/model"

	"gorm.io/gorm"
)

type fixAssetRow struct {
	ID      string
	Domain  string
	IPv4    string
	Address string
}

func fixAssetLinks(db *gorm.DB) (int, error) {
	type targetRow struct {
		ID          string
		AssetID     string
		TargetValue string
	}
	var targets []targetRow
	db.Model(&model.MonitorTarget{}).
		Select("id, asset_id, target_value").
		Where("asset_id != ''").
		Find(&targets)

	if len(targets) == 0 {
		return 0, nil
	}

	assetIDs := make([]string, 0, len(targets))
	for _, t := range targets {
		assetIDs = append(assetIDs, t.AssetID)
	}

	var assets []fixAssetRow
	db.Model(&model.Asset{}).
		Select("id, domain, ipv4, address").
		Where("id IN ?", assetIDs).
		Find(&assets)

	assetMap := make(map[string]*fixAssetRow, len(assets))
	for i := range assets {
		assetMap[assets[i].ID] = &assets[i]
	}

	fixed := 0
	for _, t := range targets {
		asset, ok := assetMap[t.AssetID]
		if !ok {
			slog.Info("[FixAssetLinks] 清除无效关联: asset 不存在",
				"target_id", t.ID, "asset_id", t.AssetID)
			db.Model(&model.MonitorTarget{}).Where("id = ?", t.ID).
				Update("asset_id", "")
			fixed++
			continue
		}

		tv := strings.ToLower(strings.TrimSpace(t.TargetValue))
		if !assetMatchesTarget(asset, tv) {
			slog.Info("[FixAssetLinks] 清除不匹配关联",
				"target_id", t.ID, "target_value", tv,
				"asset_domain", asset.Domain, "asset_ipv4", asset.IPv4)
			db.Model(&model.MonitorTarget{}).Where("id = ?", t.ID).
				Update("asset_id", "")
			fixed++
		}
	}

	if fixed > 0 {
		db.Model(&model.MonitorPathTask{}).
			Where("asset_id != '' AND asset_id NOT IN (?)",
				db.Model(&model.Asset{}).Select("id"),
			).Update("asset_id", "")
	}

	return fixed, nil
}

func assetMatchesTarget(asset *fixAssetRow, targetValue string) bool {
	if asset.Domain != "" && strings.ToLower(strings.TrimSpace(asset.Domain)) == targetValue {
		return true
	}
	if asset.IPv4 != "" && strings.ToLower(strings.TrimSpace(asset.IPv4)) == targetValue {
		return true
	}
	if asset.Address != "" {
		addr := strings.TrimSpace(asset.Address)
		if u, err := url.Parse(addr); err == nil && u.Hostname() != "" {
			if strings.ToLower(u.Hostname()) == targetValue {
				return true
			}
		}
		if strings.ToLower(addr) == targetValue {
			return true
		}
	}
	return false
}
