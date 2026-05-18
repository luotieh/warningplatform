package migration

import (
	"encoding/json"
	"log/slog"

	"vulnscan-backend/model"
	"vulnscan-backend/pkg/assetextra"

	"gorm.io/gorm"
)

func init() {
	Register("005_asset_region_code", "资产表增加地域编码并回填", func(tx *gorm.DB) error {
		if !tx.Migrator().HasColumn("vs_asset", "region_code") {
			if err := tx.Exec("ALTER TABLE vs_asset ADD COLUMN region_code VARCHAR(12) DEFAULT ''").Error; err != nil {
				return err
			}
		}
		if err := tx.Exec("CREATE INDEX IF NOT EXISTS idx_asset_region_code ON vs_asset(region_code)").Error; err != nil {
			slog.Warn("[Migration] idx_asset_region_code 跳过", "error", err)
		}

		var assets []model.Asset
		if err := tx.Find(&assets).Error; err != nil {
			return err
		}
		for _, a := range assets {
			if a.RegionCode != "" {
				continue
			}
			code := assetextra.RegionCodeFromMap(a.Extra)
			if code == "" {
				continue
			}
			if err := tx.Model(&model.Asset{}).Where("id = ?", a.ID).Update("region_code", code).Error; err != nil {
				return err
			}
			if a.Extra != nil {
				normalized := assetextra.NormalizeMap(a.Extra)
				raw, err := json.Marshal(normalized)
				if err != nil {
					return err
				}
				if err := tx.Model(&model.Asset{}).Where("id = ?", a.ID).Update("extra", string(raw)).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}
