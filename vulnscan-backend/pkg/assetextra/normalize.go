package assetextra

import "vulnscan-backend/model"

// NormalizeMap 清理 extra：剔除单位档案副本、region_code 等已独立落库的字段。
func NormalizeMap(extra model.JSONMap) model.JSONMap {
	if extra == nil {
		return model.JSONMap{}
	}
	out := make(model.JSONMap, len(extra))
	for k, v := range extra {
		if k == KeyRegionCode || IsUnitProfileKey(k) {
			continue
		}
		out[k] = v
	}
	return out
}

// RegionCodeFromMap 从 extra 读取历史 region_code（迁移回填用）。
func RegionCodeFromMap(extra model.JSONMap) string {
	if extra == nil {
		return ""
	}
	if v, ok := extra[KeyRegionCode].(string); ok {
		return v
	}
	return ""
}
